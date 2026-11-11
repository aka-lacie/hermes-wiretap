"""wiretap: Hermes-native model-call capture for every provider.

Agent hooks (``pre_api_request`` / ``post_api_request`` / ``api_request_error``) feed ``collector/capture.py``,
which writes per-call telemetry (timing, TTFB, tokens, cache hit, cost) and — unless ``capture_payloads`` is
off — the compiled request and the response into ``$HERMES_HOME/plugin-data/wiretap/telemetry.db``
(SQLite, 0600). The dashboard tab reads that store directly; no proxy or collector service is required.

When proxy logs are configured or detected, the optional CLIProxyAPI extension
enriches the same rows. Stock installations load no extension and start no poller.

The hooks never disturb a turn: they snapshot and enqueue (a background thread writes), and swallow every error.
"""
from __future__ import annotations

import importlib.util
import logging
import sys
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("wiretap")
_CAPTURE_KEY = "_wiretap_capture"
_DEFAULTS = {"enabled": True, "capture_payloads": True, "retention_hours": 72.0, "max_request_mb": 64.0}


_CAPTURE_SIBLINGS = ("_wiretap_store", "_wiretap_inspector", "_wiretap_telemetry",
                     "_wiretap_poller", "_wiretap_signals", "_wiretap_forensics")
_HERE = Path(__file__).resolve().parent / "collector"


_PRIVATE_LOCK = threading.RLock()


def _private(key: str, name: str):
    with _PRIVATE_LOCK:
        mod = sys.modules.get(key)
        if mod is None:
            spec = importlib.util.spec_from_file_location(key, _HERE / name)
            if spec is None or spec.loader is None:
                raise ImportError(f"wiretap: cannot load collector/{name}")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            try:
                mod._mt_loaded_mtime = Path(mod.__file__).stat().st_mtime
            except Exception:
                pass
            sys.modules[key] = mod
        return mod


_PROXY_ENABLED = True
_PROXY_INTERVAL = None
_PROXY_LOG_DIR = None


def _start_poller(interval: Any = None, force: bool = False) -> None:
    """Cheap activity-driven discovery; the adapter imports the extension only when eligible."""
    if not _PROXY_ENABLED:
        return
    try:
        poller = _private("_wiretap_poller", "poller.py")
        if not poller.enabled():
            return
        tel = _private("_wiretap_telemetry", "telemetry.py")
        poller.maybe_start(tel, interval=interval or _PROXY_INTERVAL,
                           configured=_PROXY_LOG_DIR, force=force)
    except Exception:
        logger.debug("wiretap proxy poller not started", exc_info=True)


def _stale(mod) -> bool:
    """A cached module whose source changed on disk since it was loaded (plugin reload after an update).

    A module without a load stamp (a sibling another collector module loaded lazily, e.g. signals) is adopted with
    its file's current mtime, not treated as stale: treating it as stale retired the whole capture module on the
    next hook — and with it every armed call and the tap's counters — each time a sibling was first loaded."""
    try:
        mt = Path(mod.__file__).stat().st_mtime
        if not hasattr(mod, "_mt_loaded_mtime"):
            mod._mt_loaded_mtime = mt
            return False
        return mt > mod._mt_loaded_mtime
    except Exception:
        return False


def _capture():
    """collector/capture.py, loaded once under a private module name (no sys.path mutation).

    A ``hermes plugins`` reload re-runs register(); if the collector sources changed meanwhile, the old copies
    (and their writer thread) are retired so the running gateway picks up the new code without a restart."""
    mod = sys.modules.get(_CAPTURE_KEY)
    sibs = [sys.modules.get(k) for k in _CAPTURE_SIBLINGS]
    if mod is not None and (_stale(mod) or any(s is not None and _stale(s) for s in sibs)):
        try:
            mod._writer.stop(2.0)
        except Exception:
            pass
        for k in (_CAPTURE_KEY, *_CAPTURE_SIBLINGS):
            sys.modules.pop(k, None)
        mod = None
    if mod is None:
        spec = importlib.util.spec_from_file_location(_CAPTURE_KEY, Path(__file__).resolve().parent / "collector" / "capture.py")
        if spec is None or spec.loader is None:
            raise ImportError("wiretap: cannot load collector/capture.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_CAPTURE_KEY] = mod
        spec.loader.exec_module(mod)
        for m in (mod, *(sys.modules.get(k) for k in _CAPTURE_SIBLINGS)):
            if m is not None:
                try:
                    m._mt_loaded_mtime = Path(m.__file__).stat().st_mtime
                except Exception:
                    pass
    return mod


def _debug(message: str) -> None:
    """Even a failing log sink (for example ENOSPC) must not escape a hook."""
    try:
        logger.debug(message, exc_info=True)
    except Exception:
        pass


def _on_pre_api_request(**kw: Any) -> None:
    try:
        _start_poller()
        _capture().on_pre(kw)
    except Exception:
        _debug("wiretap pre_api_request failed")


def _on_post_api_request(**kw: Any) -> None:
    try:
        _capture().on_post(kw)
    except Exception:
        _debug("wiretap post_api_request failed")


def _on_api_request_error(**kw: Any) -> None:
    try:
        _capture().on_error(kw)
    except Exception:
        _debug("wiretap api_request_error failed")


def _coerce(key: str, val: Any) -> Any:
    default = _DEFAULTS[key]
    if isinstance(default, bool):
        return val if isinstance(val, bool) else str(val).strip().lower() in ("1", "true", "yes", "on")
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def _cli_process() -> bool:
    """This process is ``hermes wiretap …`` (a read-only CLI run): no tap, no poller, no store writes from here."""
    return "wiretap" in sys.argv[1:4]


def _cli_setup(parser: Any) -> None:
    _private("_wiretap_cli", "cli.py").build_parser(parser)


def _cli_run(args: Any) -> None:
    rc = _private("_wiretap_cli", "cli.py").run(args)
    if rc:
        raise SystemExit(rc)


def _register_cli(ctx: Any) -> None:
    """``hermes wiretap …`` — the same read-only CLI as ``bin/wiretap`` (hosts without register_cli_command skip it)."""
    if not hasattr(ctx, "register_cli_command"):
        return
    try:
        ctx.register_cli_command(
            "wiretap", "Wiretap: read-only CLI over captured model calls and sessions", _cli_setup, _cli_run,
            description="Inspect captured model calls (signals, request layers, thinking, raw streams, diffs), "
                        "sessions, searches and costs without SQL. Read-only.")
    except Exception:
        logger.debug("wiretap: wiretap CLI not registered", exc_info=True)


def register(ctx: Any) -> None:
    global _PROXY_ENABLED, _PROXY_INTERVAL, _PROXY_LOG_DIR
    _register_cli(ctx)
    if _cli_process():
        return
    cap = _capture()
    for key in _DEFAULTS:
        try:
            val = ctx.get_config(key, cap.store.plugin_setting(key, _DEFAULTS[key]))
            if val is not None:
                cap.SETTINGS[key] = _coerce(key, val)
        except Exception:
            pass
    try:
        cap.install_http_tap()
    except Exception:
        logger.debug("wiretap http tap not installed", exc_info=True)
    ctx.register_hook("pre_api_request", _on_pre_api_request)
    ctx.register_hook("post_api_request", _on_post_api_request)
    ctx.register_hook("api_request_error", _on_api_request_error)
    try:
        enabled = _coerce("enabled", ctx.get_config("proxy_poller", True))
        interval = ctx.get_config("poll_interval", None)
        log_dir = ctx.get_config("proxy_log_dir", None)
    except Exception:
        enabled, interval, log_dir = True, None, None
    _PROXY_ENABLED, _PROXY_INTERVAL, _PROXY_LOG_DIR = enabled, interval, log_dir
    if enabled:
        _start_poller(interval, force=True)
