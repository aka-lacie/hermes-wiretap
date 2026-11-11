"""Lightweight adapter for optional enrichment; importing it starts nothing.

Only the eligibility gate lives here. CLIProxyAPI path resolution, parsing and
polling live under extensions/. With no configured/detected logs those modules
are not imported and no background thread or telemetry store is created.

Absent default logs are rechecked on agent hooks/dashboard requests (30 seconds,
no idle discovery thread). Explicit missing paths start a poller which waits for
its directory, so late proxy startup needs no plugin reload.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from pathlib import Path

THREAD_NAME = "wiretap-poller"
DEFAULT_INTERVAL = 2.0
FILE_GAP_S = 0.05
DISCOVERY_INTERVAL = 30.0
_START_LOCK = threading.RLock()
_NEXT_CHECK = 0.0


def _load(name):
    key = f"_wiretap_{name}"
    if key not in sys.modules:
        path = Path(__file__).resolve().parent.parent / "extensions" / f"{name}.py"
        spec = importlib.util.spec_from_file_location(key, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"wiretap: cannot load optional extension {name}")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[key] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(key, None)
            raise
    return sys.modules[key]


def enabled() -> bool:
    """Specific setting wins, then the short alias, then the pre-rename name."""
    raw = next((os.environ[name] for name in
                ("WIRETAP_PROXY_POLLER", "WIRETAP_POLLER", "MODEL_TELEMETRY_POLLER")
                if name in os.environ), "1")
    return raw.strip().lower() not in ("0", "false", "no", "off")


def available(store, configured=None) -> bool:
    """Eligibility only: a core-only distribution never probes host proxy paths."""
    extensions = Path(__file__).resolve().parent.parent / "extensions"
    if not all((extensions / name).is_file() for name in ("cliproxy.py", "cliproxy_poller.py")):
        return False
    raw = os.environ.get("CLIPROXY_LOG_DIR") or configured or store.plugin_setting("proxy_log_dir") or ""
    return bool(str(raw).strip()) or (Path.home() / ".cli-proxy-api" / "logs").is_dir()


def running():
    return next((t for t in threading.enumerate()
                 if t.name == THREAD_NAME and hasattr(t, "stop") and t.is_alive()), None)


def start(tel, interval=DEFAULT_INTERVAL, configured=None, **kw):
    """Explicit start, gated on a configured path or a detected directory."""
    if not enabled() or not available(tel.store, configured):
        return None
    with _START_LOCK:
        # Legacy direct callers may already have obtained ingestion attributes
        # from telemetry; use the very same extension instance in that case.
        ext = tel._proxy_extension() if hasattr(tel, "_proxy_extension") else tel
        if configured is not None:
            ext._CONFIGURED_LOG_DIR = configured
            ext.LOG_DIR = ext.proxy_log_dir()
        # Database setup belongs to the poller thread, never the agent hook.
        return _load("cliproxy_poller").start(ext, interval=interval, **kw)


def maybe_start(tel, interval=None, configured=None, force=False):
    """Activity-driven discovery; no repeated imports/scans on ordinary agent calls."""
    global _NEXT_CHECK
    if not enabled():
        return None
    with _START_LOCK:
        active = running()
        if active is not None:
            return active
        now = time.monotonic()
        if not force and now < _NEXT_CHECK:
            return None
        _NEXT_CHECK = now + DISCOVERY_INTERVAL
        if str(tel.store.plugin_setting("proxy_poller", True)).strip().lower() in ("0", "false", "no", "off"):
            return None
        interval = interval or tel.store.plugin_setting("poll_interval", DEFAULT_INTERVAL) or DEFAULT_INTERVAL
        return start(tel, interval=float(interval), configured=configured)


def status(tel):
    """Health reporting without an optional import on a stock installation."""
    if not available(tel.store):
        return {"configured": False, "log_dir": None, "exists": False}
    ext = tel._proxy_extension()
    path = ext.proxy_log_dir()
    return {"configured": True, "log_dir": str(path) if path else None,
            "exists": bool(path and path.is_dir())}


def __getattr__(name):
    # Keep explicit collector/poller.py imports used by older tests/tools.
    if name == "Poller":
        return _load("cliproxy_poller").Poller
    raise AttributeError(name)
