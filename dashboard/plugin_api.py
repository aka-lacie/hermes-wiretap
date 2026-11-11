"""Wiretap · Wire & Cache Inspector dashboard backend (plugin ``wiretap``), mounted at ``/api/plugins/wiretap/``.

Read-only. The plugin's agent hooks (and, optionally, the proxy-log collector) write
``$HERMES_HOME/plugin-data/wiretap/telemetry.db``; these routes only read it and Hermes ``state.db``.
Before the first capture every route still answers (empty data plus a ``no_data`` hint) so the tab renders.

Routes:

* ``GET /calls?hours=&family=&provider=&session=&limit=&errors=``  per-call rows (with ``error_summary``) + aggregates +
  the window's families/providers
* ``GET /sessions?hours=``                      per-session counters + main-session context gauge
* ``GET /health``                               capture / proxy status and store paths
* ``GET /inspector/sessions?q=&limit=``         session switcher
* ``GET /inspector/session?id=&before=&limit=&inactive=``  classified transcript rows + wire correlation
* ``GET /inspector/compiled?id=&call=``         the session's newest (or a chosen) captured request aligned to its rows,
  plus its call history
* ``GET /inspector/prompt?id=``                 the system prompt state.db stored for the session
* ``GET /inspector/row?id=``                    one exact ``messages`` row
* ``GET /inspector/wire?id=&which=down|up``     wire-call summary (envelope keys, items, headers, parsed response)
* ``GET /inspector/wire/part?id=&part=request|item|key|response|response_raw&i=&key=&which=``
* ``GET /inspector/wire/readable?id=&part=item|sys|key&i=&key=&rows=&which=``  one item's exact wire text as runs:
  raw state.db content vs runtime wrappers and injected parts
* ``GET /inspector/calls?t0=&t1=``              captured wire calls in a window

Collector readers use private names and refresh automatically when their source files change.
Endpoints are plain ``def`` so FastAPI runs them in its threadpool (SQLite reads never block the event loop).
"""

from __future__ import annotations

import importlib.util
import hashlib
import json
import logging
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

router = APIRouter()

_COLLECTOR = Path(__file__).resolve().parent.parent / "collector"
_LOCK = threading.Lock()
_MOD: dict[str, Any] = {}
_PRIVATE = "_wiretap_dashboard_telemetry"
_READER_PREFIX = "_wiretap_dashboard_"
_LOG = logging.getLogger(__name__)


def _source_stamp():
    paths = [*(_COLLECTOR / f"{name}.py" for name in ("telemetry", "inspector", "store", "forensics")),
             _COLLECTOR.parent / "extensions" / "unified_sessions.py"]
    stamp = []
    for path in paths:
        try:
            stat = path.stat()
            stamp.append((str(path), stat.st_mtime_ns, stat.st_size))
        except OSError:
            stamp.append((str(path), None, None))
    return tuple(stamp)


def _reader_paths(stamp):
    """Resolve the host-bound profile on every request; never infer it from the last reader."""
    resolver = _MOD.get("resolver")
    if resolver is None or _MOD.get("resolver_stamp") != stamp[2]:
        try:
            path = _COLLECTOR / "store.py"
            spec = importlib.util.spec_from_file_location(_READER_PREFIX + "paths", path)
            if spec is None:
                raise RuntimeError("cannot load Wiretap path resolver")
            fresh = importlib.util.module_from_spec(spec)
            exec(compile(path.read_bytes(), str(path), "exec"), fresh.__dict__)
            resolver = fresh
            _MOD.update(resolver=resolver, resolver_stamp=stamp[2])
        except Exception:
            if resolver is None:
                raise
            _LOG.warning("Wiretap path resolver reload failed; retaining last good resolver", exc_info=True)
    return tuple(Path(p).resolve() for p in (resolver.hermes_home(), resolver.state_db(), resolver.db_path()))


def _telemetry() -> Any:
    """One reloadable reader generation per bound profile/store pair, safe in a multiplex server."""
    with _LOCK:
        stamp = _source_stamp()
        paths = _reader_paths(stamp)
        entries = _MOD.setdefault("readers", {})
        entry = entries.get(paths, {})
        previous = entry.get("t")
        if previous is not None and entry.get("stamp") == stamp:
            sys.modules[_PRIVATE] = previous  # compatibility alias, never used to select a profile
            return previous
        scope = hashlib.sha256("\0".join(map(str, paths)).encode()).hexdigest()[:16]
        prefix = _READER_PREFIX + scope + "_"
        keys = tuple(prefix + name for name in ("telemetry", "inspector", "store", "forensics", "unified_sessions"))
        saved = {key: sys.modules[key] for key in keys if key in sys.modules}
        try:
            for key in keys:
                sys.modules.pop(key, None)
            path = _COLLECTOR / "telemetry.py"
            spec = importlib.util.spec_from_file_location(prefix + "telemetry", path)
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load collector/telemetry.py")
            mod = importlib.util.module_from_spec(spec)
            setattr(mod, "_wiretap_sibling_prefix", prefix)
            sys.modules[keys[0]] = mod
            exec(compile(path.read_bytes(), str(path), "exec"), mod.__dict__)
            # Resolve once per *profile generation*, not once per dashboard process. All memoized
            # reads, inferred Bot Chat and inspector caches belong exclusively to these stores.
            for name, value in zip(("HERMES_HOME", "STATE_DB", "DB_PATH"), paths):
                setattr(mod, name, value)
        except Exception:
            for key in keys:
                sys.modules.pop(key, None)
            sys.modules.update(saved)
            if previous is None:
                raise  # never fall back to another profile's reader/data
            _LOG.warning("Wiretap reader reload failed; keeping this profile's last good modules", exc_info=True)
            return previous
        entries[paths] = {"t": mod, "stamp": stamp}
        _MOD.update(t=mod, stamp=stamp)
        sys.modules[_PRIVATE] = mod
        return mod


def _t():
    t = _telemetry()
    _start_poller(t)
    return t


_POLLER_LOCK = threading.Lock()


def _poller_adapter():
    key = "_wiretap_poller"
    with _POLLER_LOCK:
        mod = sys.modules.get(key)
        if mod is None:
            spec = importlib.util.spec_from_file_location(key, _COLLECTOR / "poller.py")
            if spec is None or spec.loader is None:
                raise RuntimeError("cannot load enrichment adapter")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            # No other request can observe a partially initialized adapter.
            sys.modules[key] = mod
        return mod


def _start_poller(t=None) -> None:
    """No boot thread on stock Hermes; discover late logs on dashboard activity."""
    try:
        t = t if t is not None else _telemetry()
        if str(t.store.plugin_setting("proxy_poller", True)).strip().lower() in ("0", "false", "no", "off"):
            return
        _poller_adapter().maybe_start(t)
    except Exception:
        pass


def _ins():
    return _telemetry().inspector


@contextmanager
def _tcon():
    """The telemetry store, or an empty in-memory one before the first capture (views still render)."""
    t = _t()
    con = t.store.connect_ro(t.DB_PATH) if t.DB_PATH.exists() else t.store.memory_store()
    try:
        yield con
    finally:
        con.close()


def _json(obj: Any) -> Response:
    # default=str covers sqlite Row leftovers; surrogatepass keeps odd provider bytes from 500ing a whole view.
    return Response(json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8", "surrogatepass"),
                    media_type="application/json", headers={"Cache-Control": "no-store"})


_VOLATILE = ("now",)


def _json_rev(obj: dict, rev: str = "") -> Response:
    """A view with ``rev``: a digest of everything it displays (not a guess at what changed). A poll that sends the
    revision it has gets ``{"unchanged": true}`` only when every displayed fact — alignment, attribution, flags,
    contents — is identical."""
    stable = {k: v for k, v in obj.items() if k not in _VOLATILE}
    body = json.dumps(stable, default=str, ensure_ascii=False, sort_keys=True).encode("utf-8", "surrogatepass")
    digest = hashlib.blake2b(body, digest_size=12).hexdigest()
    if rev and rev == digest:
        return _json({"unchanged": True, "rev": digest, "now": obj.get("now")})
    return _json(dict(obj, rev=digest))


def _q(**kw) -> dict:
    return {k: [str(v)] for k, v in kw.items() if v is not None}


@router.get("/health")
def health():
    t = _t()
    out: dict[str, Any] = {"db": str(t.DB_PATH), "db_exists": t.DB_PATH.exists(), "state_db": str(t.STATE_DB),
                           "main_session": t.main_session(), "now": time.time(), "wire_calls": 0, "calls": 0,
                           "proxy": _poller_adapter().status(t)}
    if t.DB_PATH.exists():
        with _tcon() as con:
            out["space"] = t.store.space(con)
            out["last_capture"] = t.store.kv_get(con, "last_capture")
            out["last_scan"] = t.store.kv_get(con, "last_scan")
            out["wire_calls"] = con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0]
            out["calls"] = con.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
            out["sources"] = {r[0] or "?": r[1] for r in con.execute("SELECT source, COUNT(*) FROM calls GROUP BY source")}
            out["proxy"]["merged"] = con.execute("SELECT COUNT(*) FROM calls WHERE proxy_rid IS NOT NULL").fetchone()[0]
    out["no_data"] = not out["calls"]
    return _json(out)


@router.get("/calls")
def calls(hours: float = 6, family: str = "all", session: str = "", provider: str = "", limit: int = 100, rev: str = "",
          offset: int = 0, page: int = 0, sort: str = "started", dir: str = "desc", misses: int = 0, slow: int = 0,
          errors: int = 0):
    return _json(_t().api_calls(_q(hours=hours, family=family, session=session, provider=provider, limit=limit, rev=rev or None,
                                   offset=offset, page=page or None, sort=sort, dir=dir, misses=misses or None, slow=slow or None,
                                   errors=errors or None)))


@router.get("/sessions")
def sessions(hours: float = 24):
    return _json(_t().api_sessions(_q(hours=hours)))


def _need_state(t) -> None:
    if not t.STATE_DB.exists():
        raise HTTPException(status_code=404, detail=f"no Hermes session store at {t.STATE_DB}")


@router.get("/inspector/sessions")
def inspector_sessions(q: str = "", limit: int = Query(150, le=500)):
    t = _t()
    _need_state(t)
    main = t.main_session()
    return _json({"sessions": _ins().sessions_list(t.STATE_DB, q, limit, main or ""), "main": main})


@router.get("/inspector/session")
def inspector_session(id: Optional[str] = None, before: Optional[int] = None,
                      limit: int = Query(250, le=1500), inactive: int = 0, rev: str = ""):
    t = _t()
    _need_state(t)
    sid = id or t.main_session()
    if not sid:
        raise HTTPException(status_code=404, detail="no session")
    with _tcon() as con:
        return _json_rev(_ins().session_view(t.STATE_DB, con, sid, before, limit, bool(inactive)), rev)


@router.get("/inspector/compiled")
def inspector_compiled(id: Optional[str] = None, layer: str = "wire", rev: str = "", lane: str = "main", call: str = ""):
    if lane not in ("main", "review", "all"):
        raise HTTPException(status_code=400, detail="lane must be main, review or all")
    t = _t()
    _need_state(t)
    sid = id or t.main_session()
    if not sid:
        raise HTTPException(status_code=404, detail="no session")
    with _tcon() as con:
        return _json_rev(_ins().compiled_view(t.STATE_DB, con, sid, "hermes" if layer == "hermes" else "wire", lane=lane,
                                              call=call or None), rev)


@router.get("/inspector/prompt")
def inspector_prompt(id: str):
    t = _t()
    _need_state(t)
    return _json(_ins().session_prompt(t.STATE_DB, id))


@router.get("/inspector/row")
def inspector_row(id: int):
    t = _t()
    _need_state(t)
    with _tcon() as con:
        return _json(_ins().full_row(t.STATE_DB, con, id))


@router.get("/inspector/wire")
def inspector_wire(id: str, which: str = "down"):
    with _tcon() as con:
        return _json(_ins().wire_summary(con, id, which))


@router.get("/inspector/wire/part")
def inspector_wire_part(id: str, part: str = "request", which: str = "down", i: Optional[int] = None,
                        key: Optional[str] = None):
    with _tcon() as con:
        try:
            return _json(_ins().wire_part(con, id, part, which, i, key))
        except (IndexError, KeyError, TypeError):
            raise HTTPException(status_code=404, detail="no such item")


@router.get("/inspector/wire/readable")
def inspector_wire_readable(id: str, part: str = "item", which: str = "down", i: Optional[int] = None,
                            key: Optional[str] = None, rows: str = "", session: Optional[str] = None):
    t = _t()
    row_ids = [int(x) for x in rows.split(",") if x.strip().isdigit()][:50]
    with _tcon() as con:
        try:
            return _json(_ins().wire_readable(t.STATE_DB, con, id, which, part, i, key, row_ids, session))
        except (IndexError, KeyError, TypeError, ValueError):
            raise HTTPException(status_code=404, detail="no such item")


@router.get("/inspector/calls")
def inspector_calls(t0: Optional[float] = None, t1: Optional[float] = None):
    now = time.time()
    with _tcon() as con:
        return _json({"calls": _ins().wire_calls_list(con, t0 or now - 3600, t1 or now + 60)})
