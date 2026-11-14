"""Hermes-side request capture: runs inside the agent process, fed only by the plugin's API-request hooks.

Provider-agnostic: it records what Hermes hands its provider client (OpenAI chat, Responses/Codex,
Anthropic Messages, Bedrock, any OpenAI-compatible endpoint), read from the hook arguments. No proxy, no
transport wrapper and no caller state are involved, and nothing about the request is changed.

* ``pre_api_request``  → the compiled request: system prompt, every message item, the envelope keys Hermes passes.
* ``post_api_request`` → the response (text, thinking, tool calls, finish reason, usage, latency / TTFB).
* ``api_request_error``→ attempt status, retry counters and a truncated error message.

Cost model inside the turn: the hook only snapshots — one ``json.dumps`` per request item, so later mutation
of Hermes's lists cannot change what was recorded — and enqueues. A single daemon thread per process hashes,
compresses and writes to SQLite (WAL). A full queue drops the capture instead of blocking; every error is
swallowed. Envelope credentials (``api_key``, auth headers, cookies, …) are redacted before anything is queued.
The in-turn part does no I/O and waits on no lock (so it cannot hang); its CPU cost is bounded by
``max_request_mb``, checked against Hermes's ``request_char_count`` before anything is serialized.

What the hooks supply, and what they do not:

* ``request_messages`` and ``system_prompt`` are Hermes's raw objects, so message items and the system prompt
  are stored in full.
* The rest of the payload (``tools``, sampling parameters) reaches a hook only inside ``request``, a sanitized
  and size-capped copy: long values in it are truncated by Hermes, and a request over the cap arrives as a
  bare preview, in which case no other key is stored. Such a capture is marked ``exact=0``, the UI labels its
  envelope as coming from the hook copy, and its tools are never compared with another call's.
* ``request_tools`` and ``request_params`` are not passed by any Hermes release yet (they are proposed
  upstream). When a hook receives them they replace that copy; see ``snapshot_request``.
* The serialized HTTP body, the outgoing headers and anything a provider SDK or another plugin's client
  wrapper changes after the hook are not visible to a hook and are not recorded.
"""
from __future__ import annotations

import atexit
import importlib.util
import json
import logging
import queue
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("wiretap.capture")


def _sibling(name: str):
    key = f"_wiretap_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, Path(__file__).resolve().with_name(f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    try:
        mod._mt_loaded_mtime = Path(mod.__file__).stat().st_mtime  # a stamped sibling never retires the capture module
    except Exception:
        pass
    return mod


store = _sibling("store")
inspector = _sibling("inspector")

SETTINGS: dict[str, Any] = {
    "enabled": True,            # telemetry rows (timing, tokens, cost) — never content
    "capture_payloads": True,   # full request / response capture
    "retention_hours": 72.0,    # payload retention; call rows are kept
    "max_request_mb": 64.0,     # skip payload capture above this serialized size
}
QUEUE_MAX = 256
_ERR_CHARS = 400
_DROP_KEYS = {"timeout", "http_client", "extra_headers", "default_headers", "extra_query"}
_SECRET_KEYS = {"api_key", "authorization", "proxy_authorization", "cookie", "set_cookie", "x_api_key",
                "x_goog_api_key", "access_token", "refresh_token", "id_token", "client_secret", "password",
                "api_token", "bearer"}
_LIST_KEYS = ("messages", "input", "contents")


# ───────────────────────── serialization ─────────────────────────
def _is_secret(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    k = key.lower().replace("-", "_")
    return k in _SECRET_KEYS or k.endswith(("_api_key", "_secret", "_token")) and k not in ("max_tokens",)


def _plain(v: Any, depth: int = 0) -> Any:
    """JSON-able copy of SDK objects (pydantic, dataclasses, namespaces); no truncation."""
    if depth > 64:
        return f"<{type(v).__name__} depth limit>"
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, dict):
        return {str(k): _plain(x, depth + 1) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_plain(x, depth + 1) for x in v]
    if isinstance(v, (bytes, bytearray)):
        return f"<{len(v)} bytes>"
    for attr in ("model_dump", "dict"):
        fn = getattr(v, attr, None)
        if callable(fn):
            try:
                return _plain(fn(mode="json") if attr == "model_dump" else fn(), depth + 1)
            except TypeError:
                try:
                    return _plain(fn(), depth + 1)
                except Exception:
                    pass
            except Exception:
                pass
    try:
        from dataclasses import asdict, is_dataclass

        if is_dataclass(v) and not isinstance(v, type):
            return _plain(asdict(v), depth + 1)
    except Exception:
        pass
    if hasattr(v, "__dict__"):
        try:
            return {k: _plain(x, depth + 1) for k, x in vars(v).items() if not str(k).startswith("_")}
        except Exception:
            pass
    return str(v)


def dump(obj: Any) -> str:
    """Canonical JSON (same form the proxy capture produces, so shared items dedupe)."""
    try:
        return store.canon(obj)
    except (TypeError, ValueError):
        return store.canon(_plain(obj))


def _redact(v: Any, depth: int = 0) -> Any:
    if depth > 16:
        return v
    if isinstance(v, dict):
        return {k: ("‹redacted›" if _is_secret(k) else _redact(x, depth + 1)) for k, x in v.items()}
    if isinstance(v, list):
        return [_redact(x, depth + 1) for x in v]
    return v


def _leads_with_system(messages: Any) -> bool:
    first = messages[0] if isinstance(messages, list) and messages else None
    return isinstance(first, dict) and first.get("role") == "system"


# Request keys the raw hook arguments own: never taken from ``request_params`` or the sanitized copy.
_RAW_KEYS = {"system", "instructions", "tools", *_LIST_KEYS}


def snapshot_request(kw: dict, max_bytes: int) -> dict | None:
    """Serialize the compiled request from the hook arguments now (inside the hook), so later mutation cannot
    alter it.

    Messages come from the raw ``request_messages`` and the system prompt from the raw ``system_prompt``. Every
    other envelope key comes from ``request["body"]``, Hermes's sanitized, size-capped copy: none when Hermes
    passed a truncation preview in place of ``request``, and possibly truncated values otherwise.

    Two arguments no Hermes release passes yet are used when present, in place of that copy: ``request_tools``
    (the request's own tool list when the hook fires; ``tools_exact``) and ``request_params`` (the remaining request
    parameters, outside the size cap). With both, the capture is ``exact``."""
    req = kw.get("request") if isinstance(kw.get("request"), dict) else {}
    sb = req.get("body") if isinstance(req.get("body"), dict) else {}  # empty when Hermes passed only a preview
    tools, params = kw.get("request_tools"), kw.get("request_params")
    tools_exact, params_exact = isinstance(tools, list), isinstance(params, dict)
    if params_exact:
        body = {k: v for k, v in params.items() if k not in _DROP_KEYS and k not in _RAW_KEYS}
    else:
        body = {k: v for k, v in sb.items() if k not in _DROP_KEYS}
    if not body.get("model") and kw.get("model"):
        body["model"] = kw.get("model")
    mode = kw.get("api_mode") or ""
    msgs = kw.get("request_messages")
    sp = kw.get("system_prompt")
    if sp is not None and not _leads_with_system(msgs):
        # Hermes reports it from the request's ``system`` or ``instructions`` key; a chat-completions system
        # prompt is messages[0] and is stored with the items instead.
        body["instructions" if mode == "codex_responses" or ("instructions" in sb and "system" not in sb)
             else "system"] = sp
    if tools_exact:
        body.pop("tools", None)  # the copy's tools, possibly cut
        if tools:
            body["tools"] = tools
    if isinstance(msgs, list):
        lk = next((k for k in _LIST_KEYS if k in sb), "input" if mode == "codex_responses" else "messages")
        body[lk] = msgs  # in place of the sanitized copy's list; last when that copy carried none
    list_key = next((k for k in _LIST_KEYS if isinstance(body.get(k), list)), None)
    order = list(body.keys())
    keys = {k: dump("‹redacted›" if _is_secret(k) else _redact(v)) for k, v in body.items() if k != list_key}
    items = [dump(x) for x in (body.get(list_key) or [])] if list_key else []
    size = sum(map(len, keys.values())) + sum(map(len, items))
    if max_bytes and size > max_bytes:
        return {"too_large": True, "size": size, "n_items": len(items)}
    return {"order": order, "keys": keys, "list_key": list_key, "items": items, "size": size,
            "tools_exact": tools_exact, "exact": tools_exact and params_exact}


def _text_of(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for p in content:
            if isinstance(p, str):
                out.append(p)
            elif isinstance(p, dict) and isinstance(p.get("text"), str):
                out.append(p["text"])
            elif hasattr(p, "text") and isinstance(getattr(p, "text"), str):
                out.append(p.text)
        return "".join(out)
    return "" if content is None else str(content)


def _get(o: Any, k: str, default=None):
    return o.get(k, default) if isinstance(o, dict) else getattr(o, k, default)


def snapshot_response(kw: dict) -> dict:
    """Normalized response (same shape ``inspector.parse_response`` produces for proxy streams)."""
    am = kw.get("assistant_message")
    res: dict = {"text": "", "thinking": "", "tool_calls": [], "finish": kw.get("finish_reason"),
                 "model": kw.get("response_model") or kw.get("model"), "response_id": None, "usage": kw.get("usage")}
    if am is None and isinstance(kw.get("response"), dict):
        am = kw["response"].get("assistant_message")
    if am is not None:
        res["text"] = _text_of(_get(am, "content"))
        th = _get(am, "reasoning_content") or _get(am, "reasoning")
        if not th:
            det = _get(am, "reasoning_details")
            if isinstance(det, list):
                th = "\n".join(str(_get(d, "text") or _get(d, "summary") or "") for d in det if d is not None).strip()
        res["thinking"] = th if isinstance(th, str) else ""
        for tc in _get(am, "tool_calls") or []:
            fn = _get(tc, "function") or {}
            args = _get(fn, "arguments")
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args else {}
                except Exception:
                    pass
            res["tool_calls"].append({"id": _get(tc, "id") or _get(tc, "call_id"),
                                      "name": _get(fn, "name") or _get(tc, "name"), "args": _plain(args)})
    if res["finish"] is not None:
        res["finish"] = str(res["finish"])
    return res


# ───────────────────────── rows ─────────────────────────
def _num(v: Any) -> float | None:
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


def _int(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def call_id(kw: dict) -> str:
    rid = kw.get("api_request_id")
    return "h:" + str(rid if rid else f"{kw.get('session_id') or '-'}:{kw.get('started_at') or time.time()}")


def _lane(platform: str) -> str:
    return {"subagent": "delegate", "webhook": "webhook", "cron": "cron"}.get(platform or "", platform or "")


def _safe_url(url: Any) -> str | None:
    if not url:
        return None
    s = str(url)
    s = re.sub(r"//[^/@]*@", "//", s)        # userinfo
    return s.split("?", 1)[0][:300]          # query strings may carry keys


def execution_origin(kw: dict) -> str:
    """Read execution provenance, never infer it from platform or a cache/session key.

    Current Hermes hooks copy the caller's ContextVars to their bounded worker.
    Prefer explicit metadata when a host supplies it; older hosts without the
    provenance accessor keep working (legacy request classification is read-only).
    """
    for key in ("execution_origin", "turn_origin"):
        if isinstance(kw.get(key), str) and kw[key]:
            return kw[key]
    try:
        from tools.skill_provenance import get_current_write_origin
        return get_current_write_origin() or "foreground"
    except (ImportError, AttributeError):
        return ""


def base_row(kw: dict) -> dict:
    model = kw.get("response_model") or kw.get("model") or ""
    origin = execution_origin(kw)
    row = {
        "id": call_id(kw), "source": "hermes", "started": _num(kw.get("started_at")),
        "family": store.family_of(model, kw.get("api_mode"), kw.get("provider")), "provider": kw.get("provider"), "model": model,
        "url": _safe_url(kw.get("base_url")), "api_mode": kw.get("api_mode"),
        "client": "hermes/" + str(kw.get("api_mode") or "?"), "session_id": kw.get("session_id") or None,
        "platform": kw.get("platform") or None,
        "lane": "review" if origin == "background_review" else _lane(kw.get("platform") or ""),
        "execution_origin": origin or None,
        "message_count": kw.get("message_count"), "auth_label": kw.get("provider"),
    }
    if kw.get("context_length"):
        row["context_length"] = _int(kw.get("context_length"))
    return {k: v for k, v in row.items() if v is not None}


def ok_row(kw: dict) -> dict:
    row = base_row(kw)
    u = kw.get("usage") if isinstance(kw.get("usage"), dict) else {}
    prompt, cached = _int(u.get("prompt_tokens")), _int(u.get("cache_read_tokens"))
    cw, uncached = _int(u.get("cache_write_tokens")), _int(u.get("input_tokens"))
    out, think = _int(u.get("output_tokens")), _int(u.get("reasoning_tokens"))
    if not prompt:
        prompt = uncached + cached + cw
    started, ended, first = _num(kw.get("started_at")), _num(kw.get("ended_at")), _num(kw.get("first_chunk_at"))
    dur = _num(kw.get("api_duration"))
    if ended is None and started is not None and dur is not None:
        ended = started + dur
    row.update(
        ended=ended, total_s=round(dur, 3) if dur is not None else None,
        ttfb_s=round(first - started, 3) if first and started else None,
        gen_s=round(ended - first, 3) if first and ended else None, status=200,
        prompt_tokens=prompt, cached_tokens=cached, cache_write_tokens=cw, uncached_tokens=uncached,
        output_tokens=out, thinking_tokens=think, hit_pct=round(100.0 * cached / prompt, 1) if prompt else None)
    return {k: v for k, v in row.items() if v is not None}


def priced(row: dict, base_url: str | None) -> dict:
    """Billing mode and API-list-price estimate (Hermes's pricing tables; runs on the writer thread)."""
    model, prov = row.get("model") or "", row.get("provider")
    billing = store.billing_of(model, prov, base_url)
    if billing == "sub":  # included in a subscription: estimate the API-list equivalent from the model's maker
        prov, base_url = store.FAMILY_PROVIDER.get(row.get("family") or "", prov), None
    own = billing == "api" and store.price_call(model, prov, 1000, 0, 0, 0, 1000, base_url=base_url)[0] is not None
    cost, pv = store.price_tokens(model, prov, row.get("family"), base_url, row.get("uncached_tokens") or 0,
                                  row.get("cached_tokens") or 0, row.get("cache_write_tokens") or 0,
                                  row.get("output_tokens") or 0, row.get("prompt_tokens") or 0)
    # A route Hermes cannot price (a proxy / custom provider) has unknown billing: the equivalent is still the model
    # maker's list price, but what was actually paid stays unknown until a proxy log names the credential.
    paid = (cost if own else None) if billing == "api" else 0.0
    row.update(billing=billing, cost_equiv_usd=cost, cost_usd=paid, pricing_version=pv)
    return row


def error_detail(kw: dict) -> dict:
    err = kw.get("error")
    if not isinstance(err, dict):
        err = {"message": str(err or "")}
    return {"n": _int(kw.get("retry_count")) + 1, "status": kw.get("status_code"), "reason": kw.get("reason"),
            "retryable": kw.get("retryable"), "type": str(err.get("type") or "")[:80],
            "message": str(err.get("message") or "")[:_ERR_CHARS]}


# ───────────────────────── writer ─────────────────────────
class Writer:
    """One background writer thread per process; jobs are ``fn(con)`` callables."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self.q: "queue.Queue[Callable | None]" = queue.Queue(maxsize=QUEUE_MAX)
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.dropped = 0
        self.con = None
        self._maintenance_pending = True

    def submit(self, job: Callable) -> bool:
        with self.lock:
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._run, name="wiretap-writer", daemon=True)
                self.thread.start()
        try:
            self.q.put_nowait(job)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def _open(self):
        if self.con is None:
            self.con = store.connect(self.path, timeout=10)
            store.init(self.con)
            self._maintenance_pending = True
        return self.con

    def _maintain(self) -> None:
        """Finish historical signals in short idle slices, even with no new captures."""
        if self.con is None or not self._maintenance_pending or not self.q.empty():
            return
        try:
            with self.con:
                store.backfill_signals(self.con, budget_s=0.25)
                pending = not store.signals_backfilled(self.con)
            self._maintenance_pending = pending
        except Exception:
            # Maintenance must not terminate the capture thread, even if its log sink is full.
            try:
                logger.debug("wiretap idle maintenance failed", exc_info=True)
            except Exception:
                pass

    def _run(self) -> None:
        while True:
            try:
                job = self.q.get(timeout=0.5)
            except queue.Empty:
                self._maintain()
                continue
            if job is None:
                self.q.task_done()
                if self.con is not None:
                    try:
                        self.con.close()
                    except Exception:
                        pass
                    self.con = None
                break
            batch = [job]
            while len(batch) < 32:
                try:
                    nxt = self.q.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self.q.put_nowait(None)
                    self.q.task_done()
                    break
                batch.append(nxt)
            try:
                con = self._open()
                with con:
                    store.reserve_write(con)
                    for j in batch:
                        try:
                            j(con)
                        except Exception:
                            logger.debug("wiretap capture job failed", exc_info=True)
                    store.kv_set(con, "last_capture", {"ts": time.time(), "dropped": self.dropped,
                                                       "capture_payloads": bool(SETTINGS.get("capture_payloads"))})
                try:
                    with con:
                        store.gc(con, keep_s=float(SETTINGS.get("retention_hours") or 72) * 3600)
                except Exception:
                    logger.debug("wiretap gc failed", exc_info=True)
                self._maintain()
            except Exception:
                logger.debug("wiretap writer failed", exc_info=True)
                try:
                    if self.con is not None:
                        self.con.close()
                except Exception:
                    pass
                self.con = None
            finally:
                for _ in batch:
                    self.q.task_done()

    def flush(self, timeout: float = 2.0) -> None:
        """Wait (bounded) until queued jobs are written — tests and interpreter exit."""
        end = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < end:
            time.sleep(0.01)

    def stop(self, timeout: float = 2.0) -> None:
        """Flush, then let the writer thread close its own connection and exit."""
        self.flush(timeout)
        t = self.thread
        if t is not None and t.is_alive():
            try:
                self.q.put(None, timeout=timeout)
            except queue.Full:
                return
            t.join(timeout)


_writer = Writer()
atexit.register(lambda: _writer.stop(2.0))


def writer() -> Writer:
    return _writer


# ───────────────────────── hook entry points (called from __init__.py) ─────────────────────────
def on_pre(kw: dict) -> None:
    if not SETTINGS.get("enabled", True):
        return
    row = base_row(kw)
    row["attempts"] = _int(kw.get("retry_count")) + 1
    snap = None
    if SETTINGS.get("capture_payloads", True):
        max_bytes = int(float(SETTINGS.get("max_request_mb") or 0) * 1024 * 1024)
        chars = kw.get("request_char_count")
        if max_bytes and isinstance(chars, (int, float)) and chars > max_bytes:
            # Bound the in-turn cost before serializing anything (Hermes reports the request size up front).
            snap = {"too_large": True, "size": int(chars), "n_items": kw.get("message_count")}
        else:
            snap = snapshot_request(kw, max_bytes)
    cid = row["id"]

    def job(con):
        store.reserve_write(con)
        cur = con.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
        current = dict(cur) if cur else {}
        state = store.host_state(current)
        state["counters"]["attempts"] = max(state["counters"].get("attempts", 0), row["attempts"])
        row.update(store.layer_counters(state, current.get("proxy_attempts")), host_state=json.dumps(state))
        store.upsert(con, row)
        if not snap or snap.get("too_large"):
            if snap:
                store.upsert(con, {"id": cid, "diverge": json.dumps({"why": f"payload not captured ({snap['size']:,} bytes > max_request_mb)"})})
            return
        ref = {"order": snap["order"], "list_key": snap["list_key"],
               "keys": {k: store.put_blob_str(con, s) for k, s in snap["keys"].items()},
               "items": [store.put_blob_str(con, s) for s in snap["items"]]}
        store.upsert(con, {"id": cid, "started": row.get("started"), "family": row.get("family"), "model": row.get("model"),
                           "url": row.get("url"), "req_down": json.dumps(ref), "hdr_down": "{}",
                           "n_items": len(snap["items"]), "req_bytes": snap["size"], "captured": time.time(),
                           "session_id": row.get("session_id"), "source": "hermes",
                           # exact: no envelope key came from Hermes's sanitized hook copy.
                           # tools_exact: the tools did not, so they can be compared between calls.
                           "exact": int(snap["exact"]), "tools_exact": int(snap["tools_exact"])},
                     "wire_calls")

    _writer.submit(job)


def on_post(kw: dict) -> None:
    if not SETTINGS.get("enabled", True):
        return
    row = ok_row(kw)
    row["response_error"] = None  # a successful host retry supersedes earlier proxy-response failure
    cid = row["id"]
    base_url = kw.get("base_url")
    resp = snapshot_response(kw) if SETTINGS.get("capture_payloads", True) else None
    raw = None
    if resp is not None and kw.get("response") is not None:
        try:
            raw = dump(kw.get("response"))
        except Exception:
            raw = None

    def job(con):
        store.reserve_write(con)
        cur = con.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
        current = dict(cur) if cur else {}
        state = store.host_state(current)
        state["completed_at"] = row.get("ended") or time.time()
        state["counters"]["attempts"] = max(state["counters"].get("attempts", 0), _int(kw.get("retry_count")) + 1)
        row.update(store.layer_counters(state, current.get("proxy_attempts")), host_state=json.dumps(state))
        try:
            priced(row, base_url)
        except Exception:
            logger.debug("wiretap pricing failed", exc_info=True)
        store.upsert(con, row)
        if resp is None:
            return
        upd = {"id": cid, "ended": row.get("ended"), "status": 200, "model": row.get("model"),
               "resp": json.dumps(resp, ensure_ascii=False, default=str),
               "tc_ids": json.dumps([t["id"] for t in resp["tool_calls"] if t.get("id")]),
               "text_head": inspector.norm(resp["text"])[:400], "session_id": row.get("session_id"), "source": "hermes"}
        if raw is not None:
            upd["resp_raw"] = store.put_blob_str(con, raw)
        if not con.execute("SELECT 1 FROM wire_calls WHERE id=?", (cid,)).fetchone():
            upd.update(started=row.get("started"), family=row.get("family"), url=row.get("url"), captured=time.time())
        store.upsert(con, upd, "wire_calls")
        try:
            store.refresh_signals(con, cid)  # fallbacks / refusals / model switch, from this call's own response
        except Exception:
            logger.debug("wiretap signals failed", exc_info=True)
        try:
            d = explain_miss(con, cid, row)
            if d:
                store.upsert(con, {"id": cid, "diverge": json.dumps(d)})
        except Exception:
            logger.debug("wiretap miss forensics failed", exc_info=True)

    _writer.submit(job)


def on_error(kw: dict) -> None:
    if not SETTINGS.get("enabled", True):
        return
    row = base_row(kw)
    cid = row["id"]
    det = error_detail(kw)
    status = kw.get("status_code")
    ended = _num(kw.get("ended_at"))
    dur = _num(kw.get("api_duration"))

    def job(con):
        store.reserve_write(con)
        cur = con.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
        current = dict(cur) if cur else {}
        hist = inspector._loads(current.get("attempt_detail"), []) or []
        state = store.host_state(current)
        totals = state["counters"]
        totals.update(attempts=max(totals.get("attempts", 0), det["n"], (totals.get("nfail") or 0) + 1),
                      n429=(totals.get("n429") or 0) + int(status == 429),
                      nfail=(totals.get("nfail") or 0) + 1,
                      retry_s=round((totals.get("retry_s") or 0) + (dur or 0), 3))
        hist.append(dict(det, s=dur))
        upd: dict = dict(row, attempt_detail=json.dumps(hist[-20:]), host_state=json.dumps(state))
        upd.update(store.layer_counters(state, current.get("proxy_attempts")))
        if current.get("status") != 200:
            upd.update(status=status or 0, ended=ended, total_s=round(dur, 3) if dur is not None else None)
        store.upsert(con, {k: v for k, v in upd.items() if v is not None})
        if con.execute("SELECT 1 FROM wire_calls WHERE id=? AND COALESCE(status, 0) != 200", (cid,)).fetchone():
            store.upsert(con, {"id": cid, "status": status or 0, "ended": ended}, "wire_calls")
        if _ERR_POLICY_HINT.search(f"{det.get('reason')} {det.get('type')} {det.get('message')}"):
            try:
                store.refresh_signals(con, cid)  # a policy / safety / classifier block in the error itself
            except Exception:
                logger.debug("wiretap signals failed", exc_info=True)

    _writer.submit(job)


_ERR_POLICY_HINT = re.compile(r"polic|filter|safety|invalid_prompt|cyber|refus|prohibit|block|violat", re.I)


# ───────────────────────── miss forensics from captured items ─────────────────────────
def _prefix(con, cid: str):
    r = con.execute("SELECT req_down FROM wire_calls WHERE id=?", (cid,)).fetchone()
    ref = json.loads((r[0] if r else None) or "null") or {}
    sys_h = [ref["keys"][k] for k in inspector._SYS_KEYS if k in (ref.get("keys") or {})]
    tools = [ref["keys"]["tools"]] if "tools" in (ref.get("keys") or {}) else []
    return sys_h + tools + list(ref.get("items") or []), len(sys_h) + len(tools)


def explain_miss(con, cid: str, row: dict) -> dict | None:
    """Layer-matched forensics (inspector.explain_miss); the old body below is kept only as ``_explain_miss_any_layer``."""
    return inspector.explain_miss(con, cid, row.get("session_id"), row.get("started"), row.get("prompt_tokens"), row.get("hit_pct"))


def _explain_miss_any_layer(con, cid: str, row: dict) -> dict | None:
    """For a prefix-cache miss, the closest earlier call of the same session and the first item that changed."""
    if (row.get("prompt_tokens") or 0) < 20000 or (row.get("hit_pct") or 0) >= 60 or not row.get("session_id"):
        return None
    cur, ncur = _prefix(con, cid)
    if not cur:
        return None
    best = None
    for p in con.execute("SELECT id FROM wire_calls WHERE session_id=? AND id != ? AND started < ? AND status=200 "
                         "ORDER BY started DESC LIMIT 12", (row["session_id"], cid, row.get("started") or time.time())):
        ph, _ = _prefix(con, p[0])
        k = 0
        while k < min(len(ph), len(cur)) and ph[k] == cur[k]:
            k += 1
        if best is None or k > best[0]:
            best = (k, p[0], ph)
    if not best:
        return {"why": "first captured call of this session (no earlier request to compare)"}
    k, pid, ph = best
    info: dict = {"prev_id": pid, "common_items": k, "items": len(cur), "prev_items": len(ph)}
    if k < min(len(ph), len(cur)):
        role_c, txt_c, _ = inspector.item_norm(con, cur[k])
        _, txt_p, _ = inspector.item_norm(con, ph[k])
        n = lambda h: (con.execute("SELECT n FROM wire_blobs WHERE h=?", (h,)).fetchone() or [0])[0]  # noqa: E731
        info.update(at=k, role=role_c if k >= ncur else ("system/tools"), prev_head=txt_p[:260], cur_head=txt_c[:260],
                    prev_len=n(ph[k]), cur_len=n(cur[k]))
        info["why"] = "system prompt or tool declarations changed" if k < ncur else f"history item #{k - ncur} rewritten"
    elif k == len(ph):
        info["why"] = "prefix intact vs closest earlier call — provider-side miss (cache entry not stored/reused)"
    return info
