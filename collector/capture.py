"""Hermes-side wire capture: runs inside the agent process, fed by the plugin's API-request hooks.

Provider-agnostic: it records what Hermes hands its provider transport (OpenAI chat, Responses/Codex,
Anthropic Messages, Bedrock, Gemini, any OpenAI-compatible endpoint), so no proxy is needed.

* ``pre_api_request``  → the compiled request: system prompt, tools and envelope keys, every message item.
* ``post_api_request`` → the response (text, thinking, tool calls, finish reason, usage, latency / TTFB).
* ``api_request_error``→ attempt status, retry counters and a truncated error message.

Cost model inside the turn: the hook only snapshots — one ``json.dumps`` per request item, so later mutation
of Hermes's lists cannot change what was recorded — and enqueues. A single daemon thread per process hashes,
compresses and writes to SQLite (WAL). A full queue drops the capture instead of blocking; every error is
swallowed. Envelope credentials (``api_key``, auth headers, cookies, …) are redacted before anything is queued.
The in-turn part does no I/O and waits on no lock (so it cannot hang); its CPU cost is bounded by
``max_request_mb``, checked against Hermes's ``request_char_count`` before anything is serialized.

Final outbound body: the hook-side snapshot is what Hermes handed its provider client, which another plugin's
client wrapper or a provider adapter may still rewrite. ``install_http_tap`` wraps httpx's last pre-transport
step (``Client._send_single_request`` / ``AsyncClient._send_single_request``: after event hooks, auth and
redirects) and records the exact JSON body that left the process for the armed call. That body becomes
``req_down``; the hook snapshot is kept as ``req_hermes`` (the "pre-adapter" layer). Calls on a non-httpx
transport (e.g. boto3 for Bedrock) keep the hook snapshot only, labelled as adapter input.

Exact envelope: Hermes's documented hook kwargs carry the raw ``request_messages`` and ``system_prompt``, but
the rest of the payload (``tools``, sampling params) only as a size-capped sanitized copy. When available,
the hook reads the transport-ready ``api_kwargs`` of the calling frame (verified by item identity against
``request_messages``) for the exact envelope; otherwise it rebuilds the envelope from the sanitized copy and
marks the capture ``exact=0``.
"""
from __future__ import annotations

import atexit
import importlib.util
import json
import os
import hashlib
import logging
import queue
import re
import sys
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

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


def _redact_headers(h: Any) -> dict:
    if not isinstance(h, dict):
        return {}
    return inspector.redact_headers({str(k): v for k, v in h.items()})


def _caller_api_kwargs(request_messages: Any, max_depth: int = 14) -> dict | None:
    """The transport-ready ``api_kwargs`` of the frame that fired ``pre_api_request`` (read-only)."""
    if not isinstance(request_messages, list) or not request_messages:
        return None
    first, last = request_messages[0], request_messages[-1]
    try:
        f = sys._getframe(2)
    except Exception:
        return None
    for _ in range(max_depth):
        if f is None:
            break
        if "api_kwargs" in f.f_code.co_varnames:
            cand = f.f_locals.get("api_kwargs")
            if isinstance(cand, dict):
                lst = next((cand[k] for k in _LIST_KEYS if isinstance(cand.get(k), list)), None)
                if lst and lst[0] is first and lst[-1] is last:
                    return cand
        f = f.f_back
    return None


def snapshot_request(kw: dict, api_kwargs: dict | None, max_bytes: int) -> dict | None:
    """Serialize the compiled request now (inside the hook) so later mutation cannot alter it."""
    exact = isinstance(api_kwargs, dict)
    headers = {}
    if exact:
        body = {k: v for k, v in api_kwargs.items() if k not in _DROP_KEYS}
        headers = _redact_headers(api_kwargs.get("extra_headers"))
    else:
        req = kw.get("request") if isinstance(kw.get("request"), dict) else {}
        sb = req.get("body") if isinstance(req.get("body"), dict) else {}
        body = {} if sb.get("_truncated") else {k: v for k, v in sb.items() if k not in _DROP_KEYS}
        if not body.get("model") and kw.get("model"):
            body["model"] = kw.get("model")
        mode = kw.get("api_mode") or ""
        msgs = kw.get("request_messages")
        if isinstance(msgs, list):
            lk = next((k for k in _LIST_KEYS if k in body), "input" if mode == "codex_responses" else "messages")
            body[lk] = msgs
        sp = kw.get("system_prompt")
        if sp is not None:
            if mode == "anthropic_messages" or "system" in body:
                body["system"] = sp
            elif mode == "codex_responses" or "instructions" in body:
                body["instructions"] = sp
    list_key = next((k for k in _LIST_KEYS if isinstance(body.get(k), list)), None)
    order = list(body.keys())
    keys = {k: dump("‹redacted›" if _is_secret(k) else _redact(v)) for k, v in body.items() if k != list_key}
    items = [dump(x) for x in (body.get(list_key) or [])] if list_key else []
    size = sum(map(len, keys.values())) + sum(map(len, items))
    if max_bytes and size > max_bytes:
        return {"too_large": True, "size": size, "n_items": len(items)}
    return {"order": order, "keys": keys, "list_key": list_key, "items": items, "headers": headers,
            "exact": exact, "size": size}


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
        """Finish historical signals in short idle slices, even with no new captures or proxy poller."""
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


# ───────────────────────── final outbound body (httpx tap) ─────────────────────────
# The call whose request is about to leave the process. Hermes runs pre_api_request on a bounded worker under a
# *copy* of the caller's context, so a ContextVar set there never reaches the send (it does when hooks run on the
# caller thread, e.g. with the hook timeout off). The registry is what the tap uses in practice: every armed call
# with its host and a signature — the newest message's tool-call id, or a verbatim run of its text — which only
# that call's request contains. Concurrent calls to one host (parallel subagents on one proxy) are told apart by
# which signature the outgoing body carries, found in one pass over the body.
_ARMED: ContextVar[dict | None] = ContextVar("wiretap_armed", default=None)
_ARMED_BY_ID: dict[str, dict] = {}
_ARMED_LOCK = threading.Lock()
_ARM_TTL_S = 900.0


def _speaker(message: Any) -> str | None:
    """Conversation structure only: never interpret quoted/flattened transcript text as message boundaries."""
    if not isinstance(message, dict):
        return None
    kind, role = message.get("type"), message.get("role")
    if role in ("system", "developer") or kind == "reasoning":
        return None  # provider adapters extract system messages and split/fold reasoning items
    if kind == "function_call":
        return "assistant"
    if kind == "function_call_output":
        return "user"
    if role in ("assistant", "model"):
        return "assistant"
    if role in ("user", "tool", "function"):
        return "user"  # Claude/Gemini render tool results inside a user message
    return None


def _speaker_runs(messages: Any) -> int:
    """Lower bound preserved by normal adapters even when adjacent same-speaker messages are coalesced."""
    runs, previous = 0, None
    for message in messages if isinstance(messages, list) else []:
        speaker = _speaker(message)
        if speaker is not None and speaker != previous:
            runs += 1
            previous = speaker
    return runs


def _arm(cid: str, kw: dict) -> None:
    host = None
    try:
        host = urlsplit(str(kw.get("base_url") or "")).hostname
    except Exception:
        pass
    chars = kw.get("request_char_count")
    arm = {"id": cid, "host": host, "t": time.time(), "done": False, "got": None,
           "expect": int(chars) if isinstance(chars, (int, float)) and chars > 0 else None,
           "sig": None, "sig_k": 0}
    messages = kw.get("request_messages")
    arm["sig"], arm["sig_k"] = signature_at(messages)
    arm["speaker_runs"] = _speaker_runs(messages)
    arm["conversation_items"] = sum(_speaker(m) is not None for m in messages) if isinstance(messages, list) else 0
    arm["tools_expected"] = bool(kw.get("tool_count"))
    if arm["sig"] and isinstance(messages, list):
        signed = messages[-arm["sig_k"]]
        arm["sig_speaker"] = _speaker(signed)
        arm["sig_item_bytes"] = len(json.dumps(signed, ensure_ascii=False, default=str).encode())
    _ARMED.set(arm)
    with _ARMED_LOCK:
        _ARMED_BY_ID[cid] = arm
        stale = [k for k, v in _ARMED_BY_ID.items() if time.time() - v["t"] > _ARM_TTL_S]
        for k in stale:
            _ARMED_BY_ID.pop(k, None)


def _disarm(cid: str) -> dict | None:
    # The arm dict is shared by every context that copied it (Hermes runs the API call in a worker that copies the
    # caller's context, and post_api_request may fire in either), so mark it dead rather than only unsetting this
    # context's variable — a sidecar LLM call made later in the turn (approval classifier, compressor, …) must not
    # land on this call.
    with _ARMED_LOCK:
        arm = _ARMED_BY_ID.pop(cid, None)
    cur = _ARMED.get()
    for a in (arm, cur):
        if a and a.get("id") == cid:
            a["done"] = True
    if cur and cur.get("id") == cid:
        _ARMED.set(None)
    return arm if arm is not None else (cur if cur and cur.get("id") == cid else None)


_SIG_ID_KEYS = ("tool_call_id", "tool_use_id", "call_id", "id")
_SIG_ID_RE = re.compile(r"[A-Za-z0-9_\-]{8,128}")
# Characters every JSON encoder in the path writes verbatim (no quotes, backslashes, slashes, non-ASCII).
_SIG_TEXT_RE = re.compile(r"[A-Za-z0-9 ,.:;()\-]{24,}")
TAP_STATS: dict = {"ctx": 0, "single": 0, "sig": 0, "ambiguous": 0, "unmatched": 0, "sig_miss": 0, "validated": 0,
                   "rejected": 0, "undecodable": 0}
# Items an adapter may append after the call's newest message. 0: on 600 live exact captures (Claude, Gemini, Codex)
# the newest message's signature sat in the last item in 596; allowing a trailing item would also admit a sidecar
# that replays the conversation and appends its own instruction. Accuracy over coverage.
SIG_ADAPTER_SLACK = 0


def persist_tap_stats(con) -> None:
    """How this process's tap resolved outgoing requests (``wiretap status`` reads them): by context, the only
    armed call, signature; or refused as ambiguous / no signature (a sidecar) / unmatched."""
    try:
        con.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)",
                    (f"tap_stats:{os.getpid()}", json.dumps(dict(TAP_STATS, t=round(time.time())))))
    except Exception:
        pass


def call_signature(messages: Any) -> bytes | None:
    """Bytes only this call's request carries: the newest message's tool-call / tool-result id (as a JSON string),
    else the last 48 characters of a plain-text run of its newest text. Adapters re-wrap messages but keep ids and
    word runs verbatim; a sidecar request (classifier, compressor of another call) does not end with them."""
    return signature_at(messages)[0]


def signature_at(messages: Any) -> tuple[bytes | None, int]:
    """(signature, k): the signature and which message from the end (1 = last) it came from."""
    if not isinstance(messages, list) or not messages:
        return None, 0
    for depth, msg in enumerate(reversed(messages[-2:]), 1):
        ids: list[str] = []
        texts: list[str] = []
        stack = [msg]
        while stack:
            x = stack.pop()
            if isinstance(x, dict):
                for k, v in x.items():
                    if k in _SIG_ID_KEYS and isinstance(v, str) and _SIG_ID_RE.fullmatch(v):
                        ids.append(v)
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
                    elif isinstance(v, str) and k in ("content", "text", "output", "input_text") and len(v) >= 24:
                        texts.append(v)
            elif isinstance(x, list):
                stack.extend(x)
            elif isinstance(x, str) and len(x) >= 24:
                texts.append(x)
        if ids:
            return ('"' + ids[0] + '"').encode(), depth
        for t in texts:
            runs = _SIG_TEXT_RE.findall(t[-4000:])
            if runs:
                run = runs[-1].strip()
                if len(run) >= 24:
                    return run[-48:].encode(), depth
    return None, 0


def _miss(arms, why: str) -> None:
    for a in arms:
        if not a.get("got"):
            a["why"] = why


def _armed_for(host: str | None, body: bytes = b"") -> dict | None:
    """The armed call this outgoing body is a *candidate* for. Only a provisional choice: the writer validates it
    against the request's own structure (``_validated``) before anything is recorded or a proxy tag is honoured.

    Candidates are the live arms for the host. A candidate qualifies only if its signature is in the body (no
    signature-less guessing, no lone-call fallback); among several, the one whose signature occurs latest wins — a
    forked child's or sidecar's body carries other calls' ids and text only in earlier items. A tie is refused."""
    arm = _ARMED.get()
    if arm and not arm.get("done") and (not arm["host"] or not host or arm["host"] == host):
        TAP_STATS["ctx"] += 1
        return arm
    now = time.time()
    with _ARMED_LOCK:
        cands = [a for a in _ARMED_BY_ID.values()
                 if a["host"] and a["host"] == host and not a.get("done") and now - a["t"] <= _ARM_TTL_S]
    if not cands or not body:
        return None
    signed = [a for a in cands if a.get("sig")]
    if not signed:
        if len(cands) == 1:  # a call with no messages to sign (rare); still validated by size in the caller
            TAP_STATS["single"] += 1
            return cands[0]
        TAP_STATS["ambiguous"] += 1
        _miss(cands, "ambiguous: several unsigned calls armed for this host")
        return None
    # bytes.rfind per distinct signature (C two-way search): 2.2 ms per candidate on a 7.4 MB body, measured faster
    # than a regex alternation, which CPython does not compile into a multi-pattern automaton.
    buf = bytes(body)
    pos = {s: buf.rfind(s) for s in {a["sig"] for a in signed}}
    hit = sorted(((pos[a["sig"]], a) for a in signed if pos[a["sig"]] >= 0), key=lambda x: -x[0])
    if not hit:
        TAP_STATS["sig_miss" if len(cands) == 1 else "unmatched"] += 1
        return None  # no armed call's signature: a sidecar or unrelated request (not a miss of any armed call)
    if len(hit) > 1 and hit[0][0] == hit[1][0]:
        TAP_STATS["ambiguous"] += 1
        _miss([hit[0][1], hit[1][1]], "ambiguous: two armed calls' signatures end at the same place")
        return None
    TAP_STATS["sig" if len(signed) > 1 else "single"] += 1
    return hit[0][1]


def _validated(con, arm: dict, ref: dict) -> str | None:
    """Validate outer conversation shape AND signature position before assigning exact wire/credentials.

    Signatures inside a flattened transcript are not request identity. System extraction, same-speaker merging
    and Responses reasoning splits may change physical item counts, but not the minimum user/assistant runs.
    """
    sig = arm.get("sig")
    if not sig:
        return None
    items = ref.get("items") or []
    if not items:
        return "request has no message list (not a conversation request)"
    s = sig.decode()
    tail = max(1, int(arm.get("sig_k") or 1)) + SIG_ADAPTER_SLACK
    matching = []
    for h in items[-tail:]:
        raw = inspector.get_blob_str(con, h)
        if s in raw:
            matching.append((raw, inspector.get_blob(con, h)))
    if not matching:
        return f"signature not in the request's last {tail} items (a request carrying an older copy)"
    required_runs = arm.get("speaker_runs") or 0
    if len(items) < required_runs:
        return f"conversation structure collapsed: {len(items)} items for {required_runs} armed speaker runs (flattened sidecar)"
    if required_runs:
        runs, previous = 0, None
        for h in items:
            speaker = _speaker(inspector.get_blob(con, h))
            if speaker is not None and speaker != previous:
                runs += 1
                previous = speaker
            if runs >= required_runs:
                break
        if runs < required_runs:
            return f"conversation structure collapsed: {runs} speaker runs, expected at least {required_runs}"
    # Single conversational items can be sent with tools disabled by a wrapper; tool_count alone is not identity.
    # In a multi-item tool-enabled conversation, losing every schema is an additional sidecar mismatch.
    if arm.get("tools_expected") and arm.get("conversation_items", 0) > 1:
        keys = ref.get("keys") or {}
        if not any(inspector.get_blob(con, keys[k]) for k in ("tools", "functions") if keys.get(k)):
            return "tool schemas missing from a tool-enabled armed request (sidecar)"
    role = arm.get("sig_speaker")
    size = arm.get("sig_item_bytes")
    for raw, message in matching:
        if role is not None and _speaker(message) != role:
            continue
        # Adapters can rewrap/escape a message and add bounded framing, not pack the entire conversation into it.
        if size and len(raw.encode()) > max(size * 8, size + 4096):
            continue
        return None
    return "signature-bearing item has a different speaker or implausible expansion (flattened sidecar)"


def _is_this_call(arm: dict, n: int) -> bool:
    """Whether an outbound body of ``n`` bytes is the armed call's request, not a sidecar LLM call made while it is
    armed (another plugin's classifier, an auxiliary client). Hermes reports the request size up front; a sidecar
    is a different, far smaller request. After the first accepted body only same-size resends (SDK retries) count."""
    got = arm.get("got")
    if got:
        return 0.5 <= n / got <= 2.0
    exp = arm.get("expect")
    return not exp or n >= exp * 0.25


DECODE_HARD_CAP = 256 * 1024 * 1024


def decode_body(data: bytes, encoding: str, cap: int | None = None) -> bytes | None:
    """A content-encoded request body minus the transport encoding, decompressed into at most ``cap`` bytes (the
    capture budget): a body that would expand past it — or is truncated, multi-frame, or in an unsupported encoding —
    is None, before any of it is kept. Fails closed."""
    cap = cap or DECODE_HARD_CAP
    try:
        if encoding == "zstd":
            try:
                from compression import zstd  # Python 3.14+
            except ImportError:
                import io
                import zstandard  # type: ignore
                out = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data)).read(cap + 1)
                return out if len(out) <= cap else None
            d = zstd.ZstdDecompressor()
            out = d.decompress(data, max_length=cap + 1)
            return out if len(out) <= cap and d.eof and not d.unused_data else None
        if encoding in ("gzip", "x-gzip", "deflate"):
            import zlib
            modes = (16 + zlib.MAX_WBITS,) if encoding != "deflate" else (zlib.MAX_WBITS, -zlib.MAX_WBITS)
            for wbits in modes:
                d = zlib.decompressobj(wbits)
                try:
                    out = d.decompress(data, cap + 1)
                except zlib.error:
                    continue
                return out if len(out) <= cap and d.eof and not d.unconsumed_tail else None
            return None
        # br and anything else: no bounded decoder here — not captured
    except Exception:
        return None
    return None


_CREDENTIAL_LOCK = threading.Lock()
_CREDENTIAL_EXTENSION = None


def _credential_extension():
    """Optional local enrichment, never part of the upstream/core distribution.

    The core does not parse credentials or discover credential stores. Without
    this separately shipped module, provider/model remain the routing identity.
    """
    global _CREDENTIAL_EXTENSION
    path = Path(__file__).resolve().parent.parent / "extensions" / "credentials.py"
    if not path.is_file():
        return None
    with _CREDENTIAL_LOCK:
        if _CREDENTIAL_EXTENSION is None:
            spec = importlib.util.spec_from_file_location(__name__ + "_credentials", path)
            if spec is None or spec.loader is None:
                return None
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            _CREDENTIAL_EXTENSION = mod
        return _CREDENTIAL_EXTENSION


def credential_identity(headers: dict) -> tuple[str, str] | None:
    """Optional extension identity; stock/core capture never derives one from secrets."""
    extension = _credential_extension()
    return extension.credential_identity(headers, home=store.hermes_home()) if extension else None


def on_http_request(request: Any) -> None:
    """Called by the httpx tap with the final ``httpx.Request``; never raises, never reads a stream."""
    if not (SETTINGS.get("enabled", True) and SETTINGS.get("capture_payloads", True)):
        return
    if getattr(request, "method", "") != "POST":
        return
    url = getattr(request, "url", None)
    host = getattr(url, "host", None)
    with _ARMED_LOCK:
        live = any(a["host"] == host and not a.get("done") for a in _ARMED_BY_ID.values())
    if not live and _ARMED.get() is None:
        return  # nothing armed for this host: not a conversation call (cheap exit before touching the body)
    try:
        body = request.content  # bytes for SDK JSON bodies; streamed bodies raise and are skipped
    except Exception:
        return
    if not isinstance(body, (bytes, bytearray)):
        return
    max_bytes = int(float(SETTINGS.get("max_request_mb") or 0) * 1024 * 1024)
    enc = str(request.headers.get("content-encoding") or "").strip().lower()
    if enc and enc != "identity":
        # e.g. Hermes zstd-compresses Codex requests in an httpx event hook; bounded by the capture budget
        body = decode_body(bytes(body), enc, max_bytes or None)
        if body is None:
            TAP_STATS["undecodable"] += 1
            with _ARMED_LOCK:
                _miss([a for a in _ARMED_BY_ID.values() if a["host"] == host and not a.get("done")],
                      f"request body in {enc} could not be decoded within the capture budget")
            return
    if max_bytes and len(body) > max_bytes:
        return
    if not body.lstrip()[:1] in (b"{", b"["):
        return
    arm = _armed_for(host, body)
    if arm is None:
        return
    if not _is_this_call(arm, len(body)):
        _miss([arm], "the matching request's size does not fit the call")
        return
    first = not arm.get("got")
    arm["got"] = arm.get("got") or len(body)
    cid = arm["id"]
    nonce = os.urandom(6).hex()  # this request's tag; honoured by the proxy join only once its capture is validated
    proxy_hop = store.is_local_host(getattr(url, "host", "") or "")
    fp = None
    if proxy_hop:
        # The token here is the proxy's client key, not a provider credential: record none (the upstream one comes
        # with the proxy's log) and tag the request so that log joins this call exactly, not by timestamp. Local
        # hop only; CLIProxyAPI builds upstream headers from an allow-list and logs the downstream ones.
        if SETTINGS.get("tag_proxy_requests", True):
            try:
                request.headers[CALL_HEADER] = f"{cid}~{nonce}"
            except Exception:
                pass
    else:
        try:
            fp = credential_identity(dict(request.headers))
        except Exception:
            fp = None
    try:
        headers = _redact_headers(dict(request.headers))
    except Exception:
        headers = {}
    safe = _safe_url(str(url))

    def job(con):
        text = bytes(body).decode("utf-8", "surrogatepass")
        ref = inspector.itemize(con, text)
        if not ref:
            return
        why = _validated(con, arm, ref)
        if why:  # captured, but not attributable to this call: record nothing on it except the reason
            TAP_STATS["rejected"] += 1
            if first and arm.get("got") == len(body):
                arm["got"] = None  # let the call's real request still pass the size check
            store.upsert(con, {"id": cid, "tap_miss": why}, "wire_calls")
            persist_tap_stats(con)
            return
        TAP_STATS["validated"] += 1
        cur = con.execute("SELECT req_down, req_hermes FROM wire_calls WHERE id=?", (cid,)).fetchone()
        upd = {"id": cid, "req_down": json.dumps(ref), "hdr_down": json.dumps(headers), "req_bytes": len(body),
               "n_items": inspector.ref_item_count(ref), "url": safe, "exact": 1}
        if cur is None:
            upd.update(source="hermes", captured=time.time())
        elif cur[0] and not cur[1]:
            upd["req_hermes"] = cur[0]  # what Hermes handed the client, before any client-side rewrite
        try:
            nonces = json.loads((con.execute("SELECT tap_nonces FROM wire_calls WHERE id=?", (cid,)).fetchone() or [None])[0] or "[]")
        except Exception:
            nonces = []
        upd.update(tap_nonces=json.dumps((nonces + [nonce])[-8:]), tap_miss=None)
        store.upsert(con, upd, "wire_calls")
        persist_tap_stats(con)
        # The final request's credential wins (a failover's later attempt replaces an earlier one's); a proxy merge
        # replaces it with the upstream credential and is never overwritten here.
        tap = (None, "proxy") if proxy_hop else (fp[0], fp[1]) if fp else (None, None)
        con.execute("UPDATE wire_calls SET tap_key=?, tap_kind=? WHERE id=?", (tap[0], tap[1], cid))
        if tap[1] is not None:
            store.restore_tap_credential(con, cid)
            store.bump_calls_rev(con)

    _writer.submit(job)


CALL_HEADER = "X-Wiretap-Call"
_TAP_FLAG = "_wiretap_http_tap"
_CAPTURE_MODULE = __name__


def install_http_tap() -> bool:
    """Wrap httpx's final pre-transport step once per process. The wrappers resolve this module by name at call
    time, so a plugin reload uses the new code; with the plugin unloaded they are a pass-through."""
    try:
        import httpx
    except Exception:
        return False
    installed = False
    for cls, is_async in ((httpx.Client, False), (httpx.AsyncClient, True)):
        orig = getattr(cls, "_send_single_request", None)
        if orig is None or getattr(orig, _TAP_FLAG, False):
            continue

        def _observe(request):
            mod = sys.modules.get(_CAPTURE_MODULE)
            if mod is not None:
                try:
                    mod.on_http_request(request)
                except Exception:
                    pass

        if is_async:
            async def tapped(self, request, *a, __orig=orig, **k):
                _observe(request)
                return await __orig(self, request, *a, **k)
        else:
            def tapped(self, request, *a, __orig=orig, **k):
                _observe(request)
                return __orig(self, request, *a, **k)
        setattr(tapped, _TAP_FLAG, True)
        tapped.__wrapped__ = orig
        setattr(cls, "_send_single_request", tapped)
        installed = True
    return installed


# ───────────────────────── hook entry points (called from __init__.py) ─────────────────────────
def on_pre(kw: dict, api_kwargs: dict | None = None) -> None:
    if not SETTINGS.get("enabled", True):
        return
    row = base_row(kw)
    try:
        _arm(row["id"], kw)
    except Exception:
        pass
    row["attempts"] = _int(kw.get("retry_count")) + 1
    snap = None
    if SETTINGS.get("capture_payloads", True):
        max_bytes = int(float(SETTINGS.get("max_request_mb") or 0) * 1024 * 1024)
        chars = kw.get("request_char_count")
        if max_bytes and isinstance(chars, (int, float)) and chars > max_bytes:
            # Bound the in-turn cost before serializing anything (Hermes reports the request size up front).
            snap = {"too_large": True, "size": int(chars), "n_items": kw.get("message_count")}
        else:
            if api_kwargs is None:
                api_kwargs = _caller_api_kwargs(kw.get("request_messages"))
            snap = snapshot_request(kw, api_kwargs, max_bytes)
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
                           "url": row.get("url"), "req_down": json.dumps(ref), "hdr_down": json.dumps(snap["headers"]),
                           "n_items": len(snap["items"]), "req_bytes": snap["size"], "captured": time.time(),
                           "session_id": row.get("session_id"), "source": "hermes", "exact": 1 if snap["exact"] else 0},
                     "wire_calls")

    _writer.submit(job)


def on_post(kw: dict) -> None:
    if not SETTINGS.get("enabled", True):
        return
    row = ok_row(kw)
    row["response_error"] = None  # a successful host retry supersedes earlier proxy-response failure
    cid = row["id"]
    arm = _disarm(cid)
    miss = None if arm is None or arm.get("got") else (arm.get("why") or "no outgoing request matched this call")
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
        if miss and SETTINGS.get("capture_payloads", True):
            try:  # why this call has no exact wire (diagnosable per call, not only in process counters)
                if not con.execute("SELECT 1 FROM wire_calls WHERE id=? AND exact=1", (cid,)).fetchone():
                    store.upsert(con, {"id": cid, "tap_miss": miss}, "wire_calls")
            except Exception:
                pass
        try:
            priced(row, base_url)
            persist_tap_stats(con)
        except Exception:
            logger.debug("wiretap pricing failed", exc_info=True)
        store.upsert(con, row)
        try:  # the call may have failed over to another family after a proxy log of the first was merged in
            if con.execute("SELECT 1 FROM calls WHERE id=? AND proxy_rid IS NOT NULL", (cid,)).fetchone():
                extension = _sibling("telemetry")._proxy_extension()
                if extension is not None:
                    extension.detach_cross_family(con, cid)
        except Exception:
            logger.debug("wiretap cross-family detach failed", exc_info=True)
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
