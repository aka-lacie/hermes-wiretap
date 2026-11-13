"""Wiretap's Session & Wire Inspector — backend for wiretap.

Two jobs:
  1. Wire capture storage. Every captured model call — from the agent hook (``capture.py``, all providers) or
     from optional proxy request logs (``telemetry.py``) — is stored as a ``wire_calls`` row whose request is
     content-addressed per item (each message / top-level key is a zlib blob keyed by sha1), so a long history
     shared by consecutive calls is stored once. Proxy captures add the upstream (proxy-rewritten) request and
     raw HTTP headers (secrets redacted) to the matching Hermes-side row.
  2. Session view. Reads Hermes ``state.db`` read-only, classifies every row by its provenance (user message vs
     subagent completion vs webhook/cron notice vs compaction summary vs assistant vs tool result), diffs
     content vs api_content, correlates each assistant row to the wire call that produced it (session id and
     tool-call ids first, then response text), and reports how each user-role row was framed on the wire
     (USER_REQUEST vs SYSTEM_MESSAGE) on first send and on the latest replay. Both schema generations are read: a
     stock upstream store (provenance inferred from text), with optional session-schema adapters supplying
     authoritative provenance and lineage when their columns are present.
"""
from __future__ import annotations

import base64
import bisect
import difflib
import math
import importlib.util
import hashlib
import json
import re
import sqlite3
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path


def _sibling(name: str):
    """Load a sibling module under a private name (no sys.path mutation; safe inside Hermes processes)."""
    prefix = globals().get("_wiretap_sibling_prefix", "_wiretap_")
    key = f"{prefix}{name}"
    if key in sys.modules:
        return sys.modules[key]
    path = Path(__file__).resolve().with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"wiretap: cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    setattr(mod, "_wiretap_sibling_prefix", prefix)
    sys.modules[key] = mod
    if prefix == "_wiretap_":
        spec.loader.exec_module(mod)
    else:
        exec(compile(path.read_bytes(), str(path), "exec"), mod.__dict__)
    return mod


store = _sibling("store")
forensics = _sibling("forensics")


# This distribution ships and loads no session-schema adapter: sessions are read with the stock
# ``state.db`` columns, and every ``_adapt`` call below returns its default.
SESSION_ADAPTER = None


def _adapt(method, *args, default=None):
    """The inspector owns stock behavior; with no adapter this is always ``default``."""
    return getattr(SESSION_ADAPTER, method)(*args) if SESSION_ADAPTER is not None else default


def state_schema(scon):
    mcols = {r[1] for r in scon.execute("PRAGMA table_info(messages)")}
    scols = {r[1] for r in scon.execute("PRAGMA table_info(sessions)")}
    return _adapt("schema_label", mcols, scols) or "untyped (stock-compatible)"


def main_session_filter(available):
    return _adapt("main_session_filter", available, default="")


def notice_identity(row):
    return (str(row.get("platform_message_id") or "") + str(row.get("ref") or "")
            + _adapt("notice_identity", row, default=""))


def session_output_columns(view):
    """Additional public projection fields supplied by the optional schema adapter."""
    return _adapt("output_columns", view, default=())


put_blob, put_blob_str, get_blob, get_blob_str = store.put_blob, store.put_blob_str, store.get_blob, store.get_blob_str
SECTION_RE = re.compile(r"^=== (.+?) ===$")
SECRET_HDR = re.compile(r"(auth|key|token|cookie|secret|session-id|signature|password)", re.I)
WS = re.compile(r"\s+")
_cache_lock = threading.Lock()
_BLOB_CACHE_MAX = 30000


def init(con):
    store.init(con)


def gc(con, force=False, keep_s=None):
    store.gc(con, keep_s=keep_s, force=force)


# ───────────────────────── proxy-log capture ─────────────────────────
def _sections(path: Path):
    secs, name, cur = [], "PRE", []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = SECTION_RE.match(line)
            if m:
                secs.append((name, cur))
                name, cur = m.group(1), []
            else:
                cur.append(line)
    secs.append((name, cur))
    return secs


def redact_headers(pairs) -> dict:
    """Header lines ("K: v") or a mapping → dict with every credential-bearing value redacted."""
    out = {}
    items = pairs.items() if isinstance(pairs, dict) else (ln.split(": ", 1) for ln in pairs if ": " in ln)
    for k, v in items:
        out[str(k)] = "‹redacted›" if SECRET_HDR.search(str(k)) else str(v)
    return out


_redact_headers = redact_headers


def itemize(con, raw: str) -> dict | None:
    try:
        b = json.loads(raw)
    except Exception:
        return {"raw": put_blob(con, raw, raw=True)} if raw else None
    if not isinstance(b, dict):
        return {"raw": put_blob(con, raw, raw=True)}
    list_key = next((k for k in ("contents", "messages", "input") if isinstance(b.get(k), list)), None)
    keys = {k: put_blob(con, v) for k, v in b.items() if k != list_key}
    items = [put_blob(con, x) for x in (b.get(list_key) or [])] if list_key else []
    return {"order": list(b.keys()), "keys": keys, "list_key": list_key, "items": items}


def rebuild(con, ref: dict | None):
    if not ref:
        return None
    if "raw" in ref:
        return get_blob(con, ref["raw"])
    out = {}
    for k in ref["order"]:
        if k == ref.get("list_key"):
            out[k] = [get_blob(con, h) for h in ref["items"]]
        else:
            out[k] = get_blob(con, ref["keys"][k])
    return out


def parse_response(lines: list[str]) -> dict:
    """Normalize gemini / anthropic / openai (chat or responses) stream or JSON bodies."""
    res = {"text": "", "thinking": "", "tool_calls": [], "finish": None, "model": None, "response_id": None, "usage": None}
    tcs: dict = {}
    objs = []
    for ln in lines:
        s = ln[5:].strip() if ln.startswith("data:") else (ln if ln.startswith("{") else None)
        if not s or s == "[DONE]":
            continue
        try:
            objs.append(json.loads(s))
        except Exception:
            pass
    for o in objs:
        if not isinstance(o, dict):
            continue
        # gemini
        for c in o.get("candidates") or []:
            for p in (c.get("content") or {}).get("parts") or []:
                if "functionCall" in p:
                    fc = p["functionCall"]
                    res["tool_calls"].append({"id": fc.get("id"), "name": fc.get("name"), "args": fc.get("args")})
                elif p.get("thought"):
                    res["thinking"] += p.get("text") or ""
                elif "text" in p:
                    res["text"] += p.get("text") or ""
            if c.get("finishReason"):
                res["finish"] = c["finishReason"]
        if o.get("usageMetadata", {}).get("promptTokenCount"):
            res["usage"] = o["usageMetadata"]
        res["model"] = o.get("modelVersion") or res["model"]
        res["response_id"] = o.get("responseId") or res["response_id"]
        # anthropic
        t = o.get("type")
        if t == "message_start":
            m = o.get("message") or {}
            res["model"], res["response_id"] = m.get("model"), m.get("id")
        elif t == "content_block_start":
            cb = o.get("content_block") or {}
            if cb.get("type") == "tool_use":
                tcs[("a", o.get("index"))] = {"id": cb.get("id"), "name": cb.get("name"), "args": ""}
            elif cb.get("type") == "text":
                res["text"] += cb.get("text") or ""
        elif t == "content_block_delta":
            d = o.get("delta") or {}
            if d.get("type") == "text_delta":
                res["text"] += d.get("text") or ""
            elif d.get("type") == "thinking_delta":
                res["thinking"] += d.get("thinking") or ""
            elif d.get("type") == "input_json_delta" and ("a", o.get("index")) in tcs:
                tcs[("a", o.get("index"))]["args"] += d.get("partial_json") or ""
        elif t == "message_delta":
            res["finish"] = (o.get("delta") or {}).get("stop_reason") or res["finish"]
            res["usage"] = o.get("usage") or res["usage"]
        elif t == "message" and o.get("content"):  # non-stream anthropic
            for cb in o["content"]:
                if cb.get("type") == "text":
                    res["text"] += cb.get("text", "")
                elif cb.get("type") == "tool_use":
                    res["tool_calls"].append({"id": cb.get("id"), "name": cb.get("name"), "args": cb.get("input")})
            res["finish"] = o.get("stop_reason")
        # openai chat
        for ch in o.get("choices") or []:
            d = ch.get("delta") or ch.get("message") or {}
            res["text"] += d.get("content") or ""
            res["thinking"] += d.get("reasoning_content") or d.get("reasoning") or ""
            for tc in d.get("tool_calls") or []:
                k = ("o", tc.get("index", tc.get("id")))
                cur = tcs.setdefault(k, {"id": None, "name": None, "args": ""})
                cur["id"] = tc.get("id") or cur["id"]
                fn = tc.get("function") or {}
                cur["name"] = fn.get("name") or cur["name"]
                cur["args"] += fn.get("arguments") or ""
            if ch.get("finish_reason"):
                res["finish"] = ch["finish_reason"]
        if o.get("object") == "chat.completion.chunk" or "choices" in o:
            res["model"] = o.get("model") or res["model"]
            res["response_id"] = o.get("id") or res["response_id"]
            res["usage"] = o.get("usage") or res["usage"]
        # openai responses
        if isinstance(t, str) and t.startswith("response."):
            if t == "response.output_text.delta":
                res["text"] += o.get("delta") or ""
            elif t in ("response.reasoning_summary_text.delta", "response.reasoning_text.delta"):
                res["thinking"] += o.get("delta") or ""
            elif t == "response.output_item.done" and (o.get("item") or {}).get("type") == "function_call":
                it = o["item"]
                res["tool_calls"].append({"id": it.get("call_id"), "name": it.get("name"), "args": it.get("arguments")})
            elif t == "response.completed":
                r = o.get("response") or {}
                res["finish"], res["model"], res["response_id"] = r.get("status"), r.get("model"), r.get("id")
                res["usage"] = r.get("usage")
    for v in tcs.values():
        a = v["args"]
        if isinstance(a, str):
            try:
                v["args"] = json.loads(a) if a else {}
            except Exception:
                pass
        res["tool_calls"].append(v)
    return res


def norm(s: str) -> str:
    return WS.sub(" ", s or "").strip()


def response_body_lines(lines: list[str]) -> list[str]:
    """Proxy Body marker, or the actual downstream header/body separator.

    Completed upstream sections with metadata but no Body marker had no chunks.
    Keep the no-separator fallback for old/synthetic logs, not as a header parser.
    """
    if "Body:" in lines:
        return lines[lines.index("Body:") + 1:]
    start = (lines.index("Headers:") + 1 if "Headers:" in lines else
             next((i for i, ln in enumerate(lines) if ln.strip()), len(lines)))
    for i in range(start, len(lines)):
        if not lines[i].strip():
            return lines[i + 1:]
    return [ln for ln in lines if ln and ln not in ("Headers:", "<none>") and
            (ln.startswith(("data:", "event:")) or not re.match(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+:\s*", ln))]


def merge_proxy_attempts(previous, incoming: list[dict]) -> list[dict]:
    """Idempotent source-local identity; different proxy requests may reuse attempt 1."""
    old = _loads(previous, []) if isinstance(previous, str) else (previous or [])
    merged = {(a.get("file"), a.get("n")): a for a in old if isinstance(a, dict)}
    for a in incoming:
        key = (a.get("file"), a.get("n"))
        merged[key] = {**merged.get(key, {}), **a}
    return sorted(merged.values(), key=lambda a: (a.get("t0") or 0, a.get("file") or "", a.get("n") or 0))


def capture_file(con, path: Path, row: dict, merge_into: str | None = None):
    """Persist the wire payload of one proxy request log.

    With ``merge_into`` (the id of the Hermes-side capture of the same call) the proxy contributes what only it
    can see — the upstream request it actually sent, the real HTTP headers on both legs (secrets redacted) and
    the raw response stream — and the Hermes-side request stays the canonical downstream copy.
    """
    secs = _sections(path)
    down_body = up_body = None
    hdr_down, hdr_up, resp_lines = {}, {}, []
    attempts = []
    responses = {}
    metadata = {a["n"]: a for a in _loads(row.get("proxy_attempts"), [])}
    for name, lines in secs:
        if name == "HEADERS":
            hdr_down = redact_headers(lines)
        elif name == "REQUEST BODY":
            down_body = next((l for l in lines if l.startswith("{")), None)
        elif name.startswith("API REQUEST "):
            hdr, body, mode = [], None, None
            for ln in lines:
                if ln == "Headers:":
                    mode = "h"
                elif ln == "Body:":
                    mode = "b"
                elif mode == "h" and ln:
                    hdr.append(ln)
                elif mode == "b" and ln.startswith("{") and body is None:
                    body = ln
            n = int(name.split()[-1])
            attempts.append({**metadata.get(n, {}), "n": n, "file": path.name, "layer": "proxy_upstream",
                             "req_up": itemize(con, body) if body else None, "hdr_up": redact_headers(hdr)})
        elif name.startswith("API RESPONSE "):
            responses[int(name.split()[-1])] = lines
        elif name == "RESPONSE":
            resp_lines = lines
    for a in attempts:
        lines = responses.get(a["n"])
        a["resp_raw"] = put_blob(con, "\n".join(lines), raw=True) if lines is not None else None
    if attempts:
        req_up, hdr_up = attempts[-1]["req_up"], attempts[-1]["hdr_up"]
    else:
        req_up = None
    cid = merge_into or row["id"]
    prior = con.execute("SELECT proxy_attempts FROM wire_calls WHERE id=?", (cid,)).fetchone()
    history = merge_proxy_attempts(prior[0] if prior else None, attempts)
    # Late re-ingestion of an earlier request must not replace the final layer.
    newest = not history or history[-1].get("file") == path.name
    if not newest:
        store.upsert(con, {"id": cid, "proxy_attempts": json.dumps(history)}, "wire_calls")
        return
    raw_h = put_blob(con, "\n".join(resp_lines), raw=True)
    existing = None
    if merge_into:
        existing = con.execute("SELECT req_down, resp, req_hermes FROM wire_calls WHERE id=?", (merge_into,)).fetchone()
    if existing and existing[0]:
        upd = {"id": merge_into, "file": path.name, "req_up": json.dumps(req_up), "hdr_down": json.dumps(hdr_down),
               "hdr_up": json.dumps(hdr_up), "resp_raw": raw_h, "proxy_attempts": json.dumps(history)}
        if down_body:
            # What the client actually sent over HTTP, after any provider adapter rewrote Hermes's messages
            # (e.g. agy USER_REQUEST/SYSTEM_MESSAGE framing, native functionCall parts). Keep Hermes's own copy.
            ref = itemize(con, down_body)
            upd.update(req_down=json.dumps(ref), req_bytes=len(down_body), n_items=ref_item_count(ref))
            if not existing[2]:
                upd["req_hermes"] = existing[0]
        if not existing[1]:
            resp = parse_response(resp_lines)
            upd.update(resp=json.dumps(resp, ensure_ascii=False, default=str),
                       tc_ids=json.dumps([t["id"] for t in resp["tool_calls"] if t.get("id")]),
                       text_head=norm(resp["text"])[:400])
        store.upsert(con, upd, "wire_calls")
        _refresh_signals(con, merge_into)
        return
    req_down = itemize(con, down_body) if down_body else None
    resp = parse_response(resp_lines)
    tc_ids = [t["id"] for t in resp["tool_calls"] if t.get("id")]
    store.upsert(con, {
        "id": merge_into or row["id"], "file": path.name, "started": row.get("started"), "ended": row.get("ended"),
        "family": row.get("family"), "model": row.get("model"), "url": row.get("url"), "status": row.get("status"),
        "req_down": json.dumps(req_down), "req_up": json.dumps(req_up), "hdr_down": json.dumps(hdr_down),
        "hdr_up": json.dumps(hdr_up), "resp_raw": raw_h, "resp": json.dumps(resp, ensure_ascii=False, default=str),
        "proxy_attempts": json.dumps(history),
        "tc_ids": json.dumps(tc_ids), "text_head": norm(resp["text"])[:400],
        "n_items": len((req_down or {}).get("items") or []), "req_bytes": len(down_body or ""), "captured": time.time(),
        "session_id": row.get("session_id"), "source": "proxy", "exact": 1}, "wire_calls")
    _refresh_signals(con, merge_into or row["id"])


def _refresh_signals(con, cid: str) -> None:
    """The proxy's raw stream is the richest response record (fallback blocks, notices): re-derive signals."""
    try:
        store.refresh_signals(con, cid)
    except Exception:
        pass


def ref_item_count(ref: dict | None) -> int | None:
    """request_item_count for an already itemized body (no second parse)."""
    return len(ref["items"]) if ref and ref.get("list_key") else None


def request_item_count(raw: str | None) -> int | None:
    """Message-item count of a raw request body (for matching a proxy log to its Hermes-side capture)."""
    try:
        b = json.loads(raw or "")
    except Exception:
        return None
    if not isinstance(b, dict):
        return None
    lst = next((b[k] for k in ("contents", "messages", "input") if isinstance(b.get(k), list)), None)
    return len(lst) if lst is not None else None


# ───────────────────────── item text helpers ─────────────────────────
def item_text(obj) -> str:
    """All human-visible text in a wire item (gemini parts, anthropic blocks, openai content)."""
    out = []

    def walk(x, k=None):
        if isinstance(x, str):
            if k in ("text", "content", "output", "arguments", "thinking"):
                out.append(x)
        elif isinstance(x, dict):
            for kk, v in x.items():
                if kk in ("thoughtSignature", "signature", "data", "inlineData", "image_url", "source"):
                    continue
                walk(v, kk)
        elif isinstance(x, list):
            for v in x:
                walk(v, k)
    walk(obj)
    return "\n".join(out)


def item_role(obj) -> str:
    if isinstance(obj, dict):
        r = obj.get("role") or obj.get("type") or "?"
        if isinstance(obj.get("parts"), list):
            kinds = {next(iter(p.keys()), "?") for p in obj["parts"] if isinstance(p, dict)}
            if "functionResponse" in kinds:
                return f"{r}:functionResponse"
            if "functionCall" in kinds:
                return f"{r}:functionCall"
        if isinstance(obj.get("content"), list):
            kinds = {b.get("type") for b in obj["content"] if isinstance(b, dict)}
            if "tool_result" in kinds:
                return f"{r}:tool_result"
            if "tool_use" in kinds:
                return f"{r}:tool_use"
        if obj.get("tool_calls"):  # OpenAI chat-completions assistant turn
            return f"{r}:tool_calls"
        return str(r)
    return "?"


def is_call_role(role: str) -> bool:
    return any(k in role for k in ("functionCall", "tool_use", "tool_calls")) or role == "function_call"


def is_result_role(role: str) -> bool:
    return any(k in role for k in ("functionResponse", "tool_result")) or role in ("tool", "function_call_output")


def framing_of(text: str) -> str:
    if "<SYSTEM_MESSAGE>" in text:
        return "SYSTEM_MESSAGE"
    if "<USER_REQUEST>" in text:
        return "USER_REQUEST"
    return "plain"


_ntext_cache: "OrderedDict[str, tuple]" = OrderedDict()


def item_norm(con, h: str) -> tuple[str, str, str]:
    """(role, normalized text, framing) for a blob, cached."""
    with _cache_lock:
        if h in _ntext_cache:
            return _ntext_cache[h]
    obj = get_blob(con, h)
    t = item_text(obj)
    v = (item_role(obj), norm(t), framing_of(t))
    with _cache_lock:
        _ntext_cache[h] = v
        while len(_ntext_cache) > _BLOB_CACHE_MAX:
            _ntext_cache.popitem(last=False)
    return v


# ───────────────────────── session view (state.db, read-only) ─────────────────────────
MSG_COLS = ("id", "role", "content", "api_content", "tool_call_id", "tool_calls", "tool_name", "timestamp", "finish_reason",
            "reasoning", "reasoning_content", "platform_message_id", "active", "compacted", "display_kind", "display_metadata",
            "_compressed_summary", "token_count", "message_uid")
SESSION_COLS = ("id", "source", "model", "title", "parent_session_id", "created_source", "hidden", "started_at",
                "last_activity_at", "message_count", "billing_provider", "session_key", "chat_type")
DELEG_RE = re.compile(r"\bdeleg_[0-9a-f]{8}\b")
PROC_RE = re.compile(r"\bproc_[0-9a-f]{12}\b")
NARRATE_RE = re.compile(r"\b(just (?:finished|came back|wrapped up|pulled|landed|returned|reported)|came back with|finished (?:the|its|auditing|building)|has (?:finished|come back))\b", re.I)
# Wrapper text Hermes (or a plugin) adds at send time. Any XML-style block that is in api_content but not in
# content is reported by its tag name; bracket markers below are Hermes's own envelope lines.
TAG_BLOCK_RE = re.compile(r"<([A-Za-z][\w:-]{1,48})\b[^<>]*>.*?</\1>", re.S)
INJECT_BLOCKS = [
    ("triggering_message_id", re.compile(r"\[Triggering message id: [^\]]*\]")),
    ("timestamp", re.compile(r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d)? [A-Z]{2,5}\]", re.M)),
    ("out_of_band", re.compile(r"\[OUT-OF-BAND USER MESSAGE")),
    ("interface_switch", re.compile(r"\[System: This conversation is now being answered")),
    ("internal_notification_footer", re.compile(r"\[INTERNAL NOTIFICATION — generated by the Hermes gateway")),
]


def state_con(path: Path):
    return store.connect_ro(path)


def _select(scon, table: str, wanted) -> str:
    """Column list for ``wanted`` that tolerates older state.db schemas (missing columns read as NULL)."""
    have = {r[1] for r in scon.execute(f"PRAGMA table_info({table})")}
    wanted = tuple(dict.fromkeys(tuple(wanted) + _adapt("columns", table, have, default=())))
    return ", ".join(c if c in have else f"NULL AS {c}" for c in wanted)


def _session_source(scon, sid: str) -> str:
    try:
        r = scon.execute("SELECT source FROM sessions WHERE id=?", (sid,)).fetchone()
        return (r[0] or "") if r else ""
    except sqlite3.Error:
        return ""


_LOCAL_SOURCES = {"", "cli", "tui", "local", "api", "api_server", "acp"}


def row_parts(r) -> list | None:
    """Optional structured row content, interpreted only by the session adapter."""
    return _adapt("row_parts", r)


def classify(r: dict, source: str = "") -> dict:
    """Provenance of one state.db row. ``source`` is the session's platform (discord, telegram, cli, …).

    Adapter-provided provenance is authoritative; text heuristics classify all other rows."""
    typed = _adapt("classify", r, source)
    if typed:
        return typed
    role, c = r["role"], r.get("content") or ""
    head = c.lstrip()[:400]
    dk = r.get("display_kind") or ""
    if role == "user":
        if r.get("_compressed_summary") or head.startswith("[CONTEXT COMPACTION"):
            return {"kind": "compaction", "label": "COMPACTION SUMMARY"}
        if "[ASYNC DELEGATION BATCH COMPLETE" in head:
            m = DELEG_RE.search(head)
            return {"kind": "subagent", "label": "INTERNAL · SUBAGENT COMPLETION", "ref": m.group(0) if m else None}
        if "[HERMES_INTERNAL_NOTIFICATION]" in head:
            k = re.search(r"^kind:\s*(\S+)", c, re.M)
            src = re.search(r"^source:\s*(\S+)", c, re.M)
            kind = k.group(1) if k else "notification"
            lab = "WEBHOOK" if "webhook" in kind else "CRON" if "cron" in kind else "INTERNAL"
            return {"kind": "webhook" if lab == "WEBHOOK" else "cron" if lab == "CRON" else "internal",
                    "label": f"{lab} NOTIFICATION · {src.group(1) if src else kind}"}
        if "[BACKGROUND PROCESS" in head or "[IMPORTANT: Background process" in head:
            m = PROC_RE.search(head)
            return {"kind": "process", "label": "INTERNAL · PROCESS NOTICE", "ref": m.group(0) if m else None}
        if r.get("_first_child_user"):  # a delegated child's opening user turn is its parent's assignment
            return {"kind": "parent", "label": "PARENT ASSIGNMENT"}
        if head.startswith("Review the conversation above and consider saving"):
            return {"kind": "internal", "label": "INTERNAL · MEMORY REVIEW PROMPT"}
        if dk == "internal_notification":
            return {"kind": "internal", "label": "INTERNAL NOTIFICATION"}
        pm = str(r.get("platform_message_id") or "")
        tag = "" if (source or "").lower() in _LOCAL_SOURCES else f" · {source.lower()}"
        if head.startswith("[OUT-OF-BAND USER MESSAGE"):
            return {"kind": "user", "label": f"USER{tag} (out-of-band)"}
        if pm and not pm.startswith("["):  # a real platform message id (internal rows carry JSON tuples)
            return {"kind": "user", "label": f"USER{tag}", "ref": pm}
        return {"kind": "user", "label": "USER"}
    if role == "assistant":
        return {"kind": "assistant", "label": "ASSISTANT"}
    if role == "tool":
        return {"kind": "tool", "label": f"TOOL RESULT · {r.get('tool_name') or '?'}"}
    return {"kind": role or "?", "label": (role or "?").upper()}


# ───────────────────────── exact phrase matching in one pass ─────────────────────────
def _isword(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


class _Probes:
    """Exact ``probe in text`` for many fixed probes against texts, every string normalized by ``norm`` (single
    spaces, stripped).

    A probe of >= 3 words occurs in a text iff its interior words occur there as consecutive whole words, the first
    word as a suffix of the word before them and the last as a prefix of the word after. So each probe is filed once
    under one interior anchor (its rarest interior word bigram among all probes, longer words first; or its single
    interior word), and a text is scanned once: at most three dict lookups per word, then an O(|probe|) local check per
    anchor hit. Building is O(total probe length); ``find`` is O(|text| + hits).

    A probe of 1–2 words has no whole interior word, so it is matched at word boundaries: its words equal consecutive
    text words, except that the last may be a prefix when the probe was cut mid-word (``open_end``). Indexed by the
    first word's 6-char head."""

    __slots__ = ("uni", "bi", "head")

    def __init__(self, probes):
        entries, freq = [], {}
        self.head: dict = {}
        for pr in probes:
            key, p = pr[0], pr[1]
            open_end = pr[2] if len(pr) > 2 else False
            if not p:
                continue
            pw = p.split(" ")
            if len(pw) <= 2:
                if pw[-1] == "":
                    pw = pw[:-1]  # "word " — a following word must exist; handled as prefix "" of the next word
                    open_end = True
                    pw = pw + [""]
                self.head.setdefault(pw[0][:6], []).append((key, pw, open_end))
                continue
            if len(pw) >= 3:
                inner = pw[1:-1]
                cands = [((inner[0],), 1)] if len(inner) == 1 else \
                        [((inner[k], inner[k + 1]), k + 1) for k in range(len(inner) - 1)]
                exact = False
            entries.append((key, pw, cands, exact))
            for a, _ in cands:
                freq[a] = freq.get(a, 0) + 1
        self.uni: dict = {}
        self.bi: dict = {}
        for key, pw, cands, exact in entries:
            a, o = min(cands, key=lambda c: (freq[c[0]], -sum(map(len, c[0]))))
            if len(a) == 1:
                self.uni.setdefault(a[0], []).append((key, pw, o, exact))
            else:
                self.bi.setdefault(a, []).append((key, pw, o, exact))

    def __bool__(self) -> bool:
        return bool(self.uni or self.bi or self.head)

    def find(self, text: str) -> set:
        """Keys of the probes that occur in ``text``."""
        out: set = set()
        if not text or not (self.uni or self.bi or self.head):
            return out
        w = text.split(" ")
        n = len(w)
        uni, bi, head = self.uni, self.bi, self.head
        for i in range(n):
            if head:
                hit = head.get(w[i][:6])
                if hit:
                    for key, pw, open_end in hit:
                        if key in out or i + len(pw) > n:
                            continue
                        if len(pw) == 1:
                            ok = w[i].startswith(pw[0]) if open_end else w[i] == pw[0]
                        else:
                            ok = w[i] == pw[0] and (w[i + 1].startswith(pw[1]) if open_end else w[i + 1] == pw[1])
                        if ok:
                            out.add(key)
            if uni:
                hit = uni.get(w[i])
                if hit:
                    self._check(hit, w, i, n, out)
            if bi and i + 1 < n:
                hit = bi.get((w[i], w[i + 1]))
                if hit:
                    self._check(hit, w, i, n, out)
        return out

    @staticmethod
    def _check(hit, w, i, n, out) -> None:
        for key, pw, o, _exact in hit:
            if key in out:
                continue
            s0, ln = i - o, len(pw)
            if s0 < 0 or s0 + ln > n:
                continue
            if w[s0].endswith(pw[0]) and w[s0 + ln - 1].startswith(pw[-1]) and w[s0 + 1:s0 + ln - 1] == pw[1:-1]:
                out.add(key)


def _contains_any(text: str, phrases: list[str]) -> bool:
    """``any(p in text for p in phrases)`` in one pass over ``text``."""
    return bool(_Probes(enumerate(phrases)).find(text))


def _tag_blocks(text: str) -> list[str]:
    """Names matched, in order, by ``TAG_BLOCK_RE.finditer(text)`` — without its quadratic rescans when tags are
    unclosed. One pass collects open and close tags; each open tag tries its names longest-first exactly like the
    regex's backtracking (2–49 chars, ending at a word boundary) against the first matching close after it."""
    if not text or "<" not in text:
        return []
    closes: dict[str, list[int]] = {}
    for m in _CLOSE_TAG_RE.finditer(text):
        closes.setdefault(m.group(1), []).append(m.start())
    if not closes:
        return []
    out, cursor = [], 0
    for m in _OPEN_TAG_RE.finditer(text):
        if m.start() < cursor:
            continue
        name, end = m.group(1), m.end()  # end: just past the '>' of the open tag
        after = text[m.start() + 1 + len(name)] if m.start() + 1 + len(name) < len(text) else ""
        for L in range(min(len(name), 49), 1, -1):
            nxt = name[L] if L < len(name) else after
            if _isword(name[L - 1]) == (_isword(nxt) if nxt else False):
                continue  # no \b here
            lst = closes.get(name[:L])
            if not lst:
                continue
            k = bisect.bisect_left(lst, end)
            if k < len(lst):
                out.append(name[:L])
                cursor = lst[k] + len(name[:L]) + 3
                break
    return out


_OPEN_TAG_RE = re.compile(r"<([A-Za-z][\w:-]*)[^<>]*>")
_CLOSE_TAG_RE = re.compile(r"</([A-Za-z][\w:-]{1,48})>")


def inject_diff(content: str, api: str | None) -> dict | None:
    if not api or api == content:
        return None
    i = api.find(content) if content else -1
    d: dict = {"identical_core": i >= 0}
    if i >= 0:
        d["prefix"], d["suffix"] = api[:i], api[i + len(content):]
    have = set(_tag_blocks(content or ""))
    blocks = []
    for name in _tag_blocks(api):
        if name not in have and name not in blocks:
            blocks.append(name)
    blocks += [name for name, rx in INJECT_BLOCKS if rx.search(api) and not rx.search(content or "")]
    d["blocks"] = blocks
    d["len_content"], d["len_api"] = len(content or ""), len(api)
    return d


def _tool_ids(tc_json) -> list[str]:
    try:
        tcs = json.loads(tc_json or "[]") or []
    except Exception:
        return []
    out = []
    for t in tcs:
        for k in ("id", "call_id"):
            if t.get(k):
                out.append(t[k])
    return out


def _tool_names(tc_json) -> list[str]:
    try:
        return [((t.get("function") or {}).get("name") or t.get("name") or "?") for t in json.loads(tc_json or "[]") or []]
    except Exception:
        return []


def match_calls(tcon, rows: list[dict], sid: str | None = None) -> dict:
    """assistant row id -> wire call id. Tool-call ids first, then response-text prefix, nearest in time.

    Hermes-side captures carry the session id, so calls of other sessions are never candidates; proxy-only
    captures (no session id) stay eligible by time window."""
    asst = [r for r in rows if r["role"] == "assistant"]
    if not asst:
        return {}
    t0 = min(r["timestamp"] or 0 for r in asst) - 900
    t1 = max(r["timestamp"] or 0 for r in asst) + 120
    q = ("SELECT id, started, ended, family, model, tc_ids, text_head FROM wire_calls WHERE ended BETWEEN ? AND ? "
         "AND status=200")
    args: list = [t0, t1]
    if sid:
        q += " AND (session_id IS NULL OR session_id = '' OR session_id = ?)"
        args.append(sid)
    calls = [dict(c) for c in tcon.execute(q, args)]
    by_tc = {}
    for c in calls:
        for t in json.loads(c["tc_ids"] or "[]"):
            by_tc[t] = c["id"]
    # Text-head match, as hash lookups. A call matches a row body when the body starts with the call's head[:80]
    # (keyed by that string: one lookup per body prefix length) or the head starts with body[:80] (keyed by every
    # head prefix of 12..80 chars); head[:160] == body is implied by the latter. O(C·80 + A·80) total.
    by_h80: dict[str, list] = {}
    by_pref: dict[str, list] = {}
    for n, c in enumerate(calls):
        th = c["text_head"]
        if not th:
            continue
        by_h80.setdefault(th[:80], []).append(n)
        for L in range(12, min(len(th), 80) + 1):
            by_pref.setdefault(th[:L], []).append(n)
    out, used = {}, set()
    for r in asst:
        hit = next((by_tc[t] for t in _tool_ids(r.get("tool_calls")) if t in by_tc), None)
        if not hit:
            body = norm(r.get("content") or "")[:160]
            if len(body) >= 12:
                ts = r["timestamp"] or 0
                idx = set(by_pref.get(body[:80], ()))
                for L in range(1, min(len(body), 80) + 1):
                    idx.update(by_h80.get(body[:L], ()))
                cands = [calls[n] for n in sorted(idx) if calls[n]["id"] not in used
                         and -900 <= (ts - (calls[n]["ended"] or 0)) <= 120]
                if cands:
                    hit = min(cands, key=lambda c: abs(ts - (c["ended"] or 0)))["id"]
        if hit:
            out[r["id"]] = hit
            used.add(hit)
    return out


# ── view memo: inputs are the session's rows (state.db) and the wire store; both fingerprinted per request ──
_MEMO: "OrderedDict[tuple, tuple]" = OrderedDict()
_MEMO_MAX = 32
_MEMO_TTL_S = 120.0  # backstop for inputs outside the fingerprint (another process's settings, clock-derived labels)


class Fingerprint(tuple):
    """(counts, content revision, session-row hash, wire revision) — compared whole. ``digests`` are the per-row
    content digests of the active rows (in id order), so a consumer can tell "rows appended" from "rows rewritten"."""
    digests: tuple = ()


def _fingerprint(state_db: Path, tcon, sid: str, inactive: bool = False, before: int | None = None, limit: int = 5000):
    """A content revision of exactly the rows the view displays — the same selection as ``_session_view`` (active
    rows, or every row for the archived-history transcript; ``before`` / ``limit`` paging) — over every column of
    each row, so any field a view or the alignment reads (display_kind, reasoning_content, parts, ids, flags…) is
    covered without a hand-kept list. Plus counts and the session row. No length sums, no sampled fields."""
    try:
        scon = state_con(state_db)
        try:
            cols = {r[1] for r in scon.execute("PRAGMA table_info(messages)")}
            act = "COALESCE(active,1)" if "active" in cols else "1"
            s = tuple(scon.execute(f"SELECT MAX(id), MIN(id), COUNT(*), SUM({act}) FROM messages WHERE session_id=?", (sid,)).fetchone())
            meta = scon.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            mh = hashlib.blake2b(repr(tuple(meta) if meta else None).encode(), digest_size=12).hexdigest()
            where, args = ["session_id=?"], [sid]
            if not inactive:
                where.append(f"{act}=1")
            if before:
                where.append("id < ?")
                args.append(before)
            digests = []
            for r in scon.execute(f"SELECT * FROM (SELECT * FROM messages WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?) "
                                  "ORDER BY id", args + [limit]):
                h = hashlib.blake2b(digest_size=12)
                for v in r:
                    h.update(b"\x1f" if v is None else (v if isinstance(v, bytes) else str(v).encode("utf-8", "surrogatepass")))
                    h.update(b"\x1e")
                digests.append((r[0], h.digest()))
            content = hashlib.blake2b(b"".join(d for _, d in digests), digest_size=16).hexdigest()
        finally:
            scon.close()
    except sqlite3.Error:
        return None
    fp = Fingerprint((s, content, mh, store.session_wire_rev(tcon, sid)))
    fp.digests = tuple(digests)
    return fp


def _memo_get(key, fp):
    if fp is None:
        return None
    with _cache_lock:
        e = _MEMO.get(key)
        if e is None or e[0] != fp or time.time() - e[1] > _MEMO_TTL_S:
            return None
        _MEMO.move_to_end(key)
        return e[2]


def _memo_put(key, fp, val) -> None:
    if fp is None:
        return
    with _cache_lock:
        _MEMO[key] = (fp, time.time(), val)
        while len(_MEMO) > _MEMO_MAX:
            _MEMO.popitem(last=False)


def _req_items(tcon, call_id: str) -> list[str]:
    row = tcon.execute("SELECT req_down FROM wire_calls WHERE id=?", (call_id,)).fetchone()
    if not row or not row[0]:
        return []
    return (json.loads(row[0] or "null") or {}).get("items") or []


def locate_many(tcon, wants: list[tuple]) -> dict:
    """For each (key, snippet, call_id): the last item of that request whose text contains the snippet.

    One pass: the snippets become one ``_Probes`` set, each distinct request blob (requests share most items) is
    scanned once, and each request's item list is walked once. O(total distinct item text + total request items)."""
    probes = _Probes(w[:2] + (w[3] if len(w) > 3 else False,) for w in wants if w[1])
    if not probes:
        return {}
    blob_hits: dict[str, set] = {}
    by_call: dict[str, dict] = {}
    for cid in dict.fromkeys(w[2] for w in wants if w[2] and w[1]):
        items = _req_items(tcon, cid)
        last: dict = {}
        for i, h in enumerate(items):
            hits = blob_hits.get(h)
            if hits is None:
                hits = blob_hits[h] = probes.find(item_norm(tcon, h)[1])
            for k in hits:
                last[k] = i
        by_call[cid] = {"items": items, "last": last}
    out = {}
    for w in wants:
        k, cid = w[0], w[2]
        e = by_call.get(cid)
        if not e or k not in e["last"]:
            out[(k, cid)] = None
            continue
        i = e["last"][k]
        role, _, fr = item_norm(tcon, e["items"][i])
        out[(k, cid)] = {"i": i, "role": role, "framing": fr, "call": cid, "of": len(e["items"])}
    return out


def locate_in_request(tcon, call_id: str, snippet: str):
    """Find the last request item carrying `snippet`; returns {i, role, framing} or None."""
    if not snippet:
        return None
    return locate_many(tcon, [(0, snippet, call_id, True)]).get((0, call_id))


def _snippet(c: str) -> str:
    s = norm(c)
    # skip a leading bracket header line so the snippet hits the payload, not volatile framing
    s = re.sub(r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [^\]]+\]\s*", "", s)
    s = _LEAD_NOTE.sub("", s, count=1)
    return s[:90]


def _snippet_open(c: str) -> tuple[str, bool]:
    """(snippet, cut mid-word?)"""
    s = norm(c)
    s = re.sub(r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [^\]]+\]\s*", "", s)
    s = _LEAD_NOTE.sub("", s, count=1)
    return s[:90], len(s) > 90 and s[90] != " " and s[89] != " "


_FAKE_HEADER_RE = re.compile(r"^[ \t]*\[(?:ASYNC DELEGATION BATCH COMPLETE|HERMES_INTERNAL_NOTIFICATION|OUT-OF-BAND USER MESSAGE)", re.M)


def _trailing_no_reply(c: str) -> bool:
    """Visible text (>20 chars after a non-space) then a final standalone NO_REPLY — linear, unlike the regex
    ``\\S[\\s\\S]{20,}\\bNO_REPLY\\s*$``, which backtracks quadratically on long replies."""
    s = c.rstrip()
    if not s.endswith("NO_REPLY"):
        return False
    head = s[:-8]
    if head and (head[-1].isalnum() or head[-1] == "_"):
        return False
    lead = len(head) - len(head.lstrip())
    return len(head) - lead > 20


# Legacy stores did not capture execution provenance. Recognize only Hermes's
# complete review harness (not tool names, a UUID task id, or quoted mentions).
_review_item_cache: OrderedDict = OrderedDict()


def _legacy_review_item(tcon, h: str) -> bool:
    with _cache_lock:
        if h in _review_item_cache:
            return _review_item_cache[h]
    item = get_blob(tcon, h)
    if item is None:
        return False  # missing evidence must not poison a later capture's cache
    text = item_text(item).strip() if isinstance(item, dict) and item.get("role") == "user" else ""
    if text.startswith("<USER_REQUEST>\n") and text.endswith("</USER_REQUEST>"):
        text = text[len("<USER_REQUEST>\n"):-len("</USER_REQUEST>")].strip()
    found = text.startswith((
        "Review the conversation above and consider saving to memory if appropriate.",
        "Review the conversation above and update the skill library.",
        "Review the conversation above and update two things:",
    )) and bool(re.search(
        r"\n\nYou can only call (?:memory and skill |skill )management tools\. "
        r"Other tools will be denied at runtime — do not attempt them\."
        r"(?: Exception — these configured tools are also allowed: [^\n]+\.)?$", text))
    with _cache_lock:
        _review_item_cache[h] = found
        while len(_review_item_cache) > 8192:
            _review_item_cache.popitem(last=False)
    return found


def call_lane(tcon, cid: str, row: dict | None = None) -> str | None:
    """Execution lane, independent of physical session and provider cache identity.

    New captures use runtime provenance even with payload capture disabled. Old
    captures are classified read-only from their intact review harness; expired
    or customized legacy prompts cannot be inferred safely and keep their lane.
    """
    if row is None:
        r = tcon.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
        row = dict(r) if r else {}
    lane = row.get("lane")
    origin = row.get("execution_origin")
    if origin == "background_review" or lane == "review":
        return "review"
    if origin:
        return lane
    try:
        r = tcon.execute("SELECT req_hermes, req_down FROM wire_calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.OperationalError:
        try:
            r = tcon.execute("SELECT NULL, req_down FROM wire_calls WHERE id=?", (cid,)).fetchone()
        except sqlite3.OperationalError:
            return lane  # telemetry-only legacy store
    ref = _loads((r[0] or r[1]) if r else None, {}) or {}
    if any(_legacy_review_item(tcon, h) for h in reversed(ref.get("items") or [])):
        return "review"
    return lane


def execution_lane(tcon, cid: str) -> str:
    """Main means the session's primary execution, including delegated/cron sessions."""
    return "review" if call_lane(tcon, cid) == "review" else "main"


def comparison_scope(tcon, cid: str) -> tuple:
    r = tcon.execute("SELECT session_id, family FROM wire_calls WHERE id=?", (cid,)).fetchone()
    return (r[0], r[1], execution_lane(tcon, cid)) if r else (None, None, "main")


def session_latest_call(tcon, sid: str, finished: bool = False, lane: str = "main") -> str | None:
    """Newest capture in the selected execution lane; reviews never replace main by default."""
    if lane not in ("main", "review", "all"):
        raise ValueError("lane must be main, review or all")
    try:
        for r in tcon.execute("SELECT id FROM wire_calls WHERE session_id=? AND req_down IS NOT NULL AND req_down != 'null'"
                              + (" AND status=200" if finished else "") + " ORDER BY started DESC", (sid,)):
            if lane == "all" or execution_lane(tcon, r[0]) == lane:
                return r[0]
    except sqlite3.Error:
        return None
    return None


def session_view(state_db: Path, tcon, sid: str, before: int | None, limit: int, inactive: bool,
                 framing: bool = True) -> dict:
    """Transcript page, memoized on (session rows, wire store revision): a poll that changes nothing is a lookup."""
    key = ("session", sid, before, limit, bool(inactive), framing)
    fp = _fingerprint(state_db, tcon, sid, bool(inactive), before, limit)
    hit = _memo_get(key, fp)
    if hit is None:
        hit = _session_view(state_db, tcon, sid, before, limit, inactive, framing)
        _memo_put(key, fp, hit)
    return dict(hit, now=time.time())


def _session_view(state_db: Path, tcon, sid: str, before: int | None, limit: int, inactive: bool,
                  framing: bool = True) -> dict:
    scon = state_con(state_db)
    try:
        meta = scon.execute(f"SELECT {_select(scon, 'sessions', SESSION_COLS)} FROM sessions WHERE id=?", (sid,)).fetchone()
        has_active = "active" in {r[1] for r in scon.execute("PRAGMA table_info(messages)")}
        where, args = ["session_id=?"], [sid]
        if not inactive and has_active:
            where.append("COALESCE(active,1)=1")
        base_where = list(where)
        if before:
            where.append("id < ?")
            args.append(before)
        rows = [dict(r) for r in scon.execute(
            f"SELECT {_select(scon, 'messages', MSG_COLS)} FROM messages WHERE {' AND '.join(where)} ORDER BY id DESC LIMIT ?",
            args + [limit])]
        total = scon.execute(f"SELECT COUNT(*) FROM messages WHERE {' AND '.join(base_where)}", [sid]).fetchone()[0]
        first_id = scon.execute("SELECT MIN(id) FROM messages WHERE session_id=?", (sid,)).fetchone()[0]
    finally:
        scon.close()
    rows.reverse()
    source = (meta["source"] if meta else "") or ""
    for r in rows:
        if r.get("active") is None:
            r["active"] = 1
    m = match_calls(tcon, rows, sid)
    seen_delegs, seen_procs = set(), set()
    out = []
    turn_trigger = None
    turn_has_completion = False
    first_ts: dict = {}
    for r in rows:
        if r["id"] in m:
            first_ts.setdefault(m[r["id"]], r["timestamp"])
    matched_calls = sorted(set(m.values()), key=lambda cid: first_ts.get(cid) or 0)
    latest_call = session_latest_call(tcon, sid, finished=True)
    if not latest_call and matched_calls:
        latest_call = max(matched_calls, key=lambda cid: (tcon.execute("SELECT ended FROM wire_calls WHERE id=?", (cid,)).fetchone() or [0])[0])
    is_child = bool(meta and (meta["parent_session_id"] or (meta["source"] or "") == "subagent"
                              or (meta["created_source"] or "") == "subagent" or _adapt("is_child", dict(meta))))
    if is_child and rows and rows[0]["id"] == first_id:
        first_user = next((r for r in rows if r["role"] == "user"), None)
        if first_user is not None:
            first_user["_first_child_user"] = True
    # call of the first matched assistant row after each row (reverse pass instead of a forward scan per row)
    next_call: list = [None] * len(rows)
    nxt = None
    for idx in range(len(rows) - 1, -1, -1):
        next_call[idx] = nxt
        if rows[idx]["role"] == "assistant" and rows[idx]["id"] in m:
            nxt = m[rows[idx]["id"]]
    pending: list = []  # (row dict, snippet, first call) — located in one batch after the pass
    for idx, r in enumerate(rows):
        parts = row_parts(r)
        if parts is not None:
            r["_parts"] = parts
        cl = classify(r, source)
        c = r.get("content") or ""
        plain = _adapt("plain_text", r, default="")
        if plain and not c:
            c = plain  # parts are the truth; content is their derived view
        d = {k: r[k] for k in ("id", "role", "tool_call_id", "tool_name", "timestamp", "finish_reason",
                               "platform_message_id", "active", "compacted", "display_kind", "token_count")}
        d.update(_adapt("row_summary", r, norm, default={}))
        d.update(cl)
        d["content_len"] = len(c)
        d["content"] = c if len(c) <= 6000 else c[:6000]
        d["truncated"] = len(c) > 6000
        d["has_api_content"] = bool(r.get("api_content"))
        inj = inject_diff(c, r.get("api_content"))
        if inj:
            if len(inj.get("prefix", "")) > 20000:
                inj["prefix"] = inj["prefix"][:20000]
            d["inject"] = inj
        if r["role"] == "assistant":
            d["reasoning"] = (r.get("reasoning_content") or r.get("reasoning") or "")[:4000]
            d["tool_names"] = _tool_names(r.get("tool_calls"))
            d["tool_ids"] = _tool_ids(r.get("tool_calls"))
            d["wire"] = m.get(r["id"])
            flags = []
            ghost = set()
            narr = [(nm.start(), nm.end()) for nm in NARRATE_RE.finditer(c)]
            if narr:  # deleg ids within 160 chars of a narration: one scan for ids, bisect per narration
                dl = [(dm.start(), dm.end(), dm.group(0)) for dm in DELEG_RE.finditer(c)]
                starts = [x[0] for x in dl]
                for a, b in narr:
                    lo, hi = max(0, a - 160), b + 160
                    for k in range(bisect.bisect_left(starts, lo), len(dl)):
                        if dl[k][0] >= hi:
                            break
                        if dl[k][1] <= hi and dl[k][2] not in seen_delegs:
                            ghost.add(dl[k][2])
            ghost = sorted(ghost)
            if ghost:
                flags.append(f"narrates result of {', '.join(ghost)} — no completion row for it exists before this message")
            pghost = sorted(x for x in PROC_RE.findall(c) if x not in seen_procs)
            if pghost and re.search(r"finished|completed|passed", c, re.I):
                flags.append(f"claims {', '.join(pghost)} finished — no process-notice row precedes it")
            if narr and turn_trigger in ("user",) and not turn_has_completion and not ghost:
                flags.append("narrates a background result in a user-triggered turn with no completion row in this turn")
            if _trailing_no_reply(c):
                flags.append("visible text followed by a trailing NO_REPLY")
            if _FAKE_HEADER_RE.search(c):
                flags.append("assistant content contains a line-leading internal-turn header (fabricated next turn?)")
            d["flags"] = flags
        elif r["role"] == "tool":
            d["content"] = c[:3000]
        if cl["kind"] in ("user", "subagent", "webhook", "cron", "process", "internal", "parent", "compaction", "peer"):
            turn_trigger = cl["kind"]
            turn_has_completion = cl["kind"] in ("subagent", "process", "webhook", "cron")
            if cl.get("ref", "") and cl["kind"] == "subagent":
                seen_delegs.add(cl["ref"])
            for x in DELEG_RE.findall(c[:300]) if cl["kind"] == "subagent" else []:
                seen_delegs.add(x)
            for x in PROC_RE.findall(c[:600]) if cl["kind"] == "process" else []:
                seen_procs.add(x)
        if framing and r["role"] == "user":  # every user-role row reaches the wire, harness notices included
            pending.append((d, *_snippet_open(c), next_call[idx]))
        if not framing and r["role"] == "user":
            # what alignment needs from the same row, so it never re-reads or re-parses it
            meta_ev = None
            try:
                mj = json.loads(r["display_metadata"]) if r.get("display_metadata") else None
                if isinstance(mj, dict) and isinstance(mj.get("input_events"), list):
                    meta_ev = mj["input_events"]
            except Exception:
                pass
            inj_txt = _adapt("injection_text", r, default="")
            d["_align"] = (norm((r.get("api_content") or "") + "\n" + c + "\n" + inj_txt), meta_ev, c)
            if parts is not None:
                d["_parts"] = parts
        out.append(d)
    if pending:
        wants = []
        for n, (d, snip, open_end, first) in enumerate(pending):
            if first:
                wants.append((n, snip, first, open_end))
            if latest_call and latest_call != first:
                wants.append((n, snip, latest_call, open_end))
        try:
            found = locate_many(tcon, wants)
            err = None
        except Exception as e:
            found, err = {}, repr(e)
        for n, (d, snip, open_end, first) in enumerate(pending):
            fr = {}
            if err:
                fr["error"] = err
            else:
                if first:
                    fr["first"] = found.get((n, first)) if snip else None
                if latest_call and latest_call != first:
                    fr["latest"] = found.get((n, latest_call)) if snip else None
            if fr:
                d["framing"] = fr
    return {"session": _session_meta(meta, sid), "context": session_context(tcon, sid, meta), "rows": out, "total": total,
            "oldest_id": rows[0]["id"] if rows else None, "matched_calls": len(set(m.values())),
            "latest_call": latest_call, "now": time.time()}


LIST_COLS = ("id", "source", "model", "title", "parent_session_id", "created_source", "hidden", "started_at",
             "message_count", "api_call_count", "billing_provider", "session_key")


def session_has_activity(cols, has_messages=True) -> str:
    """Exclude empty admissions/no-op cron records, not sessions with stale zero counters.

    The fallback is an indexed existence probe, never a count or scan of message bodies.
    Metadata-only legacy archives can lack the messages table entirely.
    """
    counters = [f"COALESCE({c},0)>0" for c in ("message_count", "api_call_count", "input_tokens", "output_tokens") if c in cols]
    if has_messages:
        counters.append("EXISTS (SELECT 1 FROM messages AS activity WHERE activity.session_id=sessions.id LIMIT 1)")
    return "(" + " OR ".join(counters) + ")" if counters else "1"


def _session_search(cols, q) -> tuple[list[str], list]:
    """AND tokens across session metadata only. No transcript/telemetry joins or wildcard expansion.

    Infix matching cannot use a B-tree text index; SQLite walks the small session metadata table in
    indexed recency order and stops at the result limit. Rare searches still inspect all metadata.
    """
    tokens = str(q or "").lower().split()
    if len(str(q or "")) > 512 or len(tokens) > 16:
        raise ValueError("session search supports at most 512 characters / 16 tokens")
    fields = ("id", "title", "source", "created_source", "model", "billing_provider", "provider", "session_key",
              "parent_session_id", "root_session_id", "group_id", "lineage_kind")
    exprs = [f"COALESCE({c},'')" for c in fields if c in cols]
    if "model_config" in cols:
        exprs.append("CASE WHEN json_valid(model_config) THEN COALESCE(json_extract(model_config,'$.provider'),'') ELSE '' END")
    if "depth" in cols:
        exprs.append("CASE WHEN depth IS NOT NULL THEN 'd'||depth ELSE '' END")
    else:
        parent = "COALESCE(parent_session_id,'')='' AND " if "parent_session_id" in cols else ""
        exprs.append(f"CASE WHEN {parent}COALESCE(source,'')!='subagent' THEN 'd0 root' ELSE '' END")
    text = "lower(" + "||char(31)||".join(exprs) + ")"
    return [f"instr({text},?)>0" for _ in tokens], tokens


def _display_title(session, preview="", *, assignment=False):
    title = str(session.get("title") or "").strip()
    lineage = lineage_of(session)
    child = bool(lineage and (lineage.get("parent") or (lineage.get("depth") or 0) > 0
                              or lineage.get("kind") in ("child", "delegate"))) or session.get("source") == "subagent"
    broken = (not title or bool(re.match(r"^(?:Subagent:\s*)?(?:<|\[Parent assignment\b|[·…#\s]*$)", title)))
    if not broken:
        return title
    if not child:
        return session["id"]
    # Prefer the assignment, not forwarded human messages before it. Both typed and legacy fork
    # envelopes are presentation scaffolding, never useful session titles.
    parent = re.search(r"<parent_message\b[^>]*>\s*(.*?)(?:</parent_message>|$)", preview, re.DOTALL)
    if parent:
        preview, assignment = parent[1], True
    elif "<latest_user_message" in preview:
        preview = ""
    elif re.match(r"^\s*\[Parent assignment[^\]\n]*\]", preview):
        assignment = True
    # An inherited human turn or compaction summary is not the child's assignment.
    if not assignment:
        preview = ""
    preview = re.sub(r"^\s*\[Parent assignment[^\]\n]*\]\s*", "", preview)
    lines = [line.strip() for line in preview.splitlines() if line.strip() and not line.lstrip().startswith("<")]
    summary = next((line for line in lines if len(line) >= 12), "")
    return "Subagent: " + summary[:160] if summary else "Subagent · " + session["id"]


def context_gauge(tcon, sid, source, anchor_prompt, message_count, compression):
    """Session-local capture facts plus the selected profile's compression policy (no main heuristic)."""
    try:
        row = last = None
        for captured in tcon.execute("SELECT * FROM calls WHERE session_id=? AND (context_length>0 OR prompt_tokens>0) "
                                     "ORDER BY started DESC", (sid,)):
            captured = dict(captured)
            if call_lane(tcon, captured["id"], captured) == "review":
                continue
            if row is None and (captured.get("context_length") or 0) > 0:
                row = (captured["context_length"],)
            if last is None and (captured.get("prompt_tokens") or 0) > 0:
                last = (captured["prompt_tokens"],)
            if row and last:
                break
    except sqlite3.Error:
        return None
    if not row:
        return None
    window = int(row[0])
    enabled = str(compression.get("enabled", True)).lower() in ("true", "1", "yes")
    compressor = hygiene = None
    if enabled:
        try:
            compressor = int(window * float(compression.get("threshold", .5)))
        except (TypeError, ValueError):
            compressor = int(window * .5)
        try:
            cap = int(compression.get("threshold_tokens") or 0)
            if cap > 0:
                compressor = min(compressor, cap)
        except (TypeError, ValueError):
            pass
        if (source or "") not in ("", "cli", "tui", "subagent", "cron"):
            hygiene = int(window * .85)
    try:
        msg_limit = int(compression.get("hygiene_hard_message_limit") or 0) or None
    except (TypeError, ValueError):
        msg_limit = None
    return {"ctx_window": window, "compressor_trigger": compressor, "hygiene_trigger": hygiene,
            "hygiene_msg_limit": msg_limit if hygiene else None,
            "last_prompt_tokens": anchor_prompt or (last[0] if last else None), "message_count": message_count}


def session_context(tcon, sid, metadata):
    metadata = dict(metadata or {})
    result = {"id": sid, "title": metadata.get("title"), "source": metadata.get("source"),
              "message_count": metadata.get("message_count")}
    try:
        raw = metadata.get("model_config") or {}
        config = json.loads(raw) if isinstance(raw, str) else raw
        anchor = (config.get("_usage_anchor") or {}).get("prompt_tokens")
    except (ValueError, TypeError, AttributeError):
        anchor = None
    gauge = context_gauge(tcon, sid, metadata.get("source"), anchor, metadata.get("message_count"),
                          (store.hermes_config().get("compression") or {}))
    if gauge:
        result.update(gauge)
    return result


def _session_meta(meta, sid: str) -> dict:
    """Session header: the row as stored (JSON columns parsed) plus a compact lineage summary."""
    if not meta:
        return {"id": sid}
    d = dict(meta)
    for k, v in d.items():
        d[k] = _adapt("decode_column", k, v, default=v)
    d["lineage"] = lineage_of(d)
    return d


def lineage_of(s: dict) -> dict | None:
    """Adapter lineage where available, otherwise stock parent/session-source inference."""
    typed = _adapt("lineage", s)
    if typed:
        return typed
    parent = s.get("parent_session_id")
    if parent or (s.get("source") or "") == "subagent" or (s.get("created_source") or "") == "subagent":
        return {"kind": "child", "depth": None, "root": None, "parent": parent, "typed": False}
    return None


def sessions_list(state_db: Path, q: str, limit: int, main: str, source: str | None = None, model: str | None = None,
                  since: float | None = None) -> list[dict]:
    """Recent nonempty sessions (main first). Search ANDs tokens across metadata; filters are
    applied before LIMIT. Bodies are read only for bounded, displayed malformed-title fallbacks."""
    scon = state_con(state_db)
    try:
        cols = {r[1] for r in scon.execute("PRAGMA table_info(sessions)")}
        tcol = "last_activity_at" if "last_activity_at" in cols else "started_at"
        sel = _select(scon, "sessions", LIST_COLS) + f", {tcol} AS t"
        has_messages = scon.execute("SELECT 1 FROM sqlite_master WHERE name='messages'").fetchone() is not None
        activity = session_has_activity(cols, has_messages)
        where, args = _session_search(cols, q)
        where.append(activity)
        if source:
            where.append("COALESCE(source,'') = ?")
            args.append(source)
        if model and "model" in cols:
            where.append("COALESCE(model,'') LIKE ?")
            args.append(f"%{model}%")
        if since is not None:
            where.append(f"COALESCE({tcol}, started_at) >= ?")
            args.append(since)
        limit = max(1, min(int(limit), 500))
        sql = (f"SELECT {sel} FROM sessions WHERE {' AND '.join(where)} "
               f"ORDER BY COALESCE({tcol}, started_at) DESC LIMIT ?")
        out = [dict(r) for r in scon.execute(sql, args + [limit])]
        if main and not (q or source or model or since is not None) and not any(s["id"] == main for s in out):
            r = scon.execute(f"SELECT {sel} FROM sessions WHERE id=? AND {activity}", (main,)).fetchone()
            if r:
                out.insert(0, dict(r))
                out = out[:limit]
        mcols = {r[1] for r in scon.execute("PRAGMA table_info(messages)")} if has_messages else set()
        preview_filter = " AND COALESCE(_compressed_summary,0)=0" if "_compressed_summary" in mcols else ""
        if "part_kind" in mcols:
            preview_filter += " AND COALESCE(part_kind,'')!='compaction'"
        parent_evidence = [f"{c}='{value}'" for c, value in (("sender_kind", "parent"), ("part_kind", "parent_message")) if c in mcols]
        parent_expr = " OR ".join(parent_evidence) or "0"
        for s in out:
            title = _display_title(s)
            if has_messages and title != (s.get("title") or "").strip() and lineage_of(s):
                preview = scon.execute(f"SELECT substr(content,1,8192), ({parent_expr}) FROM messages WHERE session_id=? "
                                       f"AND role='user'{preview_filter} ORDER BY id LIMIT 1", (s["id"],)).fetchone()
                title = _display_title(s, preview[0] or "", assignment=bool(preview[1])) if preview else title
            s["display_title"] = title
    finally:
        scon.close()
    for s in out:
        s["main"] = s["id"] == main
        s["lineage"] = lineage_of(s)
    out.sort(key=lambda s: (not s["main"],))
    return out


def full_row(state_db: Path, tcon, mid: int) -> dict:
    scon = state_con(state_db)
    try:
        r = scon.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        source = _session_source(scon, r["session_id"]) if r is not None and "session_id" in r.keys() else ""
    finally:
        scon.close()
    if not r:
        return {"error": "not found"}
    d = {}
    for k in r.keys():
        v = r[k]
        if isinstance(v, bytes):
            v = v.hex()
        elif isinstance(v, str) and k in ("tool_calls", "display_metadata", "reasoning_details", "provider_data",
                                          "gemini_content", "codex_reasoning_items", "codex_message_items",
                                          "absorbed_message_uids", "tool_call_uids") and v[:1] in "[{":
            try:
                v = json.loads(v)
            except Exception:
                pass
        d[k] = _adapt("decode_column", k, v, default=v)
    row = dict(r)
    out = {"row": d, "class": classify(row, source), "inject": inject_diff(row.get("content") or "", row.get("api_content"))}
    out.update(_adapt("full_row", row, norm, default={}))
    return out


NO_WIRE = ("no wire capture for this call — it predates capture, payload capture is off, or it is past the "
           "retention window")


def _loads(s, default=None):
    try:
        v = json.loads(s) if s else None
    except Exception:
        v = None
    return default if v is None else v


def wire_summary(tcon, cid: str, which: str = "down") -> dict:
    w = tcon.execute("SELECT * FROM wire_calls WHERE id=?", (cid,)).fetchone()
    if not w:
        return {"error": NO_WIRE}
    w = dict(w)
    up = _loads(w.get("req_up"), {})
    hermes = _loads(w.get("req_hermes"), {})
    has_upstream = bool(up)
    which = which if (which == "up" and has_upstream) or (which == "hermes" and hermes) else "down"
    ref = up if which == "up" else hermes if which == "hermes" else _loads(w.get("req_down"), {})
    if ref.get("same_as_down"):
        ref = _loads(w.get("req_down"), {})
    items = []
    for i, h in enumerate(ref.get("items") or []):
        role, txt, fr = item_norm(tcon, h)
        n = (tcon.execute("SELECT n FROM wire_blobs WHERE h=?", (h,)).fetchone() or [0])[0]
        items.append({"i": i, "h": h, "role": role, "len": n, "framing": fr, "head": txt[:220]})
    keys = []
    for k in ref.get("order") or []:
        if k == ref.get("list_key"):
            keys.append({"key": k, "list": True, "n": len(items)})
        else:
            h = ref["keys"][k]
            n = (tcon.execute("SELECT n FROM wire_blobs WHERE h=?", (h,)).fetchone() or [0])[0]
            keys.append({"key": k, "h": h, "len": n})
    call = tcon.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
    meta = {k: w.get(k) for k in ("file", "started", "ended", "family", "model", "url", "status", "n_items", "req_bytes",
                                  "session_id", "source", "exact", "tools_exact")}
    # down = what went over HTTP. Post-adapter whenever the proxy saw it; a Hermes-only capture is the request
    # Hermes handed its provider client, which a native adapter may still rewrite before sending.
    layer = "wire" if (hermes or w.get("source") == "proxy") else "hermes"
    return {"id": cid, "meta": meta, "which": which, "layer": layer if which == "down" else which,
            "has_hermes": bool(hermes) or layer == "hermes",
            "call": dict(call) if call else None, "keys": keys, "list_key": ref.get("list_key"), "items": items,
            "headers_down": _loads(w.get("hdr_down"), {}), "headers_up": _loads(w.get("hdr_up"), {}),
            "has_upstream": has_upstream, "upstream_differs": has_upstream and not up.get("same_as_down", False),
            "response": _loads(w.get("resp"), {})}


def wire_part(tcon, cid: str, part: str, which: str = "down", i: int | None = None, key: str | None = None):
    w = tcon.execute("SELECT req_down, req_up, resp_raw, resp, req_hermes FROM wire_calls WHERE id=?", (cid,)).fetchone()
    if not w:
        return {"error": NO_WIRE}
    up, hermes = _loads(w["req_up"], {}), _loads(w["req_hermes"], {})
    ref = up if which == "up" and up else hermes if which == "hermes" and hermes else _loads(w["req_down"], {})
    if ref.get("same_as_down"):
        ref = _loads(w["req_down"], {})
    if part == "item":
        return get_blob(tcon, ref["items"][int(i)])
    if part == "key":
        return get_blob(tcon, ref["keys"][key])
    if part == "request":
        return rebuild(tcon, ref)
    if part == "response_raw":
        return {"raw": get_blob_str(tcon, w["resp_raw"]) if w["resp_raw"] else ""}
    if part == "response":
        return _loads(w["resp"], {})
    return {"error": "unknown part"}


def wire_calls_list(tcon, t0: float, t1: float) -> list[dict]:
    return [dict(r) for r in tcon.execute(
        "SELECT w.id, w.started, w.ended, w.family, w.model, w.status, w.n_items, w.req_bytes, w.text_head, w.tc_ids, "
        "w.session_id, w.source, c.prompt_tokens, c.cached_tokens, c.hit_pct, c.total_s, c.client "
        "FROM wire_calls w LEFT JOIN calls c ON c.id=w.id "
        "WHERE COALESCE(w.ended, w.started) BETWEEN ? AND ? ORDER BY COALESCE(w.ended, w.started) DESC LIMIT 400", (t0, t1))]


# ───────────────────────── compiled session shape ─────────────────────────
_SYS_KEYS = ("systemInstruction", "system_instruction", "system", "instructions")


# ───────────────────────── prefix-cache miss forensics, layer-matched ─────────────────────────
# A call's stored request can be at two layers: what Hermes handed its client (pre-adapter) and what left the
# process / reached the proxy (post-adapter). A provider adapter re-shapes every item (chat messages → Gemini
# contents, system message → systemInstruction), so items of different layers never hash equal: comparing them
# reports "item #0 changed" for an untouched system prompt. Two calls are compared only at a layer both have.
def call_layers(tcon, cid: str) -> dict:
    """{"post": ref, "pre": ref} for whichever layers a call has stored."""
    r = tcon.execute("SELECT req_down, req_hermes, source, file FROM wire_calls WHERE id=?", (cid,)).fetchone()
    if not r or not r[0]:
        return {}
    return store.layer_refs(r[0], r[1], r[2], r[3])


_NO_TOOLS = ""  # in a compared prefix: this request declared no tools


def _prefix_of(ref: dict, tools: bool = True, pad: bool = False) -> tuple[list, int, int]:
    """(item hashes in send order, # of envelope keys (system/tools) in front, # of those that are tools).
    ``tools=False`` leaves the tool declarations out of the compared prefix; ``pad`` holds their place in a
    request without any, so it lines up with one that has them."""
    keys = ref.get("keys") or {}
    sys_h = [keys[k] for k in _SYS_KEYS if k in keys]
    tool_h = [] if not tools else [keys["tools"]] if "tools" in keys else [_NO_TOOLS] if pad else []
    return sys_h + tool_h + list(ref.get("items") or []), len(sys_h) + len(tool_h), len(tool_h)


def hook_copy_envelope(tcon, cid: str, layer: str) -> bool:
    """Whether this call's ``layer`` request took its tools from Hermes's sanitized hook copy (``exact=0`` and
    no ``tools_exact``).

    Hermes caps that copy by the size of the whole request, so the same tool declarations can be stored whole
    for one call, truncated for the next and absent for a third. Such tools are shown, never compared."""
    if layer != "pre":
        return False
    try:
        r = tcon.execute(f"SELECT {store.select_cols(tcon, 'wire_calls', ('exact', 'req_hermes', 'tools_exact'))} "
                         "FROM wire_calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return False
    return bool(r) and r[0] == 0 and not r[1] and not r[2]


def enrich_miss(tcon, cid: str, miss: dict | None) -> dict | None:
    """Upgrade old stored diagnostics read-only, using the exact compared blobs.

    Cross-lane/family comparisons are recomputed before enriching the diff.
    Compatible diagnostics retain their comparison call; expired evidence never
    turns into invented diff content.
    """
    try:
        if isinstance(miss, dict) and miss.get("prev_id") and comparison_scope(tcon, cid) != comparison_scope(tcon, miss["prev_id"]):
            c = tcon.execute("SELECT session_id, started, prompt_tokens, hit_pct FROM calls WHERE id=?", (cid,)).fetchone()
            if c:
                return explain_miss(tcon, cid, *c)
    except sqlite3.Error:
        # Telemetry-only archives can retain diagnostics without wire tables.
        # Missing optional evidence must not break listing or trigger migration.
        return miss
    if not isinstance(miss, dict) or miss.get("at") is None or not miss.get("prev_id"):
        return miss
    if (miss.get("change") or {}).get("v") == 2:
        return miss
    try:
        current, previous = call_layers(tcon, cid), call_layers(tcon, miss["prev_id"])
    except sqlite3.Error:
        return miss
    layer = miss.get("layer") or ("post" if "post" in current and "post" in previous else "pre")
    if layer not in current or layer not in previous:
        return miss
    tools = miss.get("tools_compared", True)
    ch, ncur, _ = _prefix_of(current[layer], tools)
    ph, _, _ = _prefix_of(previous[layer], tools)
    at = miss["at"]
    if not isinstance(at, int) or not 0 <= at < min(len(ch), len(ph)):
        return miss
    # Only a few hundred bounded change windows are cached, never full payloads.
    key = (ph[at], ch[at], current[layer].get("list_key"), at, ncur)
    with _cache_lock:
        cached = _miss_change_cache.get(key)
    if cached is None:
        leading = [k for k in _SYS_KEYS if k in (current[layer].get("keys") or {})]
        if tools and "tools" in (current[layer].get("keys") or {}):
            leading.append("tools")
        path = leading[at] if at < ncur else f"{current[layer].get('list_key') or 'messages'}[{at-ncur}]"
        cached = forensics.describe(get_blob(tcon, ph[at]), get_blob(tcon, ch[at]), path)
        if cached is None:
            return miss
        with _cache_lock:
            _miss_change_cache[key] = cached
            while len(_miss_change_cache) > 256:
                _miss_change_cache.popitem(last=False)
    out = dict(miss, change=cached)
    for field, side in (("prev_head", "before"), ("cur_head", "after")):
        excerpt = cached[side]
        out[field] = ("…" if excerpt["omitted_prefix"] else "") + excerpt["prefix"] + excerpt["change"] + ("…" if excerpt["omitted_change"] else "") + excerpt["suffix"]
    return out


_miss_change_cache: OrderedDict = OrderedDict()


def explain_miss(tcon, cid: str, session_id: str | None, started: float | None, prompt_tokens, hit_pct) -> dict | None:
    """For a prefix-cache miss: the earlier call of the session sharing the longest prefix at the same layer, and
    the first item that differs."""
    if (prompt_tokens or 0) < 20000 or (hit_pct or 0) >= 60 or not session_id:
        return None
    cur = call_layers(tcon, cid)
    if not cur:
        return None
    best = None
    scope = comparison_scope(tcon, cid)
    candidates = 0
    for (pid,) in tcon.execute("SELECT id FROM wire_calls WHERE session_id=? AND family IS ? AND id != ? AND started < ? AND status=200 "
                               "ORDER BY started DESC", (session_id, scope[1], cid, started or time.time())):
        if execution_lane(tcon, pid) != scope[2]:
            continue
        # Apply the comparison budget AFTER lane filtering. A 16-call review
        # must not hide the previous primary request behind the old LIMIT 12.
        candidates += 1
        if candidates > 12:
            break
        prev = call_layers(tcon, pid)
        layer = "post" if "post" in cur and "post" in prev else "pre" if "pre" in cur and "pre" in prev else None
        if layer is None:
            continue
        tools = not (hook_copy_envelope(tcon, cid, layer) or hook_copy_envelope(tcon, pid, layer))
        pad = ("tools" in (cur[layer].get("keys") or {})) != ("tools" in (prev[layer].get("keys") or {}))
        ch, ncur, ntools = _prefix_of(cur[layer], tools, pad)
        ph, _, _ = _prefix_of(prev[layer], tools, pad)
        k = 0
        while k < min(len(ph), len(ch)) and ph[k] == ch[k]:
            k += 1
        if best is None or k > best[0]:
            best = (k, pid, ph, ch, ncur, ntools, layer, tools)
    if not best:
        return {"why": "first captured call in this session/family/execution lane at a comparable layer (no earlier request to compare)"}
    k, pid, ph, ch, ncur, ntools, layer, tools = best
    info: dict = {"prev_id": pid, "common_items": k, "items": len(ch), "prev_items": len(ph), "layer": layer}
    if not tools:
        info["tools_compared"] = False
    if k < min(len(ph), len(ch)) and _NO_TOOLS in (ph[k], ch[k]):
        info.update(role="tools", why="tool declarations " + ("added" if ph[k] == _NO_TOOLS else "removed"))
    elif k < min(len(ph), len(ch)):
        role_c, txt_c, _ = item_norm(tcon, ch[k])
        _, txt_p, _ = item_norm(tcon, ph[k])
        n = lambda h: (tcon.execute("SELECT n FROM wire_blobs WHERE h=?", (h,)).fetchone() or [0])[0]  # noqa: E731
        is_tools = ncur - ntools <= k < ncur
        role = ("tools" if is_tools else "system") if k < ncur else role_c
        info.update(at=k, role=role, prev_head=txt_p[:260], cur_head=txt_c[:260], prev_len=n(ph[k]), cur_len=n(ch[k]))
        if k < ncur:
            info["why"] = "tool declarations changed" if is_tools else "system prompt changed"
        elif role_c in ("system", "developer"):
            info["why"] = "system prompt changed"
        else:
            lead = 0  # system/developer messages at the head of the list are not "history" (chat-completions shape)
            while ncur + lead < k and item_norm(tcon, ch[ncur + lead])[0] in ("system", "developer"):
                lead += 1
            info["why"] = f"history item #{k - ncur - lead} rewritten"
    elif k == len(ph):
        info["why"] = ("prefix intact vs closest earlier call — provider-side miss (cache entry not stored/reused)" if tools
                       # either a tool change or a provider-side miss: this capture cannot tell which
                       else "system prompt and messages unchanged — tools not compared (hook copy)")
    return enrich_miss(tcon, cid, info)


def refresh_miss(tcon, cid: str) -> None:
    """Recompute a Hermes-side call's miss forensics from its stored layers (after a proxy merge adds one)."""
    c = tcon.execute("SELECT session_id, started, prompt_tokens, hit_pct FROM calls WHERE id=? AND source='hermes'", (cid,)).fetchone()
    if not c:
        return
    d = explain_miss(tcon, cid, c[0], c[1], c[2], c[3])
    tcon.execute("UPDATE calls SET diverge=? WHERE id=?", (json.dumps(d) if d else None, cid))


MISS_REV = "2"


def recompute_misses(tcon) -> int:
    """Once per MISS_REV: redo every Hermes-side miss explanation (older ones compared items across layers)."""
    try:
        r = tcon.execute("SELECT v FROM kv WHERE k='miss_rev'").fetchone()
        if r and r[0] == MISS_REV:
            return 0
        ids = [x[0] for x in tcon.execute("SELECT id FROM calls WHERE source='hermes' AND diverge IS NOT NULL")]
        for cid in ids:
            refresh_miss(tcon, cid)
        tcon.execute("INSERT OR REPLACE INTO kv VALUES ('miss_rev', ?)", (MISS_REV,))
        return len(ids)
    except sqlite3.Error:
        return 0


def _req_ref(tcon, cid: str, which: str = "down") -> dict:
    col = "req_hermes" if which == "hermes" else "req_down"
    r = tcon.execute(f"SELECT {col} FROM wire_calls WHERE id=?", (cid,)).fetchone()
    return (json.loads(r[0] or "null") or {}) if r else {}


def _post_adapter_call(tcon, sid: str, newest: str) -> str:
    """The compiled view is the newest request, always. (Preferring an older call that had a post-adapter body
    showed a stale request as "now". A newest call with only Hermes's copy is shown as that copy, labelled as
    the request Hermes handed its provider client.)"""
    return newest


def newest_extension(tcon, cid: str) -> str:
    """The newest captured request that extends call `cid`'s history (same system prompt, same leading items):
    the session's most recent compiled shape, even if no transcript row has been correlated to it yet."""
    base = tcon.execute("SELECT started, family, model FROM wire_calls WHERE id=?", (cid,)).fetchone()
    ref = _req_ref(tcon, cid)
    items = ref.get("items") or []
    sys_h = next((ref.get("keys", {}).get(k) for k in _SYS_KEYS if k in (ref.get("keys") or {})), None)
    if not base or not items:
        return cid
    need = max(1, len(items) - 4)
    best = cid
    scope = comparison_scope(tcon, cid)
    for r in tcon.execute("SELECT id, req_down FROM wire_calls WHERE started > ? AND family=? AND status=200 "
                          "ORDER BY started ASC LIMIT 80", (base[0], base[1])):
        if comparison_scope(tcon, r[0]) != scope:
            continue
        d = json.loads(r[1] or "null") or {}
        its = d.get("items") or []
        sh = next((d.get("keys", {}).get(k) for k in _SYS_KEYS if k in (d.get("keys") or {})), None)
        if sh == sys_h and len(its) >= need and its[:need] == items[:need]:
            best, items, need = r[0], its, max(1, len(its) - 4)
    return best


def _row_snip(r: dict) -> str:
    c = r.get("content") or ""
    if not c.strip():
        return ""  # pure tool-call turns carry no text to align on
    return _snippet(c)[:70] if r["role"] != "tool" else norm(c)[:50]


def compiled_view(state_db: Path, tcon, sid: str, layer: str = "wire", lane: str = "main", call: str | None = None) -> dict:
    """A compiled request for `sid` — the newest one in the selected execution lane, or the session's captured call
    `call` (any lane) — memoized on (session rows, wire store revision). An earlier call is aligned against every row,
    archived ones included: rows compacted away since then were still live when it was sent."""
    if lane not in ("main", "review", "all"):
        raise ValueError("lane must be main, review or all")
    historic = bool(call) and call != session_latest_call(tcon, sid, lane=lane)
    key = ("compiled", sid, layer, lane, call if historic else None)
    fp = _fingerprint(state_db, tcon, sid, inactive=historic)
    hit = _memo_get(key, fp)
    if hit is None:
        hit = _compiled_view(state_db, tcon, sid, layer, fp, lane=lane, call=call if historic else None)
        _memo_put(key, fp, hit)
    return dict(hit, now=time.time())


def session_calls(tcon, sid: str, fallback=(), limit: int = 400) -> dict:
    """The session's captured requests, oldest first, numbered from the session's first retained call: the Wire
    view's call history. Proxy-only sessions (no capture names them) fall back to the calls correlated by text."""
    base = ("SELECT w.id, w.started, w.ended, w.status, w.model, w.family, w.n_items, w.source, "
            "c.prompt_tokens, c.hit_pct, {lane} AS lane FROM wire_calls w LEFT JOIN calls c ON c.id=w.id ")
    try:
        lane = "c.lane" if "lane" in store.columns(tcon, "calls") else "NULL"
        sel = base.format(lane=lane)
        has = "w.req_down IS NOT NULL AND w.req_down != 'null'"
        total = tcon.execute(f"SELECT COUNT(*) FROM wire_calls w WHERE w.session_id=? AND {has}", (sid,)).fetchone()[0]
        rows = tcon.execute(sel + f"WHERE w.session_id=? AND {has} ORDER BY w.started DESC LIMIT ?", (sid, limit)).fetchall()
        if not rows:
            ids = [c for c in dict.fromkeys(fallback) if c][-limit:]
            rows = tcon.execute(sel + f"WHERE w.id IN ({','.join('?' * len(ids))}) AND {has} ORDER BY w.started DESC",
                                ids).fetchall() if ids else []
            total = len(rows)
    except sqlite3.Error:
        return {"calls": [], "total": 0}
    out = [dict(r) for r in reversed(rows)]
    first = total - len(out)
    for n, c in enumerate(out):
        c["n"] = first + n + 1
        if execution_lane(tcon, c["id"]) == "review":  # a background-review fork in this session's id
            c["lane"], c["review"] = "review", True
    return {"calls": out, "total": total}


def _call_in_session(tcon, sid: str, call: str, history: dict, correlated) -> bool:
    """A requested call belongs to this session: captured under its id, or (proxy-only, unattributed) correlated
    to its rows by text. A bare call id from another session is refused, never spliced onto this transcript."""
    if any(c["id"] == call for c in history["calls"]):
        return True
    try:
        r = tcon.execute("SELECT session_id FROM wire_calls WHERE id=? AND req_down IS NOT NULL AND req_down != 'null'",
                         (call,)).fetchone()
    except sqlite3.Error:
        return False
    if not r:
        return False
    return r[0] == sid if r[0] else call in {c for c in correlated if c}


# ── alignment memo: the expensive part of a compiled rebuild, keyed by its actual inputs ──
_ALIGN: "OrderedDict[tuple, tuple]" = OrderedDict()
_ALIGN_MAX = 16
ALIGN_STATS = {"hit": 0, "append_reuse": 0, "run": 0}


def _alignable(it: dict) -> bool:
    return it.get("role") not in ("system", "developer") and it.get("type") != "reasoning" and not it.get("tools")


def _aligned_cached(tcon, state_db: Path, sid: str, rows: list[dict], items: list[dict], cid: str, which: str,
                    fp) -> None:
    """align_items, reused when its inputs are unchanged: the same request (its stored item refs — immutable blobs)
    and the same active rows (content digests). A status-only write to the call (ended, usage) or the poll after a
    response therefore costs a lookup. Rows *appended* after the request reuse the previous alignment only when it
    left no alignable item unmapped (an appended row could otherwise supply a missing mapping); any rewrite of an
    existing row reruns it."""
    digests = getattr(fp, "digests", None) if fp is not None else None
    if digests is not None:
        digests = (fp[2],) + tuple(digests)  # the session row (source, lineage) feeds row kinds and labels
    try:
        ref = tcon.execute(f"SELECT {'req_hermes' if which == 'hermes' else 'req_down'} FROM wire_calls WHERE id=?",
                           (cid,)).fetchone()
    except sqlite3.Error:
        ref = None
    if digests is None or not ref or not ref[0]:
        ALIGN_STATS["run"] += 1
        align_items(tcon, state_db, sid, rows, items)
        return
    key = (sid, cid, which, hashlib.blake2b(ref[0].encode(), digest_size=16).hexdigest(), len(items))
    with _cache_lock:
        e = _ALIGN.get(key)
    if e is not None:
        old, complete, deltas = e
        reuse = old == digests or (complete and len(digests) > len(old) and digests[:len(old)] == old)  # [0]: session row
        if reuse:
            ALIGN_STATS["hit" if old == digests else "append_reuse"] += 1
            for it, d in zip(items, deltas):
                it.update(json.loads(d) if d else {})
            return
    ALIGN_STATS["run"] += 1
    before = [dict(it) for it in items]
    align_items(tcon, state_db, sid, rows, items)
    deltas = []
    for b, it in zip(before, items):
        d = {k: v for k, v in it.items() if k not in b or b[k] != v}
        deltas.append(json.dumps(d, default=str) if d else "")  # serialized: callers mutate their copies
    complete = all(it.get("row_id") or it.get("row_ids") or it.get("compaction") for it in items if _alignable(it))
    with _cache_lock:
        _ALIGN[key] = (digests, complete, deltas)
        _ALIGN.move_to_end(key)
        while len(_ALIGN) > _ALIGN_MAX:
            _ALIGN.popitem(last=False)


def _compiled_view(state_db: Path, tcon, sid: str, layer: str = "wire", fp=None, lane: str = "main",
                   call: str | None = None) -> dict:
    """System prompt + tools + every wire item in order, each aligned to the state.db row(s) it renders, plus
    what is NOT on the wire. ``call`` selects one of the session's earlier captured requests instead of the newest."""
    view = _session_view(state_db, tcon, sid, None, 5000, bool(call), framing=False)
    rows = view["rows"]
    out: dict = {"session": view["session"], "context": view.get("context"),
                 "matched_calls": view["matched_calls"], "now": time.time()}
    scon = state_con(state_db)
    try:
        stored_prompt = _stored_prompt(scon, sid)
        has_active = "active" in {r[1] for r in scon.execute("PRAGMA table_info(messages)")}
        out["archived_count"] = scon.execute("SELECT COUNT(*) FROM messages WHERE session_id=? AND COALESCE(active,1)=0",
                                             (sid,)).fetchone()[0] if has_active else 0
    finally:
        scon.close()
    out["stored_prompt_len"] = len(stored_prompt)
    # A review keeps the parent's session_id for cache warmth, not UI ownership.
    out["lane"] = lane
    out["lane_options"] = ["main", "review", "all"]
    cid = session_latest_call(tcon, sid, lane=lane)
    lc = cid
    if not lc and lane != "review" and not session_latest_call(tcon, sid, lane="all"):
        lc = view.get("latest_call")  # proxy-only correlation, never another explicit lane
        if lc and lane != "all" and execution_lane(tcon, lc) != lane:
            lc = None
    if not cid and lc:  # proxy-only capture: correlated by text, so walk forward to the newest extension
        cid = newest_extension(tcon, lc)
    # every captured call of the session, review forks included (labelled), for the call-history selector
    history = session_calls(tcon, sid, [r.get("wire") for r in rows] + [lc, cid])
    out["calls"], out["calls_total"] = history["calls"], history["total"]
    out["latest_call"] = out["newest_call"] = cid
    if call and not _call_in_session(tcon, sid, call, history, [r.get("wire") for r in rows] + [lc, cid]):
        out["call_missing"], call = call, None  # never splice another session's request onto this transcript
    if not cid and not call:
        out["error"] = ("no captured request for this session yet — capture starts with the session's next model call "
                        "after the plugin is enabled") if not history["calls"] else (
                        f"no captured {lane} request for this session — pick one of its {history['total']} captured calls")
        out["rows_tail"] = [{k: r.get(k) for k in ("id", "label", "kind", "role", "timestamp")} for r in rows[-40:]]
        return out
    newest = cid
    if call:
        cid = call
    if layer != "hermes":
        cid = _post_adapter_call(tcon, sid, cid)
    which = "hermes" if layer == "hermes" else "down"
    w = wire_summary(tcon, cid, which)
    which = w.get("which", "down")
    out["call_id"], out["correlated_call"] = cid, lc or cid
    out["newest_call"], out["layer"] = newest, w.get("layer")
    out["latest_call"], out["historic"] = newest, cid != newest
    out["wire"] = w
    # system prompt on the wire vs what state.db stored for the session
    ref = _req_ref(tcon, cid, which)
    keys = ref.get("keys") or {}
    sys_key, sys_item, sys_obj = _system_of(tcon, ref, (w.get("items") or [{}])[0].get("role"))
    wire_sys = norm(sys_obj if isinstance(sys_obj, str) else item_text(sys_obj)) if sys_obj is not None else ""
    out["system"] = {"key": sys_key, "item": sys_item, "wire_len": len(wire_sys), "stored_len": len(stored_prompt),
                     "matches_stored": bool(stored_prompt) and norm(stored_prompt) == wire_sys}
    if "tools" in keys:
        tools = get_blob(tcon, keys["tools"])
        names = []
        for t in tools if isinstance(tools, list) else []:
            if isinstance(t, dict):
                for fd in t.get("functionDeclarations") or []:
                    names.append(fd.get("name"))
                if t.get("name"):
                    names.append(t["name"])
                if isinstance(t.get("function"), dict):
                    names.append(t["function"].get("name"))
        out["tool_names"] = [n for n in names if n]
    # align wire items to transcript rows (ids first, then unwrapped text, then order)
    _aligned_cached(tcon, state_db, sid, rows, w.get("items") or [], cid, which, fp)
    fold_reasoning(tcon, w.get("items") or [])
    mapped = {rid for it in w.get("items") or [] for rid in (it.get("row_ids") or ([it["row_id"]] if it.get("row_id") else []))}
    started = (w.get("meta") or {}).get("started") or 0
    out["rows_after"] = [{"id": r["id"], "label": r["label"], "kind": r["kind"]} for r in rows
                         if (r.get("timestamp") or 0) > started and r["id"] not in mapped]
    out["rows_unmapped"] = sum(1 for r in rows if r["id"] not in mapped and (r.get("timestamp") or 0) <= started
                               and r.get("active", 1))
    for r in rows:
        r.pop("_align", None)
        r.pop("_parts", None)
    return out


def _system_of(tcon, ref: dict, first_role: str | None = None):
    """(envelope key, item index, value) of a stored request's system prompt: a top-level key (Gemini, Anthropic,
    Responses) or chat-completions' leading system/developer message."""
    keys = ref.get("keys") or {}
    sys_key = next((k for k in _SYS_KEYS if k in keys), None)
    if sys_key:
        return sys_key, None, get_blob(tcon, keys[sys_key])
    items = ref.get("items") or []
    if items:
        role = first_role if first_role is not None else item_norm(tcon, items[0])[0]
        if role in ("system", "developer"):
            return None, 0, get_blob(tcon, items[0])
    return None, None, None


# ───────────────────────── readable wire text: raw state.db content vs runtime-constructed text ─────────────────────────
# One wire string, partitioned into runs: what state.db stored as the row's authored content ("raw"), typed injection
# parts the runtime renders in at send time ("injection", by kind), and everything else the runtime/adapters built
# around them ("wrapper", labelled by its enclosing XML-style tag or Hermes envelope marker). Typed parts are used
# when the session adapter provides them; stock rows use content (and api_content to tell persisted wrappers from
# wire-only ones). Matching is literal: exact, then the needle stripped, then line by line.
_READABLE_MAX = 400_000
_STRUCTURED_TYPES = {"tool_use", "tool_result", "function_call", "function_call_output", "reasoning", "thinking",
                     "redacted_thinking", "image", "image_url", "input_image", "input_file", "document", "file"}
RAW, INJ, WRAP, UNAL = 1, 2, 3, 4
_RUN_KIND = {RAW: "raw", INJ: "injection", WRAP: "wrapper", UNAL: "unaligned"}


def text_segments(obj, path: str = "") -> list[tuple[str, str]]:
    """(path, text) of the human-readable strings of a wire item or envelope value, in wire order. Tool calls/results,
    reasoning and media are structured, not text, and are skipped."""
    out: list = []

    def walk(x, p):
        if isinstance(x, str):
            out.append((p, x))
        elif isinstance(x, list):
            for n, y in enumerate(x):
                walk(y, f"{p}[{n}]")
        elif isinstance(x, dict):
            if (x.get("type") in _STRUCTURED_TYPES or x.get("thought") is True or x.get("role") == "tool"
                    or any(k in x for k in ("functionCall", "functionResponse", "inlineData", "fileData"))):
                return
            for k in ("text", "content", "parts"):
                if k in x:
                    walk(x[k], f"{p}.{k}" if p else k)

    walk(obj, path)
    return out


def _find_free(text: str, needle: str, marks: bytearray, start: int = 0) -> int:
    """First occurrence of ``needle`` at or after ``start`` that overlaps no already-marked character."""
    i = text.find(needle, start)
    while i >= 0:
        if not any(marks[i:i + len(needle)]):
            return i
        i = text.find(needle, i + 1)
    return -1


def _mark(text: str, needle: str, marks: bytearray, labels: list, code: int, label) -> str | None:
    """Mark ``needle`` in ``text``; returns how it matched (exact / stripped / lines) or None."""
    for how, nd in (("exact", needle), ("stripped", needle.strip())):
        if not nd:
            return None
        i = _find_free(text, nd, marks)
        if i >= 0:
            marks[i:i + len(nd)] = bytes([code]) * len(nd)
            for j in range(i, i + len(nd)):
                labels[j] = label
            return how
    hit = cur = 0
    for line in needle.splitlines():
        s = line.strip()
        if len(s) < 3:
            continue
        i = _find_free(text, s, marks, cur)
        if i < 0:
            i = _find_free(text, s, marks)
        if i >= 0:
            marks[i:i + len(s)] = bytes([code]) * len(s)
            for j in range(i, i + len(s)):
                labels[j] = label
            hit += len(s)
            cur = i + len(s)
    return "lines" if hit else None


def _tag_label(text: str, a: int, b: int, events: list) -> list[tuple[int, int, str]]:
    """Split the wrapper run text[a:b] at tag tokens; label each piece by its tag, else the innermost open tag around
    it, else a Hermes envelope marker it contains, else "runtime"."""
    cuts = sorted({a, b} | {p for s, e, _n, _o in events for p in (s, e) if a < p < b})
    out = []
    for x, y in zip(cuts, cuts[1:]):
        stack = []
        tok = None
        for s, e, name, is_open in events:
            if s >= y:
                break
            if s >= x and e <= y:
                tok = tok or name
            if e <= x:
                if is_open:
                    stack.append(name)
                elif name in stack:
                    del stack[len(stack) - 1 - stack[::-1].index(name):]
        piece = text[x:y]
        label = tok or (stack[-1] if stack else None)
        if not label:
            label = next((n for n, rx in INJECT_BLOCKS if rx.search(piece)), None)
        if not label and out and not piece.strip():
            label = out[-1][2]  # whitespace between two tags stays with what precedes it
        out.append((x, y, label or "runtime"))
    return out


def readable_runs(text: str, raw=(), injected=(), persisted: str = "") -> dict:
    """Partition ``text`` into runs ``{t, k, label[, persisted]}``. ``raw``: authored strings (label = their source);
    ``injected``: (text, kind) typed injection parts. ``persisted``: the row's api_content, to flag wrapper text that
    state.db also kept. With nothing to match, only tag tokens are marked and the rest is "unaligned"."""
    n = len(text)
    if n > _READABLE_MAX:
        return {"runs": [{"t": text, "k": "unaligned", "label": None}], "too_large": True, "matched": []}
    marks, labels, matched = bytearray(n), [None] * n, []
    for body, kind in injected:
        if body and (how := _mark(text, body, marks, labels, INJ, kind or "injection")):
            matched.append({"k": "injection", "label": kind, "how": how})
    for body, label in raw:
        if body and (how := _mark(text, body, marks, labels, RAW, label)):
            matched.append({"k": "raw", "label": label, "how": how})
    events = sorted([(m.start(), m.end(), m.group(1), True) for m in _OPEN_TAG_RE.finditer(text) if not m.group(0).endswith("/>")]
                    + [(m.start(), m.end(), m.group(1), False) for m in _CLOSE_TAG_RE.finditer(text)])
    rest = UNAL if not (raw or injected) else WRAP
    runs, i = [], 0
    while i < n:
        code, j = marks[i], i + 1
        while j < n and marks[j] == code and (code == 0 or labels[j] == labels[i]):
            j += 1
        if code:
            runs.append({"t": text[i:j], "k": _RUN_KIND[code], "label": labels[i]})
        elif rest == UNAL:
            last = i
            for s, e, name, _o in events:
                if e <= i or s >= j:
                    continue
                if s > last:
                    runs.append({"t": text[last:s], "k": "unaligned", "label": None})
                runs.append({"t": text[max(s, last):e], "k": "wrapper", "label": name})
                last = e
            if last < j:
                runs.append({"t": text[last:j], "k": "unaligned", "label": None})
        else:
            for x, y, label in _tag_label(text, i, j, events):
                if runs and runs[-1]["k"] == "wrapper" and runs[-1]["label"] == label:
                    runs[-1]["t"] += text[x:y]
                else:
                    runs.append({"t": text[x:y], "k": "wrapper", "label": label})
        i = j
    if persisted:
        for run in runs:
            if run["k"] == "wrapper" and run["t"].strip():
                run["persisted"] = run["t"].strip() in persisted
    return {"runs": runs, "matched": matched}


def _needles(state_db: Path, row_ids) -> tuple[list, list, str, list]:
    """(raw, injected, api_content, source) for the aligned transcript rows: typed authored/injection parts when the
    session adapter reads them, else each row's content."""
    raw, inj, api, source = [], [], [], []
    if not row_ids or not Path(state_db).exists():
        return raw, inj, "", source
    scon = state_con(state_db)
    try:
        rows = [dict(r) for r in scon.execute(f"SELECT * FROM messages WHERE id IN ({','.join('?' * len(row_ids))}) "
                                              "ORDER BY id", list(row_ids))]
    finally:
        scon.close()
    for r in rows:
        authored = _adapt("authored_texts", r)
        parts = _adapt("injection_parts", r, default=None)
        if authored is not None:
            raw.extend((t, f"state.db #{r['id']} · authored part") for t in authored if t)
            source.append("parts")
        elif r.get("content"):
            raw.append((r["content"], f"state.db #{r['id']} · content"))
            source.append("content")
        inj.extend(parts or ())
        if r.get("api_content"):
            api.append(r["api_content"])
    return raw, inj, "\n".join(api), source


def wire_readable(state_db: Path, tcon, cid: str, which: str = "down", part: str = "item", i: int | None = None,
                  key: str | None = None, row_ids=(), sid: str | None = None) -> dict:
    """The exact wire text of one item (or the system prompt / an envelope key) as readable runs."""
    w = tcon.execute("SELECT req_down, req_up, req_hermes, session_id FROM wire_calls WHERE id=?", (cid,)).fetchone()
    if not w:
        return {"error": NO_WIRE}
    up, hermes = _loads(w["req_up"], {}), _loads(w["req_hermes"], {})
    ref = up if which == "up" and up else hermes if which == "hermes" and hermes else _loads(w["req_down"], {})
    if ref.get("same_as_down"):
        ref = _loads(w["req_down"], {})
    raw, inj, api, source = [], [], "", []
    if part == "sys":
        sys_key, sys_item, obj = _system_of(tcon, ref)
        sid = sid or w["session_id"]
        if sid and Path(state_db).exists():
            scon = state_con(state_db)
            try:
                stored = _stored_prompt(scon, sid)
            finally:
                scon.close()
            if stored:
                raw, source = [(stored, "state.db system prompt")], ["prompt"]
        path = sys_key or (f"{ref.get('list_key') or 'messages'}[{sys_item}]" if sys_item is not None else "")
    elif part == "key":
        obj, path = get_blob(tcon, ref["keys"][key]), key
    else:
        obj, path = get_blob(tcon, ref["items"][int(i)]), f"{ref.get('list_key') or 'items'}[{int(i)}]"
        raw, inj, api, source = _needles(state_db, list(row_ids)[:50])
    segs = []
    for p, t in text_segments(obj, path) if obj is not None else []:
        segs.append(dict(readable_runs(t, raw, inj, api), path=p, len=len(t)))
    return {"id": cid, "part": part, "segments": segs, "source": sorted(set(source)), "rows": list(row_ids)[:50],
            "has_api_content": bool(api)}


# ───────────────────────── wire item ↔ transcript row alignment ─────────────────────────
# Adapters and plugins wrap, split and group what Hermes stored, in formats this plugin cannot know in advance.
# So alignment never parses an adapter's wrapper: it uses only what Hermes core itself records — tool-call ids,
# the row's platform message id / input-event origins / delegation and event ids — looked up as plain tokens in
# whatever text the item carries, then containment of the row's own text (minus Hermes's own envelope) inside the
# item, then verbatim fragments of the row's api_content (turn context an adapter split into its own item).
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,}")
_DELEG_ID = re.compile(r"\bdeleg_[0-9a-f]{6,}\b")
_EVENT_ID = re.compile(r"^event_id:\s*(\S+)", re.M)
_ORIGIN_LINE = re.compile(r"^Message origin \(data\):\s*(\{.*\})\s*$", re.M)
# Hermes core's own envelope on a stored row (gateway timestamp + routing note, media lines, steer envelope)
_TAIL_MEDIA = re.compile(r"(?:\n?\[(?:screenshot[^\]]*|Image attached at:[^\]]*)\])+\s*$")
_LEAD_TS = re.compile(r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) [^\]\n]+\]\s*")
_LEAD_NOTE = re.compile(r"^\[Triggering message id: `[^`\n]*`[^\]\n]*\]\s*|^\[Triggering message id:[^\]\n]*\]\s*")
_MIN_FRAG = 32
# Presentation evidence only: alignment itself remains provider-neutral. Require a complete standalone
# system frame, never a quoted marker within a human request or a notice folded into a tool result.
_SYSTEM_ITEM = re.compile(
    r"^(?:The following is a <SYSTEM_MESSAGE>[^<]*\s+)?<SYSTEM_MESSAGE>\s*"
    r"\[Message\]\s+(?P<header>.*?)\bcontent=(?P<body>.*?)\s*</SYSTEM_MESSAGE>$", re.DOTALL)


def _injection_badge(tcon, item, row):
    role, text, _ = item_norm(tcon, item["h"])
    kind = None
    if role not in ("system", "developer"):
        if role != "user" or not (match := _SYSTEM_ITEM.fullmatch(text)):
            return
        header = match["header"]
        if not re.search(r"(?:^|\s)sender=system(?:\s|$)", header):
            return
        named = re.search(r"(?:^|\s)kind=([^\s]+)", header)
        if not named:
            return
        kind, text = named[1], norm(match["body"])
    provenance = _adapt("injection_provenance", row, text, kind, norm)
    if provenance:
        item.update(provenance)


def _ids_in(obj) -> tuple[list[str], list[str]]:
    """(tool-call ids an item issues, tool-call ids it answers) for every provider wire shape."""
    calls, results = [], []

    def walk(x):
        if isinstance(x, dict):
            fc, fr = x.get("functionCall"), x.get("functionResponse")
            if isinstance(fc, dict) and fc.get("id"):
                calls.append(str(fc["id"]))
            if isinstance(fr, dict) and fr.get("id"):
                results.append(str(fr["id"]))
            t = x.get("type")
            if t == "tool_use" and x.get("id"):
                calls.append(str(x["id"]))
            elif t == "tool_result" and x.get("tool_use_id"):
                results.append(str(x["tool_use_id"]))
            elif t == "function_call" and (x.get("call_id") or x.get("id")):
                calls.append(str(x.get("call_id") or x.get("id")))
            elif t == "function_call_output" and x.get("call_id"):
                results.append(str(x["call_id"]))
            for tc in x.get("tool_calls") or []:
                if isinstance(tc, dict) and tc.get("id"):
                    calls.append(str(tc["id"]))
            if x.get("role") == "tool" and x.get("tool_call_id"):
                results.append(str(x["tool_call_id"]))
            for k, v in x.items():
                if k not in ("functionCall", "functionResponse", "args", "input", "arguments", "response", "content",
                             "thoughtSignature", "signature", "inlineData", "data"):
                    walk(v)
                elif k in ("content",) and isinstance(v, list):
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(obj)
    return calls, results


def _row_bodies(r: dict, events: list | None) -> list[str]:
    """Normalized authored text(s) of a row: its typed human / system_event parts when it has them, else batch
    events individually, else content minus host framing."""
    authored = _adapt("authored_texts", r)
    if authored is not None:
        out = [norm(text) for text in authored]
        return [b for b in out if len(b) >= 6]
    out = []
    for e in events or []:
        if isinstance(e, dict) and isinstance(e.get("text"), str) and e["text"].strip():
            out.append(norm(e["text"]))
    c = r.get("content") or ""
    if c:
        c = _LEAD_NOTE.sub("", _LEAD_TS.sub("", c, count=1), count=1)
        c = _TAIL_MEDIA.sub("", c)
        if "[OUT-OF-BAND USER MESSAGE" in c[:200]:
            # steer envelope: keep only what the human wrote
            c = _OOB_NOISE.sub("", c)
        out.append(norm(c))
    return [b for b in out if len(b) >= 6]


_OOB_NOISE = re.compile(r"^(?:\[/?OUT-OF-BAND USER MESSAGE[^\n]*|For reactions to these messages[^\n]*|Message origin \(data\):[^\n]*"
                        r"|\[Runtime reminder\][\s\S]*)$", re.M)


def _frags(text: str, n: int = 7, cap: int = 120) -> list[str]:
    """Verbatim word runs of a text (normalized): what survives an adapter re-wrapping a line around it."""
    out = []
    for ln in (text or "").splitlines():
        w = ln.split()
        for k in range(0, max(1, len(w) - n + 1), 3):
            f = " ".join(w[k:k + n])
            if len(f) >= _MIN_FRAG:
                out.append(f)
            if len(out) >= cap:
                return out
    return out


def align_items(tcon, state_db: Path, sid: str, rows: list[dict], items: list[dict]) -> None:
    """Bind each wire item to the transcript row(s) it renders. Linear: one pass over rows builds every index (tool
    ids, identity tokens, a phrase-probe set of row texts), one pass over items does hash lookups and scans each
    item's text at most once; split-out context and folded rows reuse those scans."""
    if not items:
        return
    events: dict[int, list] = {}
    api: dict[int, str] = {}
    part_rows = {r["id"]: r for r in rows}
    need = []
    for r in rows:
        if r["role"] != "user":
            continue
        al = r.get("_align")
        if al is not None:  # prepared by the same pass that read the row (compiled view)
            api[r["id"]], ev, _ = al
            if ev is not None:
                events[r["id"]] = ev
        else:
            need.append(r["id"])
    if need:
        try:
            scon = state_con(state_db)
            try:
                sel = _select(scon, "messages", ("id", "display_metadata", "api_content", "content"))
                for i in range(0, len(need), 500):
                    chunk = need[i:i + 500]
                    for raw in scon.execute(f"SELECT {sel} FROM messages WHERE id IN ({','.join('?' * len(chunk))})", chunk):
                        record = dict(raw)
                        rid, meta, ac, full = (record[k] for k in ("id", "display_metadata", "api_content", "content"))
                        try:
                            m = json.loads(meta) if meta else None
                        except Exception:
                            m = None
                        if isinstance(m, dict) and isinstance(m.get("input_events"), list):
                            events[rid] = m["input_events"]
                        inj = _adapt("injection_text", record, default="")
                        if _adapt("row_parts", record) is not None:
                            part_rows[rid] = record
                        # everything Hermes stored for the row, envelope included: an adapter may lift any of it
                        api[rid] = norm((ac or "") + "\n" + (full or "") + ("\n" + inj if inj else ""))
            finally:
                scon.close()
        except Exception:
            pass
    pos = {r["id"]: k for k, r in enumerate(rows)}
    R = len(rows)
    for r in rows:
        if r["role"] == "user" and r["id"] not in api and r.get("content"):
            api[r["id"]] = norm(r["content"])
    by_call, by_result = {}, {}
    tok_rows: dict[str, set] = {}
    tok_rank: dict[str, int] = {}

    def own(tok, r, rank):
        # rank: 0 = the row's own message identity (platform id / origin), 1 = unit id in its header, 2 = event id
        tok = str(tok)
        tok_rows.setdefault(tok, set()).add(r["id"])
        tok_rank[tok] = min(rank, tok_rank.get(tok, rank))

    # ── the single pass over rows: ids, identity tokens, normalized bodies → phrase probes ──
    bodies: dict[int, list[str]] = {}
    probe_list = []
    for k, r in enumerate(rows):
        for tid in r.get("tool_ids") or []:
            by_call[tid] = r
        if r["role"] == "tool":
            if r.get("tool_call_id"):
                by_result[str(r["tool_call_id"])] = r
            continue
        bs = _row_bodies(r, events.get(r["id"]))
        bodies[r["id"]] = bs
        for b in bs:
            probe_list.append(((k, len(b) >= 12), b[:60], len(b) > 60 and b[60] != " " and b[59] != " "))
        if r["role"] != "user":
            continue
        c = r.get("content") or ""
        for t in _TOKEN.findall(str(r.get("platform_message_id") or "")):
            own(t, r, 0)
        for token, rank in _adapt("identity_tokens", r, default=()):
            for t in _TOKEN.findall(str(token)):
                own(t, r, rank)
        if "DELEGATION" in c[:160]:  # Hermes's delegation notice names its unit in the header
            for d in _DELEG_ID.findall(c[:160]):
                own(d, r, 1)
        if m := _EVENT_ID.search(c[:600]):
            own(m.group(1), r, 2)
        for line in _ORIGIN_LINE.findall(c):  # a steer batch row carries each message's origin inline
            try:
                mid = json.loads(line).get("message_id")
            except Exception:
                mid = None
            if mid:
                own(mid, r, 0)
        for e in events.get(r["id"], []):
            o = e.get("origin") if isinstance(e, dict) else None
            if isinstance(o, dict) and o.get("message_id"):
                own(o["message_id"], r, 0)
    row_by_id = {r["id"]: r for r in rows}
    # a token several rows share (e.g. a kind label inside a composite id) identifies none of them
    by_tok = {t: row_by_id[next(iter(rs))] for t, rs in tok_rows.items() if len(rs) == 1}
    probes = _Probes(probe_list)
    item_hits: dict[int, set] = {}  # item index -> probe keys found in its text (each item scanned at most once)

    def hits_of(n: int, txt: str | None = None) -> set:
        h = item_hits.get(n)
        if h is None:
            if txt is None:
                txt = item_norm(tcon, items[n]["h"])[1]
            h = item_hits[n] = probes.find(txt)
        return h

    def bind(it, found, via):
        seen, uniq = set(), []
        for r in found:
            if r["id"] not in seen:
                seen.add(r["id"])
                uniq.append(r)
        if not uniq:
            return False
        r0 = uniq[0]
        it.update(row_id=r0["id"], row_label=r0["label"], row_kind=r0["kind"], row_flags=r0.get("flags") or [],
                  row_ids=[r["id"] for r in uniq], align=via)
        return True

    def by_identity(text, j, ranks):
        """The row whose recorded identity the item carries: rows not yet passed first, then the strongest kind of
        identity, then the one mentioned first (an item names itself before it quotes others)."""
        cands = []
        for occ, tk in enumerate(dict.fromkeys(_TOKEN.findall(text))):
            r = by_tok.get(tk)
            if r is not None and tok_rank[tk] in ranks:
                cands.append((pos[r["id"]] < j, tok_rank[tk], occ, r))
        return [min(cands, key=lambda c: c[:3])[3]] if cands else []

    j = 0
    prev = None
    for n, it in enumerate(items):
        role, txt, _ = item_norm(tcon, it["h"])
        is_model = role.startswith(("model", "assistant"))
        compaction = "[CONTEXT COMPACTION" in txt[:400]
        if compaction:
            it["compaction"] = True
        hit_rows, via = [], None
        try:
            obj = get_blob(tcon, it["h"])
        except Exception:
            obj = None
        calls, results = _ids_in(obj) if obj is not None else ([], [])
        if calls or results:
            hit_rows = [by_call.get(c) for c in calls] + [by_result.get(c) for c in results]
            hit_rows = [r for r in hit_rows if r is not None]
            via = "tool-call id"
            if results:  # a notice an adapter appended to a tool result's output, identified by its own unit id
                folded = [by_tok[d] for d in dict.fromkeys(_DELEG_ID.findall(txt)) if d in by_tok
                          and d in notice_identity(by_tok[d])]
                if folded:
                    hit_rows += folded
                    via = "tool-call id + folded notice"
        if not hit_rows and not is_call_role(role) and not is_result_role(role):
            ident = not is_model and not compaction
            if ident:
                # the row's own message identity, wherever the adapter put it in the item
                hit_rows = by_identity(txt, j, (0,))
                via = "id" if hit_rows else None
            if not hit_rows:
                # the first row at/after the cursor (wrapping) whose text the item contains
                best = None
                for k, _ in hits_of(n, txt):
                    r = rows[k]
                    if is_model != (r["role"] == "assistant"):
                        continue
                    key = (k - j) % R
                    if best is None or key < best[0]:
                        best = (key, r)
                if best is not None:
                    hit_rows, via = [best[1]], "text"
            if not hit_rows and not is_model and prev is not None and prev.get("row_id") in api:
                # turn context the adapter split out of the preceding row: verbatim runs of what Hermes stored for it
                frags = _frags(item_text(obj) if obj is not None else "")
                if frags and _contains_any(api[prev["row_id"]], frags):
                    hit_rows, via = [row_by_id[prev["row_id"]]], "context of previous row"
            if not hit_rows and ident:
                hit_rows = by_identity(txt, j, (1, 2))
                via = "id" if hit_rows else None
        if not hit_rows and j < R:
            # text-less items (pure tool calls / empty tool results without ids) align positionally
            r0 = rows[j]
            call_item = is_call_role(role) or (is_model and not txt)
            if (call_item and r0["role"] == "assistant") or (is_result_role(role) and r0["role"] == "tool"):
                hit_rows, via = [r0], "position"
        if hit_rows and bind(it, hit_rows, via):
            j = max(j, max(pos.get(r["id"], -1) for r in hit_rows) + 1)
        prev = it

    # Rows the adapter folded into another item (internal notices and steers appended to a tool result, repeated
    # continuation nudges): attach each to the first item after its predecessor's item that carries its text.
    # Each lookup is a set probe on that item's (once-computed) hits; the 40-item horizon bounds a row's search.
    mapped = {rid for it in items for rid in (it.get("row_ids") or [])}
    item_of = {}
    for n, it in enumerate(items):
        for rid in it.get("row_ids") or []:
            item_of.setdefault(rid, n)
    model_side: dict[int, bool] = {}
    last_item = 0
    for k, r in enumerate(rows):
        if r["id"] in mapped:
            last_item = max(last_item, item_of.get(r["id"], last_item))
            continue
        if r["role"] == "tool" or not any(len(b) >= 12 for b in bodies.get(r["id"]) or []):
            continue
        want = (k, True)
        for n in range(last_item, min(len(items), last_item + 40)):
            if n not in model_side:
                model_side[n] = item_norm(tcon, items[n]["h"])[0].startswith(("model", "assistant"))
            if model_side[n] != (r["role"] == "assistant"):
                continue  # a reply quoting a notice is not where the notice went
            if want in hits_of(n):
                it = items[n]
                it.setdefault("row_ids", [it["row_id"]] if it.get("row_id") else []).append(r["id"])
                if not it.get("row_id"):
                    it.update(row_id=r["id"], row_label=r["label"], row_kind=r["kind"], row_flags=r.get("flags") or [])
                it["align"] = (it.get("align") or "text") + " + folded row"
                mapped.add(r["id"])
                last_item = n
                break

    # Keep transcript linkage separate from the provenance of an adapter's split context item.
    for item in items:
        if item.get("row_id") in part_rows:
            _injection_badge(tcon, item, part_rows[item["row_id"]])


def fold_reasoning(tcon, items: list[dict]) -> None:
    """OpenAI Responses requests carry each turn's reasoning as separate ``{"type": "reasoning"}`` input items just
    before the turn's ``message`` / ``function_call`` items. They are part of that assistant turn (opaque
    ``encrypted_content`` plus an optional summary), not rows of their own: each run of reasoning items is folded into
    the next model-side item, which lists them (``reasoning``) and shares its row alignment with them. The items stay
    in the list (``folded_into``) so the wire is complete; the UI shows them inside the turn."""
    run: list[dict] = []
    for it in items:
        if it.get("role") == "reasoning":
            run.append(it)
            continue
        if run and (it.get("role", "").startswith(("assistant", "model")) or it.get("role") == "function_call"):
            info = []
            for r in run:
                try:
                    obj = get_blob(tcon, r["h"])
                except Exception:
                    obj = None
                summ = []
                enc = 0
                if isinstance(obj, dict):
                    for s in obj.get("summary") or []:
                        if isinstance(s, dict) and isinstance(s.get("text"), str):
                            summ.append(s["text"])
                    enc = len(obj.get("encrypted_content") or "")
                    for c in obj.get("content") or []:  # reasoning_text blocks (open-weight Responses servers)
                        if isinstance(c, dict) and isinstance(c.get("text"), str):
                            summ.append(c["text"])
                info.append({"i": r["i"], "summary": "\n\n".join(summ), "encrypted_chars": enc})
                r["folded_into"] = it["i"]
                for k in ("row_id", "row_ids", "row_label", "row_kind", "row_flags"):
                    if it.get(k) is not None:
                        r[k] = it[k]
                if it.get("row_id"):
                    r["align"] = "folded into #%d" % it["i"]
            it["reasoning"] = info
        run = []


def _stored_prompt(scon, sid: str) -> str:
    """The session's compiled system prompt as Hermes stored it (inline column, else the hash-keyed table)."""
    try:
        cols = {c[1] for c in scon.execute("PRAGMA table_info(sessions)")}
        if not {"system_prompt", "system_prompt_hash"} & cols:
            return ""
        sel = ", ".join(c if c in cols else "NULL" for c in ("system_prompt", "system_prompt_hash"))
        r = scon.execute(f"SELECT {sel} FROM sessions WHERE id=?", (sid,)).fetchone()
    except sqlite3.Error:
        return ""
    if not r:
        return ""
    if r[0]:
        return r[0]
    if r[1]:
        try:
            p = scon.execute("SELECT prompt FROM system_prompts WHERE hash=?", (r[1],)).fetchone()
            return (p[0] if p else None) or ""
        except sqlite3.Error:
            return ""
    return ""


def session_prompt(state_db: Path, sid: str) -> dict:
    scon = state_con(state_db)
    try:
        text = _stored_prompt(scon, sid)
        try:
            h = scon.execute("SELECT system_prompt_hash FROM sessions WHERE id=?", (sid,)).fetchone()
        except sqlite3.Error:
            h = None
    finally:
        scon.close()
    return {"text": text, "hash": h[0] if h else None}


# ───────────────────────── agent CLI read API (read-only; collector/cli.py) ─────────────────────────
# Request layers by name. A call stores up to three copies of its request; each answers a different question.
LAYER_DOC = {
    "hermes": "what Hermes handed its provider client, before any adapter or client wrapper "
              "(wire_calls.req_hermes, or req_down when the call has only Hermes's own snapshot)",
    "wire": "what left the process / reached the proxy, after every adapter (wire_calls.req_down)",
    "upstream": "what the proxy sent the provider (wire_calls.req_up)",
}
LAYERS = ("hermes", "wire", "upstream")


def request_layers(tcon, cid: str) -> dict:
    """{name: (ref, source column)} for the request layers a call stored (``hermes`` / ``wire`` / ``upstream``)."""
    try:
        w = tcon.execute(f"SELECT {store.select_cols(tcon, 'wire_calls', ('req_down', 'req_hermes', 'req_up', 'source', 'file'))} "
                         "FROM wire_calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return {}
    if not w:
        return {}
    lay = store.layer_refs(w[0], w[1], w[3], w[4])
    out = {}
    if "pre" in lay:
        out["hermes"] = (lay["pre"], "req_hermes" if _loads(w[1]) else "req_down")
    if "post" in lay:
        out["wire"] = (lay["post"], "req_down")
    up = _loads(w[2], None)
    if isinstance(up, dict) and up:
        if up.get("same_as_down"):
            if "wire" in out:
                out["upstream"] = (out["wire"][0], "req_up (same as req_down)")
        else:
            out["upstream"] = (up, "req_up")
    return out


def _blob_len(tcon, h) -> int:
    if not h:
        return 0
    return (tcon.execute("SELECT n FROM wire_blobs WHERE h=?", (h,)).fetchone() or [0])[0]


def item_selection(total: int, limit: int | None = None, items: tuple | None = None,
                   head_tail: bool = False) -> tuple[list[int], dict]:
    """Bounded, zero-based item selection. Explicit slices are end-exclusive; an open end uses ``limit``.

    Metadata always describes the whole collection, never just the selected rows. ``next_items`` is directly
    reusable as ``--items``; head/tail previews point to the first omitted range rather than skipping the middle.
    ``limit=None`` is the intentionally unbounded API (and CLI ``--full``) path.
    """
    if limit is not None and (isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0):
        raise ValueError("item limit must be a positive integer")
    start = 0
    if items is not None:
        start, end = items
        start = 0 if start is None else start
        start = max(0, total + start) if start < 0 else min(total, start)
        if end is None:
            end = total if limit is None else min(total, start + limit)
        else:
            end = max(0, total + end) if end < 0 else min(total, end)
        if end < start:
            raise ValueError("--items end must not precede start")
        indices = list(range(start, end))
    elif limit is None or total <= limit:
        indices = list(range(total))
    elif head_tail and limit > 1:
        indices = [0] + list(range(total - limit + 1, total))
    else:
        indices = list(range(min(total, limit)))
    ranges = []
    for i in indices:
        if ranges and ranges[-1][1] == i:
            ranges[-1][1] = i + 1
        else:
            ranges.append([i, i + 1])
    # A preview's gap comes before its tail; a slice's continuation comes after its last index.
    if items is None and len(ranges) > 1:
        nxt, stop = ranges[0][1], ranges[1][0]
    else:
        nxt = ranges[-1][1] if ranges else (start if items is not None else 0)
        stop = total
    has_more = nxt < stop
    next_end = min(stop, nxt + (limit or max(1, total)))
    return indices, {"total": total, "shown": len(indices), "truncated": len(indices) < total,
                     "ranges": ranges, "has_more": has_more,
                     "next_items": f"{nxt}:{next_end}" if has_more else None}


def ref_summary(tcon, ref: dict, small: int = 200, item_limit: int | None = None,
                items: tuple | None = None) -> dict:
    """Envelope keys and bounded role/length/head previews. Existing API callers stay unbounded by default."""
    if "raw" in (ref or {}):
        return {"raw": True, "len": _blob_len(tcon, ref["raw"])}
    keys = {}
    for k in ref.get("order") or []:
        if k == ref.get("list_key"):
            continue
        h = (ref.get("keys") or {}).get(k)
        n = _blob_len(tcon, h)
        ent: dict = {"len": n}
        if h and n <= small:
            try:
                ent["value"] = get_blob(tcon, h)
            except Exception:
                pass
        keys[k] = ent
    refs = ref.get("items") or []
    indices, page = item_selection(len(refs), item_limit, items, head_tail=True)
    previews = []
    for i in indices:
        h = refs[i]
        role, txt, _ = item_norm(tcon, h)
        previews.append({"i": i, "role": role, "len": _blob_len(tcon, h), "head": _snip(txt, 0, 0, pad=100)})
    return {"order": ref.get("order"), "list_key": ref.get("list_key"), "keys": keys, "n_items": len(refs),
            "bytes": sum(k["len"] for k in keys.values()) + sum(_blob_len(tcon, h) for h in refs),
            "items": previews, **page}


def layer_diff(tcon, a: dict | None, b: dict | None, small: int = 600, show: int = 5) -> dict | None:
    """What changed from request layer ``a`` to ``b``: envelope keys added / removed / changed (small values
    inline), item counts, the shared prefix by content hash and the first differing items on both sides."""
    if not a or not b or "raw" in a or "raw" in b:
        return None
    ka, kb = a.get("keys") or {}, b.get("keys") or {}
    out: dict = {"keys_added": [], "keys_removed": [], "keys_changed": []}
    for k in kb:
        if k not in ka:
            n = _blob_len(tcon, kb[k])
            e = {"key": k, "len": n}
            if n <= small:
                e["value"] = get_blob(tcon, kb[k])
            out["keys_added"].append(e)
    out["keys_removed"] = [{"key": k, "len": _blob_len(tcon, ka[k])} for k in ka if k not in kb]
    for k in ka:
        if k in kb and ka[k] != kb[k]:
            na, nb = _blob_len(tcon, ka[k]), _blob_len(tcon, kb[k])
            e = {"key": k, "len_a": na, "len_b": nb}
            if na <= small and nb <= small:
                e["value_a"], e["value_b"] = get_blob(tcon, ka[k]), get_blob(tcon, kb[k])
            out["keys_changed"].append(e)
    ia, ib = a.get("items") or [], b.get("items") or []
    k = 0
    while k < min(len(ia), len(ib)) and ia[k] == ib[k]:
        k += 1
    # align by content hash so one inserted / moved item reads as that, not as "every later position differs"
    ops = [op for op in difflib.SequenceMatcher(None, ia, ib, autojunk=False).get_opcodes() if op[0] != "equal"]

    def side(lst, i):
        if i >= len(lst):
            return None
        role, txt, _ = item_norm(tcon, lst[i])
        return {"i": i, "role": role, "len": _blob_len(tcon, lst[i]), "head": txt[:200]}

    first = []
    for tag, a0, a1, b0, b1 in ops:
        for n in range(max(a1 - a0, b1 - b0)):
            if len(first) >= show:
                break
            first.append({"op": tag, "a": side(ia, a0 + n) if a0 + n < a1 else None,
                          "b": side(ib, b0 + n) if b0 + n < b1 else None})
    sa = set(ia)
    out.update(items_a=len(ia), items_b=len(ib), common_prefix=k,
               same_position=sum(1 for i in range(min(len(ia), len(ib))) if ia[i] == ib[i]),
               b_items_found_in_a=sum(1 for h in ib if h in sa),
               ops=[{"op": t, "a": [a0, a1], "b": [b0, b1]} for t, a0, a1, b0, b1 in ops[:20]], n_ops=len(ops),
               first_differing=k if k < max(len(ia), len(ib)) else None, first_diffs=first)
    return out


def _call_row(tcon, cid: str) -> dict | None:
    try:
        c = tcon.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return None
    if not c:
        return None
    d = dict(c)
    for k in ("attempt_detail", "proxy_attempts", "diverge", "signals"):
        if isinstance(d.get(k), str):
            d[k] = _loads(d[k], d[k])
    return d


def call_signals(tcon, cid: str, row: dict | None = None) -> tuple[dict | None, str]:
    """(signals, "stored" | "computed"): the persisted ``calls.signals``, else computed now (read-only) — so a store
    the backfill has not reached yet still answers."""
    s = (row or {}).get("signals")
    if isinstance(s, dict) and s.get("v"):
        return s, "stored"
    return store.compute_signals(tcon, cid), "computed"


WANT = ("request", "response", "thinking", "wire", "diff")


def call_detail(tcon, cid: str, want=WANT, full: bool = False, item: int | None = None,
                item_limit: int | None = None, items: tuple | None = None) -> dict:
    """Everything the store knows about one call, by part. CLI summaries bound items; other callers retain all."""
    want = set(want or ())
    c = _call_row(tcon, cid)
    if c:
        c["lane"] = call_lane(tcon, cid, c)
    w = tcon.execute("SELECT * FROM wire_calls WHERE id=?", (cid,)).fetchone()
    w = dict(w) if w else None
    if not c and not w:
        return {"error": f"unknown call id {cid}"}
    out: dict = {"id": cid, "call": c}
    if w:
        out["wire"] = {k: w.get(k) for k in ("file", "started", "ended", "family", "model", "url", "status", "n_items",
                                              "req_bytes", "session_id", "source", "exact", "tools_exact")}
    else:
        out["wire"] = None
        out["note"] = NO_WIRE
    sig, how = call_signals(tcon, cid, c)
    out["signals"], out["signals_source"] = sig, how
    layers = request_layers(tcon, cid)
    out["proxy_attempts"] = []
    for a in _loads((w or {}).get("proxy_attempts"), []):
        detail = {k: v for k, v in a.items() if k not in ("req_up", "resp_raw", "hdr_up")}
        if "request" in want:
            ref = a.get("req_up")
            detail["upstream_request_json"] = (rebuild(tcon, ref) if full else
                dict(ref_summary(tcon, ref, item_limit=item_limit, items=items), _summary=True)) if ref else None
        if "wire" in want:
            detail["headers"] = a.get("hdr_up")
        if "response" in want:
            detail["response"] = parse_response((get_blob_str(tcon, a["resp_raw"]) or "").splitlines()) if a.get("resp_raw") else None
        out["proxy_attempts"].append(detail)
    out["layers"] = {n: {"column": col, "about": LAYER_DOC[n]} for n, (ref, col) in layers.items()}
    out["requested_model"] = store.request_models(tcon, cid) if w else {}
    resp = _loads((w or {}).get("resp"), {})
    raw = store.read_blob_str(tcon, w["resp_raw"]) if w and w.get("resp_raw") else None
    if "request" in want:
        for n in LAYERS:
            if n not in layers:
                out[f"{n}_request_json"] = None
                continue
            ref = layers[n][0]
            out[f"{n}_request_json"] = rebuild(tcon, ref) if full else dict(
                ref_summary(tcon, ref, item_limit=item_limit, items=items), _summary=True)
            if item is not None:
                its = ref.get("items") or []
                out[f"{n}_request_item"] = get_blob(tcon, its[item]) if -len(its) <= item < len(its) else None
    if "response" in want:
        out["response"] = resp
    if "thinking" in want:
        tb = store.signals_mod().thinking_blocks(raw)
        stored = resp.get("thinking") or ""
        stream = "".join(b["text"] for b in tb["blocks"])
        out["thinking"] = {"stream": tb, "stored": stored, "stored_chars": len(stored),
                           "stored_matches_stream": (norm(stored) == norm(stream)) if raw else None,
                           "raw_response": bool(raw)}
    if "wire" in want:
        out["response_raw"] = raw
        out["headers_down"] = _loads((w or {}).get("hdr_down"), {})
        out["headers_up"] = _loads((w or {}).get("hdr_up"), {})
    if "diff" in want:
        miss = (c or {}).get("diverge")
        miss_src = "stored" if miss else None
        if not miss and c and w:
            try:
                miss = explain_miss(tcon, cid, c.get("session_id"), c.get("started"), c.get("prompt_tokens"), c.get("hit_pct"))
            except sqlite3.Error:  # an older store without per-call session ids
                miss = None
            miss_src = "computed" if miss else None
        miss = enrich_miss(tcon, cid, miss)
        out["diff"] = {
            "miss": miss, "miss_source": miss_src,
            "adapter": layer_diff(tcon, (layers.get("hermes") or (None,))[0], (layers.get("wire") or (None,))[0]),
            "proxy": layer_diff(tcon, (layers.get("wire") or (None,))[0], (layers.get("upstream") or (None,))[0])
            if layers.get("upstream", (None, ""))[1] == "req_up" else None,
            "signals": sig}
    return out


def _searchable(s: str) -> str:
    return s.replace("\\n", " ").replace("\\t", " ")


def _snip(s: str, at: int, n: int, pad: int = 90) -> str:
    """A window around a hit, widened to whole tokens (so a credential is never cut into a fragment that a
    downstream scrubber can no longer recognise)."""
    a, b = max(0, at - pad), min(len(s), at + n + pad)
    lo, hi = max(0, a - 200), min(len(s), b + 200)
    while a > lo and not s[a - 1].isspace():
        a -= 1
    while b < hi and not s[b].isspace():
        b += 1
    return norm(s[a:b])


def _search_key(hit):
    return (-(hit.get("started") or 0), hit.get("call_id") or "", hit.get("scope") or "",
            hit.get("layer") or "", str(hit.get("item", "")),
            f"{hit.get('field') or ''}:{hit.get('match_index', 0)}")


def _search_cursor(cursor):
    if cursor is None:
        return None
    try:
        if len(cursor) > 4096:
            raise ValueError()
        obj = json.loads(base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True))
        key = obj["key"]
        if (not isinstance(key, list) or len(key) != 6 or isinstance(key[0], bool)
                or not isinstance(key[0], (int, float)) or not math.isfinite(key[0])
                or not all(isinstance(x, str) for x in key[1:])):
            raise ValueError()
        return tuple(key)
    except (ValueError, KeyError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError("invalid search cursor; use next_cursor from the same query and filters") from None


def search(tcon, query: str, session: str | None = None, scopes=("request", "response", "thinking"),
           since: float | None = None, limit: int = 50, cursor: str | None = None) -> dict:
    """Case-insensitive substring search over stored calls. ``request`` searches every request layer's items and
    envelope keys as canonical JSON (ids and names included; ``\\n`` reads as a space); each distinct item is reported
    once, at the first call that sent it, with how many calls carried it. ``response`` / ``thinking`` search each
    call's parsed response text and tool calls / its thinking. Newest hits first."""
    after = _search_cursor(cursor)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise ValueError("search limit must be a positive integer")
    q = (query or "").lower()
    if not q:
        return {"results": [], "total": 0, "truncated": False, "has_more": False,
                "next_cursor": None, "scanned": {"calls": 0, "request_blobs": 0}}
    scopes = set(scopes)
    where, args = [], []
    if session:
        where.append("session_id = ?")
        args.append(session)
    if since is not None:
        where.append("COALESCE(started, captured) >= ?")
        args.append(since)
    sql = (f"SELECT {store.select_cols(tcon, 'wire_calls', ('id', 'started', 'session_id', 'model', 'resp'))} FROM wire_calls "
           + ("WHERE " + " AND ".join(where) if where else "") + " ORDER BY COALESCE(started, captured)")
    if session and "session_id" not in store.columns(tcon, "wire_calls"):
        return {"results": [], "total": 0, "truncated": False, "has_more": False, "next_cursor": None,
                "scanned": {"calls": 0, "request_blobs": 0}, "note": "this store predates per-call session ids"}
    hits: list[dict] = []
    by_blob: dict = {}
    miss: set = set()
    n_calls = n_blobs = 0
    for cid, started, sid, model, resp_s in tcon.execute(sql, args).fetchall():
        n_calls += 1
        if "request" in scopes:
            carried = set()
            for lname, (ref, _col) in request_layers(tcon, cid).items():
                if "raw" in ref:
                    parts = [("raw", ref["raw"])]
                else:
                    parts = [(f"key:{k}", h) for k, h in (ref.get("keys") or {}).items()]
                    parts += [(i, h) for i, h in enumerate(ref.get("items") or [])]
                for where_, h in parts:
                    if h in by_blob:
                        if h not in carried:
                            by_blob[h]["calls_carrying"] += 1
                            carried.add(h)
                        continue
                    if h in miss:
                        continue
                    s = store.read_blob_str(tcon, h) or ""
                    n_blobs += 1
                    ss = _searchable(s)
                    at = ss.lower().find(q)
                    if at < 0:
                        miss.add(h)
                        continue
                    try:
                        obj = json.loads(s)
                        role = item_role(obj) if isinstance(where_, int) else where_
                        txt = norm(obj if isinstance(obj, str) else item_text(obj))
                    except Exception:
                        role, txt = "?", ""
                    t_at = txt.lower().find(q)  # prefer the readable text over escaped JSON for the snippet
                    snippet = _snip(txt, t_at, len(q)) if t_at >= 0 else _snip(ss.replace('\\"', '"'), at, len(q))
                    hit = {"scope": "request", "layer": lname, "call_id": cid, "started": started, "session_id": sid,
                           "model": model, "item": where_, "role": role, "len": len(s), "calls_carrying": 1,
                           "snippet": snippet}
                    by_blob[h] = hit
                    carried.add(h)
                    hits.append(hit)
        if scopes & {"response", "thinking"}:
            resp = _loads(resp_s, {})
            fields = []
            if "response" in scopes:
                fields.append(("text", resp.get("text") or ""))
                for tc in resp.get("tool_calls") or []:
                    fields.append((f"tool_call:{tc.get('name')}", json.dumps(tc, ensure_ascii=False, default=str)))
            if "thinking" in scopes:
                fields.append(("thinking", resp.get("thinking") or ""))
            for match_index, (fname, s) in enumerate(fields):
                at = s.lower().find(q) if s else -1
                if at >= 0:
                    hits.append({"scope": "thinking" if fname == "thinking" else "response", "field": fname,
                                 "match_index": match_index, "call_id": cid, "started": started, "session_id": sid, "model": model,
                                 "snippet": _snip(s, at, len(q))})
    hits.sort(key=_search_key)
    remaining = hits if after is None else [h for h in hits if _search_key(h) > after]
    page = remaining[:limit]
    more = len(remaining) > limit
    next_cursor = (base64.urlsafe_b64encode(json.dumps({"key": _search_key(page[-1])},
                   separators=(",", ":")).encode()).decode().rstrip("=") if more else None)
    return {"results": page, "total": len(hits), "truncated": len(page) < len(hits),
            "has_more": more, "next_cursor": next_cursor,
            "scanned": {"calls": n_calls, "request_blobs": n_blobs}}


def session_meta(state_db: Path, sid: str) -> dict:
    """Session header plus row counts by role (and active / archived) — no wire work."""
    scon = state_con(state_db)
    try:
        meta = scon.execute(f"SELECT {_select(scon, 'sessions', SESSION_COLS)} FROM sessions WHERE id=?", (sid,)).fetchone()
        cols = {r[1] for r in scon.execute("PRAGMA table_info(messages)")}
        act = "SUM(COALESCE(active,1))" if "active" in cols else "COUNT(*)"
        roles = {r[0]: {"n": r[1], "active": r[2]} for r in scon.execute(
            f"SELECT role, COUNT(*), {act} FROM messages WHERE session_id=? GROUP BY role", (sid,))}
        span = scon.execute("SELECT MIN(timestamp), MAX(timestamp), MAX(id) FROM messages WHERE session_id=?", (sid,)).fetchone()
    finally:
        scon.close()
    if not meta:
        return {"error": f"unknown session {sid}"}
    d = _session_meta(meta, sid)
    d["messages"] = {"by_role": roles, "total": sum(v["n"] for v in roles.values()),
                     "first_at": span[0], "last_at": span[1], "max_id": span[2]}
    return d
