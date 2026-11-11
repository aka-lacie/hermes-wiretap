"""Response signals: provider fallbacks, refusals, safety blocks, provider notices and model switches.

Read from a call's raw response (an SSE stream or a JSON body, any of the four wire protocols: Anthropic Messages,
Gemini, OpenAI chat completions, OpenAI Responses), its parsed summary and its attempt history. Pure functions,
stdlib only: ``store.refresh_signals`` persists the result in ``calls.signals``; the CLI computes it on the fly for
rows that predate the column.

What each kind means (``items[].kind``):

* ``fallback``        — the provider served the request with another model and said so in the stream (an Anthropic
                        ``{"type": "fallback", "from", "to", "trigger"}`` content block). ``trigger.type == "refusal"``
                        is a classifier refusal of the requested model.
* ``fallback_iterations`` — the usage block lists more than one serving iteration (e.g. ``message`` on the
                        requested model, then ``fallback_message`` on the fallback model).
* ``notice``          — a provider note about how it changed the input (``input_transformations``: e.g.
                        ``thinking_dropped`` / ``model_binding_mismatch``), grouped per type and reason.
* ``refusal``         — the provider marked the answer itself a refusal (Anthropic ``stop_reason: refusal``, OpenAI
                        ``refusal`` content).
* ``safety``          — a safety filter blocked or cut the output (OpenAI ``content_filter``, Gemini
                        ``finishReason`` SAFETY / PROHIBITED_CONTENT / BLOCKLIST / SPII / RECITATION, Gemini
                        ``promptFeedback.blockReason`` or a ``blocked`` safety rating).
* ``error_refusal``   — a failed attempt whose error names a policy / safety / classifier block.
* ``model_switch``    — the model the request asked for (closest layer to the provider) differs from the one that
                        answered.
* ``refusal_wording`` — HEURISTIC: the visible text opens like a refusal ("I can't …", "I'm not going to …").
                        A model's own refusal leaves no provider marker; this is the only trace, and it can misfire.
"""
from __future__ import annotations

import json
import re

SIGNALS_V = 1
GEMINI_BLOCK = {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION", "IMAGE_SAFETY",
                "IMAGE_PROHIBITED_CONTENT", "MODEL_ARMOR"}
REFUSAL_KINDS = {"refusal", "safety", "error_refusal"}
_ERR_POLICY = re.compile(r"usage polic|content[_ ]filter|content[_ ]policy|safety|invalid_prompt|cyber|refus|"
                         r"prohibited|blocked by|violat", re.I)
# Openings of a refusal in the visible text. HEURISTIC (labelled so in every output): the strong forms anywhere in
# the first 1500 chars, "I can't <verb>" only right at the start, where a refusal opens.
_STRONG = re.compile(
    r"\bI(?:'m| am) (?:not going to (?:help|do|carry|assist|provide|continue|go along)|going to stop here|"
    r"declining|(?:unable|not able) to help|not comfortable (?:helping|doing|with))\b|"
    r"\bI (?:won't|will not) (?:help|do that|do this|assist|carry|provide|comply|step over|go along|go through)\b|"
    r"\bI (?:must|have to|need to) decline\b|\bI refuse to\b|\bI (?:can't|cannot) (?:help|assist) with (?:this|that)\b|"
    r"\bI (?:can't|cannot) comply\b|\ba line I won't\b|\bnot something I(?:'ll| will| can) help with\b", re.I)
_OPENING = re.compile(r"^\W{0,4}(?:sorry,? )?I (?:can't|cannot|can not|won't) (?:use|access|read|pull|provide|share|help|"
                      r"assist|do|go|continue|carry|retrieve|bypass|intercept|get|reach|log|open)\b", re.I)


def iter_objects(raw: str | None):
    """Every JSON value in a raw response: SSE ``data:`` lines, bare JSON lines, else the whole text as one value."""
    if not raw or raw == "null":
        return
    found = False
    for ln in raw.splitlines():
        s = ln.strip()
        if s.startswith("data:"):
            s = s[5:].strip()
        if not s or s[0] not in "{[":
            continue
        try:
            o = json.loads(s)
        except ValueError:
            continue
        found = True
        yield o
    if not found:
        s = raw.strip()
        if s[:1] in "{[":
            try:
                yield json.loads(s)
            except ValueError:
                pass


def _dicts(o):
    """Every dict nested in a JSON value (iterative: provider payloads can be deep)."""
    stack = [o]
    while stack:
        x = stack.pop()
        if isinstance(x, dict):
            yield x
            stack.extend(v for v in x.values() if isinstance(v, (dict, list)))
        elif isinstance(x, list):
            stack.extend(v for v in x if isinstance(v, (dict, list)))


def _served_of(o, cur):
    if not isinstance(o, dict):
        return cur
    t = o.get("type")
    if t == "message_start":
        return (o.get("message") or {}).get("model") or cur
    if t == "message" and o.get("model"):
        return o["model"]
    if isinstance(t, str) and t.startswith("response.") and isinstance(o.get("response"), dict):
        return o["response"].get("model") or cur
    if o.get("modelVersion"):
        return o["modelVersion"]
    if ("choices" in o or o.get("object") in ("response", "chat.completion")) and o.get("model"):
        return o["model"]
    return cur


def same_model(a: str | None, b: str | None) -> bool:
    a, b = (a or "").split("/")[-1].lower(), (b or "").split("/")[-1].lower()
    return a == b or a.startswith(b) or b.startswith(a)


def refusal_wording(text: str | None) -> dict | None:
    """The HEURISTIC refusal-opening match in visible text, or None."""
    if not text:
        return None
    t = text.replace("\u2019", "'")
    m = _OPENING.search(t[:400].lstrip()) or _STRONG.search(t[:1500])
    if not m:
        return None
    return {"kind": "refusal_wording", "heuristic": True, "match": m.group(0).strip(), "at": m.start()}


def extract(raw: str | None, resp: dict | None = None, requested: str | None = None,
            served: str | None = None, attempts: list | None = None) -> dict:
    """Signals of one call. ``raw``: the stored raw response; ``resp``: the parsed summary (text, finish, model);
    ``requested``: the model the request asked for; ``attempts``: ``calls.attempt_detail``."""
    items: list[dict] = []
    seen: set = set()

    def add(d):
        k = json.dumps(d, sort_keys=True, default=str)
        if k not in seen:
            seen.add(k)
            items.append(d)

    transforms: dict = {}
    refusal_texts: list[str] = []
    served_raw = None
    any_raw = False
    for o in iter_objects(raw):
        any_raw = True
        served_raw = _served_of(o, served_raw)
        for d in _dicts(o):
            dt = d.get("type")
            if dt == "fallback" and ("from" in d or "to" in d):
                add({"kind": "fallback", "from": d.get("from"), "to": d.get("to"), "trigger": d.get("trigger")})
            it = d.get("input_transformations")
            if isinstance(it, list):
                for x in it:
                    if isinstance(x, dict):
                        e = transforms.setdefault((x.get("type"), x.get("reason")), {"count": 0, "paths": []})
                        e["count"] += 1
                        if x.get("path") and len(e["paths"]) < 5:
                            e["paths"].append(x["path"])
            its = d.get("iterations")
            if isinstance(its, list) and its and all(isinstance(x, dict) for x in its):
                seq = [{"type": x.get("type"), "model": x.get("model")} for x in its]
                if len({s["model"] for s in seq}) > 1 or any("fallback" in str(s["type"] or "") for s in seq):
                    add({"kind": "fallback_iterations", "iterations": seq})
            if d.get("stop_reason") == "refusal":
                add({"kind": "refusal", "source": "anthropic.stop_reason", "value": "refusal"})
            fr = d.get("finishReason")
            if isinstance(fr, str) and fr.upper() in GEMINI_BLOCK:
                add({"kind": "safety", "source": "gemini.finishReason", "value": fr})
            pf = d.get("promptFeedback")
            if isinstance(pf, dict) and pf.get("blockReason"):
                add({"kind": "safety", "source": "gemini.promptFeedback.blockReason", "value": pf["blockReason"],
                     "message": pf.get("blockReasonMessage")})
            if d.get("blocked") is True and d.get("category"):
                add({"kind": "safety", "source": "gemini.safetyRatings", "value": d["category"],
                     "probability": d.get("probability")})
            if d.get("finish_reason") == "content_filter":
                add({"kind": "safety", "source": "openai.finish_reason", "value": "content_filter"})
            inc = d.get("incomplete_details")
            if isinstance(inc, dict) and inc.get("reason") == "content_filter":
                add({"kind": "safety", "source": "openai.incomplete_details", "value": "content_filter"})
            ref = d.get("refusal")
            if isinstance(ref, str) and ref.strip():
                refusal_texts.append(ref)
            elif dt == "response.refusal.delta" and isinstance(d.get("delta"), str):
                refusal_texts.append(d["delta"])
    if refusal_texts:
        full = max(refusal_texts, key=len)
        joined = "".join(t for t in refusal_texts if t is not full)
        text = full if len(full) >= len(joined) else joined
        add({"kind": "refusal", "source": "openai.refusal", "value": text[:400]})
    for (t, reason), e in transforms.items():
        add({"kind": "notice", "type": t, "reason": reason, "count": e["count"], "paths": e["paths"]})
    resp = resp if isinstance(resp, dict) else {}
    fin = str(resp.get("finish") or "")
    if not any_raw and fin:  # no raw stream: the parsed finish reason is all there is
        if fin.lower() == "refusal":
            add({"kind": "refusal", "source": "finish_reason", "value": fin})
        elif fin.lower() == "content_filter" or fin.upper() in GEMINI_BLOCK:
            add({"kind": "safety", "source": "finish_reason", "value": fin})
    for a in attempts or ():
        if not isinstance(a, dict) or a.get("status") in (None, 200):
            continue
        blob = " ".join(str(a.get(k) or "") for k in ("reason", "type", "message"))
        m = _ERR_POLICY.search(blob)
        if m:
            add({"kind": "error_refusal", "status": a.get("status"), "type": a.get("type") or a.get("reason"),
                 "message": str(a.get("message") or "")[:300], "match": m.group(0)})
    served_model = served_raw or served or resp.get("model")
    if requested and served_model and not same_model(requested, served_model):
        add({"kind": "model_switch", "requested": requested, "served": served_model})
    w = refusal_wording(resp.get("text"))
    if w:
        add(w)
    kinds = sorted({i["kind"] for i in items})
    provider = any(i["kind"] in REFUSAL_KINDS for i in items) or any(
        i["kind"] == "fallback" and str((i.get("trigger") or {}).get("type") or "") == "refusal" for i in items)
    return {"v": SIGNALS_V, "refusal": bool(provider or w),
            "basis": "provider" if provider else "heuristic" if w else None,
            "kinds": kinds, "requested_model": requested, "served_model": served_model, "items": items}


def dumps(sig: dict) -> str:
    """The stored form: compact, so ``"refusal":true`` is a stable LIKE filter."""
    return json.dumps(sig, ensure_ascii=False, separators=(",", ":"), default=str)


def summary(sig: dict | None) -> str:
    """One line for list views."""
    if not sig or not sig.get("items"):
        return ""
    out = []
    for i in sig["items"]:
        k = i["kind"]
        if k == "fallback":
            tr = i.get("trigger") or {}
            why = "/".join(str(x) for x in (tr.get("type"), tr.get("category")) if x)
            out.append(f"fallback {(i.get('from') or {}).get('model')}→{(i.get('to') or {}).get('model')}"
                       + (f" ({why})" if why else ""))
        elif k == "notice":
            out.append(f"notice {i.get('type')}×{i.get('count')}" + (f" ({i['reason']})" if i.get("reason") else ""))
        elif k in ("refusal", "safety"):
            out.append(f"{k} {i.get('source')}={str(i.get('value'))[:40]}")
        elif k == "error_refusal":
            out.append(f"error_refusal {i.get('status')} {i.get('match')}")
        elif k == "model_switch":
            out.append(f"model_switch {i.get('requested')}→{i.get('served')}")
        elif k == "refusal_wording":
            out.append(f"refusal_wording[heuristic] \"{i.get('match')}\"")
        elif k == "fallback_iterations":
            out.append("iterations " + "→".join(f"{s.get('type')}:{s.get('model')}" for s in i.get("iterations") or []))
        else:
            out.append(k)
    return " · ".join(out)


# ───────────────────────── exact thinking from the raw stream ─────────────────────────
def thinking_blocks(raw: str | None) -> dict:
    """The model's thinking exactly as the provider streamed it, block by block, with signature presence.

    Anthropic ``thinking`` / ``redacted_thinking`` blocks (stream deltas or a full message), Gemini ``thought``
    parts (consecutive parts merged) and ``thoughtSignature``, OpenAI chat ``reasoning_content``, OpenAI
    Responses ``reasoning`` items (summary + encrypted_content length). Signatures are reported by length only."""
    blocks: dict = {}
    order: list = []
    sigs: list[dict] = []
    resp_reasoning: list[dict] = []
    resp_deltas: list[str] = []
    chat = {"text": ""}
    gem = {"cur": None}

    def block(key, typ):
        if key not in blocks:
            blocks[key] = {"type": typ, "text": "", "signature_chars": 0, "redacted_chars": 0}
            order.append(key)
        return blocks[key]

    for o in iter_objects(raw):
        for top in (o if isinstance(o, list) else [o]):
            if not isinstance(top, dict):
                continue
            t = top.get("type")
            if t == "content_block_start":
                cb = top.get("content_block") or {}
                if cb.get("type") in ("thinking", "redacted_thinking"):
                    b = block(("a", top.get("index")), cb["type"])
                    b["text"] += cb.get("thinking") or ""
                    b["signature_chars"] += len(cb.get("signature") or "")
                    b["redacted_chars"] += len(cb.get("data") or "")
            elif t == "content_block_delta":
                d = top.get("delta") or {}
                key = ("a", top.get("index"))
                if d.get("type") == "thinking_delta":
                    block(key, "thinking")["text"] += d.get("thinking") or ""
                elif d.get("type") == "signature_delta":
                    block(key, "thinking")["signature_chars"] += len(d.get("signature") or "")
            msg = top if t == "message" else (top.get("message") if t == "message_start" else None)
            for n, cb in enumerate((msg or {}).get("content") or []):
                if isinstance(cb, dict) and cb.get("type") in ("thinking", "redacted_thinking"):
                    b = block(("m", n), cb["type"])
                    b["text"] += cb.get("thinking") or ""
                    b["signature_chars"] += len(cb.get("signature") or "")
                    b["redacted_chars"] += len(cb.get("data") or "")
            for c in top.get("candidates") or []:
                for p in (c.get("content") or {}).get("parts") or []:
                    if not isinstance(p, dict):
                        continue
                    if p.get("thought"):
                        if gem["cur"] is None:
                            gem["cur"] = ("g", len(order))
                        block(gem["cur"], "thought")["text"] += p.get("text") or ""
                    elif "text" in p or "functionCall" in p:
                        gem["cur"] = None
                    if p.get("thoughtSignature"):
                        on = "thought" if p.get("thought") else "functionCall" if "functionCall" in p else "text"
                        sigs.append({"on": on, "chars": len(p["thoughtSignature"])})
            for ch in top.get("choices") or []:
                d = ch.get("delta") or ch.get("message") or {}
                r = d.get("reasoning_content") or d.get("reasoning")
                if isinstance(r, str):
                    chat["text"] += r
            if t in ("response.reasoning_summary_text.delta", "response.reasoning_text.delta"):
                resp_deltas.append(top.get("delta") or "")
            items = []
            if t == "response.output_item.done" and isinstance(top.get("item"), dict):
                items = [top["item"]]
            elif isinstance(top.get("output"), list):  # a non-stream Response object
                items = top["output"]
            elif t == "response.completed" and isinstance((top.get("response") or {}).get("output"), list):
                items = top["response"]["output"]
            for it in items:
                if isinstance(it, dict) and it.get("type") == "reasoning":
                    txt = [s.get("text") for s in it.get("summary") or [] if isinstance(s, dict) and s.get("text")]
                    txt += [c.get("text") for c in it.get("content") or [] if isinstance(c, dict) and c.get("text")]
                    rec = {"type": "reasoning", "text": "\n\n".join(txt), "signature_chars": 0,
                           "redacted_chars": len(it.get("encrypted_content") or ""), "id": it.get("id")}
                    if not any(x.get("id") == rec["id"] and rec["id"] for x in resp_reasoning):
                        resp_reasoning.append(rec)
    out = [dict(blocks[k], chars=len(blocks[k]["text"])) for k in order]
    if chat["text"]:
        out.append({"type": "reasoning_content", "text": chat["text"], "chars": len(chat["text"]),
                    "signature_chars": 0, "redacted_chars": 0})
    if resp_reasoning:
        out.extend(dict(r, chars=len(r["text"])) for r in resp_reasoning)
    elif resp_deltas:
        txt = "".join(resp_deltas)
        out.append({"type": "reasoning", "text": txt, "chars": len(txt), "signature_chars": 0, "redacted_chars": 0})
    return {"blocks": out, "signatures": sigs,
            "chars": sum(b["chars"] for b in out),
            "signed": any(b.get("signature_chars") for b in out) or bool(sigs)}
