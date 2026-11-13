"""wiretap — the agent-facing CLI over Wiretap's stores (read-only).

Agents inspect captured model calls and unified sessions through this instead of ad hoc SQL. Every query goes through
the plugin's own collector APIs (``store`` / ``telemetry`` / ``inspector``); this module only parses arguments,
resolves the two databases, opens them read-only, scrubs secrets and formats.

Entry points: ``plugins/wiretap/bin/wiretap`` (standalone, no Hermes import needed) and ``hermes wiretap``
(registered by the plugin). Database resolution, first match wins: ``--telemetry-db`` / ``--state-db`` → ``--home``
→ ``TELEMETRY_DB`` / ``WIRETAP_STATE_DB`` → ``$HERMES_HOME`` → the active profile's default.

Output: concise text by default; ``--json`` one stable JSON document ``{"wiretap": 1, "command": …, …}``; ``--jsonl``
one JSON object per result for list / search commands.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SCHEMA_V = 1
RED = "‹redacted›"


def _sibling(name: str):
    key = f"_wiretap_{name}"
    if key in sys.modules:
        return sys.modules[key]
    spec = importlib.util.spec_from_file_location(key, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[key] = mod
    spec.loader.exec_module(mod)
    return mod


# ───────────────────────── secrets ─────────────────────────
_TEXT_SECRETS = (
    (re.compile(r"(?im)^((?:proxy-)?authorization|x-api-key|x-goog-api-key|api-key|cookie|set-cookie)[ \t]*:[ \t]*\S.*$"),
     r"\1: " + RED),
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/\-]{12,}=*"), r"\1 " + RED),
    (re.compile(r"\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{16,}"), "sk-" + RED),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{30,}"), "AIza" + RED),
    (re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"), "gh_" + RED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"), "xox-" + RED),
    (re.compile(r"(?i)(\"?(?:api[_-]?key|x-api-key|x-goog-api-key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
                r"client[_-]?secret|password|authorization)\"?\s*[:=]\s*\"?)(?!‹)([^\"\s,}]{6,})"), r"\1" + RED),
)


def _secret_key(k) -> bool:
    try:
        return bool(_sibling("capture")._is_secret(k))
    except Exception:
        s = str(k).lower().replace("-", "_")
        return s in ("api_key", "authorization", "cookie", "x_api_key", "x_goog_api_key", "password") or \
            s.endswith(("_api_key", "_secret", "_token"))


def scrub_text(s: str) -> str:
    for rx, rep in _TEXT_SECRETS:
        s = rx.sub(rep, s)
    return s


def scrub(v, depth: int = 0):
    """Every emitted structure: credential-named keys redacted (the capture layer's rule, at any depth) and
    bearer tokens / provider keys / ``key=value`` credentials scrubbed out of every string."""
    if depth > 200:
        return v
    if isinstance(v, dict):
        return {k: (RED if _secret_key(k) and x not in (None, "", RED) and not isinstance(x, (dict, list))
                    else scrub(x, depth + 1)) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [scrub(x, depth + 1) for x in v]
    if isinstance(v, str):
        return scrub_text(v)
    return v


# ───────────────────────── context ─────────────────────────
class Ctx:
    """Resolved paths, the collector modules and lazily opened read-only connections."""

    def __init__(self, args):
        env = os.environ
        home = Path(args.wt_home).expanduser() if getattr(args, "wt_home", None) else None
        hh = Path(env["HERMES_HOME"]).expanduser() if env.get("HERMES_HOME") else None
        self.store = _sibling("store")
        tdb = (getattr(args, "wt_telemetry_db", None) or (self.store.data_dir(home) / "telemetry.db" if home else None)
               or env.get("TELEMETRY_DB") or (self.store.data_dir(hh) / "telemetry.db" if hh else None)
               or self.store.db_path())
        sdb = (getattr(args, "wt_state_db", None) or (home / "state.db" if home else None) or env.get("WIRETAP_STATE_DB")
               or (hh / "state.db" if hh else None) or self.store.state_db())
        self.tdb, self.sdb = Path(tdb).expanduser(), Path(sdb).expanduser()
        # every call below passes these paths explicitly; the modules' import-time defaults are never relied on
        self.tel = _sibling("telemetry")
        self.ins = _sibling("inspector")
        self.sig = self.store.signals_mod()
        self._tcon = None

    @property
    def tcon(self):
        if self._tcon is None:
            if not self.tdb.exists():
                raise CliError(f"no telemetry store at {self.tdb} (set --telemetry-db / --home / TELEMETRY_DB)")
            self._tcon = self.store.connect_ro(self.tdb)
            # One read snapshot per command: counts, pages and deduplicated blobs must see the same store revision.
            self._tcon.execute("BEGIN")
        return self._tcon

    def need_state(self):
        if not self.sdb.exists():
            raise CliError(f"no Hermes state.db at {self.sdb} (set --state-db / --home / WIRETAP_STATE_DB)")
        return self.sdb

    def main(self):
        try:
            return self.tel.main_session(self.sdb) if self.sdb.exists() else None
        except Exception:
            return None

    def close(self):
        if self._tcon is not None:
            self._tcon.close()


class CliError(Exception):
    pass


# ───────────────────────── parsing helpers ─────────────────────────
_DUR = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhdw]?)\s*$", re.I)


def parse_since(s: str | None, now: float | None = None) -> float | None:
    """``6h`` / ``30m`` / ``2d`` / ``90s`` / ``1w`` / a bare number of hours / an ISO date-time (local) → epoch."""
    if s is None or str(s).strip() == "":
        return None
    now = time.time() if now is None else now
    m = _DUR.match(str(s))
    if m:
        n, u = float(m.group(1)), (m.group(2) or "h").lower()
        return now - n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[u]
    try:
        return datetime.fromisoformat(str(s).strip()).timestamp()
    except ValueError:
        raise CliError(f"cannot read --since {s!r} (use 6h, 30m, 2d, or an ISO date-time)")


def _ts(t) -> str:
    if not t:
        return "-"
    try:
        return datetime.fromtimestamp(float(t)).strftime("%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(t)


def _k(n) -> str:
    if n is None:
        return "-"
    n = float(n)
    return f"{n / 1e6:.2f}M" if n >= 1e6 else f"{n / 1e3:.1f}k" if n >= 1e3 else f"{int(n)}"


def _usd(v) -> str:
    return "?" if v is None else f"${v:.4f}"


def _head(s, n=140) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _resolve_call(ctx, cid: str) -> str:
    con = ctx.tcon
    for t in ("calls", "wire_calls"):
        if con.execute(f"SELECT 1 FROM {t} WHERE id=?", (cid,)).fetchone():
            return cid
    esc = cid.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    hits = {r[0] for t in ("calls", "wire_calls") for r in con.execute(
        f"SELECT id FROM {t} WHERE id LIKE ? ESCAPE '\\' LIMIT 3", (f"%{esc}%",))}
    if len(hits) == 1:
        return hits.pop()
    if hits:
        raise CliError(f"call id {cid!r} is ambiguous: {', '.join(sorted(hits))} …")
    raise CliError(f"unknown call id {cid!r}")


# ───────────────────────── commands ─────────────────────────
def cmd_status(ctx, a) -> dict:
    st, ins = ctx.store, ctx.ins
    out: dict = {"telemetry_db": {"path": str(ctx.tdb), "exists": ctx.tdb.exists()},
                 "state_db": {"path": str(ctx.sdb), "exists": ctx.sdb.exists()}}
    if ctx.tdb.exists():
        con = ctx.tcon
        t = out["telemetry_db"]
        t["bytes"] = ctx.tdb.stat().st_size
        t["mode"] = oct(ctx.tdb.stat().st_mode & 0o777)
        t["space"] = st.space(con)
        cols = set(st.columns(con, "calls"))
        t["calls"] = con.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
        t["calls_by_source"] = {r[0] or "": r[1] for r in con.execute("SELECT source, COUNT(*) FROM calls GROUP BY source")}
        t["wire_calls"] = con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0]
        t["blobs"] = con.execute("SELECT COUNT(*) FROM wire_blobs").fetchone()[0]
        span = con.execute("SELECT MIN(started), MAX(started) FROM calls").fetchone()
        t["first_call"], t["last_call"] = span[0], span[1]
        t["signals_column"] = "signals" in cols
        t["signals_stored"] = con.execute("SELECT COUNT(*) FROM calls WHERE signals IS NOT NULL").fetchone()[0] \
            if "signals" in cols else 0
        t["signals_rev"] = _kv_raw(con, "signals_rev")
        t["refusals_stored"] = con.execute("SELECT COUNT(*) FROM calls WHERE signals LIKE ?",
                                           (ctx.tel.REFUSAL_LIKE,)).fetchone()[0] if "signals" in cols else None
        t["last_capture"] = st.kv_get(con, "last_capture", {})
        t["last_scan"] = st.kv_get(con, "last_scan", {})
    if ctx.sdb.exists():
        s = out["state_db"]
        s["bytes"] = ctx.sdb.stat().st_size
        scon = ins.state_con(ctx.sdb)
        try:
            s["schema"] = ins.state_schema(scon)
            s["sessions"] = scon.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            s["messages"] = scon.execute("SELECT MAX(id) FROM messages").fetchone()[0]
        finally:
            scon.close()
        s["main_session"] = ctx.main()
    return out


def _kv_raw(con, key):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return r[0] if r else None
    except sqlite3.Error:
        return None


def cmd_sessions_list(ctx, a) -> list:
    sdb = ctx.need_state()
    rows = ctx.ins.sessions_list(sdb, a.wt_query or "", a.wt_limit, ctx.main() or "", source=a.wt_source,
                                 model=a.wt_model, since=parse_since(a.wt_since))
    keep = ("id", "title", "display_title", "source", "model", "billing_provider", "started_at", "t", "message_count", "parent_session_id",
            "hidden", "main", "lineage") + ctx.ins.session_output_columns("sessions")
    return [{k: r.get(k) for k in keep} for r in rows]


def cmd_session_show(ctx, a) -> dict:
    sdb = ctx.need_state()
    ins, sid = ctx.ins, a.wt_session_id
    meta = ins.session_meta(sdb, sid)
    if meta.get("error"):
        raise CliError(meta["error"])
    out: dict = {"session": meta, "mode": "compiled" if a.wt_compiled else "transcript" if a.wt_transcript else "summary"}
    tcon = ctx.tcon if ctx.tdb.exists() else ctx.store.memory_store()
    out["latest_call"] = ins.session_latest_call(tcon, sid)
    try:
        out["calls"] = tcon.execute("SELECT COUNT(*), SUM(prompt_tokens), SUM(cost_equiv_usd) FROM calls WHERE session_id=?",
                                    (sid,)).fetchone()[:]
        out["calls"] = dict(zip(("n", "prompt_tokens", "cost_equiv_usd"), out["calls"]))
    except sqlite3.Error:
        out["calls"] = None
    if a.wt_transcript:
        v = ins.session_view(sdb, tcon, sid, a.wt_before, a.wt_limit, a.wt_inactive)
        out["rows"] = [{k: r.get(k) for k in (
            "id", "role", "kind", "label", "timestamp", "content_len", "content", "truncated", "tool_name",
            "tool_call_id", "tool_names", "tool_ids", "wire", "flags", "ref", "inject", "framing", "active", "finish_reason")
            + ins.session_output_columns("transcript")
            if r.get(k) is not None} for r in v["rows"]]
        out.update(total=v["total"], oldest_id=v["oldest_id"], matched_calls=v["matched_calls"])
    elif a.wt_compiled:
        c = ins.compiled_view(sdb, tcon, sid, a.wt_layer, lane=a.wt_lane)
        if c.get("error"):
            out["compiled"] = {"error": c["error"]}
        else:
            w = c.get("wire") or {}
            items = []
            for it in w.get("items") or []:
                items.append({k: it.get(k) for k in ("i", "role", "len", "framing", "head", "row_id", "row_ids", "row_label",
                                                      "row_kind", "align", "folded_into", "reasoning") if it.get(k) is not None})
            indices, page = ins.item_selection(len(items), None if a.wt_full else a.wt_limit, a.wt_items)
            # Keep alignment counts global, but never duplicate an entire system prompt / transcript in this view.
            system = c.get("system") or {}
            system = {k: v for k, v in system.items() if k not in ("wire", "stored", "wire_text", "stored_text", "diff")}
            after, unmapped = c.get("rows_after") or [], c.get("rows_unmapped") or 0
            out["compiled"] = {
                "call_id": c.get("call_id"), "layer": c.get("layer"), "newest_call": c.get("newest_call"),
                "lane": c.get("lane"), "lane_options": c.get("lane_options"),
                "system": system, "tool_names": c.get("tool_names"), "keys": w.get("keys"),
                "items": [items[i] for i in indices], "n_items": len(items), **page,
                "next_cursor": page["next_items"],
                "unaligned": sum(1 for it in items if not it.get("row_id") and not it.get("row_ids")
                                 and it.get("folded_into") is None),
                "folded_reasoning": sum(1 for it in items if it.get("folded_into") is not None),
                "rows_after": after if a.wt_full else after[:a.wt_limit], "rows_after_total": len(after),
                "rows_unmapped": unmapped,
                "archived_count": c.get("archived_count")}
            if not a.wt_full:
                for it in out["compiled"]["items"]:
                    it.update(scrub(it))
                    if "head" in it:
                        it["head"] = _head(it["head"], 120)
                    for r in it.get("reasoning") or []:
                        text = r.get("summary") or ""
                        if len(text) > 120:
                            r["summary_chars"] = len(text)
                            r["summary_truncated"] = True
                            r["summary"] = _head(text, 120)
    return out


def _filters(ctx, a) -> dict:
    return {"since": parse_since(getattr(a, "wt_since", None)), "session": getattr(a, "wt_session", None),
            "family": getattr(a, "wt_family", None), "model": getattr(a, "wt_model", None),
            "provider": getattr(a, "wt_provider", None), "upstream": getattr(a, "wt_upstream", None),
            "credential": getattr(a, "wt_credential", None), "project": getattr(a, "wt_project", None),
            "status": getattr(a, "wt_status", None), "errors": getattr(a, "wt_errors", False),
            "misses": getattr(a, "wt_misses", False), "refusals": getattr(a, "wt_refusals", False)}


def cmd_calls_list(ctx, a) -> dict:
    return ctx.tel.list_calls_page(ctx.tcon, _filters(ctx, a), limit=a.wt_limit, cursor=a.wt_cursor)


def cmd_call_show(ctx, a) -> dict:
    cid = _resolve_call(ctx, a.wt_call_id)
    want = set(ctx.ins.WANT) if a.wt_all else {p for p in ctx.ins.WANT if getattr(a, f"wt_{p}", False)}
    want = want or {"response"}  # bare `call show`: the row, signals, layers and the parsed response
    d = ctx.ins.call_detail(ctx.tcon, cid, want, full=a.wt_full, item=a.wt_item,
                            item_limit=a.wt_limit, items=a.wt_items)
    if d.get("error"):
        raise CliError(d["error"])
    d["parts"] = sorted(want)
    return d


def cmd_search(ctx, a) -> dict:
    scopes = [s for s in ("request", "response", "thinking") if getattr(a, f"wt_{s}", False)]
    if a.wt_all or not scopes:
        scopes = ["request", "response", "thinking"]
    r = ctx.ins.search(ctx.tcon, a.wt_text, session=a.wt_session, scopes=scopes, since=parse_since(a.wt_since),
                       limit=a.wt_limit, cursor=a.wt_cursor)
    r["scopes"] = scopes
    return r


def cmd_costs(ctx, a) -> dict:
    return ctx.tel.costs(ctx.tcon, _filters(ctx, a), by={"session": "session_id", "upstream": "upstream_provider"}.get(
        a.wt_by, a.wt_by))


# ───────────────────────── human formatting ─────────────────────────
def _sig_lines(sig, indent="  ") -> list[str]:
    if not sig or not sig.get("items"):
        return []
    head = f"{indent}signals ({'REFUSAL · ' + str(sig.get('basis')) if sig.get('refusal') else 'no refusal'}): "
    return [head + _sibling("store").signals_mod().summary(sig)]


def fmt_status(d) -> list[str]:
    t, s = d["telemetry_db"], d["state_db"]
    out = [f"telemetry.db  {t['path']}" + ("" if t["exists"] else "  (missing)")]
    if t.get("exists"):
        src = ", ".join(f"{k or '?'} {v}" for k, v in sorted(t["calls_by_source"].items()))
        out.append(f"  {t['bytes'] / 1e6:.1f} MB, mode {t['mode']} · calls {t['calls']} ({src}) · wire {t['wire_calls']} "
                   f"· blobs {t['blobs']} · {_ts(t['first_call'])} → {_ts(t['last_call'])}")
        space = t.get("space") or {}
        if space:
            out.append(f"  pages {space['pages']} × {space['page_size']} B · free {space['free_pages']} "
                       f"({space['free_bytes'] / 1e6:.1f} MB) · auto-vacuum {space['vacuum']}")
        if t["signals_column"]:
            out.append(f"  signals: stored on {t['signals_stored']} calls (backfill rev {t['signals_rev'] or 'not run'}), "
                       f"{t['refusals_stored']} flagged refusal")
        else:
            out.append("  signals: no column yet (older store) — computed on the fly per row")
        lc = t.get("last_capture") or {}
        out.append(f"  last capture {_ts(lc.get('ts'))} (dropped {lc.get('dropped', 0)})")
    out.append(f"state.db      {s['path']}" + ("" if s["exists"] else "  (missing)"))
    if s.get("exists"):
        out.append(f"  {s['bytes'] / 1e6:.1f} MB · schema {s['schema']} · sessions {s['sessions']} · messages ≤ {s['messages']}"
                   f" · main session {s.get('main_session') or '-'}")
    return out


def fmt_sessions(rows) -> list[str]:
    out = []
    for r in rows:
        lin = r.get("lineage") or {}
        tag = f"{lin.get('kind')}·d{lin.get('depth')}" if lin and lin.get("depth") is not None else (lin.get("kind") or "root") if lin else "root"
        out.append(f"{_ts(r.get('t') or r.get('started_at'))}  {r['id']}  {r.get('source') or '-'}  {r.get('model') or '-'}  "
                   f"{tag}{' MAIN' if r.get('main') else ''}  msgs {r.get('message_count') or 0}  {_head(r.get('display_title') or r.get('title'), 60)}")
    return out or ["(no sessions)"]


def fmt_session(d) -> list[str]:
    s = d["session"]
    lin = s.get("lineage") or {}
    m = s.get("messages") or {}
    roles = ", ".join(f"{k} {v['n']}" + (f" ({v['active']} active)" if v.get("active") != v["n"] else "")
                      for k, v in sorted((m.get("by_role") or {}).items()))
    out = [f"SESSION {s.get('id')}  {_head(s.get('title'), 80)}",
           f"  source {s.get('source') or '-'} · model {s.get('model') or '-'} · lineage "
           f"{(lin.get('kind') or '-') + (' d' + str(lin['depth']) if lin.get('depth') is not None else '') if lin else 'root'}"
           f"{' · parent ' + str(lin.get('parent')) if lin.get('parent') else ''}"
           f"{' · root ' + str(lin.get('root')) if lin.get('root') else ''}",
           f"  messages {m.get('total', 0)}: {roles} · {_ts(m.get('first_at'))} → {_ts(m.get('last_at'))}",
           f"  captured calls {(d.get('calls') or {}).get('n') or 0} · latest {d.get('latest_call') or '-'}"]
    if d["mode"] == "transcript":
        out.append(f"TRANSCRIPT ({len(d['rows'])} of {d['total']} rows)")
        for r in d["rows"]:
            extra = ""
            if r.get("tool_names"):
                extra += " → " + ", ".join(r["tool_names"])
            if r.get("wire"):
                extra += f"  [{r['wire']}]"
            out.append(f"  #{r['id']} {_ts(r.get('timestamp'))} {r.get('label')} ({r.get('content_len', 0)})  "
                       f"{_head(r.get('content'), 140)}{extra}")
            for f in r.get("flags") or []:
                out.append(f"      ⚑ {f}")
    elif d["mode"] == "compiled":
        c = d["compiled"]
        if c.get("error"):
            out.append(f"COMPILED: {c['error']}")
            return out
        sy = c.get("system") or {}
        out.append(f"COMPILED {c['call_id']}  layer {c['layer']}  items {len(c['items'])}/{c['n_items']}  unaligned {c['unaligned']}  "
                   f"folded reasoning {c['folded_reasoning']}")
        if c.get("next_items"):
            out.append(f"  next: --items {c['next_items']} (same call_id required; newest request can change)")
        out.append(f"  system: wire {sy.get('wire_len')} chars vs stored {sy.get('stored_len')} — "
                   f"{'matches' if sy.get('matches_stored') else 'differs'}"
                   f"{' · tools ' + str(len(c.get('tool_names') or [])) if c.get('tool_names') is not None else ''}")
        for it in c["items"]:
            if it.get("folded_into") is not None:
                continue
            rows = it.get("row_ids") or ([it["row_id"]] if it.get("row_id") else [])
            al = f"row {','.join('#' + str(x) for x in rows)} ({it.get('align')})" if rows else "UNALIGNED"
            rs = it.get("reasoning") or []
            rtag = f" +{len(rs)} reasoning" if rs else ""
            out.append(f"  [{it['i']}] {it.get('role')} {it.get('len')}  {al}{rtag}  {_head(it.get('head'), 100)}")
        if c.get("rows_after"):
            out.append(f"  after this request: {len(c['rows_after'])} rows "
                       + ", ".join(f"#{r['id']} {r['label']}" for r in c["rows_after"][:6]))
    return out


def fmt_call_line(r) -> list[str]:
    out = [f"{_ts(r.get('started'))}  {r.get('status') or '-'}  {r.get('family') or '-'}  {r.get('model') or '-'}  "
           f"{r.get('provider') or '-'}  in {_k(r.get('prompt_tokens'))} hit {r.get('hit_pct') if r.get('hit_pct') is not None else '-'}%  "
           f"out {_k(r.get('output_tokens'))}  {_usd(r.get('cost_usd'))} (eq {_usd(r.get('cost_equiv_usd'))})"
           + (f"  429×{r['n429']}" if r.get("n429") else ""),
           f"  {r['id']}  session {r.get('session_id') or '-'}"
           + (f" · credential {r.get('auth_label') or r.get('auth_key')}" if r.get('auth_label') or r.get('auth_key') else "")
           + (f" · project {r['project']}" if r.get('project') else "")]
    out += _sig_lines(r.get("signals"))
    if r.get("miss"):
        out.append(f"  miss: {r['miss']}")
    return out


def fmt_calls(page) -> list[str]:
    out = []
    for r in page["results"]:
        out += fmt_call_line(r)
    out = out or ["(no calls)"]
    out.append(f"{len(page['results'])} shown · {page['total']} matching · has_more {page['has_more']}")
    if page.get("next_cursor"):
        out.append(f"next: --cursor {page['next_cursor']}")
    return out


def _layer_summary_lines(name, ref, about) -> list[str]:
    if ref is None:
        return [f"{name.upper()} REQUEST: not stored"]
    if not ref.get("_summary"):
        return [f"{name.upper()} REQUEST ({name}_request_json — {about})", json.dumps(ref, ensure_ascii=False, default=str)]
    if ref.get("raw"):
        return [f"{name.upper()} REQUEST ({about}): unparsed body, {ref.get('len')} chars"]
    keys = " · ".join(f"{k}={json.dumps(v['value'], ensure_ascii=False)[:60]}" if "value" in v else f"{k}({v['len']})"
                      for k, v in (ref.get("keys") or {}).items())
    out = [f"{name.upper()} REQUEST ({name}_request_json — {about})",
           f"  {ref['n_items']} {ref.get('list_key') or 'items'} · {ref['bytes']:,} chars · keys: {keys}"]
    its = ref.get("items") or []
    if ref.get("truncated"):
        out.append(f"  showing {len(its)} of {ref['total']} items · next --items {ref.get('next_items') or '(end)'}")
    for it in its:
        out.append(f"  [{it['i']}] {it['role']} {it['len']}  {_head(it.get('head'), 110)}")
    return out


def _diff_lines(label, d) -> list[str]:
    if not d:
        return [f"  {label}: not comparable (layer missing)"]
    out = [f"  {label}: items {d['items_a']} → {d['items_b']}, shared prefix {d['common_prefix']}, same position "
           f"{d['same_position']}, {d['b_items_found_in_a']} of {d['items_b']} found in the earlier layer, "
           f"{d['n_ops']} change op(s)"
           + (": " + ", ".join(f"{o['op']} a[{o['a'][0]}:{o['a'][1]}]→b[{o['b'][0]}:{o['b'][1]}]" for o in d["ops"][:6])
              if d["ops"] else "")]
    for e in d["keys_added"]:
        out.append(f"    + key {e['key']} ({e['len']})" + (f" = {json.dumps(e['value'], ensure_ascii=False)[:300]}" if "value" in e else ""))
    for e in d["keys_removed"]:
        out.append(f"    - key {e['key']} ({e['len']})")
    for e in d["keys_changed"]:
        v = (f" {json.dumps(e['value_a'], ensure_ascii=False)[:120]} → {json.dumps(e['value_b'], ensure_ascii=False)[:120]}"
             if "value_a" in e else "")
        out.append(f"    ~ key {e['key']} ({e['len_a']} → {e['len_b']}){v}")
    for x in d["first_diffs"]:
        a_, b_ = x.get("a") or {}, x.get("b") or {}
        out.append(f"    {x['op']}: a#{a_.get('i', '∅')} {a_.get('role', '')} {a_.get('len', '')} → "
                   f"b#{b_.get('i', '∅')} {b_.get('role', '')} {b_.get('len', '')}  {_head(b_.get('head') or a_.get('head'), 90)}")
    return out


def fmt_call(d) -> list[str]:
    c = d.get("call") or {}
    w = d.get("wire") or {}
    rm = d.get("requested_model") or {}
    sig = d.get("signals") or {}
    served = sig.get("served_model") or (d.get("response") or {}).get("model") or c.get("model")
    out = [f"CALL {d['id']}",
           f"  {_ts(c.get('started') or w.get('started'))} · status {c.get('status', w.get('status'))} · source "
           f"{c.get('source') or w.get('source')} · session {c.get('session_id') or w.get('session_id') or '-'} · lane {c.get('lane') or '-'}",
           f"  model requested {rm.get('upstream') or rm.get('wire') or rm.get('hermes') or '?'}"
           + (f" (hermes {rm.get('hermes')}, wire {rm.get('wire')}, upstream {rm.get('upstream')})" if len(set(rm.values())) > 1 else "")
           + f" → served {served or '?'} · provider {c.get('provider') or '-'}"
           + (f" (upstream {c['upstream_provider']})" if c.get("upstream_provider") else "")
           + f" · api {c.get('api_mode') or '-'}",
           f"  tokens in {c.get('prompt_tokens') or 0:,} (cached {c.get('cached_tokens') or 0:,}, {c.get('hit_pct')}%) "
           f"out {c.get('output_tokens') or 0:,} think {c.get('thinking_tokens') or 0:,} · {_usd(c.get('cost_usd'))} "
           f"(eq {_usd(c.get('cost_equiv_usd'))}, {c.get('billing') or '?'}) · total {c.get('total_s')}s ttfb {c.get('ttfb_s')}s"
           + (f" · attempts {c.get('attempts')} (429×{c.get('n429') or 0})" if (c.get("attempts") or 1) > 1 else "")]
    lay = d.get("layers") or {}
    out.append("  layers: " + (" · ".join(f"{n}={v['column']}" for n, v in lay.items()) or "none stored"))
    if d.get("note"):
        out.append(f"  note: {d['note']}")
    out.append(f"SIGNALS ({d.get('signals_source')}; {'REFUSAL, basis ' + str(sig.get('basis')) if sig.get('refusal') else 'no refusal'})")
    for i in sig.get("items") or []:
        out.append("  - " + json.dumps(i, ensure_ascii=False, default=str))
    if not sig.get("items"):
        out.append("  (none)")
    parts = set(d.get("parts") or [])
    if "request" in parts:
        for n in ("hermes", "wire", "upstream"):
            out += _layer_summary_lines(n, d.get(f"{n}_request_json"), (lay.get(n) or {}).get("about", ""))
            if f"{n}_request_item" in d:
                out.append(f"  item: {json.dumps(d[f'{n}_request_item'], ensure_ascii=False, default=str)}")
    resp = d.get("response")
    if resp is not None:
        out.append(f"RESPONSE (finish {resp.get('finish')}, model {resp.get('model')})")
        if resp.get("text"):
            out.append(resp["text"])
        for tc in resp.get("tool_calls") or []:
            out.append(f"  tool_call {tc.get('name')} {tc.get('id') or ''} {json.dumps(tc.get('args'), ensure_ascii=False, default=str)[:600]}")
        if resp.get("usage"):
            out.append(f"  usage {json.dumps(resp['usage'], ensure_ascii=False, default=str)[:600]}")
    th = d.get("thinking")
    if th is not None:
        st = th["stream"]
        out.append(f"THINKING (exact, from the raw response: {len(st['blocks'])} blocks, {st['chars']} chars"
                   f"{', signed' if st['signed'] else ''}; stored resp.thinking {th['stored_chars']} chars"
                   + ("" if th["stored_matches_stream"] is None else
                      f", {'matches' if th['stored_matches_stream'] else 'DIFFERS from'} the stream") + ")")
        if not th["raw_response"]:
            out.append("  (no raw response stored; showing the parsed resp.thinking)")
            if th["stored"]:
                out.append(th["stored"])
        for n, b in enumerate(st["blocks"]):
            out.append(f"--- [{n}] {b['type']} · {b['chars']} chars"
                       + (f" · signature {b['signature_chars']} chars" if b.get("signature_chars") else "")
                       + (f" · encrypted/redacted {b['redacted_chars']} chars" if b.get("redacted_chars") else ""))
            if b["text"]:
                out.append(b["text"])
        if st["signatures"]:
            out.append("  thoughtSignatures: " + ", ".join(f"{s['on']} {s['chars']} chars" for s in st["signatures"]))
    if "diff" in parts:
        df = d.get("diff") or {}
        out.append("DIFF")
        m = df.get("miss")
        if m:
            out.append(f"  miss forensics ({df.get('miss_source')}): {m.get('why')} · common {m.get('common_items')} of "
                       f"{m.get('items')} items vs {m.get('prev_id')} (layer {m.get('layer', '?')})")
            if m.get("at") is not None:
                out.append(f"    first changed #{m['at']} ({m.get('role')}) {m.get('prev_len')}→{m.get('cur_len')} chars")
        else:
            out.append("  miss forensics: none (not a qualifying miss)")
        out += _diff_lines("pre-adapter (hermes) → post-adapter (wire)", df.get("adapter"))
        out += _diff_lines("post-adapter (wire) → upstream (proxy→provider)", df.get("proxy"))
    if "wire" in parts:
        out.append("HEADERS down " + json.dumps(d.get("headers_down") or {}, ensure_ascii=False))
        out.append("HEADERS up " + json.dumps(d.get("headers_up") or {}, ensure_ascii=False))
        out.append("RAW RESPONSE")
        out.append(d.get("response_raw") or "(none stored)")
    return out


def fmt_search(d) -> list[str]:
    out = [f"{d.get('total', 0)} hits{' (showing ' + str(len(d['results'])) + ')' if d.get('truncated') else ''} · scanned "
           f"{d['scanned'].get('calls', 0)} calls, {d['scanned'].get('request_blobs', 0)} request items · scopes {','.join(d.get('scopes') or [])}"]
    for h in d["results"]:
        if h["scope"] == "request":
            where = f"item #{h['item']}" if isinstance(h["item"], int) else h["item"]
            out.append(f"{_ts(h.get('started'))}  request/{h['layer']}  {where} {h.get('role')}  {h['call_id']}"
                       + (f"  (carried by {h['calls_carrying']} calls)" if h.get("calls_carrying", 1) > 1 else ""))
        else:
            out.append(f"{_ts(h.get('started'))}  {h['scope']}/{h.get('field')}  {h['call_id']}")
        out.append(f"    …{h['snippet']}…")
    return out


def fmt_costs(d) -> list[str]:
    out = [f"{'key (' + d['by'] + ')':<34} {'calls':>6} {'prompt':>9} {'hit%':>6} {'out':>8} {'cost':>11} {'equiv':>11}"]
    for r in d["rows"] + [dict(d["total"], key="TOTAL")]:
        out.append(f"{_head(r['key'] or '-', 34):<34} {r['calls'] or 0:>6} {_k(r.get('prompt_tokens')):>9} "
                   f"{(r['hit_pct'] if r.get('hit_pct') is not None else '-'):>6} {_k(r.get('output_tokens')):>8} "
                   f"{_usd(r.get('cost_usd')):>11} {_usd(r.get('cost_equiv_usd')):>11}"
                   + (f"  ({r['unpriced']} unpriced)" if r.get("unpriced") else ""))
    return out


COMMANDS = {
    "status": (cmd_status, fmt_status, False),
    "sessions list": (cmd_sessions_list, fmt_sessions, True),
    "session show": (cmd_session_show, fmt_session, False),
    "calls list": (cmd_calls_list, fmt_calls, "results"),
    "call show": (cmd_call_show, fmt_call, False),
    "search": (cmd_search, fmt_search, "results"),
    "costs": (cmd_costs, fmt_costs, "rows"),
}


# ───────────────────────── argparse ─────────────────────────
def positive_int(value):
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def item_range(value):
    if not re.fullmatch(r"-?\d*:-?\d*", value) or value in ("-:", ":-", "-:-"):
        raise argparse.ArgumentTypeError("use START:END (zero-based, end exclusive; either end may be omitted)")
    try:
        return tuple(int(x) if x else None for x in value.split(":"))
    except ValueError:
        raise argparse.ArgumentTypeError("use START:END with integer bounds") from None


def _parse_command(argv):
    # Diagnostic labels come only from our vocabulary, never arbitrary IDs / invalid actions / secret values.
    actions = {"calls": "list", "call": "show", "sessions": "list", "session": "show"}
    for i, token in enumerate(argv):
        if token in actions:
            return f"{token} {actions[token]}" if argv[i + 1:i + 2] == [actions[token]] else token
        if token in ("status", "search", "costs"):
            return token
    return None


class WiretapParser(argparse.ArgumentParser):
    _active_argv: list[str] | None = None

    def error(self, message):
        argv = WiretapParser._active_argv
        argv = sys.argv[1:] if argv is None else argv
        if "--json" in argv or "--jsonl" in argv:
            sys.stdout.write(json.dumps(scrub({"wiretap": SCHEMA_V, "command": _parse_command(argv),
                                               "error": message, "error_type": "argument"}),
                                        ensure_ascii=False) + "\n")
            raise SystemExit(2)
        argparse.ArgumentParser.error(self, scrub_text(message))


def _parse_wiretap_known_args(parser, args=None, namespace=None):
    """Own unknown arguments in the Wiretap subtree; leave the host's other command parsers untouched."""
    before = WiretapParser._active_argv
    if before is None:
        WiretapParser._active_argv = list(sys.argv[1:] if args is None else args)
    try:
        parsed, unknown = argparse.ArgumentParser.parse_known_args(parser, args, namespace)
        if unknown:
            parser.error("unrecognized arguments: " + " ".join(unknown))
        return parsed, unknown
    finally:
        WiretapParser._active_argv = before


def _opt(p, *flags, **kw):
    name = kw.pop("name", None) or flags[-1].lstrip("-").replace("-", "_")
    p.add_argument(*flags, dest="wt_" + name, **kw)


def _common(p, root: bool):
    d = {} if root else {"default": argparse.SUPPRESS}
    _opt(p, "--json", action="store_true", help="one stable JSON document", **d)
    _opt(p, "--jsonl", action="store_true", help="one JSON object per result (list/search commands)", **d)
    _opt(p, "--telemetry-db", metavar="PATH", help="telemetry store (default: TELEMETRY_DB, else the profile's)", **d)
    _opt(p, "--state-db", metavar="PATH", help="Hermes state.db (default: WIRETAP_STATE_DB, else the profile's)", **d)
    _opt(p, "--home", metavar="HERMES_HOME", help="a Hermes home whose stores to read", **d)
    _opt(p, "--fields", metavar="PATHS", help="JSON only: comma-separated result fields (dot paths; list commands project each row)", **d)


def build_parser(p: argparse.ArgumentParser | None = None) -> argparse.ArgumentParser:
    """The ``wiretap`` argument tree, on ``p`` (``hermes wiretap``'s subparser) or a new parser."""
    from types import MethodType
    if p is None:
        p = WiretapParser(prog="wiretap", description=(__doc__ or "").split("\n\n")[1],
                          formatter_class=argparse.RawDescriptionHelpFormatter)
    else:
        # Scope overrides to the provided Wiretap subparser, never the host's shared root parser.
        p.error = MethodType(WiretapParser.error, p)
    p.parse_known_args = MethodType(_parse_wiretap_known_args, p)
    _common(p, True)
    sub = p.add_subparsers(dest="wt_cmd", metavar="COMMAND", parser_class=WiretapParser)
    sub.required = True

    def leaf(parent, name, help_):
        q = parent.add_parser(name, help=help_, description=help_)
        _common(q, False)
        return q

    leaf(sub, "status", "store paths, sizes, schema flavour, capture freshness, signals coverage")

    ss = sub.add_parser("sessions", help="list sessions").add_subparsers(dest="wt_sub", metavar="ACTION")
    ss.required = True
    q = leaf(ss, "list", "recent sessions, newest first (main session first when unfiltered)")
    _opt(q, "--source", help="exact session source (discord, cli, subagent, cron …)")
    _opt(q, "--model", help="model substring")
    _opt(q, "--since", help="active since: 6h, 30m, 2d, or an ISO date-time")
    _opt(q, "-q", "--query", help="substring of id / title / source")
    _opt(q, "--limit", type=int, default=30)

    s1 = sub.add_parser("session", help="one session").add_subparsers(dest="wt_sub", metavar="ACTION")
    s1.required = True
    q = leaf(s1, "show", "session header and row counts; --transcript rows; --compiled the latest request aligned to rows")
    q.add_argument("wt_session_id", metavar="SESSION_ID")
    g = q.add_mutually_exclusive_group()
    _opt(g, "--transcript", action="store_true", help="classified state.db rows (provenance, flags, wire call)")
    _opt(g, "--compiled", action="store_true", help="the newest request's items, each aligned to its row(s)")
    _opt(q, "--layer", choices=("wire", "hermes"), default="wire", help="compiled: post-adapter wire or Hermes's copy")
    _opt(q, "--lane", choices=("main", "review", "all"), default="main", help="compiled execution lane (default: main; excludes background reviews)")
    _opt(q, "--limit", type=positive_int, default=12, help="compiled items per page (12); transcript rows (newest)")
    _opt(q, "--items", "--cursor", name="items", type=item_range, metavar="START:END", help="compiled item slice/cursor (end exclusive; negative bounds supported)")
    _opt(q, "--full", action="store_true", help="compiled: all item previews and reasoning summaries")
    _opt(q, "--before", type=int, help="transcript rows with id below this")
    _opt(q, "--inactive", action="store_true", help="include compacted-away (archived) rows")

    def call_filters(q, since_default=None):
        _opt(q, "--session", help="session id")
        _opt(q, "--family", help="model family (claude, gemini, openai …; '!a,b' = none of them)")
        _opt(q, "--model", help="model substring")
        _opt(q, "--provider", help="exact Hermes provider (anthropic, openai-codex …)")
        _opt(q, "--upstream", help="exact upstream provider (proxy→provider)")
        _opt(q, "--credential", help="exact non-secret credential label or stored key fingerprint (not the API secret)")
        _opt(q, "--project", help="exact stored project")
        _opt(q, "--status", type=int, help="exact HTTP status (e.g. 200, 429)")
        _opt(q, "--since", default=since_default, help="6h, 30m, 2d, or an ISO date-time")

    cs = sub.add_parser("calls", help="list calls").add_subparsers(dest="wt_sub", metavar="ACTION")
    cs.required = True
    q = leaf(cs, "list", "calls newest first, with signals (fallbacks / refusals / model switches) and miss verdicts")
    call_filters(q)
    _opt(q, "--errors", action="store_true", help="failed calls or calls with failed attempts")
    _opt(q, "--misses", action="store_true", help="prefix-cache misses (>20k prompt, <50%% cached)")
    _opt(q, "--refusals", action="store_true",
         help="refusals: provider fallback on refusal, refusal stop / content, safety blocks, policy errors, "
              "plus HEURISTIC refusal wording (labelled)")
    _opt(q, "--limit", type=positive_int, default=50)
    _opt(q, "--cursor", help="opaque next_cursor from a previous page; repeat the same filters")

    c1 = sub.add_parser("call", help="one call").add_subparsers(dest="wt_sub", metavar="ACTION")
    c1.required = True
    q = leaf(c1, "show", "one call: row, signals, request layers, response, exact thinking, raw stream, diffs")
    q.add_argument("wt_call_id", metavar="CALL_ID", help="full id, or a unique substring of one")
    _opt(q, "--request", action="store_true",
         help="hermes_request_json (pre-adapter), wire_request_json (post-adapter), upstream_request_json (proxy→provider)")
    _opt(q, "--response", action="store_true", help="the parsed response (text, tool calls, finish, usage)")
    _opt(q, "--thinking", action="store_true", help="exact thinking blocks from the raw stream, signature presence")
    _opt(q, "--wire", action="store_true", help="raw response stream and the (redacted) HTTP headers")
    _opt(q, "--diff", action="store_true", help="miss forensics + pre- vs post-adapter + wire vs upstream + signals")
    _opt(q, "--all", action="store_true", help="every part")
    _opt(q, "--full", action="store_true", help="with --request: complete request bodies instead of summaries (unbounded)")
    _opt(q, "--limit", type=positive_int, default=4, help="request item previews per layer (head/tail; default 4)")
    _opt(q, "--items", type=item_range, metavar="START:END", help="request preview slice per layer (end exclusive; overrides preview limit)")
    _opt(q, "--item", type=int, help="with --request: also dump item N of each layer (negative counts from the end)")

    q = leaf(sub, "search", "substring search over stored requests, responses and thinking")
    q.add_argument("wt_text", metavar="QUERY")
    _opt(q, "--session", help="session id")
    _opt(q, "--since", help="6h, 30m, 2d, or an ISO date-time")
    _opt(q, "--request", action="store_true", help="request items and envelope keys (every layer)")
    _opt(q, "--response", action="store_true", help="response text and tool calls")
    _opt(q, "--thinking", action="store_true", help="stored thinking")
    _opt(q, "--all", action="store_true", help="all scopes (the default)")
    _opt(q, "--limit", type=positive_int, default=50)
    _opt(q, "--cursor", help="opaque next_cursor from a previous page; repeat the same filters")

    q = leaf(sub, "costs", "billed cost and API-list equivalent with the token split, grouped")
    call_filters(q)
    _opt(q, "--by", "--group-by", name="by", choices=("family", "model", "provider", "credential", "billing", "session", "upstream"), default="family")
    return p


def _command_of(args) -> str:
    c = args.wt_cmd
    return f"{c} {args.wt_sub}" if getattr(args, "wt_sub", None) else c


def _project(value, fields):
    """Projection is explicit and fail-closed: a misspelled field never silently returns an empty document."""
    result = {}
    for field in fields.split(","):
        field = field.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", field):
            raise CliError(f"invalid --fields path {field!r}")
        keys = field.split(".")
        src = value
        for key in keys:
            if not isinstance(src, dict) or key not in src:
                raise CliError(f"unknown --fields path {field!r}")
            src = src[key]
        dst = result
        for key in keys[:-1]:
            if key not in dst:
                dst[key] = {}
            if not isinstance(dst[key], dict):
                raise CliError("--fields paths overlap; select the parent field only")
            dst = dst[key]
        dst[keys[-1]] = src
    return result


def _validate_args(a, json_mode):
    fields = getattr(a, "wt_fields", None)
    if fields is not None:
        if not json_mode:
            raise CliError("--fields requires --json or --jsonl")
        for field in fields.split(","):
            if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", field.strip()):
                raise CliError(f"invalid --fields path {field.strip()!r}")
    if getattr(a, "wt_json", False) and getattr(a, "wt_jsonl", False):
        raise CliError("choose --json or --jsonl, not both")
    if getattr(a, "wt_full", False) and getattr(a, "wt_items", None) is not None:
        raise CliError("choose --full or --items, not both")
    if a.wt_cmd == "session" and not a.wt_compiled and (a.wt_full or a.wt_items is not None):
        raise CliError("--full / --items require --compiled")
    if a.wt_cmd == "call" and not (a.wt_request or a.wt_all) and (
            a.wt_full or a.wt_items is not None or a.wt_item is not None):
        raise CliError("--full / --items / --item require --request")


def run(args, out=None) -> int:
    """Execute parsed args; returns the exit code (0 ok, 1 query error). Argument errors exit 2."""
    out = out or sys.stdout
    name = _command_of(args)
    fn, fmt, listy = COMMANDS[name]
    as_json, as_jsonl = bool(getattr(args, "wt_json", False)), bool(getattr(args, "wt_jsonl", False))
    ctx = None
    try:
        _validate_args(args, as_json or as_jsonl)
        ctx = Ctx(args)
        data: Any = scrub(fn(ctx, args))
        page = {k: v for k, v in data.items() if k != "results"} if name in ("calls list", "search") else None
        fields = getattr(args, "wt_fields", None)
        if fields:
            if name in ("calls list", "search"):
                data["results"] = [_project(r, fields) for r in data["results"]]
            elif listy is True:
                data = [_project(r, fields) for r in data]
            else:
                data = _project(data, fields)
    except (CliError, ValueError, sqlite3.Error) as e:
        msg = ("store read failed: " if isinstance(e, sqlite3.Error) else "") + str(e)
        if as_json or as_jsonl:
            out.write(json.dumps({"wiretap": SCHEMA_V, "command": name, "error": scrub_text(msg)}, ensure_ascii=False) + "\n")
        else:
            sys.stderr.write(f"wiretap {name}: {scrub_text(msg)}\n")
        return 1
    finally:
        if ctx is not None:
            ctx.close()
    if as_jsonl and listy:
        items = data if listy is True else data.get(listy) or []
        for it in items:
            out.write(json.dumps(it, ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
        # Keep stdout exclusively data rows: every stderr line is independently parseable JSON too.
        if page is not None:
            sys.stderr.write(json.dumps({"wiretap": SCHEMA_V, "command": name, "page": page},
                                        ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
        return 0
    if as_json or as_jsonl:
        doc = {"wiretap": SCHEMA_V, "command": name}
        if name == "calls list":
            doc["results"], doc["page"] = data["results"], page
        elif listy is True:
            doc["results"] = data
        else:
            doc["result"] = data
        out.write(json.dumps(doc, ensure_ascii=False, default=str, separators=(",", ":")) + "\n")
        return 0
    for line in fmt(data):
        out.write(line + "\n")
    return 0


def main(argv=None) -> int:
    before = WiretapParser._active_argv
    WiretapParser._active_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = build_parser().parse_args(argv)
    finally:
        WiretapParser._active_argv = before
    try:
        return run(args)
    except BrokenPipeError:  # `wiretap … | head`
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
