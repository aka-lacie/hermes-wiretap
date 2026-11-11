#!/usr/bin/env python3
"""Wiretap's provider-neutral dashboard and CLI read APIs.

CLIProxyAPI parsing, log discovery and enrichment live in extensions/cliproxy.py.
Legacy ingestion attributes are lazy adapters: ordinary imports and read queries
never import that optional extension or start its poller.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import math
import os
import re
import sqlite3
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from pathlib import Path


def _sibling(name: str):
    """Load a sibling under a private name without mutating sys.path."""
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
    try:
        mod._mt_loaded_mtime = Path(mod.__file__).stat().st_mtime
    except Exception:
        pass
    return mod


store = _sibling("store")
inspector = _sibling("inspector")
HERMES_HOME = store.hermes_home()
STATE_DB = store.state_db()
DB_PATH = store.db_path()
MAIN_SESSION_ENV = os.environ.get("MAIN_SESSION", "").strip()
_main_cache = {"at": 0.0, "id": None}
GATEWAY_HYGIENE_PCT = 0.85
_PROXY = None
_PROXY_LOCK = threading.Lock()
_PROXY_API = frozenset({
    "LOG_DIR", "MATCH_WINDOW_S", "TAG_PENDING", "MATCH_SCAN_MAX", "TAG_WAIT_S", "FULL_SCAN_S", "DIR_RECHECK_S",
    "PROXY_FIELDS", "parse_ts", "dur_s", "parse_request_log", "body_items", "store_body", "explain_miss",
    "match_hermes_call", "merge_into_hermes", "scan_request_logs", "tail_main_log", "ingest_once", "backfill_step",
    "poll_once", "ingest_loop", "_SCAN", "_POLL", "_BACKFILL", "_sizes_agree", "_same_request", "_same_model",
    "_last_call_id", "_ref_last_call_id", "_usage_objs", "_head",
})


def proxy_available() -> bool:
    return (Path(__file__).resolve().parent.parent / "extensions" / "cliproxy.py").is_file()


def _proxy_extension():
    global _PROXY
    if not proxy_available():
        return None
    with _PROXY_LOCK:
        if _PROXY is None:
            # One instance per telemetry reader; avoid duplicate imports from
            # concurrent dashboard requests without changing sys.path.
            key = f"{__name__}_cliproxy"
            spec = importlib.util.spec_from_file_location(key, Path(__file__).resolve().parent.parent / "extensions" / "cliproxy.py")
            if spec is None or spec.loader is None:
                raise ImportError("wiretap: cannot load optional CLIProxyAPI extension")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[key] = mod
            try:
                spec.loader.exec_module(mod)
            except BaseException:
                sys.modules.pop(key, None)
                raise
            mod.DB_PATH = DB_PATH
            _PROXY = mod
    return _PROXY


def __getattr__(name):
    if name in _PROXY_API:
        extension = _proxy_extension()
        if extension is not None:
            return getattr(extension, name)
    raise AttributeError(name)


def main_session(state_db: Path | None = None) -> str | None:
    """Explicit override, otherwise the most recent canonical Bot Chat (never an arbitrary root)."""
    if MAIN_SESSION_ENV:
        return MAIN_SESSION_ENV
    if state_db is not None:
        return _main_from(Path(state_db))
    if _main_cache["id"] and time.time() - _main_cache["at"] < 60:
        return _main_cache["id"]
    sid = _main_from(STATE_DB)
    _main_cache.update(at=time.time(), id=sid)
    return sid


def _main_from(path: Path) -> str | None:
    sid = None
    try:
        con = store.connect_ro(path, timeout=5)
        cols = {r[1] for r in con.execute("PRAGMA table_info(sessions)")}
        t = "last_activity_at" if "last_activity_at" in cols else "started_at"
        if "title" not in cols:
            con.close()
            return None
        lin = inspector.main_session_filter(cols)
        child = " AND COALESCE(created_source,'') != 'subagent'" if "created_source" in cols else ""
        parent = " AND COALESCE(parent_session_id,'') = ''" if "parent_session_id" in cols else ""
        r = con.execute(f"SELECT id FROM sessions WHERE title='Bot Chat' "
                        f"AND COALESCE(source,'') NOT IN ('subagent','cron','webhook',''){child}{parent}{lin} "
                        f"ORDER BY COALESCE({t}, started_at) DESC LIMIT 1").fetchone()
        con.close()
        sid = r[0] if r else None
    except Exception:
        pass
    return sid


def db() -> sqlite3.Connection:
    return store.connect(DB_PATH)


@contextmanager
def _con(*, readonly: bool = False):
    # Dashboard reads must not even change a legacy store's journal mode or
    # permissions. Keep the writable connection for explicit initialization.
    con = store.connect_ro(DB_PATH) if readonly else db()
    try:
        with con:
            yield con
    finally:
        con.close()


def init_db():
    with _con() as con:
        store.init(con)
        inspector.recompute_misses(con)
    store.secure_files(DB_PATH)


def upsert(con, row: dict):
    store.upsert(con, row, "calls")


def _empty_calls() -> dict:
    return {"rows": [], "agg": [], "keys": [], "fail_keys": [], "last_scan": {}, "last_capture": {}, "oldest": None,
            "families": [], "providers": [], "now": time.time(), "no_data": True}


_CALLS_MEMO: dict = {}


def api_calls(q: dict) -> dict:
    """Dashboard calls; revisions short-circuit unchanged queries, then memoize identical queries."""
    if not DB_PATH.exists():
        return _empty_calls()
    key = json.dumps({k: v for k, v in sorted(q.items()) if k != "rev"})
    now = time.time()
    try:
        hours = float(q.get("hours", ["6"])[0])
    except ValueError:
        hours = 6.0
    try:
        with _con(readonly=True) as con:
            base = store.calls_rev(con)
            ev = con.execute("SELECT MAX(rowid) FROM events").fetchone()[0]
            oldest = con.execute("SELECT MIN(started) FROM calls WHERE started >= ?", (now - hours * 3600,)).fetchone()[0]
            fresh = {"last_scan": store.kv_get(con, "last_scan", {}) or {},
                     "last_capture": store.kv_get(con, "last_capture", {}) or {}}
    except Exception:
        base, ev, oldest, fresh = "", None, None, {}
    rev = ""
    if base:
        qh = hashlib.blake2b(key.encode(), digest_size=6).hexdigest()
        rev = f"{base}:{ev or 0}:{round(oldest, 3) if oldest else 0}:{qh}"
    if rev and q.get("rev", [""])[0] == rev:
        return {"unchanged": True, "rev": rev, "now": now, **fresh}
    hit = _CALLS_MEMO.get(key)
    if rev and hit and hit[0] == rev:
        return dict(hit[1], now=now, **fresh)
    out = _api_calls(q)
    out["rev"] = rev
    if rev:
        if len(_CALLS_MEMO) > 16:
            _CALLS_MEMO.clear()
        _CALLS_MEMO[key] = (rev, out)
    return out


SORTABLE = {"started", "lane", "model", "auth_key", "attempts", "n429", "retry_s", "ttfb_s", "gen_s", "total_s",
            "prompt_tokens", "cached_tokens", "hit_pct", "cache_write_tokens", "output_tokens", "thinking_tokens",
            "cost_usd", "cost_equiv_usd", "diverge", "errors"}
# Call outcome as a sort key, the same classification the dashboard's error chips use: failed (no 2xx final status,
# status 0 = transport / invalid response) > recovered (2xx after recorded failures) > succeeded; no numeric status
# (in flight, interrupted, uncaptured, or an SDK's string code) is unknown and sorts last either way.
ERROR_RANK = ("(CASE WHEN status IS NULL OR typeof(status) NOT IN ('integer', 'real') THEN NULL "
              "WHEN status >= 200 AND status < 300 THEN (CASE WHEN COALESCE(nfail, 0) > 0 THEN 1 ELSE 0 END) ELSE 2 END)")


def _decorate(con, rows: list[dict]) -> None:
    """Stored events, cache-affinity verdict and lane for just the returned page."""
    rids = [r.get("proxy_rid") or r["id"] for r in rows if r.get("proxy_rid") or r["source"] in ("cliproxy", "proxy")]
    ev: dict[str, list] = {}
    for i in range(0, len(rids), 500):
        chunk = rids[i:i + 500]
        for e in con.execute(f"SELECT rid,ts,kind,detail FROM events WHERE rid IN ({','.join('?' * len(chunk))}) ORDER BY ts", chunk):
            ev.setdefault(e["rid"], []).append({"ts": e["ts"], "kind": e["kind"], "detail": e["detail"]})
    main = main_session()
    for r in rows:
        miss = inspector._loads(r.get("diverge"), None)
        if miss:
            try:
                r["diverge"] = json.dumps(inspector.enrich_miss(con, r["id"], miss), ensure_ascii=False)
            except (sqlite3.Error, KeyError, TypeError, ValueError):
                pass  # expired/legacy evidence keeps its original verdict
        sig = r.pop("signals", None)
        if sig and '"refusal":true' in sig:
            r["refusal"] = True
        r.pop("pricing_version", None)
        r["events"] = ev.get(r.get("proxy_rid") or r["id"], [])
        r["error_summary"] = error_summary(r)
        evk = " ".join(e["kind"] for e in r["events"])
        r["aff"] = ("rebound" if "bound to new auth" in evk else "compaction-hit" if "compaction hit" in evk
                    else "lcp-hit" if "LCP cache hit" in evk else "")
        r["lane"] = inspector.call_lane(con, r["id"], r)
        if main and r.get("session_id") == main and r["lane"] != "review":
            r["lane"] = "main"


def _quant(xs: list, q: float):
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else None


def family_summary(con, where: list, args: list) -> dict:
    """Whole-window family cards and percentiles in a single narrow query."""
    out, lat, ttfb = {}, {}, {}
    semantic = "response_error" if "response_error" in store.columns(con, "calls") else "NULL"
    for f, p, c, o, t, cost, eq, tot, tf, st, n429, retry, hit, nfail, response_error in con.execute(
            f"SELECT COALESCE(family, 'other'), prompt_tokens, cached_tokens, output_tokens, thinking_tokens, cost_usd, "
            f"cost_equiv_usd, total_s, ttfb_s, status, n429, retry_s, hit_pct, nfail, {semantic} FROM calls WHERE {' AND '.join(where)}", args):
        s = out.get(f)
        if s is None:
            s = out[f] = {"n": 0, "p": 0, "c": 0, "o": 0, "t": 0, "cost": 0.0, "eq": 0.0, "miss": 0, "n429": 0, "retry": 0.0,
                          "err": 0, "empty": 0, "failed_calls": 0, "affected_calls": 0,
                          "recovered_calls": 0, "unknown_calls": 0, "recorded_failure_observations": 0}
            lat[f], ttfb[f] = [], []
        s["n"] += 1
        s["p"] += p or 0; s["c"] += c or 0; s["o"] += o or 0; s["t"] += t or 0
        s["cost"] += cost or 0; s["eq"] += eq or 0
        s["n429"] += n429 or 0; s["retry"] += retry or 0
        if (p or 0) > 20000 and (hit or 0) < 50:
            s["miss"] += 1
        failure = error_summary({"status": st, "nfail": nfail, "response_error": response_error})
        s["err"] += int(failure["outcome"] == "failed")
        s["failed_calls"] += int(failure["outcome"] == "failed")
        s["unknown_calls"] += int(failure["outcome"] == "unknown")
        s["affected_calls"] += int(failure["affected"])
        s["recovered_calls"] += int(failure["recovered"])
        s["recorded_failure_observations"] += nfail or 0
        if st == 200 and not p:
            s["empty"] += 1
        if tot is not None:
            lat[f].append(tot)
        if tf is not None:
            ttfb[f].append(tf)
    for f, s in out.items():
        lat[f].sort(); ttfb[f].sort()
        s.update(lat50=_quant(lat[f], .5), lat95=_quant(lat[f], .95), ttfb50=_quant(ttfb[f], .5))
    return out


def _api_calls(q: dict) -> dict:
    hours = float(q.get("hours", ["6"])[0])
    fam = q.get("family", ["all"])[0] or "all"
    sess = q.get("session", [""])[0]
    prov = q.get("provider", [""])[0]
    limit = min(int(q.get("limit", ["100"])[0]), 5000)
    offset = max(0, int(q.get("offset", ["0"])[0] or 0))
    page_only = q.get("page", [""])[0] in ("1", "true")
    sort = q.get("sort", ["started"])[0]
    sort = sort if sort in SORTABLE else "started"
    desc = q.get("dir", ["desc"])[0] != "asc"
    since = time.time() - hours * 3600
    where, args = ["started >= ?"], [since]
    if sess:
        where.append("session_id = ?")
        args.append(sess)
    win_where, win_args = list(where), list(args)
    if prov:
        where.append("COALESCE(provider, '') = ?")
        args.append(prov)
    fam_where, fam_args = list(where), list(args)
    if fam.startswith("!"):
        ex = [f for f in fam[1:].split(",") if f]
        if ex:
            where.append(f"COALESCE(family, 'other') NOT IN ({','.join('?' * len(ex))})")
            args += ex
    elif fam != "all":
        where.append("COALESCE(family, 'other') = ?")
        args.append(fam)
    with _con(readonly=True) as con:
        cols = set(store.columns(con, "calls"))
        xw, xa = call_filters({"model": q.get("model", [""])[0], "errors": q.get("errors", [""])[0] in ("1", "true"),
                               "misses": q.get("misses", [""])[0] in ("1", "true"),
                               "refusals": q.get("refusals", [""])[0] in ("1", "true")}, cols)
        where, args = where + xw, args + xa
        if q.get("slow", [""])[0] in ("1", "true"):
            where.append("COALESCE(total_s, 0) > 30")
        d = 'DESC' if desc else 'ASC'
        if sort == "started":
            order = f"started {d}"
        elif sort == "errors":
            rank = ERROR_RANK
            if "response_error" in cols:
                rank = rank.replace("(CASE WHEN", "(CASE WHEN response_error = 'empty_response' THEN 2 WHEN", 1)
            order = f"{rank} IS NULL, {rank} {d}, COALESCE(nfail, 0) {d}, started DESC"
        else:
            order = f"{sort} IS NULL, {sort} {d}, started DESC"
        rows = [dict(r) for r in con.execute(
            f"SELECT * FROM calls WHERE {' AND '.join(where)} ORDER BY {order} LIMIT ? OFFSET ?", args + [limit + 1, offset])]
        has_more = len(rows) > limit
        rows = rows[:limit]
        if page_only:
            _decorate(con, rows)
            return {"rows": rows, "offset": offset, "has_more": has_more, "now": time.time()}
        total = con.execute(f"SELECT COUNT(*) FROM calls WHERE {' AND '.join(where)}", args).fetchone()[0]
        summary = family_summary(con, where, args)
        families = [{"family": r[0], "label": store.family_label(r[0]), "n": r[1]} for r in con.execute(
            f"SELECT COALESCE(family, 'other') f, COUNT(*) n FROM calls WHERE {' AND '.join(fam_where)} GROUP BY f ORDER BY n DESC, f", fam_args)]
        providers = [{"provider": r[0], "n": r[1]} for r in con.execute(
            f"SELECT provider, COUNT(*) n FROM calls WHERE {' AND '.join(win_where)} AND COALESCE(provider, '') != '' GROUP BY provider ORDER BY n DESC, provider", win_args)]
        _decorate(con, rows)
        agg = [dict(r) for r in con.execute(
            f"SELECT family, model, COUNT(*) n, SUM(prompt_tokens) prompt, SUM(cached_tokens) cached, "
            f"SUM(output_tokens) output, SUM(thinking_tokens) thinking, AVG(total_s) avg_s, MAX(total_s) max_s, "
            f"SUM(n429) n429, SUM(CASE WHEN attempts>1 THEN 1 ELSE 0 END) retried, SUM(retry_s) retry_s, "
            f"SUM(cost_usd) cost, SUM(cost_equiv_usd) cost_equiv, "
            f"SUM(CASE WHEN prompt_tokens>20000 AND hit_pct<50 THEN 1 ELSE 0 END) misses "
            f"FROM calls WHERE {' AND '.join(where)} GROUP BY family, model ORDER BY n DESC", args)]
        # Archived stores may predate optional routing enrichment. Missing
        # fields are unknown, not a reason to discard their real usage/costs.
        key_fields = ("family", "provider", "upstream_provider", "auth_label", "auth_key", "project", "auth_type")
        key_select = store.select_cols(con, "calls", key_fields)
        key_group = ", ".join(c for c in ("family", "provider", "upstream_provider", "auth_key", "project") if c in cols)
        semantic = "COALESCE(response_error = 'empty_response', 0)" if "response_error" in cols else "0"
        keys = [dict(r) for r in con.execute(
            f"SELECT {key_select}, COUNT(*) n, SUM(n429) n429, "
            # HTTP evidence and semantic invalid-response evidence stay distinct.
            f"SUM(CASE WHEN {semantic} OR (typeof(status) = 'integer' AND (status < 200 OR status >= 300)) THEN 1 ELSE 0 END) failed_calls, "
            f"SUM(CASE WHEN NOT ({semantic}) AND typeof(status) = 'integer' AND status >= 200 AND status < 300 AND COALESCE(nfail, 0) > 0 THEN 1 ELSE 0 END) recovered_calls, "
            f"AVG(total_s) avg_s, AVG(hit_pct) avg_hit FROM calls WHERE {' AND '.join(where)} AND auth_key IS NOT NULL "
            f"GROUP BY {key_group} ORDER BY n DESC", args)]
        fail_keys = [dict(r) for r in con.execute(
            # every proxy-logged failed upstream attempt (kind fail:<status>), with its 429 subset
            "SELECT substr(detail, instr(detail,'key=')+4, 4) key, COUNT(*) n, SUM(kind = 'fail:429') n429, MAX(ts) last FROM events "
            "WHERE kind LIKE 'fail:%' AND ts >= ? GROUP BY key", (since,))]
        last = store.kv_get(con, "last_scan", {}) or {}
        cap = store.kv_get(con, "last_capture", {}) or {}
        oldest = con.execute("SELECT MIN(started) FROM calls").fetchone()[0]
    return {"rows": rows, "offset": offset, "has_more": has_more, "total": total, "summary": summary, "agg": agg, "keys": keys,
            "fail_keys": fail_keys, "last_scan": last, "last_capture": cap, "families": families, "providers": providers,
            "family": fam, "provider": prov, "oldest": oldest, "now": time.time()}


REFUSAL_LIKE = '%"refusal":true%'
MISS_SQL = "COALESCE(prompt_tokens, 0) > 20000 AND COALESCE(hit_pct, 0) < 50"
ERROR_SQL = "((typeof(status) = 'integer' AND (status < 200 OR status >= 300)) OR COALESCE(nfail, 0) > 0)"


def error_summary(row: dict) -> dict:
    """Observed call outcome, never a claim about terminal turn/user delivery.

    A missing status is unknown (possibly in flight), not failure. Status 0 is
    the collector's explicit non-HTTP failure sentinel. ``nfail`` counts stored
    observations, not globally deduplicated physical requests across a proxy.
    No response/error text or credential material enters this summary.
    """
    raw_status = row.get("status")
    # SDK error codes are not necessarily HTTP numbers (e.g. insufficient_quota).
    status = raw_status if isinstance(raw_status, int) and not isinstance(raw_status, bool) else None
    semantic_error = row.get("response_error") == "empty_response"
    failed = semantic_error or status is not None and not 200 <= status < 300
    succeeded = not semantic_error and status is not None and 200 <= status < 300
    observations = row.get("nfail")
    had_failures = (observations or 0) > 0
    category = None
    if failed:
        if semantic_error:
            category = "invalid_response"
        elif status == 0:
            category = "transport_or_invalid_response"
        elif status == 401:
            category = "authentication"
        elif status == 403:
            category = "permission"
        elif status == 429:
            category = "rate_limit"
        elif status is not None and status >= 500:
            category = "server"
        else:
            category = "http"
    return {"v": 1, "scope": "call", "outcome": "failed" if failed else "succeeded" if succeeded else "unknown",
            "category": category, "affected": failed or had_failures,
            "recovered": succeeded and had_failures, "recorded_failure_observations": observations}

CALL_FIELDS = ("id", "started", "ended", "session_id", "source", "family", "provider", "upstream_provider", "model",
               "api_mode", "auth_label", "auth_key", "project", "status", "attempts", "n429", "nfail", "retry_s", "prompt_tokens", "cached_tokens",
               "cache_write_tokens", "uncached_tokens", "output_tokens", "thinking_tokens", "hit_pct", "billing",
               "cost_usd", "cost_equiv_usd", "total_s", "ttfb_s", "lane", "platform", "message_count", "proxy_rid", "response_error")


def call_filters(f: dict, cols: set) -> tuple[list, list]:
    """SQL predicates shared by read-only call lists, cost reports and pagination."""
    where, args = [], []
    if f.get("since") is not None:
        where.append("started >= ?")
        args.append(f["since"])
    if f.get("until") is not None:
        where.append("started < ?")
        args.append(f["until"])
    if f.get("session"):
        where.append("session_id = ?")
        args.append(f["session"])
    if f.get("provider"):
        where.append("COALESCE(provider, '') = ?")
        args.append(f["provider"])
    if f.get("credential"):
        fields = [c for c in ("auth_label", "auth_key") if c in cols]
        where.append("(" + " OR ".join(c + " = ?" for c in fields) + ")" if fields else "0 = 1")
        args.extend([f["credential"]] * len(fields))
    for key, column in (("upstream", "upstream_provider"), ("project", "project")):
        if f.get(key):
            where.append(column + " = ?" if column in cols else "0 = 1")
            if column in cols:
                args.append(f[key])
    if f.get("status") is not None:
        status = f["status"]
        if isinstance(status, bool) or not (isinstance(status, int) or isinstance(status, str) and re.fullmatch(r"[+-]?\d+", status)):
            raise ValueError("status must be an integer")
        where.append("status = ?" if "status" in cols else "0 = 1")
        if "status" in cols:
            args.append(int(status))
    fam = f.get("family") or "all"
    if fam.startswith("!"):
        ex = [x for x in fam[1:].split(",") if x]
        if ex:
            where.append(f"COALESCE(family, 'other') NOT IN ({','.join('?' * len(ex))})")
            args += ex
    elif fam != "all":
        where.append("COALESCE(family, 'other') = ?")
        args.append(fam)
    if f.get("model"):
        where.append("COALESCE(model, '') LIKE ?")
        args.append(f"%{f['model']}%")
    if f.get("errors"):
        predicate = ERROR_SQL
        if "response_error" in cols:
            predicate = f"({predicate} OR response_error = 'empty_response')"
        where.append(predicate)
    if f.get("misses"):
        where.append(MISS_SQL)
    if f.get("refusals") and "signals" in cols:
        where.append("signals LIKE ?")
        args.append(REFUSAL_LIKE)
    return where, args


def _call_out(con, r: dict) -> dict:
    d = {k: r.get(k) for k in CALL_FIELDS}
    d["lane"] = inspector.call_lane(con, r["id"], r)
    d["error_summary"] = error_summary(r)
    miss = inspector.enrich_miss(con, r["id"], inspector._loads(r.get("diverge"), None))
    d["miss"] = miss.get("why") if isinstance(miss, dict) else None
    sig = inspector._loads(r.get("signals"), None)
    if isinstance(sig, dict) and sig.get("v"):
        d["signals"], d["signals_source"] = sig, "stored"
    else:
        d["signals"], d["signals_source"] = store.compute_signals(con, r["id"]), "computed"
    return d


def list_calls(con, f: dict, limit: int = 50) -> list[dict]:
    """Newest matching calls, including computed fallback signals for legacy rows."""
    cols = set(store.columns(con, "calls"))
    if not f.get("refusals"):
        where, args = call_filters(f, cols)
        sql = f"SELECT * FROM calls {'WHERE ' + ' AND '.join(where) if where else ''} ORDER BY started DESC LIMIT ?"
        return [_call_out(con, dict(r)) for r in con.execute(sql, args + [limit])]
    base, bargs = call_filters(dict(f, refusals=False), cols)
    if "signals" in cols:
        base = base + ["(signals LIKE ? OR signals IS NULL)"]
        bargs = bargs + [REFUSAL_LIKE]
    sql = f"SELECT * FROM calls {'WHERE ' + ' AND '.join(base) if base else ''} ORDER BY started DESC"
    out = []
    for r in con.execute(sql, bargs):
        d = _call_out(con, dict(r))
        if (d["signals"] or {}).get("refusal"):
            out.append(d)
            if len(out) >= limit:
                break
    return out


def _calls_cursor_encode(r: dict) -> str:
    raw = json.dumps({"started": r["started"], "id": r["id"]}, separators=(",", ":"), allow_nan=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")


def _calls_cursor_decode(cursor: str) -> dict:
    """Decode an opaque URL-safe JSON position, never SQL or an offset."""
    try:
        if not isinstance(cursor, str) or not cursor or len(cursor) > 16384 or not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", cursor):
            raise ValueError
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
        pos = json.loads(raw.decode("utf-8"))
        if not isinstance(pos, dict) or set(pos) != {"started", "id"}:
            raise ValueError
        started = pos["started"]
        if started is not None and (isinstance(started, bool) or not isinstance(started, (int, float)) or not math.isfinite(started)):
            raise ValueError
        if not isinstance(pos["id"], str) or not pos["id"]:
            raise ValueError
        return pos
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError, binascii.Error) as exc:
        raise ValueError("invalid calls cursor: expected an opaque position with numeric/null started and nonempty id") from exc


def list_calls_page(con, f: dict, limit: int = 50, cursor: str | None = None) -> dict:
    """Newest-first keyset page; total covers all matches, not only remaining rows."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("calls page limit must be a positive integer")
    pos = _calls_cursor_decode(cursor) if cursor is not None else None
    cols = set(store.columns(con, "calls"))
    refusal = bool(f.get("refusals"))
    where, args = call_filters(dict(f, refusals=False) if refusal else f, cols)
    if refusal and "signals" in cols:
        where.append("(signals LIKE ? OR signals IS NULL)")
        args.append(REFUSAL_LIKE)
    w = " WHERE " + " AND ".join(where) if where else ""
    after, aargs = [], []
    if pos is not None:
        if pos["started"] is None:
            after, aargs = ["(started IS NULL AND id < ?)"], [pos["id"]]
        else:
            after = ["(started < ? OR (started = ? AND id < ?) OR started IS NULL)"]
            aargs = [pos["started"], pos["started"], pos["id"]]
    page_where = where + after
    pw = " WHERE " + " AND ".join(page_where) if page_where else ""
    order = " ORDER BY started DESC, id DESC"
    if not refusal:
        total = con.execute("SELECT COUNT(*) FROM calls" + w, args).fetchone()[0]
        rows = [dict(r) for r in con.execute("SELECT * FROM calls" + pw + order + " LIMIT ?", args + aargs + [limit + 1])]
        has_more = len(rows) > limit
        rows = rows[:limit]
        results = [_call_out(con, r) for r in rows]
    else:
        membership = after[0] if after else "1"
        query = "SELECT *, " + membership + " AS _after_cursor FROM calls" + w + order
        total, rows, results = 0, [], []
        for raw in con.execute(query, aargs + args):
            r = dict(raw)
            d = _call_out(con, r)
            if not (d["signals"] or {}).get("refusal"):
                continue
            total += 1
            if r["_after_cursor"] and len(rows) <= limit:
                rows.append(r)
                results.append(d)
        has_more = len(rows) > limit
        rows, results = rows[:limit], results[:limit]
    return {"results": results, "total": total, "has_more": has_more,
            "next_cursor": _calls_cursor_encode(rows[-1]) if has_more else None}


COST_GROUPS = ("family", "model", "provider", "billing", "session_id", "upstream_provider", "credential")


def costs(con, f: dict, by: str = "family") -> dict:
    """Billed and API-list-equivalent cost, with the actual token split."""
    by = by if by in COST_GROUPS else "family"
    cols = set(store.columns(con, "calls"))
    if by != "credential" and by not in cols:
        by = "family"
    if by == "credential":
        label = "COALESCE(auth_label, '')" if "auth_label" in cols else "''"
        key = "COALESCE(auth_key, '')" if "auth_key" in cols else "''"
        select = f"COALESCE(NULLIF({label}, ''), {key}) AS key, {label} AS auth_label, {key} AS auth_key"
        group = f"{label}, {key}" if {"auth_label", "auth_key"} & cols else "key"
    else:
        select, group = f"COALESCE({by}, '') AS key", "key"
    where, args = call_filters(f, cols)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    agg = ("COUNT(*) calls, SUM(prompt_tokens) prompt_tokens, SUM(cached_tokens) cached_tokens, "
           "SUM(cache_write_tokens) cache_write_tokens, SUM(output_tokens) output_tokens, "
           "SUM(thinking_tokens) thinking_tokens, ROUND(SUM(cost_usd), 6) cost_usd, "
           "ROUND(SUM(cost_equiv_usd), 6) cost_equiv_usd, SUM(CASE WHEN cost_usd IS NULL THEN 1 ELSE 0 END) unpriced")
    rows = [dict(r) for r in con.execute(
        f"SELECT {select}, {agg} FROM calls {w} GROUP BY {group} ORDER BY cost_equiv_usd DESC, calls DESC", args)]
    total = dict(con.execute(f"SELECT {agg} FROM calls {w}", args).fetchone())
    for r in rows + [total]:
        p = r.get("prompt_tokens") or 0
        r["hit_pct"] = round(100.0 * (r.get("cached_tokens") or 0) / p, 1) if p else None
    return {"by": by, "rows": rows, "total": total}


def _compression_settings() -> dict:
    comp = store.hermes_config().get("compression") or {}
    return comp if isinstance(comp, dict) else {}


def context_gauge(main: str | None, source: str | None, anchor_prompt: int | None, message_count: int | None) -> dict | None:
    """Compatibility wrapper; the computation is session-local and shared with Inspector."""
    if not main or not DB_PATH.exists():
        return None
    with _con(readonly=True) as con:
        return inspector.context_gauge(con, main, source, anchor_prompt, message_count, _compression_settings())


def api_sessions(q: dict) -> dict:
    hours = float(q.get("hours", ["24"])[0])
    since, out, main_row, MAIN = time.time() - hours * 3600, [], None, main_session()
    try:
        con = store.connect_ro(STATE_DB, timeout=5)
        con.row_factory = sqlite3.Row
        cols = {r[1] for r in con.execute("PRAGMA table_info(sessions)")}
        t_col = "last_activity_at" if "last_activity_at" in cols else ("updated_at" if "updated_at" in cols else "started_at")
        want = ("id", "source", "model", "billing_provider", "title", "api_call_count", "input_tokens", "output_tokens",
                "cache_read_tokens", "cache_write_tokens", "reasoning_tokens", "estimated_cost_usd", "started_at")
        sel = ", ".join(c if c in cols else f"NULL AS {c}" for c in want)
        has_messages = con.execute("SELECT 1 FROM sqlite_master WHERE name='messages'").fetchone() is not None
        sql = (f"SELECT {sel}, {t_col} AS t FROM sessions "
               f"WHERE (COALESCE({t_col}, started_at) >= ? OR id = ?) AND {inspector.session_has_activity(cols, has_messages)} "
               f"ORDER BY COALESCE({t_col}, started_at) DESC LIMIT 300")
        for r in con.execute(sql, (since, MAIN)):
            d = dict(r)
            p = (d["input_tokens"] or 0) + (d["cache_read_tokens"] or 0) + (d["cache_write_tokens"] or 0)
            d["hit_pct"] = round(100.0 * (d["cache_read_tokens"] or 0) / p, 1) if p else None
            out.append(d)
        msel = ", ".join(c if c in cols else f"NULL AS {c}" for c in ("model_config", "message_count", "source"))
        main_row = con.execute(f"SELECT {msel} FROM sessions WHERE id=?", (MAIN,)).fetchone()
        con.close()
    except Exception as e:
        return {"error": repr(e), "sessions": out, "main": {"id": MAIN}}
    anchor = {}
    try:
        anchor = (json.loads(main_row["model_config"] or "{}").get("_usage_anchor") or {}) if main_row else {}
    except Exception:
        pass
    main = {"id": MAIN}
    try:
        g = context_gauge(MAIN, main_row["source"] if main_row else None, anchor.get("prompt_tokens"), main_row["message_count"] if main_row else None)
        if g:
            main.update(g)
    except Exception:
        traceback.print_exc()
    return {"sessions": out, "main": main}


def main():
    """Legacy explicit collector entrypoint; the default plugin needs no collector."""
    extension = _proxy_extension()
    if extension is not None:
        extension.main()


if __name__ == "__main__":
    main()
