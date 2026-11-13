"""Shared store for wiretap: profile paths, the SQLite schema, content-addressed blobs and pricing.

Imported (under private module names) by the processes that write or read the same
``$HERMES_HOME/plugin-data/wiretap/telemetry.db``:

* the agent hook (``collector/capture.py``, inside Hermes) — the only writer in this package;
* the dashboard API (``dashboard/plugin_api.py``) and the CLI (``collector/cli.py``) — readers.

Stdlib only. SQLite runs in WAL mode so the writers and the reader never block each other for long.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import sys
import threading
import time
import zlib
from collections import OrderedDict
from pathlib import Path

PLUGIN = "wiretap"


# ───────────────────────── paths ─────────────────────────
def hermes_home() -> Path:
    """The active profile's HERMES_HOME (``hermes_constants`` when importable, else the env var)."""
    try:
        from hermes_constants import get_hermes_home  # type: ignore

        return Path(get_hermes_home())
    except Exception:
        env = os.environ.get("HERMES_HOME")
        return Path(env) if env else Path.home() / ".hermes"


def data_dir(home: Path | None = None) -> Path:
    """Prefer Wiretap, retaining an existing legacy store without copying private data."""
    root = Path(home) if home is not None else hermes_home()
    current = root / "plugin-data" / PLUGIN
    legacy = root / "plugin-data" / "model-telemetry"
    if not (current / "telemetry.db").exists() and (legacy / "telemetry.db").exists():
        return legacy
    return current


def db_path() -> Path:
    env = os.environ.get("TELEMETRY_DB")
    return Path(env) if env else data_dir() / "telemetry.db"


def state_db() -> Path:
    """The Hermes session store; ``WIRETAP_STATE_DB`` points Wiretap at another one (a demo or a copied file)."""
    env = os.environ.get("WIRETAP_STATE_DB")
    return Path(env) if env else hermes_home() / "state.db"


def hermes_config() -> dict:
    """The merged Hermes config (read-only), or ``{}`` outside a Hermes runtime."""
    try:
        from hermes_cli.config import load_config_readonly  # type: ignore

        cfg = load_config_readonly()
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        pass
    try:
        from hermes_cli.config import load_config  # type: ignore  (older runtimes)

        cfg = load_config()
        return cfg if isinstance(cfg, dict) else {}
    except Exception:
        return {}


def plugin_setting(key: str, default=None):
    """New-slug settings win per key; missing keys inherit the legacy installation.

    Both modern ``settings`` and older ``config`` entry formats are accepted.
    Explicit false/zero values are settings, not missing values.
    """
    try:
        entries = (hermes_config().get("plugins") or {}).get("entries") or {}
        for slug in (PLUGIN, "model-telemetry"):
            entry = entries.get(slug) or {}
            for sub in ("settings", "config"):
                val = (entry.get(sub) or {}).get(key)
                if val is not None:
                    return val
    except Exception:
        pass
    return default


# ───────────────────────── schema ─────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS calls (
  id TEXT PRIMARY KEY, source TEXT, file TEXT, started REAL, ended REAL, total_s REAL,
  ttfb_s REAL, gen_s REAL, url TEXT, family TEXT, provider TEXT, model TEXT, auth_label TEXT,
  auth_key TEXT, auth_type TEXT, project TEXT, attempts INTEGER, n429 INTEGER, nfail INTEGER,
  retry_s REAL, attempt_detail TEXT, status INTEGER, prompt_tokens INTEGER, cached_tokens INTEGER,
  cache_write_tokens INTEGER, uncached_tokens INTEGER, output_tokens INTEGER, thinking_tokens INTEGER,
  hit_pct REAL, billing TEXT, cost_usd REAL, cost_equiv_usd REAL, pricing_version TEXT, client TEXT,
  session_id TEXT, platform TEXT, lane TEXT, context_length INTEGER, message_count INTEGER,
  diverge TEXT, proxy_rid TEXT, api_mode TEXT
);
CREATE INDEX IF NOT EXISTS calls_started ON calls(started);
CREATE TABLE IF NOT EXISTS bodies (id TEXT PRIMARY KEY, started REAL, family TEXT, model TEXT, hashes TEXT, heads TEXT);
CREATE INDEX IF NOT EXISTS bodies_started ON bodies(started);
CREATE TABLE IF NOT EXISTS events (rid TEXT, ts REAL, level TEXT, kind TEXT, detail TEXT);
CREATE INDEX IF NOT EXISTS events_rid ON events(rid);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS seen_files (name TEXT PRIMARY KEY, size INTEGER, ingested REAL);
CREATE TABLE IF NOT EXISTS wire_blobs (h TEXT PRIMARY KEY, z BLOB, n INTEGER);
CREATE TABLE IF NOT EXISTS wire_calls (
  id TEXT PRIMARY KEY, file TEXT, started REAL, ended REAL, family TEXT, model TEXT, url TEXT, status INTEGER,
  req_down TEXT, req_up TEXT, hdr_down TEXT, hdr_up TEXT, resp_raw TEXT, resp TEXT, tc_ids TEXT, text_head TEXT,
  n_items INTEGER, req_bytes INTEGER, captured REAL, session_id TEXT, source TEXT, exact INTEGER);
CREATE INDEX IF NOT EXISTS wire_calls_ended ON wire_calls(ended);
"""
# Columns added after the first release; ALTERed onto stores created by older versions.
MIGRATIONS = (
    ("calls", "host_state", "TEXT"),  # payload-independent completion and host-local counters
    ("calls", "proxy_attempts", "TEXT"),  # source-specific observations; never overwrite host retry evidence
    ("calls", "response_error", "TEXT"),  # semantic failure independent of the observed HTTP status
    ("wire_calls", "proxy_attempts", "TEXT"),  # every retained proxy request/response, keyed by file + attempt
    ("calls", "execution_origin", "TEXT"),  # execution fork provenance, independent of session/cache identity
    ("calls", "proxy_family", "TEXT"),
    ("wire_calls", "rev", "INTEGER"),
    ("calls", "upstream_provider", "TEXT"),
    ("calls", "proxy_rid", "TEXT"),
    ("calls", "api_mode", "TEXT"),
    ("wire_calls", "session_id", "TEXT"),
    ("wire_calls", "source", "TEXT"),
    ("wire_calls", "exact", "INTEGER"),
    # 1: this call's tools are the list Hermes handed its provider client (not its size-capped hook copy).
    ("wire_calls", "tools_exact", "INTEGER"),
    # Hermes's own request (adapter input) once the proxy's post-adapter body became req_down.
    ("wire_calls", "req_hermes", "TEXT"),
    # Response signals (collector/signals.py): fallbacks, refusals, safety blocks, notices, model switches.
    ("calls", "signals", "TEXT"),
)
POST_MIGRATION = """
CREATE INDEX IF NOT EXISTS wire_calls_session ON wire_calls(session_id, started);
CREATE INDEX IF NOT EXISTS calls_session ON calls(session_id, started);
CREATE INDEX IF NOT EXISTS calls_proxy ON calls(proxy_rid);
CREATE INDEX IF NOT EXISTS wire_calls_rev ON wire_calls(rev);
"""

# ── capture revisions: DB-assigned generations ──
# ``wire_calls.rev`` is not a timestamp. Every committed INSERT and UPDATE of a capture row (upsert, direct UPDATE,
# INSERT OR REPLACE, delete + reinsert, any column) gets the next value of one persistent sequence, assigned by a
# trigger inside the writing transaction — i.e. under SQLite's writer lock, so generations are strictly increasing in
# commit order across every connection and process, whatever ``rev`` the writer proposed and whatever its clock said.
# A committed generation is therefore never reused, which is what GC's lock-time recheck (equality with the value seen
# at the mark) and ``session_wire_rev``'s MAX(rev) cache key rely on.
#
# ``wire_rev_seq`` holds one row (k=0): ``n`` the last generation issued, ``rid`` the rowid it was issued to. The
# update trigger's WHEN clause skips only its own stamping UPDATE (that row, the current generation, rev just changed
# to it), so it terminates even with ``PRAGMA recursive_triggers=ON``; any other write — including one that sets rev
# explicitly, stale or not — is restamped. The first statement re-seeds from the surviving maximum only if the
# sequence row was removed by hand (install always creates it); it is conflict-free on purpose — inside a trigger the
# firing statement's conflict policy (an UPSERT's, an INSERT OR REPLACE's) overrides the body's own OR IGNORE.
REV_SEQ_SQL = "CREATE TABLE IF NOT EXISTS wire_rev_seq (k INTEGER PRIMARY KEY CHECK (k = 0), n INTEGER NOT NULL, rid INTEGER)"
_REV_STAMP = (
    "INSERT INTO wire_rev_seq (k, n) SELECT 0, (SELECT COALESCE(MAX(rev), 0) FROM wire_calls) "
    "WHERE NOT EXISTS (SELECT 1 FROM wire_rev_seq WHERE k = 0); "
    "UPDATE wire_rev_seq SET n = n + 1, rid = NEW.rowid WHERE k = 0; "
    "UPDATE wire_calls SET rev = (SELECT n FROM wire_rev_seq WHERE k = 0) WHERE rowid = NEW.rowid;")
REV_TRIGGERS = (
    ("wire_calls_rev_gen1_ins",
     f"CREATE TRIGGER IF NOT EXISTS wire_calls_rev_gen1_ins AFTER INSERT ON wire_calls BEGIN {_REV_STAMP} END"),
    ("wire_calls_rev_gen1_upd",
     "CREATE TRIGGER IF NOT EXISTS wire_calls_rev_gen1_upd AFTER UPDATE ON wire_calls WHEN NOT ("
     "NEW.rowid IS (SELECT rid FROM wire_rev_seq WHERE k = 0) AND NEW.rev IS (SELECT n FROM wire_rev_seq WHERE k = 0) "
     f"AND OLD.rev IS NOT NEW.rev) BEGIN {_REV_STAMP} END"),
)
# Earlier versions' trigger (local OLD.rev + 1 on reference UPDATEs only; an explicitly set rev bypassed it). An
# older process still running recreates it on its next init; coexisting with it is harmless — the generation
# triggers restamp its write too — and install drops it again.
LEGACY_REV_TRIGGER = "wire_calls_refs_rev"


def _kv_int(con, key: str) -> int:
    try:
        r = con.execute("SELECT CAST(v AS INTEGER) FROM kv WHERE k=?", (key,)).fetchone()
        return int(r[0] or 0) if r else 0
    except (sqlite3.Error, TypeError, ValueError):
        return 0


def rev_generations_installed(con) -> bool:
    try:
        names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='wire_calls'")}
        seeded = con.execute("SELECT 1 FROM wire_rev_seq WHERE k=0").fetchone() is not None
    except sqlite3.Error:
        return False
    return seeded and LEGACY_REV_TRIGGER not in names and all(n in names for n, _ in REV_TRIGGERS)


def install_rev_generations(con) -> bool:
    """Install (or repair) the generation sequence and its triggers; True when it changed the schema.

    One ``BEGIN IMMEDIATE`` transaction: the sequence is raised to at least every existing ``rev`` (and the last
    ``wire_rev`` stamp and the current clock, which bound legacy timestamp revisions of rows already deleted) and the
    triggers become active before any other writer can commit — a legacy writer's row either committed before (and
    is counted in the maximum) or is restamped. Re-running it only ever raises the sequence. Writers call it from
    ``init``; read-only connections never need it (nothing reads ``wire_rev_seq``)."""
    if rev_generations_installed(con):
        return False
    own = not con.in_transaction
    if own:
        con.execute("BEGIN IMMEDIATE")
    try:
        con.execute(REV_SEQ_SQL)
        floor = max(time.time_ns(), _kv_int(con, "wire_rev"))
        top = con.execute("SELECT CAST(COALESCE(MAX(rev), 0) AS INTEGER) FROM wire_calls").fetchone()[0] or 0
        con.execute("INSERT OR IGNORE INTO wire_rev_seq (k, n) VALUES (0, 0)")
        con.execute("UPDATE wire_rev_seq SET n = MAX(n, ?, ?) WHERE k = 0", (int(top), int(floor)))
        con.execute(f"DROP TRIGGER IF EXISTS {LEGACY_REV_TRIGGER}")
        for _, sql in REV_TRIGGERS:
            con.execute(sql)
        if own:
            con.execute("COMMIT")
    except BaseException:
        if own and con.in_transaction:
            con.execute("ROLLBACK")
        raise
    return True


def connect(path: Path | None = None, timeout: float = 30) -> sqlite3.Connection:
    p = Path(path or db_path())
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(p.parent, 0o700)
    except OSError:
        pass
    con = sqlite3.connect(p, timeout=timeout)
    try:
        con.row_factory = sqlite3.Row
        # Must precede WAL too: SQLite cannot enable auto-vacuum on an empty
        # WAL database without a VACUUM. No table means this is a new store.
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
            con.execute("PRAGMA auto_vacuum=INCREMENTAL")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
        # Telemetry is not a ledger: NORMAL preserves process-crash safety in
        # WAL mode, but the last commits may roll back after a power loss.
        con.execute("PRAGMA synchronous=NORMAL")
        con.execute("PRAGMA journal_size_limit=67108864")
        return con
    except BaseException:
        con.close()
        raise


def connect_ro(path: Path | None = None, timeout: float = 10) -> sqlite3.Connection:
    """A read-only connection (``mode=ro``): no journal-mode change, no schema creation, no writes. What the CLI and
    any other pure reader use; raises ``sqlite3.OperationalError`` when the file does not exist."""
    from urllib.parse import quote

    p = Path(path or db_path())
    con = sqlite3.connect(f"file:{quote(str(p))}?mode=ro", uri=True, timeout=timeout)
    con.row_factory = sqlite3.Row
    con.execute(f"PRAGMA busy_timeout={int(timeout * 1000)}")
    con.execute("PRAGMA query_only=1")
    return con


def columns(con, table: str) -> list[str]:
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})")]


def select_cols(con, table: str, wanted) -> str:
    """A column list for ``wanted`` that reads columns an older store lacks as NULL."""
    have = set(columns(con, table))
    return ", ".join(c if c in have else f"NULL AS {c}" for c in wanted)


def space(con) -> dict:
    """Read-only SQLite page accounting, including reusable bytes and vacuum mode.

    Bytes describe database pages (including uncheckpointed WAL changes), not
    the combined sizes of the database and its WAL/SHM files. No migration,
    checkpoint or reclamation is performed, including on a read-only store.
    """
    try:
        page = int(con.execute("PRAGMA page_size").fetchone()[0])
        count = int(con.execute("PRAGMA page_count").fetchone()[0])
        free = int(con.execute("PRAGMA freelist_count").fetchone()[0])
        mode = int(con.execute("PRAGMA auto_vacuum").fetchone()[0])
    except (sqlite3.Error, TypeError, ValueError, IndexError):
        return {}
    return {"page_size": page, "pages": count, "free_pages": free,
            "bytes": page * count, "free_bytes": page * free,
            "vacuum": {0: "none", 1: "full", 2: "incremental"}.get(mode, "none")}


def init(con) -> None:
    # Set before the first table is created. Existing NONE-mode databases need
    # an explicit offline VACUUM to convert; never rewrite a large live store.
    if not con.execute("SELECT 1 FROM sqlite_master WHERE type='table' LIMIT 1").fetchone():
        con.execute("PRAGMA auto_vacuum=INCREMENTAL")
    con.executescript(SCHEMA)
    for table, col, typ in MIGRATIONS:
        if col not in columns(con, table):
            try:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
            except sqlite3.OperationalError:  # a concurrent writer added it first
                pass
    con.executescript(POST_MIGRATION)
    install_rev_generations(con)  # before the repairs below: their rewrites are stamped by the generation triggers
    backfill_families(con)
    backfill_costs(con)
    backfill_signals(con, budget_s=1.0)  # a bounded slice; the capture writer finishes it when idle
    con.commit()
    secure_files()


def secure_files(path: Path | None = None) -> None:
    """The store holds full prompts and responses: owner-only permissions."""
    p = Path(path or db_path())
    for suffix in ("", "-wal", "-shm"):
        q = Path(str(p) + suffix)
        try:
            if q.exists() and (q.stat().st_mode & 0o077):
                os.chmod(q, 0o600)
        except OSError:
            pass


def memory_store() -> sqlite3.Connection:
    """An empty in-memory store with the full schema (the dashboard's stand-in before any capture)."""
    con = sqlite3.connect(":memory:", check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    for table, col, typ in MIGRATIONS:  # same columns as a migrated file store
        if col not in columns(con, table):
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    con.executescript(POST_MIGRATION)
    install_rev_generations(con)
    return con


_EMAIL = re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9-]+)((?:\.[A-Za-z0-9-]+)+)")


def _mask_one(m: re.Match) -> str:
    local, dom, tld = m.group(1), m.group(2), m.group(3)
    lm = local[0] + "***" + (local[-1] if len(local) > 2 else "")
    return f"{lm}@{dom[0]}***{tld.rsplit('.', 1)[-1] and '.' + tld.rsplit('.', 1)[-1]}"


def mask_email(s):
    """``someone@example.com`` → ``s***e@e***.com`` (display helper; stored labels are kept as-is)."""
    return _EMAIL.sub(_mask_one, s) if isinstance(s, str) and "@" in s else s


def upsert(con, row: dict, table: str = "calls") -> None:
    if table == "wire_calls":
        # rev is the database's to assign (a generation per write, see REV_TRIGGERS): a caller-proposed value — a
        # timestamp, a stale copy — is never written
        row = {k: v for k, v in row.items() if k != "rev"}
    cols = set(columns(con, table))
    keys = [k for k in row if k in cols]
    if not keys:
        return
    upd = [k for k in keys if k != "id"]
    con.execute(
        f"INSERT INTO {table} ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)}) "
        + (f"ON CONFLICT(id) DO UPDATE SET {','.join(f'{k}=excluded.{k}' for k in upd)}" if upd else "ON CONFLICT(id) DO NOTHING"),
        [row[k] for k in keys])
    if table == "wire_calls":
        bump_wire_rev(con)
    elif table == "calls":
        bump_calls_rev(con)


def reserve_write(con) -> None:
    """Reserve the SQLite writer BEFORE read/modify/write state snapshots.

    ``with con`` alone does not begin a transaction before SELECT. An existing
    deferred transaction also needs upgrading before reading; a zero-row UPDATE
    reserves the writer without changing records, triggers or capture revisions.
    The owning batch/caller commits or rolls back (this helper never does).
    """
    if con.in_transaction:
        con.execute("UPDATE calls SET id=id WHERE 0")
    else:
        con.execute("BEGIN IMMEDIATE")


def host_state(row: dict) -> dict:
    """Writer-side source-local metadata, independent of optional payload capture.

    Before the first proxy merge, legacy counters are host-only. Already merged
    legacy rows have ambiguous totals: seed only from identifiable host details,
    never treat a mixed-scope maximum as a host-local counter to increment.
    """
    state = _loads(row.get("host_state"), None)
    if isinstance(state, dict) and isinstance(state.get("counters"), dict):
        return state
    if not row.get("proxy_attempts") and not row.get("proxy_rid"):
        counters = {k: row.get(k) or 0 for k in ("attempts", "n429", "nfail", "retry_s")}
    else:
        hist = [a for a in (_loads(row.get("attempt_detail"), []) or []) if isinstance(a, dict)
                and a.get("layer") != "proxy_upstream" and "key" not in a and "label" not in a]
        counters = {"attempts": max((a.get("n") or 0 for a in hist), default=0), "nfail": len(hist),
                    "n429": sum(a.get("status") == 429 for a in hist), "retry_s": sum(a.get("s") or 0 for a in hist)}
    return {"v": 1, "counters": counters}


def layer_counters(state: dict, proxy_attempts) -> dict:
    """One projection used by BOTH writers; observations from different layers never add."""
    hist = _loads(proxy_attempts, []) if isinstance(proxy_attempts, str) else (proxy_attempts or [])
    hist = [a for a in hist if not a.get("detached")]
    failed = [a for a in hist if a.get("error")]
    proxy = {"attempts": len(hist), "n429": sum(a.get("status") == 429 for a in hist),
             "nfail": len(failed), "retry_s": round(sum(a.get("s") or 0 for a in failed), 3)}
    host = state["counters"]
    return {k: max(host.get(k) or 0, proxy[k]) for k in proxy}


# A kv revision stamp: the clock when it is ahead, else the previous stamp + 1 — read and written in one statement,
# which holds the writer lock, so a frozen or rolled-back clock can never repeat or lower a committed stamp.
_KV_STAMP = ("INSERT OR REPLACE INTO kv VALUES (?, CAST(MAX(?, COALESCE((SELECT CAST(v AS INTEGER) FROM kv WHERE k=?), 0) + 1) "
             "AS TEXT))")


def bump_wire_rev(con) -> None:
    """Readers memoize views on this value: any write to wire_calls must change it (same transaction)."""
    con.execute(_KV_STAMP, ("wire_rev", time.time_ns(), "wire_rev"))


def bump_calls_rev(con) -> None:
    con.execute(_KV_STAMP, ("calls_rev", time.time_ns(), "calls_rev"))


def calls_rev(con) -> str:
    """Changes on every write to ``calls`` (and with the row count, on any insert)."""
    try:
        r = con.execute("SELECT v FROM kv WHERE k='calls_rev'").fetchone()
        n = con.execute("SELECT MAX(rowid) FROM calls").fetchone()
    except sqlite3.Error:
        return ""
    return f"{r[0] if r else ''}:{n[0] if n else ''}"


def session_wire_rev(con, sid: str) -> str:
    """Revision of one session's captured requests: changes only when one of *its* wire rows is written, so other
    sessions' traffic and background repairs leave its cached views valid.

    Sound because every committed write of a row (insert, update of any column, reinsert) gives it a generation
    above every one issued before (REV_TRIGGERS): a write into the session raises MAX(rev); a delete lowers COUNT.
    The key can only recur when the session's rows are exactly a set seen earlier, unchanged — the rows whose
    generation is <= an earlier MAX were all present, unwritten, at that earlier point."""
    try:
        if "rev" not in columns(con, "wire_calls"):
            return wire_rev(con)
        r = con.execute("SELECT MAX(rev), COUNT(*), MAX(rowid) FROM wire_calls WHERE session_id=?", (sid,)).fetchone()
    except sqlite3.Error:
        return ""
    if not r[1]:  # no capture names this session: its views come from proxy logs matched by text — any write counts
        return wire_rev(con)
    return f"{r[0]}:{r[1]}:{r[2]}"


def wire_rev(con) -> str:
    try:
        r = con.execute("SELECT v FROM kv WHERE k='wire_rev'").fetchone()
        n = con.execute("SELECT MAX(rowid) FROM wire_calls").fetchone()
    except sqlite3.Error:
        return ""
    return f"{r[0] if r else ''}:{n[0] if n else ''}"


def kv_get(con, key: str, default=None):
    try:
        r = con.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default
    except Exception:
        return default


def kv_set(con, key: str, value) -> None:
    con.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (key, json.dumps(value, default=str)))


# ───────────────────────── content-addressed blobs ─────────────────────────
_cache_lock = threading.Lock()
_blob_cache: "OrderedDict[str, str]" = OrderedDict()
_BLOB_CACHE_MAX = 30000
_last_gc = [0.0, 0.0]  # last attempt, last full mark/sweep


def canon(obj) -> str:
    """Canonical compact JSON — the same form for Hermes-side and proxy-side captures, so shared items dedupe."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def put_blob_str(con, s: str) -> str:
    b = s.encode("utf-8", "surrogatepass")
    h = hashlib.sha1(b).hexdigest()
    if not con.execute("SELECT 1 FROM wire_blobs WHERE h=?", (h,)).fetchone():
        con.execute("INSERT OR IGNORE INTO wire_blobs VALUES (?,?,?)", (h, zlib.compress(b, 6), len(s)))
    return h


def put_blob(con, obj, raw: bool = False) -> str:
    """Store obj as canonical compact JSON (or a raw string when raw=True); returns its sha1."""
    return put_blob_str(con, obj if raw else canon(obj))


def get_blob_str(con, h: str) -> str:
    with _cache_lock:
        if h in _blob_cache:
            _blob_cache.move_to_end(h)
            return _blob_cache[h]
    r = con.execute("SELECT z FROM wire_blobs WHERE h=?", (h,)).fetchone()
    s = zlib.decompress(r[0]).decode("utf-8", "surrogatepass") if r else "null"
    if r:
        with _cache_lock:
            _blob_cache[h] = s
            while len(_blob_cache) > _BLOB_CACHE_MAX:
                _blob_cache.popitem(last=False)
    return s


def get_blob(con, h: str):
    return json.loads(get_blob_str(con, h))


def read_blob_str(con, h: str) -> str | None:
    """One blob, decompressed, without touching the shared cache (for one-off reads of big response streams:
    the cache is bounded by entry count, not size). None when absent."""
    if not h:
        return None
    with _cache_lock:
        if h in _blob_cache:
            return _blob_cache[h]
    r = con.execute("SELECT z FROM wire_blobs WHERE h=?", (h,)).fetchone()
    return zlib.decompress(r[0]).decode("utf-8", "surrogatepass") if r else None


# ───────────────────────── request layers and response signals ─────────────────────────
def _loads(s, default=None):
    try:
        v = json.loads(s) if s else None
    except Exception:
        v = None
    return default if v is None else v


def layer_refs(req_down, req_hermes, source, file) -> dict:
    """{"post": ref, "pre": ref} for the layers a wire row stored. post = what left the process / reached the proxy
    (after any adapter); pre = what Hermes handed its provider client. Arguments are the raw column values."""
    down, herm = _loads(req_down, None), _loads(req_hermes, None)
    if not down:
        return {}
    if herm:                       # a post-adapter body replaced req_down and Hermes's copy was kept
        return {"post": down, "pre": herm}
    if source == "proxy" or file:  # proxy-only capture
        return {"post": down}
    return {"pre": down}           # Hermes's own snapshot only


_URL_MODEL = re.compile(r"models[/-]([A-Za-z0-9][A-Za-z0-9._\-]*?)(?=:|-(?:stream)?[gG]enerateContent|[/?]|$)")


def _ref_model(con, ref) -> str | None:
    h = ((ref or {}).get("keys") or {}).get("model") if isinstance(ref, dict) else None
    if not h:
        return None
    try:
        v = get_blob(con, h)
    except Exception:
        return None
    return v if isinstance(v, str) else None


def request_models(con, cid: str) -> dict:
    """The model each stored request layer asked for: {"hermes", "wire", "upstream"} (absent layers omitted).
    A Gemini-native body names its model in the URL, so the wire layer falls back to the URL / proxy log name."""
    try:
        r = con.execute(f"SELECT {select_cols(con, 'wire_calls', ('req_down', 'req_hermes', 'req_up', 'url', 'file', 'source'))} "
                        "FROM wire_calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return {}
    if not r:
        return {}
    lay = layer_refs(r[0], r[1], r[5], r[4])
    out = {}
    if "pre" in lay:
        out["hermes"] = _ref_model(con, lay["pre"])
    if "post" in lay:
        m = _ref_model(con, lay["post"])
        if not m:
            for s in (r[3], r[4]):
                mm = _URL_MODEL.search(s or "")
                if mm:
                    m = mm.group(1)
                    break
        out["wire"] = m
    up = _loads(r[2], None)
    if isinstance(up, dict) and up:
        out["upstream"] = out.get("wire") if up.get("same_as_down") else _ref_model(con, up)
    return {k: v for k, v in out.items() if v}


_signals_mod = [None]


def signals_mod():
    """collector/signals.py under its private name (pure parsing; no store dependency)."""
    if _signals_mod[0] is None:
        key = "_wiretap_signals"
        mod = sys.modules.get(key)
        if mod is None:
            import importlib.util

            spec = importlib.util.spec_from_file_location(key, Path(__file__).resolve().with_name("signals.py"))
            mod = importlib.util.module_from_spec(spec)
            sys.modules[key] = mod
            spec.loader.exec_module(mod)
            try:
                mod._mt_loaded_mtime = Path(mod.__file__).stat().st_mtime  # stamped: never retires the capture module
            except Exception:
                pass
        _signals_mod[0] = mod
    return _signals_mod[0]


def compute_signals(con, cid: str) -> dict | None:
    """Signals of a stored call from its raw response, parsed response, request layers and attempts (read-only).
    None when the store knows nothing about the call."""
    try:
        w = con.execute("SELECT resp_raw, resp FROM wire_calls WHERE id=?", (cid,)).fetchone()
        c = con.execute("SELECT attempt_detail FROM calls WHERE id=?", (cid,)).fetchone()
    except sqlite3.Error:
        return None
    if not w and not c:
        return None
    raw = read_blob_str(con, w[0]) if w and w[0] else None
    resp = _loads(w[1], {}) if w else {}
    models = request_models(con, cid) if w else {}
    requested = models.get("upstream") or models.get("wire") or models.get("hermes")
    attempts = _loads(c[0], []) if c else []
    sig = signals_mod().extract(raw, resp, requested=requested, attempts=attempts if isinstance(attempts, list) else [])
    sig["requested_by_layer"] = models
    return sig


def refresh_signals(con, cid: str) -> dict | None:
    """Recompute and store ``calls.signals`` for one call (writers only)."""
    if "signals" not in columns(con, "calls"):
        return None
    sig = compute_signals(con, cid)
    if sig is not None:
        con.execute("UPDATE calls SET signals=? WHERE id=?", (signals_mod().dumps(sig), cid))
    return sig


SIGNALS_REV = "1"
_SIGNALS_FAIL = {"v": 1, "refusal": False, "basis": None, "kinds": [], "items": [], "error": "signals unreadable"}


def signals_backfilled(con) -> bool:
    try:
        r = con.execute("SELECT v FROM kv WHERE k='signals_rev'").fetchone()
    except sqlite3.Error:
        return False
    return bool(r and r[0] == SIGNALS_REV)


def backfill_signals(con, budget_s: float | None = None, batch: int = 50) -> int:
    """Compute signals for stored calls that have none yet (a response or an attempt history to read), newest
    first, until done — then mark SIGNALS_REV. ``budget_s`` bounds one invocation (each raw response is
    decompressed once, outside the shared blob cache, ~5 ms a call): init does a slice, the capture writer finishes
    the rest when idle, so no writer ever holds the store's lock for the whole backfill."""
    try:
        if signals_backfilled(con) or "signals" not in columns(con, "calls"):
            return 0
        end = time.time() + budget_s if budget_s else None
        n = 0
        while True:
            ids = [x[0] for x in con.execute(
                "SELECT id FROM calls WHERE signals IS NULL AND (id IN (SELECT id FROM wire_calls) "
                "OR attempt_detail IS NOT NULL) ORDER BY started DESC LIMIT ?", (batch,))]
            if not ids:
                con.execute("INSERT OR REPLACE INTO kv VALUES ('signals_rev', ?)", (SIGNALS_REV,))
                return n
            for cid in ids:
                try:
                    if refresh_signals(con, cid) is None:
                        raise ValueError("no signals")
                except Exception:  # never re-select a row that cannot be read
                    con.execute("UPDATE calls SET signals=? WHERE id=?", (signals_mod().dumps(_SIGNALS_FAIL), cid))
            n += len(ids)
            if end is not None and time.time() >= end:
                return n
    except sqlite3.Error:
        return 0


def keep_seconds(default_hours: float = 72) -> float:
    try:
        return float(os.environ.get("WIRE_KEEP_HOURS") or plugin_setting("retention_hours", default_hours)) * 3600
    except (TypeError, ValueError):
        return default_hours * 3600


GC_FULL_SWEEP_S = 6 * 3600  # orphans from rewrites (repairs, merges) are swept this often even with nothing expired


def _mark_refs(rows, live: set) -> None:
    for r in rows:
        if len(r) > 4 and r[4]:
            for a in _loads(r[4], []):
                _mark_refs([(json.dumps(a.get("req_up")), None, a.get("resp_raw"), None)], live)
        if r[2]:
            live.add(r[2])
        for ref in (r[0], r[1], r[3]):
            try:
                d = json.loads(ref or "null") or {}
            except Exception:
                continue
            live.update(d.get("items") or [])
            live.update((d.get("keys") or {}).values())
            if d.get("raw"):
                live.add(d["raw"])


_GC_AFTER_MARK = None  # test seam: called between the read-snapshot mark and taking the writer lock


def gc(con, keep_s: float | None = None, force: bool = False) -> dict:
    """Drop wire captures past retention and every blob no remaining capture references.

    1. Mark, in one read transaction (a single snapshot, no writer lock): the blob set, every capture's ``rev``, and
       the references of every capture that is not expired.
    2. ``BEGIN IMMEDIATE`` (the writer lock), then compare every capture's current ``rev`` with the one seen at the
       mark — by inequality, not by time order — and re-mark each capture that changed or is new. A writer that took
       its ``rev`` before the mark but committed after it is caught: its row's rev differs from the snapshot's. (Every
       committed write of a capture row — upsert, direct UPDATE, delete + reinsert, whatever rev or clock the writer
       had — gets a fresh, never reused generation from REV_TRIGGERS, so an equal rev means an unwritten row.)
    3. Delete expired captures and only those blobs that existed at the mark and are still unreferenced; a blob added
       after the mark was not in the marked set and is never touched.
    Nothing expired and a recent full sweep: no-op. Called with no transaction open; the caller commits."""
    now = time.time()
    if not force and now - _last_gc[0] < 1800:
        return {"skipped": "interval"}
    _last_gc[0] = now
    keep_s = keep_seconds() if keep_s is None else keep_s
    cutoff = now - keep_s
    expired = con.execute("SELECT COUNT(*) FROM wire_calls WHERE COALESCE(ended, started, captured) < ?", (cutoff,)).fetchone()[0]
    if not expired and not force and now - _last_gc[1] < GC_FULL_SWEEP_S:
        return {"skipped": "nothing expired"}
    if con.in_transaction:
        return {"skipped": "called inside a transaction"}  # the mark must not run under a writer lock
    _last_gc[1] = now
    has_h = "req_hermes" in columns(con, "wire_calls")
    has_a = "proxy_attempts" in columns(con, "wire_calls")
    sel = ("SELECT req_down, req_up, resp_raw" + (", req_hermes" if has_h else ", NULL")
           + (", proxy_attempts" if has_a else ", NULL") + " FROM wire_calls")
    live: set = set()
    con.execute("BEGIN")  # deferred: a read snapshot only
    try:
        existed = {h for (h,) in con.execute("SELECT h FROM wire_blobs")}
        seen = {i: r for i, r in con.execute("SELECT id, rev FROM wire_calls")}
        _mark_refs(con.execute(sel + " WHERE COALESCE(ended, started, captured) >= ?", (cutoff,)), live)
    finally:
        con.execute("COMMIT")
    if _GC_AFTER_MARK is not None:
        _GC_AFTER_MARK()
    # ── write transaction: short ──
    con.execute("BEGIN IMMEDIATE")
    changed = [i for i, r in con.execute("SELECT id, rev FROM wire_calls") if i not in seen or seen[i] != r]
    for i in range(0, len(changed), 500):
        chunk = changed[i:i + 500]
        _mark_refs(con.execute(sel + f" WHERE id IN ({','.join('?' * len(chunk))}) AND COALESCE(ended, started, captured) >= ?",
                               chunk + [cutoff]), live)
    con.execute("DELETE FROM wire_calls WHERE COALESCE(ended, started, captured) < ?", (cutoff,))
    dead = [h for h in existed if h not in live]
    for i in range(0, len(dead), 500):
        chunk = dead[i:i + 500]
        con.execute(f"DELETE FROM wire_blobs WHERE h IN ({','.join('?' * len(chunk))})", chunk)
    bump_wire_rev(con)
    # Consume all result rows: stepping incremental_vacuum only once reclaims
    # just one page on some SQLite builds. The caller commits both pruning and
    # reclamation; WAL readers remain valid, with disk shrink at checkpoint.
    con.execute("PRAGMA incremental_vacuum").fetchall()
    return {"expired": expired, "dead_blobs": len(dead), "rechecked": len(changed)}


# ───────────────────────── pricing (Hermes's own snapshot tables) ─────────────────────────
_price_cache: dict[tuple, object] = {}


def _usage_pricing():
    try:
        import agent.usage_pricing as up  # type: ignore  (importable inside any Hermes process)

        return up
    except ImportError:
        src = os.environ.get("HERMES_SRC")
        if src and Path(src).is_dir() and src not in sys.path:
            sys.path.append(src)
        try:
            import agent.usage_pricing as up  # type: ignore

            return up
        except Exception:
            return None
    except Exception:
        return None


def billing_of(model: str, provider: str | None, base_url: str | None) -> str:
    """'sub' for subscription-included routes (Hermes's billing route), else 'api'."""
    up = _usage_pricing()
    try:
        route = up.resolve_billing_route(model or "", provider=provider, base_url=base_url) if up else None
        return "sub" if route is not None and route.billing_mode == "subscription_included" else "api"
    except Exception:
        return "api"


def _pricing(model: str, provider: str | None, base_url: str | None):
    key = (model, provider, base_url)
    if key in _price_cache:
        return _price_cache[key]
    entry = None
    up = _usage_pricing()
    if up is not None:
        try:
            if hasattr(up, "get_pricing_entry"):  # Hermes's own resolver (bundled snapshot, OpenRouter, models.dev)
                entry = up.get_pricing_entry(model, provider=provider, base_url=base_url)
                if entry is not None and getattr(entry, "source", None) == "none" and getattr(entry, "input_cost_per_million", None) is None:
                    entry = None
            if entry is None:
                route = up.resolve_billing_route(model, provider=provider, base_url=base_url)
                entry = up._lookup_official_docs_pricing(route)
                if entry is None:
                    entry = up._models_dev_pricing_entry(route)
        except Exception:
            entry = None
    _price_cache[key] = entry
    return entry


def price_call(model: str, provider: str | None, uncached: int, cached: int, cache_write: int, output: int,
               prompt: int, base_url: str | None = None):
    """API-list-price estimate (USD, pricing_version), or (None, version) when a bucket has no rate."""
    e = _pricing(model or "", provider, base_url)
    if e is None:
        return None, None

    def rate(name):
        base = getattr(e, name, None)
        thr = getattr(e, "tier_threshold_tokens", None)
        above = getattr(e, name + "_above", None)
        if thr is not None and prompt > thr and above is not None:
            return float(above)
        return float(base) if base is not None else None

    total = 0.0
    for toks, nm in ((uncached, "input_cost_per_million"), (cached, "cache_read_cost_per_million"),
                     (cache_write, "cache_write_cost_per_million"), (output, "output_cost_per_million")):
        r = rate(nm)
        if r is None:
            r = rate("input_cost_per_million") if nm != "output_cost_per_million" else None
        if toks and r is None:
            return None, getattr(e, "pricing_version", None)
        total += (toks or 0) * (r or 0) / 1e6
    return round(total, 6), getattr(e, "pricing_version", None)


FAMILY_PROVIDER = {"gemini": "gemini", "claude": "anthropic", "openai": "openai"}


def price_tokens(model: str, provider: str | None, family: str | None, base_url: str | None, uncached: int, cached: int,
                 cache_write: int, output: int, prompt: int):
    """API-list price for a token split: the route's own table first, then the model maker's (a proxy or custom
    provider has no table of its own, but the model's list price still applies)."""
    cost, pv = price_call(model, provider, uncached, cached, cache_write, output, prompt, base_url=base_url)
    maker = FAMILY_PROVIDER.get(family or "")
    if cost is None and maker and maker != provider:
        cost, pv = price_call(model, maker, uncached, cached, cache_write, output, prompt)
    return cost, pv


def reprice(con, cid: str) -> None:
    """Price a stored call from its final token split: ``cost_equiv_usd`` is that split at list price and
    ``cost_usd`` is the same number when the route bills per token (else $0). One computation for both, so cost
    can never exceed its API equivalent."""
    r = con.execute("SELECT model, provider, family, url, billing, uncached_tokens, cached_tokens, cache_write_tokens, "
                    "output_tokens, prompt_tokens, auth_type, proxy_rid FROM calls WHERE id=?", (cid,)).fetchone()
    if not r:
        return
    model, prov, fam, url, billing = r[0] or "", r[1], r[2], r[3], r[4]
    auth = r[10] if r[11] else None  # only the proxy's upstream credential says how the provider bills
    if auth:  # the proxy saw the serving credential: that decides billing
        billing = "api" if auth == "api_key" else "sub"
    maker = FAMILY_PROVIDER.get(fam or "")
    own = price_call(model, prov, 1000, 0, 0, 0, 1000, base_url=url)[0] is not None
    if billing == "sub":  # subscription route: the equivalent is the maker's list price
        prov, url = maker or prov, None
    cost, pv = price_tokens(model, prov, fam, url, r[5] or 0, r[6] or 0, r[7] or 0, r[8] or 0, r[9] or 0)
    if cost is None:
        paid = 0.0 if billing == "sub" else None
    elif billing == "api" and (own or auth == "api_key"):
        paid = cost
    elif billing == "api":  # Hermes could not resolve this route's billing and nothing says it is per-token
        paid = None
    else:
        paid = 0.0
    con.execute("UPDATE calls SET billing=?, cost_equiv_usd=?, cost_usd=?, pricing_version=COALESCE(?, pricing_version) WHERE id=?",
                (billing, cost, paid, pv, cid))


COST_REV = "1"


def backfill_costs(con) -> int:
    """Once per COST_REV: re-price Hermes-side rows whose cost and equivalent came from different computations
    (a proxy merge set cost_usd from the proxy's pricing and left the Hermes-side equivalent, which a proxy route
    could not price, empty)."""
    try:
        r = con.execute("SELECT v FROM kv WHERE k='cost_rev'").fetchone()
        if r and r[0] == COST_REV:
            return 0
        ids = [x[0] for x in con.execute(
            "SELECT id FROM calls WHERE source='hermes' AND COALESCE(prompt_tokens, 0) > 0 AND "
            "(cost_equiv_usd IS NULL OR cost_usd IS NULL OR cost_usd > cost_equiv_usd + 1e-9 OR proxy_rid IS NOT NULL)")]
        for cid in ids:
            reprice(con, cid)
        con.execute("INSERT OR REPLACE INTO kv VALUES ('cost_rev', ?)", (COST_REV,))
        return len(ids)
    except sqlite3.Error:
        return 0


# Model family (who made the model), independent of the route that served it: a router such as OpenRouter or a
# proxy carries many families, so the family comes from the model name first, then an ``org/`` prefix, then a
# vendor provider, then the wire API, and only then from the name's own first word.
FAMILY_LABELS = {
    "claude": "Claude", "gemini": "Gemini", "openai": "OpenAI", "deepseek": "DeepSeek", "glm": "GLM",
    "minimax": "MiniMax", "qwen": "Qwen", "nous": "Nous", "llama": "Llama", "kimi": "Kimi",
    "grok": "Grok", "mistral": "Mistral", "cohere": "Cohere", "phi": "Phi", "other": "Other",
}
_MODEL_FAMILIES = (  # (family, name prefixes at a word start) — checked in order on the model's last path segment
    ("claude", ("claude",)),
    ("gemini", ("gemini", "gemma")),
    ("deepseek", ("deepseek",)),
    ("glm", ("glm", "chatglm")),
    ("minimax", ("minimax", "abab")),
    ("qwen", ("qwen", "qwq")),
    ("kimi", ("kimi", "moonshot")),
    ("nous", ("hermes", "nous")),
    ("llama", ("llama",)),
    ("grok", ("grok",)),
    ("mistral", ("mistral", "mixtral", "codestral", "magistral", "devstral", "ministral")),
    ("cohere", ("command-r", "command-a")),
    ("phi", ("phi-",)),
)
_OPENAI_RE = re.compile(r"^(?:gpt|chatgpt|codex|o[134](?:$|[-_.]))")
_ORG_FAMILY = {  # OpenRouter-style org prefixes and vendor provider ids
    "anthropic": "claude", "google": "gemini", "gemini": "gemini", "openai": "openai", "openai-codex": "openai",
    "deepseek": "deepseek", "z-ai": "glm", "zai": "glm", "zhipuai": "glm", "thudm": "glm", "minimax": "minimax",
    "qwen": "qwen", "alibaba": "qwen", "moonshotai": "kimi", "kimi": "kimi", "kimi-coding": "kimi",
    "nousresearch": "nous", "nous": "nous", "meta-llama": "llama", "meta": "llama", "x-ai": "grok", "xai": "grok",
    "mistralai": "mistral", "mistral": "mistral", "cohere": "cohere", "microsoft": "phi",
}
_API_FAMILY = {"anthropic_messages": "claude", "codex_responses": "openai"}


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def family_of(model: str | None, api_mode: str | None = None, provider: str | None = None) -> str:
    full = (model or "").strip().lower()
    org, _, name = full.rpartition("/")
    if name:
        for fam, keys in _MODEL_FAMILIES:
            if any(re.search(r"(?:^|[-_.:\s])" + re.escape(k), name) for k in keys):  # at a word start: not "ollama"
                return fam
        if _OPENAI_RE.match(name):
            return "openai"
    for o in [x for x in org.split("/") if x]:  # "openrouter/anthropic/claude…", "deepseek/…"
        if o in _ORG_FAMILY:
            return _ORG_FAMILY[o]
    p = (provider or "").strip().lower()
    if p in _ORG_FAMILY:
        return _ORG_FAMILY[p]
    if not name and api_mode in _API_FAMILY:
        return _API_FAMILY[api_mode]
    if org:
        return _slug(org.split("/")[-1]) or "other"
    first = re.match(r"[a-z]+", name or "")
    return first.group(0) if first and len(first.group(0)) >= 2 else "other"


def family_label(fam: str | None) -> str:
    f = fam or "other"
    return FAMILY_LABELS.get(f) or " ".join(w[:1].upper() + w[1:] for w in f.split("-"))


FAMILY_REV = "2"


def backfill_families(con) -> int:
    """Re-derive stored families once per FAMILY_REV (older rows used a three-way split plus "other")."""
    try:
        r = con.execute("SELECT v FROM kv WHERE k='family_rev'").fetchone()
        if r and r[0] == FAMILY_REV:
            return 0
        n = 0
        has_api = "api_mode" in columns(con, "calls")
        sel = "model, provider, " + ("api_mode" if has_api else "NULL") + ", family"
        for model, prov, mode, fam in con.execute(f"SELECT DISTINCT {sel} FROM calls").fetchall():
            if not model:
                continue  # family came from the wire protocol; nothing better to derive
            new = family_of(model, mode, prov)
            if new != fam:
                n += con.execute("UPDATE calls SET family=? WHERE model=? AND COALESCE(provider,'')=? AND family IS ?",
                                 (new, model, prov or "", fam)).rowcount
        for table in ("wire_calls", "bodies"):
            for model, fam in con.execute(f"SELECT DISTINCT model, family FROM {table}").fetchall():
                if model and family_of(model) != fam:
                    con.execute(f"UPDATE {table} SET family=? WHERE model=? AND family IS ?", (family_of(model), model, fam))
        con.execute("INSERT OR REPLACE INTO kv VALUES ('family_rev', ?)", (FAMILY_REV,))
        return n
    except sqlite3.Error:
        return 0
