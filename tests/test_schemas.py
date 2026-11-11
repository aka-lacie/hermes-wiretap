"""The inspector reads both state.db generations it meets in the field.

(a) a stock upstream schema: the classic ``sessions`` / ``messages`` columns only — no ``api_content``,
    ``platform_message_id``, ``display_*``, ``active``, ``system_prompt_hash`` — so every optional column reads as NULL
    and provenance comes from the text heuristics;
(b) a typed-provenance schema: typed provenance columns (``sender_kind`` / ``sender_id`` / ``sent_at`` /
    ``source_event_id`` / ``intent`` / ``part_kind`` / ``turn_outcome`` / ``parts_json``) and session lineage
    (``lineage_kind`` / ``depth`` / ``root_session_id`` …). Typed columns are authoritative: a row whose text reads
    like one thing is labelled by what its columns say it is.

Each fixture carries a minimal Hermes-side wire capture so session_view / compiled_view correlate and align.
"""
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def _load_inspector():
    spec = importlib.util.spec_from_file_location("_mt_schema_test_inspector", HERE / "collector" / "inspector.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _insert(con, table, row):
    con.execute(f"INSERT INTO {table} ({','.join(row)}) VALUES ({','.join('?' * len(row))})", list(row.values()))


def _add_call(ins, tcon, cid, sid, t, messages, text="", tool_calls=()):
    body = {"model": "test-model", "messages": messages, "tools": [{"type": "function", "function": {"name": "delegate_task"}}]}
    ref = ins.itemize(tcon, json.dumps(body))
    resp = {"text": text, "thinking": "", "tool_calls": [{"id": i, "name": "delegate_task", "args": {}} for i in tool_calls],
            "finish": "stop", "model": "test-model", "response_id": None, "usage": None}
    ins.store.upsert(tcon, {"id": cid, "started": t - 2, "ended": t - 0.5, "family": "openai", "model": "test-model",
                            "status": 200, "req_down": json.dumps(ref), "resp": json.dumps(resp),
                            "tc_ids": json.dumps(list(tool_calls)), "text_head": ins.norm(text)[:400],
                            "n_items": len(ref["items"]), "req_bytes": len(json.dumps(body)), "captured": t,
                            "session_id": sid, "source": "hermes", "exact": 1}, "wire_calls")
    tcon.commit()


def _tc(cid):
    return json.dumps([{"id": cid, "type": "function", "function": {"name": "delegate_task", "arguments": "{}"}}])


def _human(text, mid, delivery="turn", t=None):
    return {"type": "human", "v": 1, "text": text, "delivery": delivery,
            "origin": {"platform": "discord", "message_id": mid, "channel_id": "c1", "sent_at": t}}


def _event(kind, text, meta=None):
    return {"type": "system_event", "v": 1, "kind": kind, "text": text, "meta": meta or {}}


# ───────────────────────── (a) stock upstream schema ─────────────────────────
STOCK_SCHEMA = """
CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL, user_id TEXT, model TEXT, model_config TEXT,
  system_prompt TEXT, parent_session_id TEXT, started_at REAL NOT NULL, ended_at REAL, end_reason TEXT,
  message_count INTEGER DEFAULT 0, tool_call_count INTEGER DEFAULT 0, input_tokens INTEGER DEFAULT 0,
  output_tokens INTEGER DEFAULT 0, title TEXT);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL,
  content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL NOT NULL, token_count INTEGER,
  finish_reason TEXT);
"""


class StockUpstreamSchema(unittest.TestCase):
    SID = "stock_main"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "state.db"
        cls.ins = _load_inspector()
        cls.tcon = cls.ins.store.memory_store()
        t0 = time.time() - 300
        con = sqlite3.connect(cls.db)
        con.executescript(STOCK_SCHEMA)
        _insert(con, "sessions", {"id": cls.SID, "source": "cli", "model": "test-model", "system_prompt": "SOUL",
                                  "started_at": t0, "message_count": 6, "title": "stock session title"})
        _insert(con, "sessions", {"id": "stock_child", "source": "cli", "parent_session_id": cls.SID, "started_at": t0 + 1})
        cron = "[HERMES_INTERNAL_NOTIFICATION]\nkind: cron\nsource: nightly\nThe nightly digest ran."
        done = "[ASYNC DELEGATION BATCH COMPLETE — deleg_0123abcd]\nThe worker finished its audit."
        reply = "Build is green and the worker finished."
        rows = [
            {"id": 1, "role": "user", "content": "please check the build status for me", "timestamp": t0 + 10},
            {"id": 2, "role": "assistant", "content": "", "tool_calls": _tc("call_s1"), "timestamp": t0 + 12,
             "finish_reason": "tool_calls"},
            {"id": 3, "role": "tool", "content": '{"ok": true}', "tool_call_id": "call_s1", "tool_name": "delegate_task",
             "timestamp": t0 + 13},
            {"id": 4, "role": "user", "content": cron, "timestamp": t0 + 20},
            {"id": 5, "role": "user", "content": done, "timestamp": t0 + 21},
            {"id": 6, "role": "assistant", "content": reply, "timestamp": t0 + 30, "finish_reason": "stop"},
        ]
        for r in rows:
            _insert(con, "messages", {"session_id": cls.SID, **r})
        _insert(con, "messages", {"session_id": "stock_child", "role": "user", "content": "go audit", "timestamp": t0 + 2})
        con.commit()
        con.close()
        sysm = {"role": "system", "content": "SOUL"}
        u1 = {"role": "user", "content": "please check the build status for me"}
        a1 = {"role": "assistant", "content": None, "tool_calls": [{"id": "call_s1", "type": "function",
                                                                     "function": {"name": "delegate_task", "arguments": "{}"}}]}
        t1 = {"role": "tool", "tool_call_id": "call_s1", "content": '{"ok": true}'}
        _add_call(cls.ins, cls.tcon, "stock_c1", cls.SID, t0 + 12, [sysm, u1], tool_calls=["call_s1"])
        _add_call(cls.ins, cls.tcon, "stock_c2", cls.SID, t0 + 30,
                  [sysm, u1, a1, t1, {"role": "user", "content": cron + "\n\n" + done}], text=reply)
        cls.view = cls.ins.session_view(cls.db, cls.tcon, cls.SID, None, 250, False)
        cls.rows = {r["id"]: r for r in cls.view["rows"]}

    @classmethod
    def tearDownClass(cls):
        cls.tcon.close()
        cls.tmp.cleanup()

    def test_session_view_classifies_by_text(self):
        r = self.rows
        self.assertEqual(r[1]["label"], "USER")
        self.assertEqual(r[3]["label"], "TOOL RESULT · delegate_task")
        self.assertEqual((r[4]["kind"], r[4]["label"]), ("cron", "CRON NOTIFICATION · nightly"))
        self.assertEqual((r[5]["kind"], r[5].get("ref")), ("subagent", "deleg_0123abcd"))
        for row in r.values():
            self.assertNotIn("typed", row, "a stock schema has no typed provenance")
            self.assertNotIn("parts", row)
            self.assertEqual(row["active"], 1, "missing active column reads as active")
        self.assertEqual(self.view["total"], 6)

    def test_assistant_rows_correlate(self):
        self.assertEqual(self.rows[2]["wire"], "stock_c1")
        self.assertEqual(self.rows[6]["wire"], "stock_c2")
        self.assertEqual(self.rows[6]["flags"], [])

    def test_compiled_view_aligns(self):
        c = self.ins.compiled_view(self.db, self.tcon, self.SID)
        self.assertEqual(c["call_id"], "stock_c2")
        self.assertTrue(c["system"]["matches_stored"], "inline sessions.system_prompt is the stored copy")
        self.assertEqual(c["archived_count"], 0)
        items = c["wire"]["items"]
        self.assertEqual([it.get("row_id") for it in items[1:]], [1, 2, 3, 4])
        self.assertIn(5, items[4]["row_ids"], "the merged notice item carries both notices")

    def test_full_row_prompt_and_list(self):
        fr = self.ins.full_row(self.db, self.tcon, 4)
        self.assertEqual(fr["class"]["kind"], "cron")
        self.assertNotIn("parts", fr)
        self.assertNotIn("provenance", fr)
        self.assertIsNone(fr["inject"])
        p = self.ins.session_prompt(self.db, self.SID)
        self.assertEqual(p, {"text": "SOUL", "hash": None})
        ss = {s["id"]: s for s in self.ins.sessions_list(self.db, "", 50, self.SID)}
        self.assertTrue(ss[self.SID]["main"])
        self.assertIsNone(ss[self.SID]["lineage"])
        self.assertEqual(ss["stock_child"]["lineage"]["kind"], "child")
        self.assertFalse(ss["stock_child"]["lineage"]["typed"])
        child = self.ins.session_view(self.db, self.tcon, "stock_child", None, 50, False)
        self.assertEqual(child["rows"][0]["kind"], "parent", "a child's first user row is its parent's assignment")
        self.assertEqual(child["session"]["lineage"]["parent"], self.SID)


# ───────────────────────── (b) typed-provenance schema ─────────────────────────
# Columns of the typed-provenance state schema (the subset the inspector reads, plus a few it must ignore).
TYPED_SCHEMA = """
CREATE TABLE system_prompts (hash TEXT PRIMARY KEY, prompt TEXT NOT NULL);
CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL, created_source TEXT, user_id TEXT, session_key TEXT,
  chat_type TEXT, origin_json TEXT, model TEXT, model_config TEXT, system_prompt TEXT, system_prompt_hash TEXT,
  parent_session_id TEXT, started_at REAL NOT NULL, ended_at REAL, end_reason TEXT, message_count INTEGER DEFAULT 0,
  billing_provider TEXT, title TEXT, last_activity_at REAL, hidden INTEGER NOT NULL DEFAULT 0,
  lineage_kind TEXT, depth INTEGER, delivery_target TEXT, route TEXT, status TEXT, workspace TEXT, fork_origin TEXT,
  role TEXT, root_session_id TEXT, group_id TEXT);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL, content TEXT,
  tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, effect_disposition TEXT, timestamp REAL NOT NULL,
  token_count INTEGER, finish_reason TEXT, reasoning TEXT, reasoning_content TEXT, reasoning_details TEXT,
  platform_message_id TEXT, observed INTEGER DEFAULT 0, _compressed_summary INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1, compacted INTEGER NOT NULL DEFAULT 0, api_content TEXT, display_kind TEXT,
  display_metadata TEXT, display_identity BLOB, display_order INTEGER, message_uid TEXT,
  sender_kind TEXT, sender_id TEXT, sent_at REAL, source_event_id TEXT, intent TEXT, part_kind TEXT,
  parts_json TEXT, turn_outcome TEXT);
"""


if __name__ == "__main__":
    unittest.main()
