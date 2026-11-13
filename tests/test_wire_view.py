"""The Wire view's backend: any captured call of a session (not only the newest), its call history, and one item's
exact wire text partitioned into raw state.db content vs runtime-constructed wrappers and injected parts.

Runs on a stock schema (content / api_content only).
"""
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def _load_inspector(name):
    spec = importlib.util.spec_from_file_location(name, HERE / "collector" / "inspector.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _insert(con, table, row):
    con.execute(f"INSERT INTO {table} ({','.join(row)}) VALUES ({','.join('?' * len(row))})", list(row.values()))


def _add_call(ins, tcon, cid, sid, t, messages, text="", system=None):
    body = {"model": "test-model", "messages": messages,
            "tools": [{"type": "function", "function": {"name": "read_file", "description": "Read a file"}}]}
    if system is not None:
        body["instructions"] = system
    ref = ins.itemize(tcon, json.dumps(body))
    resp = {"text": text, "thinking": "", "tool_calls": [], "finish": "stop", "model": "test-model", "response_id": None, "usage": None}
    ins.store.upsert(tcon, {"id": cid, "started": t - 2, "ended": t - 0.5, "family": "openai", "model": "test-model",
                            "status": 200, "req_down": json.dumps(ref), "resp": json.dumps(resp), "tc_ids": "[]",
                            "text_head": ins.norm(text)[:400], "n_items": len(ref["items"]), "req_bytes": len(json.dumps(body)),
                            "captured": t, "session_id": sid, "source": "hermes", "exact": 1}, "wire_calls")
    tcon.commit()


STOCK = """
CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT NULL, model TEXT, system_prompt TEXT, parent_session_id TEXT,
  started_at REAL NOT NULL, message_count INTEGER DEFAULT 0, title TEXT);
CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, role TEXT NOT NULL,
  content TEXT, api_content TEXT, tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL NOT NULL,
  token_count INTEGER, finish_reason TEXT);
"""
SID = "wire_view"
PROMPT = "You are a careful assistant."
ASK = "please check why the cache missed"
API = "[Sun 2026-11-08 13:49 PST]\n\n" + ASK + "\n\n<ADDITIONAL_METADATA>\nchannel: discord\n</ADDITIONAL_METADATA>"
WIRE_ASK = "<USER_REQUEST>\n" + API + "\n</USER_REQUEST>"


class WireViewStock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "state.db"
        cls.ins = _load_inspector("_mt_wire_view_stock")
        cls.tcon = cls.ins.store.memory_store()
        now = time.time() - 120
        with sqlite3.connect(cls.db) as con:
            con.executescript(STOCK)
            _insert(con, "sessions", {"id": SID, "source": "discord", "started_at": now, "system_prompt": PROMPT})
            for row in ({"role": "user", "content": ASK, "api_content": API, "timestamp": now},
                        {"role": "assistant", "content": "It was the tool list.", "timestamp": now + 10},
                        {"role": "user", "content": "thanks, now fix it", "timestamp": now + 20},
                        {"role": "assistant", "content": "Fixed.", "timestamp": now + 30}):
                _insert(con, "messages", {"session_id": SID, **row})
        con.close()
        first = [{"role": "user", "content": WIRE_ASK}]
        _add_call(cls.ins, cls.tcon, "call-one", SID, now + 10, first, "It was the tool list.", PROMPT + "\n\n# plugin section")
        second = first + [{"role": "assistant", "content": "It was the tool list."}, {"role": "user", "content": "thanks, now fix it"}]
        _add_call(cls.ins, cls.tcon, "call-two", SID, now + 30, second, "Fixed.", PROMPT)
        # a background memory review forks the conversation under the same session id, after its last turn
        review = second + [{"role": "assistant", "content": "Fixed."}, {"role": "user", "content": "Review the conversation above."}]
        _add_call(cls.ins, cls.tcon, "call-review", SID, now + 40, review, "Nothing to save.", PROMPT)
        cls.ins.store.upsert(cls.tcon, {"id": "call-review", "session_id": SID, "started": now + 38, "lane": "review",
                                        "execution_origin": "background_review"}, "calls")
        cls.tcon.commit()

    @classmethod
    def tearDownClass(cls):
        cls.tcon.close()
        cls.tmp.cleanup()

    def test_call_history_lists_every_captured_call_oldest_first(self):
        view = self.ins.compiled_view(self.db, self.tcon, SID)
        self.assertEqual((view["call_id"], view["latest_call"], view["historic"]), ("call-two", "call-two", False),
                         "a newer background review never becomes the default Wire call")
        self.assertEqual([(c["id"], c["n"], c.get("review", False)) for c in view["calls"]],
                         [("call-one", 1, False), ("call-two", 2, False), ("call-review", 3, True)])
        self.assertEqual(view["calls_total"], 3)

    def test_a_review_fork_can_be_opened_and_is_labelled(self):
        view = self.ins.compiled_view(self.db, self.tcon, SID, call="call-review")
        self.assertEqual((view["call_id"], view["latest_call"], view["historic"]), ("call-review", "call-two", True))
        self.assertEqual(self.ins.compiled_view(self.db, self.tcon, SID, lane="review")["call_id"], "call-review")

    def test_an_earlier_call_is_compiled_against_rows_written_after_it(self):
        view = self.ins.compiled_view(self.db, self.tcon, SID, call="call-one")
        self.assertEqual((view["call_id"], view["latest_call"], view["historic"]), ("call-one", "call-two", True))
        self.assertEqual([it.get("row_id") for it in view["wire"]["items"]], [1])
        self.assertEqual({r["id"] for r in view["rows_after"]}, {2, 3, 4}, "rows newer than the selected call")
        self.assertFalse(view["system"]["matches_stored"], "that call's system prompt carried a plugin section")
        self.assertTrue(self.ins.compiled_view(self.db, self.tcon, SID)["system"]["matches_stored"])
        self.assertEqual(self.ins.compiled_view(self.db, self.tcon, SID, call="call-two")["historic"], False,
                         "naming the newest call is the live view")

    def test_an_unknown_call_falls_back_to_the_newest_and_says_so(self):
        view = self.ins.compiled_view(self.db, self.tcon, SID, call="nope")
        self.assertEqual((view["call_id"], view["call_missing"]), ("call-two", "nope"))

    def test_another_sessions_call_is_never_spliced_onto_this_transcript(self):
        _add_call(self.ins, self.tcon, "foreign-call", "other_session", time.time() - 5,
                  [{"role": "user", "content": "someone else's secret"}], "theirs")
        view = self.ins.compiled_view(self.db, self.tcon, SID, call="foreign-call")
        self.assertEqual((view["call_id"], view["call_missing"], view["session"]["id"]), ("call-two", "foreign-call", SID))
        self.assertNotIn("foreign-call", [c["id"] for c in view["calls"]])
        self.assertNotIn("someone else", json.dumps(view["wire"]))

    def test_a_review_only_session_still_opens_its_calls(self):
        sid = "review_only"
        con = sqlite3.connect(self.db)
        _insert(con, "sessions", {"id": sid, "source": "discord", "started_at": time.time() - 50, "system_prompt": PROMPT})
        _insert(con, "messages", {"session_id": sid, "role": "user", "content": "please look at the cache numbers", "timestamp": time.time() - 50})
        con.commit()
        con.close()
        _add_call(self.ins, self.tcon, "lone-review", sid, time.time() - 20,
                  [{"role": "user", "content": "please look at the cache numbers"}, {"role": "user", "content": "Review the conversation above."}], "ok")
        self.ins.store.upsert(self.tcon, {"id": "lone-review", "session_id": sid, "started": time.time() - 22, "lane": "review",
                                          "execution_origin": "background_review"}, "calls")
        self.tcon.commit()
        default = self.ins.compiled_view(self.db, self.tcon, sid)
        self.assertIn("error", default, "no main capture: nothing is shown by default")
        self.assertEqual([(c["id"], c.get("review")) for c in default["calls"]], [("lone-review", True)],
                         "…but the history still offers the review call")
        self.assertIsNone(default["latest_call"])
        picked = self.ins.compiled_view(self.db, self.tcon, sid, call="lone-review")
        self.assertNotIn("error", picked)
        self.assertEqual((picked["call_id"], picked["historic"], picked["latest_call"]), ("lone-review", True, None))
        self.assertEqual([it.get("row_id") for it in picked["wire"]["items"]][:1], [5])

    def test_readable_wire_text_separates_raw_content_from_wrappers(self):
        rd = self.ins.wire_readable(self.db, self.tcon, "call-two", part="item", i=0, row_ids=[1])
        seg = rd["segments"][0]
        self.assertEqual(seg["path"], "messages[0].content")
        self.assertEqual("".join(r["t"] for r in seg["runs"]), WIRE_ASK, "the runs are the exact wire string, in order")
        raw = [r for r in seg["runs"] if r["k"] == "raw"]
        self.assertEqual([r["t"] for r in raw], [ASK])
        labels = {r["label"]: r.get("persisted") for r in seg["runs"] if r["k"] == "wrapper"}
        self.assertFalse(labels["USER_REQUEST"], "the adapter's USER_REQUEST frame exists only on the wire")
        self.assertTrue(labels["ADDITIONAL_METADATA"], "turn metadata state.db also kept in api_content")
        self.assertEqual(rd["source"], ["content"])

    def test_readable_system_prompt_marks_sections_added_at_send_time(self):
        rd = self.ins.wire_readable(self.db, self.tcon, "call-one", part="sys")
        runs = rd["segments"][0]["runs"]
        self.assertEqual(rd["segments"][0]["path"], "instructions")
        self.assertEqual([(r["k"], r["t"]) for r in runs], [("raw", PROMPT), ("wrapper", "\n\n# plugin section")])

    def test_unaligned_items_only_mark_tags(self):
        rd = self.ins.wire_readable(self.db, self.tcon, "call-two", part="item", i=0)
        kinds = [(r["k"], r["label"]) for r in rd["segments"][0]["runs"]]
        self.assertEqual(kinds[0], ("wrapper", "USER_REQUEST"))
        self.assertIn(("unaligned", None), kinds)
        self.assertNotIn("raw", {k for k, _ in kinds})

    def test_injected_parts_win_over_identical_human_text_and_large_texts_are_verbatim(self):
        text = "<turn_note>hi there</turn_note>\nhi there"
        runs = self.ins.readable_runs(text, [("hi there", "human")], [("hi there", "turn_note")])["runs"]
        self.assertEqual([(r["k"], r["t"]) for r in runs],
                         [("wrapper", "<turn_note>"), ("injection", "hi there"), ("wrapper", "</turn_note>\n"), ("raw", "hi there")])
        big = "x" * (self.ins._READABLE_MAX + 1)
        self.assertEqual(self.ins.readable_runs(big, [("x", "r")])["runs"], [{"t": big, "k": "unaligned", "label": None}])

    def test_lines_fallback_when_whitespace_was_rewrapped(self):
        runs = self.ins.readable_runs("<q>\nfirst line\nsecond line\n</q>", [("first line\n\n  second line", "row")])
        self.assertEqual([r["t"] for r in runs["runs"] if r["k"] == "raw"], ["first line", "second line"])
        self.assertEqual(runs["matched"][0]["how"], "lines")

    def test_dashboard_routes(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except Exception as e:  # pragma: no cover
            self.skipTest(f"fastapi unavailable: {e}")
        import os
        from unittest import mock
        home = Path(self.tmp.name) / "home"
        (home / "plugin-data" / "wiretap").mkdir(parents=True, exist_ok=True)
        tdb = home / "plugin-data" / "wiretap" / "telemetry.db"
        disk = sqlite3.connect(tdb)
        self.tcon.backup(disk)
        disk.close()
        (home / "state.db").write_bytes(self.db.read_bytes())
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(home), "TELEMETRY_DB": str(tdb), "MAIN_SESSION": ""}):
            spec = importlib.util.spec_from_file_location("_mt_wire_view_api", HERE / "dashboard" / "plugin_api.py")
            api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(api)
            app = FastAPI()
            app.include_router(api.router, prefix="/w")
            c = TestClient(app)
            comp = c.get("/w/inspector/compiled", params={"id": SID, "call": "call-one"}).json()
            self.assertEqual((comp["call_id"], comp["historic"]), ("call-one", True))
            rd = c.get("/w/inspector/wire/readable", params={"id": "call-two", "i": 0, "rows": "1"}).json()
            self.assertEqual([r["t"] for r in rd["segments"][0]["runs"] if r["k"] == "raw"], [ASK])
            self.assertEqual(c.get("/w/inspector/wire/readable", params={"id": "call-two", "i": 99}).status_code, 404)


if __name__ == "__main__":
    unittest.main()
