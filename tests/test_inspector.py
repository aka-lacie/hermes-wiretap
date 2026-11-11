"""Collector + inspector + dashboard API, end to end against a synthetic profile and cliproxy log dir.

Covers the contracts the UI depends on: wire payloads survive log rotation and dedupe across calls, every
transcript row gets its true provenance, assistant rows correlate to the call that produced them, replay
framing is reported per row, fabricated continuations are flagged, and the read-only API serves all of it.
"""
import importlib.util
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent

SESSION = "20261104_100000_main01"


def _ts(epoch: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000000+00:00")


def _gemini_log(path: Path, t0: float, contents: list, parts: list, prompt: int, cached: int) -> None:
    body = json.dumps({"contents": contents, "systemInstruction": {"parts": [{"text": "SOUL"}]},
                       "tools": [{"functionDeclarations": [{"name": "delegate_task"}]}],
                       "generationConfig": {"temperature": 1}})
    up = json.loads(body)
    up["model"] = "gemini-2.5-pro"
    chunks = [json.dumps({"candidates": [{"content": {"role": "model", "parts": [p]}}], "modelVersion": "gemini-2.5-pro"})
              for p in parts]
    chunks.append(json.dumps({"candidates": [{"content": {"role": "model", "parts": [{"text": ""}]}, "finishReason": "STOP"}],
                              "usageMetadata": {"promptTokenCount": prompt, "cachedContentTokenCount": cached,
                                                "candidatesTokenCount": 9}, "modelVersion": "gemini-2.5-pro"}))
    data = "\n\n".join("data: " + c for c in chunks)
    path.write_text("\n".join([
        "=== REQUEST INFO ===", "URL: /v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
        f"Timestamp: {_ts(t0)}", "", "=== HEADERS ===", "User-Agent: test-client", "X-Api-Key: secret-down", "",
        "=== REQUEST BODY ===", body, "",
        "=== API REQUEST 1 ===", f"Timestamp: {_ts(t0 + 0.1)}",
        "Upstream URL: https://aiplatform.example/v1/projects/proj-a/locations/global/x",
        "Auth: provider=gemini, auth_id=k1, label=vertex, type=api_key value=AIzaXXXX1234", "", "Headers:",
        "Authorization: Bearer secret-up", "Content-Type: application/json", "", "Body:", json.dumps(up), "",
        "=== API RESPONSE 1 ===", f"Timestamp: {_ts(t0 + 2)}", "", "Status: 200", "", "Body:", data, "",
        "=== RESPONSE ===", "Status: 200", "Content-Type: text/event-stream", "", data, ""]))
    os.utime(path, (t0 + 3, t0 + 3))


def _state_db(path: Path, rows: list) -> None:
    con = sqlite3.connect(path)
    con.executescript("""
    CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, title TEXT, parent_session_id TEXT,
      created_source TEXT, hidden INTEGER, started_at REAL, last_activity_at REAL, message_count INTEGER,
      billing_provider TEXT, session_key TEXT, chat_type TEXT, model_config TEXT, api_call_count INTEGER,
      input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER, cache_write_tokens INTEGER,
      reasoning_tokens INTEGER, estimated_cost_usd REAL);
    CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, api_content TEXT,
      tool_call_id TEXT, tool_calls TEXT, tool_name TEXT, timestamp REAL, finish_reason TEXT, reasoning TEXT,
      reasoning_content TEXT, platform_message_id TEXT, active INTEGER, compacted INTEGER, display_kind TEXT,
      display_metadata TEXT, _compressed_summary INTEGER, token_count INTEGER, message_uid TEXT, display_identity BLOB);
    """)
    con.execute("INSERT INTO sessions (id, source, model, title, started_at, last_activity_at, message_count) "
                "VALUES (?,?,?,?,?,?,?)", (SESSION, "discord", "gemini-2.5-pro", "Bot Chat", 1.0, time.time(), len(rows)))
    con.execute("INSERT INTO sessions (id, source, started_at, last_activity_at) VALUES ('sub1','subagent',1,?)",
                (time.time() + 5,))
    for r in rows:
        r = {"session_id": SESSION, "active": 1, "compacted": 0, "_compressed_summary": 0, **r}
        con.execute(f"INSERT INTO messages ({','.join(r)}) VALUES ({','.join('?' * len(r))})", list(r.values()))
    con.commit()
    con.close()


class InspectorEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.home, cls.logs = root / "home", root / "logs"
        cls.home.mkdir()
        cls.logs.mkdir()
        now = time.time() - 600
        notice = "[ASYNC DELEGATION BATCH COMPLETE — deleg_aaaa1111]\nA background unit finished."
        user_text = "can you check the wire framing?"
        t_user, t_a1, t_notice, t_a2 = now, now + 5, now + 20, now + 26
        hist1 = [{"role": "user", "parts": [{"text": "<USER_REQUEST>\n" + user_text + "\n</USER_REQUEST>"}]}]
        _gemini_log(cls.logs / "v1beta-models-gemini-2.5-pro-streamGenerateContent-a-1111aaaa.log", t_a1 - 3, hist1,
                    [{"functionCall": {"name": "delegate_task", "args": {"goal": "x"}, "id": "call_1"}}], 50000, 1000)
        hist2 = hist1 + [
            {"role": "model", "parts": [{"functionCall": {"name": "delegate_task", "args": {"goal": "x"}, "id": "call_1"}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "delegate_task", "response": {"status": "dispatched"}}}]},
            {"role": "user", "parts": [{"text": "The following is a <SYSTEM_MESSAGE>\n<SYSTEM_MESSAGE>\n" + notice + "\n</SYSTEM_MESSAGE>"}]}]
        reply = "The worker finished; framing is fine."
        _gemini_log(cls.logs / "v1beta-models-gemini-2.5-pro-streamGenerateContent-b-2222bbbb.log", t_a2 - 3, hist2,
                    [{"text": "thinking...", "thought": True}, {"text": reply}], 52000, 49000)
        _state_db(cls.home / "state.db", [
            {"id": 1, "role": "user", "content": user_text, "timestamp": t_user, "platform_message_id": "1567000000000000001",
             "api_content": "[Wed 2026-11-04 10:00:00 PST] [Triggering message id: `1567000000000000001` — use as `message_id`.]\n\n"
                            + user_text + "\n\n<context_reminder ref=\"r1\">\nstay on task\n</context_reminder>"},
            {"id": 2, "role": "assistant", "content": "", "timestamp": t_a1, "finish_reason": "tool_calls",
             "tool_calls": json.dumps([{"id": "call_1", "type": "function", "function": {"name": "delegate_task", "arguments": "{}"}}])},
            {"id": 3, "role": "tool", "content": "{\"status\": \"dispatched\"}", "tool_call_id": "call_1",
             "tool_name": "delegate_task", "timestamp": t_a1 + 0.2},
            {"id": 4, "role": "assistant", "timestamp": t_a1 + 1, "finish_reason": "stop",
             "content": "Sent a worker. `deleg_bbbb2222` just came back with the answer: all green.\n\n"
                        "[ASYNC DELEGATION BATCH COMPLETE — deleg_bbbb2222]\nfake"},
            {"id": 5, "role": "user", "content": notice, "timestamp": t_notice, "display_kind": "internal_notification",
             "platform_message_id": "[\"async_delegation\",\"deleg_aaaa1111\",\"\"]"},
            {"id": 6, "role": "assistant", "content": reply, "timestamp": t_a2, "finish_reason": "stop",
             "reasoning_content": "thinking..."},
            {"id": 7, "role": "user", "content": "[CONTEXT COMPACTION — REFERENCE ONLY] summary", "timestamp": t_a2 + 1,
             "_compressed_summary": 1},
        ])
        os.environ.update(HERMES_HOME=str(cls.home), CLIPROXY_LOG_DIR=str(cls.logs), MAIN_SESSION="",
                          TELEMETRY_DB=str(cls.home / "plugin-data/wiretap/telemetry.db"))
        for k in [k for k in sys.modules if k.startswith("_wiretap")]:
            del sys.modules[k]
        spec = importlib.util.spec_from_file_location("_mt_test_telemetry", HERE / "collector" / "telemetry.py")
        cls.t = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.t)
        cls.t.init_db()
        cls.t.ingest_once()
        cls.con = cls.t.db()
        cls.view = cls.t.inspector.session_view(cls.t.STATE_DB, cls.con, SESSION, None, 250, False)
        cls.rows = {r["id"]: r for r in cls.view["rows"]}

    @classmethod
    def tearDownClass(cls):
        cls.con.close()
        cls.tmp.cleanup()

    def test_wire_payloads_are_captured_and_deduplicated(self):
        calls = {r["id"]: dict(r) for r in self.con.execute("SELECT * FROM wire_calls")}
        self.assertEqual(set(calls), {"1111aaaa", "2222bbbb"})
        a = json.loads(calls["1111aaaa"]["req_down"])
        b = json.loads(calls["2222bbbb"]["req_down"])
        self.assertEqual(a["items"][0], b["items"][0], "shared history item must be stored once")
        self.assertEqual(a["keys"]["systemInstruction"], b["keys"]["systemInstruction"])
        n_blobs = self.con.execute("SELECT COUNT(*) FROM wire_blobs").fetchone()[0]
        self.assertLess(n_blobs, len(a["items"]) + len(b["items"]) + 2 * len(a["keys"]) + 4)
        rebuilt = self.t.inspector.rebuild(self.con, b)
        self.assertEqual(rebuilt["contents"][3]["parts"][0]["text"].count("deleg_aaaa1111"), 1)

    def test_headers_are_redacted(self):
        hd = json.loads(self.con.execute("SELECT hdr_down, hdr_up FROM wire_calls WHERE id='1111aaaa'").fetchone()[0])
        hu = json.loads(self.con.execute("SELECT hdr_up FROM wire_calls WHERE id='1111aaaa'").fetchone()[0])
        self.assertNotIn("secret-down", json.dumps(hd))
        self.assertNotIn("secret-up", json.dumps(hu))
        self.assertEqual(hu["Content-Type"], "application/json")

    def test_rows_get_true_provenance(self):
        self.assertEqual(self.rows[1]["label"], "USER · discord")
        self.assertEqual(self.rows[5]["kind"], "subagent")
        self.assertEqual(self.rows[7]["kind"], "compaction")
        self.assertEqual(self.rows[3]["kind"], "tool")

    def test_assistant_rows_correlate_to_their_wire_call(self):
        self.assertEqual(self.rows[2]["wire"], "1111aaaa")  # by tool-call id
        self.assertEqual(self.rows[6]["wire"], "2222bbbb")  # by response text
        self.assertIsNone(self.rows[4].get("wire"), "a row no call produced must not be matched")

    def test_replay_framing_is_reported(self):
        self.assertEqual(self.rows[1]["framing"]["first"]["framing"], "USER_REQUEST")
        self.assertEqual(self.rows[5]["framing"]["first"]["framing"], "SYSTEM_MESSAGE")

    def test_injected_blocks_are_diffed(self):
        inj = self.rows[1]["inject"]
        self.assertTrue(inj["identical_core"])
        self.assertIn("context_reminder", inj["blocks"])
        self.assertIn("triggering_message_id", inj["blocks"])

    def test_fabricated_continuation_is_flagged(self):
        flags = " ".join(self.rows[4]["flags"])
        self.assertIn("deleg_bbbb2222", flags)
        self.assertIn("internal-turn header", flags)
        self.assertEqual(self.rows[6]["flags"], [], "a reply after a real completion row is not flagged")

    def test_main_session_autodetects_human_chat(self):
        self.assertEqual(self.t.main_session(), SESSION)

    def test_adapter_wrapped_split_and_folded_items_align(self):
        """agy-shaped wire: USER_REQUEST + ADDITIONAL_METADATA, its split-out SYSTEM_MESSAGE, grouped tool results,
        a notice folded into a tool result — every item gets its row(s), none by guessing on wrapper text."""
        ins = self.t.inspector
        put = lambda obj: ins.put_blob(self.con, obj)  # noqa: E731
        rows = [
            {"id": 10, "role": "user", "label": "USER · discord", "kind": "user", "platform_message_id": "1567000000000000111",
             "content": "[Wed 2026-11-04 18:02:35 PST] [Triggering message id: `1567000000000000111` — use as `message_id`.]\n\n"
                        "why are the tags gone?\n\n[Image attached at: /tmp/x.jpeg]\n[screenshot]\n\n"
                        "[Runtime reminder] Prioritize the user input and incorporate relevant task results."},
            {"id": 11, "role": "assistant", "label": "ASSISTANT", "kind": "assistant", "content": "", "tool_ids": ["call_a", "call_b"]},
            {"id": 12, "role": "tool", "label": "TOOL RESULT", "kind": "tool", "tool_call_id": "call_a", "content": "{}"},
            {"id": 13, "role": "tool", "label": "TOOL RESULT", "kind": "tool", "tool_call_id": "call_b", "content": "{}"},
            {"id": 14, "role": "user", "label": "INTERNAL · SUBAGENT COMPLETION", "kind": "subagent",
             "platform_message_id": '["async_delegation","deleg_abcdef12",""]',
             "content": "[ASYNC DELEGATION BATCH COMPLETE — deleg_abcdef12]\nA unit finished."},
        ]
        items = [
            {"i": 0, "h": put({"role": "user", "parts": [{"text": "<USER_REQUEST>\nwhy are the tags gone?\n</USER_REQUEST>\n"
                     "<ADDITIONAL_METADATA>\nThe current local time is: Wed 2026-11-04 18:02:35 PST.\n"
                     "Discord message_id (use for reply/react/pin via the discord tools): 1567000000000000111\n</ADDITIONAL_METADATA>"},
                     {"inlineData": {"mimeType": "image/png", "data": "AAAA"}}]})},
            {"i": 1, "h": put({"role": "user", "parts": [{"text": "The following is a <SYSTEM_MESSAGE> ...\n<SYSTEM_MESSAGE>\n[Message] "
                     "sender=system content=Prioritize the user input and incorporate relevant task results.\n</SYSTEM_MESSAGE>"}]})},
            {"i": 2, "h": put({"role": "model", "parts": [{"functionCall": {"name": "a", "args": {}, "id": "call_a"}},
                                                          {"functionCall": {"name": "b", "args": {}, "id": "call_b"}}]})},
            {"i": 3, "h": put({"role": "user", "parts": [
                {"functionResponse": {"name": "a", "id": "call_a", "response": {"output": "ok"}}},
                {"functionResponse": {"name": "b", "id": "call_b", "response": {"output": "ok\n\n<SYSTEM_MESSAGE>\n"
                                      "[ASYNC DELEGATION BATCH COMPLETE — deleg_abcdef12]\nA unit finished.\n</SYSTEM_MESSAGE>"}}}]})},
        ]
        for it in items:
            role, txt, fr = ins.item_norm(self.con, it["h"])
            it.update(role=role, framing=fr, head=txt[:220])
        ins.align_items(self.con, self.t.STATE_DB, SESSION, rows, items)
        got = [(it.get("row_ids"), it.get("align")) for it in items]
        self.assertEqual(got[0], ([10], "id"))
        self.assertEqual(got[1], ([10], "context of previous row"))
        self.assertEqual(got[2][0], [11])
        self.assertEqual(sorted(got[3][0]), [12, 13, 14], "grouped results + the folded notice")

        # An adapter this plugin has never seen: its own wrapper syntax, the id in its own metadata field,
        # the gateway header dropped. Alignment only relies on what Hermes recorded for the rows.
        items2 = [
            {"i": 0, "h": put({"role": "human", "content": "### turn\n>> why are the tags gone? <<\n(meta ref=1567000000000000111)"})},
            {"i": 1, "h": put({"role": "human", "content": "::note:: [ASYNC DELEGATION BATCH COMPLETE — deleg_abcdef12]\nA unit finished. ::end::"})},
        ]
        for it in items2:
            role, txt, fr = ins.item_norm(self.con, it["h"])
            it.update(role=role, framing=fr, head=txt[:220])
        ins.align_items(self.con, self.t.STATE_DB, SESSION, rows, items2)
        self.assertEqual([it.get("row_ids") for it in items2], [[10], [14]])
        # these blobs belong to no capture; keep the shared store's blob accounting clean for the other tests
        hs = [it["h"] for it in items + items2]
        self.con.execute(f"DELETE FROM wire_blobs WHERE h IN ({','.join('?' * len(hs))})", hs)
        self.con.commit()

    def test_one_pass_phrase_matcher_equals_substring_search(self):
        """_Probes.find == {k: p in text} for normalized strings (probes of >= 3 words; 1–2-word probes are
        whole-word by design), on randomized texts with partial-word edges and repeats."""
        import random
        ins = self.t.inspector
        rnd = random.Random(7)
        vocab = ["a", "ab", "abc", "the", "of", "x_y", "deleg_1", "<tag>", "</tag>", "—", "é", "USER", "call_9"]
        for _ in range(300):
            text = " ".join(rnd.choice(vocab) for _ in range(rnd.randint(0, 40)))
            probes = []
            for k in range(12):
                if text and rnd.random() < 0.6:  # a real slice of the text (cut anywhere) or a random phrase
                    a = rnd.randrange(len(text)); b = min(len(text), a + rnd.randint(1, 30))
                    p = ins.norm(text[a:b])
                else:
                    p = " ".join(rnd.choice(vocab) for _ in range(rnd.randint(1, 8)))
                if len(p.split(" ")) >= 3 and not p.startswith(" "):
                    probes.append((k, p))
            want = {k for k, p in probes if p in text}
            self.assertEqual(ins._Probes(probes).find(text), want, (text, probes))

    def test_linear_tag_scan_equals_the_regex(self):
        import random
        ins = self.t.inspector
        rnd = random.Random(3)
        parts = ["<a>", "</a>", "<ab>", "</ab>", "<ab-c x=1>", "</ab-c>", "<ab->", "</ab->", "<USER_REQUEST>", "</USER_REQUEST>",
                 "<b:c>", "</b:c>", "<a <b>", "txt", " ", "\n", "<", ">", "<abcd_e>", "</abcd>", "</abcd_e>"]
        for _ in range(2000):
            s = "".join(rnd.choice(parts) for _ in range(rnd.randint(0, 25)))
            self.assertEqual(ins._tag_blocks(s), [m.group(1) for m in ins.TAG_BLOCK_RE.finditer(s)], s)

    def test_responses_reasoning_items_fold_into_their_turn(self):
        ins = self.t.inspector
        put = lambda obj: ins.put_blob(self.con, obj)  # noqa: E731
        objs = [{"role": "user", "content": [{"type": "input_text", "text": "fix it"}]},
                {"type": "reasoning", "encrypted_content": "gAAAA" * 40, "summary": []},
                {"type": "reasoning", "encrypted_content": "gAAAB" * 10, "summary": [{"type": "summary_text", "text": "Plan: read the file."}]},
                {"type": "function_call", "call_id": "call_r1", "name": "read_file", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "call_r1", "output": "ok"},
                {"type": "reasoning", "encrypted_content": "gAAAC", "summary": []},
                {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "All done, the file is fixed."}]}]
        items = []
        for n, o in enumerate(objs):
            h = put(o)
            role, txt, fr = ins.item_norm(self.con, h)
            items.append({"i": n, "h": h, "role": role, "framing": fr, "head": txt[:200]})
        rows = [{"id": 1, "role": "user", "label": "USER", "kind": "user", "content": "fix it"},
                {"id": 2, "role": "assistant", "label": "ASSISTANT", "kind": "assistant", "content": "", "tool_ids": ["call_r1"]},
                {"id": 3, "role": "tool", "label": "TOOL RESULT", "kind": "tool", "tool_call_id": "call_r1", "content": "ok"},
                {"id": 4, "role": "assistant", "label": "ASSISTANT", "kind": "assistant", "content": "All done, the file is fixed."}]
        ins.align_items(self.con, self.t.STATE_DB, SESSION, rows, items)
        ins.fold_reasoning(self.con, items)
        hs = [it["h"] for it in items]
        self.con.execute(f"DELETE FROM wire_blobs WHERE h IN ({','.join('?' * len(hs))})", hs)
        self.con.commit()
        self.assertEqual([it.get("folded_into") for it in items], [None, 3, 3, None, None, 6, None])
        self.assertEqual([x["i"] for x in items[3]["reasoning"]], [1, 2])
        self.assertEqual((items[3]["reasoning"][0]["encrypted_chars"], items[3]["reasoning"][1]["summary"]), (200, "Plan: read the file."))
        self.assertEqual([it.get("row_id") for it in items], [1, 2, 2, 2, 3, 4, 4], "reasoning aligned via its turn")

    def test_linear_no_reply_check_matches_the_regex(self):
        ins = self.t.inspector
        rx = re.compile(r"\S[\s\S]{20,}\bNO_REPLY\s*$")
        samples = ["NO_REPLY", "  NO_REPLY  ", "ok NO_REPLY", "x" * 30 + "NO_REPLY", "x" * 30 + " NO_REPLY",
                   "Sounds good, I'll handle it.\n\nNO_REPLY\n", " \n" + "a" * 20 + " NO_REPLY", " \n" + "a" * 21 + " NO_REPLY",
                   "a" * 40 + " NO_REPLY trailing", "a" * 40 + "\nNO_REPLY_x", "é" * 30 + "NO_REPLY", "a" * 25 + "-NO_REPLY"]
        for s in samples:
            self.assertEqual(ins._trailing_no_reply(s), bool(rx.search(s)), repr(s))

    def test_views_are_memoized_until_the_wire_store_changes(self):
        ins = self.t.inspector
        a = ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        b = ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertIs(a["wire"], b["wire"], "unchanged inputs: served from the memo")
        rev = ins.store.wire_rev(self.con)
        ins.store.upsert(self.con, {"id": a["call_id"], "status": 200}, "wire_calls")
        self.assertNotEqual(ins.store.wire_rev(self.con), rev)
        c = ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertIsNot(c["wire"], a["wire"], "a wire_calls write invalidates")
        self.assertEqual(c["call_id"], a["call_id"])

    def test_compiled_view_is_the_latest_wire_request_aligned_to_rows(self):
        c = self.t.inspector.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertEqual(c["call_id"], "2222bbbb")
        self.assertEqual(c["system"]["key"], "systemInstruction")
        self.assertEqual(c["tool_names"], ["delegate_task"])
        rows = [it.get("row_id") for it in c["wire"]["items"]]
        # user turn by text, text-less tool call + tool result positionally, notice by text; the fabricated row 4 never
        # reached the wire, so nothing aligns to it
        self.assertEqual(rows, [1, 2, 3, 5])
        self.assertEqual([it["framing"] for it in c["wire"]["items"]][-1], "SYSTEM_MESSAGE")
        after = {r["id"] for r in c["rows_after"]}
        self.assertEqual(after, {6, 7}, "rows written after the request are reported as not yet on the wire")
        self.assertEqual(c["rows_unmapped"], 1)

    def test_dashboard_api_serves_views(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except Exception as e:  # pragma: no cover - plain-python runs
            self.skipTest(f"fastapi unavailable: {e}")
        spec = importlib.util.spec_from_file_location("_mt_test_api", HERE / "dashboard" / "plugin_api.py")
        api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(api)
        app = FastAPI()
        app.include_router(api.router, prefix="/api/plugins/wiretap")
        c = TestClient(app)
        h = c.get("/api/plugins/wiretap/health").json()
        self.assertTrue(h["db_exists"])
        self.assertEqual(h["wire_calls"], 2)
        s = c.get("/api/plugins/wiretap/inspector/session").json()
        self.assertEqual(s["session"]["id"], SESSION)
        w = c.get("/api/plugins/wiretap/inspector/wire", params={"id": "2222bbbb"}).json()
        self.assertEqual([x["framing"] for x in w["items"]][-1], "SYSTEM_MESSAGE")
        self.assertEqual(w["response"]["text"], "The worker finished; framing is fine.")
        item = c.get("/api/plugins/wiretap/inspector/wire/part", params={"id": "2222bbbb", "part": "item", "i": 0}).json()
        self.assertEqual(item["role"], "user")
        self.assertEqual(c.get("/api/plugins/wiretap/inspector/wire/part",
                               params={"id": "2222bbbb", "part": "item", "i": 99}).status_code, 404)
        calls = c.get("/api/plugins/wiretap/calls", params={"hours": 2}).json()
        self.assertEqual(len(calls["rows"]), 2)
        self.assertEqual(c.get("/api/plugins/wiretap/inspector/row", params={"id": 4}).json()["class"]["kind"], "assistant")


if __name__ == "__main__":
    unittest.main()
