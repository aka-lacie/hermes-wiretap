"""Outer-message structural validation rejects flattened compressor sidecars without losing adapter transforms."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


class CaptureStructureTest(unittest.TestCase):
    def setUp(self):
        name = "_mt_structure_capture"
        spec = importlib.util.spec_from_file_location(name, HERE / "collector/capture.py")
        assert spec and spec.loader
        cap = importlib.util.module_from_spec(spec)
        sys.modules[name] = cap
        spec.loader.exec_module(cap)
        self.cap = cap
        self.con = cap.store.memory_store()
        self.addCleanup(self.con.close)
        self.addCleanup(cap._writer.stop)
        self.messages = [{"role": "user", "content": "older user context " * 40},
                         {"role": "assistant", "content": "older assistant context " * 40},
                         {"role": "user", "content": "Please analyze the subtle database locking behavior and explain what happened."}]

    def arm(self, messages=None, tools=0):
        self.cap._arm("main", {"base_url": "https://fixture.example/v1", "request_messages": messages or self.messages,
                               "request_char_count": 1500, "tool_count": tools})
        arm = self.cap._ARMED_BY_ID["main"]
        self.cap._ARMED.set(None)
        return arm

    def validate(self, arm, body):
        ref = self.cap.inspector.itemize(self.con, json.dumps(body))
        return self.cap._validated(self.con, arm, ref)

    def test_flattened_three_message_transcript_is_not_the_main_request_or_credential(self):
        import httpx
        arm = self.arm()
        side = {"model": "gpt-test", "messages": [{"role": "user", "content":
            "Compress this conversation into a short summary:\n" + json.dumps(self.messages) + "\nReturn only the summary."}]}
        data = json.dumps(side).encode()
        self.assertIs(self.cap._armed_for("fixture.example", data), arm, "signature selection alone is not identity")
        self.assertTrue(self.cap._is_this_call(arm, len(data)), "the old coarse size guard allows this regression")
        self.assertIn("structure", self.validate(arm, side))
        self.cap.store.upsert(self.con, {"id": "main", "source": "hermes", "provider": "fixture"}, "calls")
        writer = SimpleNamespace(submit=lambda job: job(self.con))
        with mock.patch.object(self.cap, "_writer", writer), mock.patch.object(self.cap, "credential_identity", return_value=("SIDE", "api_key")):
            self.cap.on_http_request(httpx.Request("POST", "https://fixture.example/v1/chat/completions", json=side))
            row = self.con.execute("SELECT w.exact,w.tap_miss,c.auth_key FROM wire_calls w JOIN calls c ON c.id=w.id WHERE w.id='main'").fetchone()
            self.assertNotEqual(row[0], 1)
            self.assertIn("structure", row[1])
            self.assertIsNone(row[2], "sidecar credential never lands on the main call")
            self.cap.on_http_request(httpx.Request("POST", "https://fixture.example/v1/chat/completions",
                                                 json={"model": "gpt-test", "messages": self.messages}))
        row = self.con.execute("SELECT exact,n_items,tap_miss FROM wire_calls WHERE id='main'").fetchone()
        self.assertEqual(tuple(row), (1, 3, None), "rejecting the sidecar leaves the genuine request eligible")

    def test_normal_multiturn_claude_gemini_codex_transforms_all_validate(self):
        source = [{"role": "system", "content": "system instructions"}, *self.messages]
        arm = self.arm(source)
        claude = {"system": "system instructions", "messages": [
            {"role": m["role"], "content": [{"type": "text", "text": m["content"]}]} for m in self.messages]}
        gemini = {"systemInstruction": {"parts": [{"text": "system instructions"}]}, "contents": [
            {"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]} for m in self.messages]}
        codex = {"instructions": "system instructions", "input": [
            {"type": "message", "role": m["role"], "content": [{"type": "output_text" if m["role"] == "assistant" else "input_text", "text": m["content"]}]}
            for m in self.messages]}
        codex["input"].insert(1, {"type": "reasoning", "id": "rs_history_123456", "encrypted_content": "opaque"})
        for name, body in [("claude", claude), ("gemini", gemini), ("codex", codex)]:
            with self.subTest(provider=name):
                self.assertIsNone(self.validate(arm, body))

    def test_same_speaker_merging_is_allowed(self):
        messages = [self.messages[0], {"role": "user", "content": "additional context"}, *self.messages[1:]]
        arm = self.arm(messages)
        merged = [{"role": "user", "content": [{"type": "text", "text": messages[0]["content"]},
                                                 {"type": "text", "text": messages[1]["content"]}]}, *messages[2:]]
        self.assertIsNone(self.validate(arm, {"messages": merged}))

    def test_tools_must_survive_a_tool_enabled_call(self):
        arm = self.arm(tools=1)
        self.assertIn("schemas", self.validate(arm, {"messages": self.messages}))
        self.assertIsNone(self.validate(arm, {"messages": self.messages, "tools": [{"name": "read_file"}]}))
        self.assertIsNone(self.validate(arm, {"messages": self.messages, "functions": [{"name": "read_file"}]}))

    def test_signed_item_role_and_bounded_size_relation(self):
        arm = self.arm()
        wrong_role = self.messages[:-1] + [{"role": "assistant", "content": self.messages[-1]["content"]}]
        self.assertIsNotNone(self.validate(arm, {"messages": wrong_role}))
        inflated = self.messages[:-1] + [{"role": "user", "content": "preamble " * 1200 + self.messages[-1]["content"]}]
        self.assertIn("expansion", self.validate(arm, {"messages": inflated}))

    def test_tool_result_adapter_roles_are_equivalent(self):
        source = [{"role": "system", "content": "sys"}, {"role": "user", "content": "Please inspect the result carefully and continue."},
                  {"role": "assistant", "content": "", "tool_calls": [{"id": "call_abcdefgh1234", "function": {"name": "read_file", "arguments": "{}"}}]},
                  {"role": "tool", "tool_call_id": "call_abcdefgh1234", "content": "result"}]
        arm = self.arm(source, tools=1)
        claude = {"system": "sys", "tools": [{"name": "read_file"}], "messages": [source[1],
            {"role": "assistant", "content": [{"type": "tool_use", "id": "call_abcdefgh1234", "name": "read_file", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "call_abcdefgh1234", "content": "result"}]}]}
        codex = {"instructions": "sys", "tools": [{"type": "function", "name": "read_file"}], "input": [source[1],
            {"type": "function_call", "call_id": "call_abcdefgh1234", "name": "read_file", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "call_abcdefgh1234", "output": "result"}]}
        gemini = {"systemInstruction": {"parts": [{"text": "sys"}]}, "tools": [{"functionDeclarations": [{"name": "read_file"}]}], "contents": [
            {"role": "user", "parts": [{"text": source[1]["content"]}]},
            {"role": "model", "parts": [{"functionCall": {"id": "call_abcdefgh1234", "name": "read_file", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"id": "call_abcdefgh1234", "name": "read_file", "response": {"result": "result"}}}]}]}
        for name, body in [("claude", claude), ("gemini", gemini), ("codex", codex)]:
            with self.subTest(provider=name):
                self.assertIsNone(self.validate(arm, body))


if __name__ == "__main__":
    unittest.main()
