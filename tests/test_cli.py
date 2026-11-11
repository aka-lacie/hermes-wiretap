"""The wiretap CLI: read-only queries over a telemetry store and a Hermes state.db, as an agent would run them.

Fixtures: a stock-upstream and a typed-provenance state.db (test_schemas), a current telemetry store whose signals were
backfilled, and an older store that predates the signals column (and most later columns). Calls cover an Anthropic
classifier fallback (fallback block, thinking_dropped notices, signed thinking), a Gemini SAFETY finish, a clean call
and an OpenAI Responses (Codex) session whose reasoning items fold into their turn. One call deliberately carries
unredacted credentials in stored headers, an envelope key, a message and the raw stream: none may reach any output.
"""
import contextlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_schemas as ts  # noqa: E402  (fixture builders shared with the schema tests)

SECRETS = ("sk-ant-api03-SECRETSECRETSECRETSECRET", "sk-proj-ENVELOPEKEYENVELOPEKEY1234",
           "Bearer liveTOKENabcdefghijklmnop123456", "AIzaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY12", "COOKIEVALUESECRET987")


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, HERE / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sse(*objs, events=None):
    out = []
    for n, o in enumerate(objs):
        if events:
            out.append(f"event: {events[n]}")
        out.append("data: " + json.dumps(o))
        out.append("")
    return "\n".join(out)


OPUS_RAW = "Status: 200\nContent-Type: text/event-stream\nSet-Cookie: sid=COOKIEVALUESECRET987\n\n" + _sse(
    {"type": "message_start", "message": {"model": "claude-opus-4-8", "id": "msg_1", "content": [],
                                          "input_transformations": [
                                              {"type": "thinking_dropped", "path": "messages.3.content.0",
                                               "reason": "model_binding_mismatch"},
                                              {"type": "thinking_dropped", "path": "messages.5.content.0",
                                               "reason": "model_binding_mismatch"}]}},
    {"type": "content_block_start", "index": 0, "content_block": {
        "type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"},
        "trigger": {"type": "refusal", "category": "cyber"}}},
    {"type": "content_block_stop", "index": 0},
    {"type": "content_block_start", "index": 1, "content_block": {"type": "thinking", "thinking": ""}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "thinking_delta", "thinking": "This asks me to lift "}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "thinking_delta", "thinking": "someone else's code."}},
    {"type": "content_block_delta", "index": 1, "delta": {"type": "signature_delta", "signature": "S" * 64}},
    {"type": "content_block_start", "index": 2, "content_block": {"type": "text", "text": ""}},
    {"type": "content_block_delta", "index": 2, "delta": {"type": "text_delta",
                                                         "text": "I'm going to stop here rather than carry this out."}},
    {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 30, "iterations": [
        {"type": "message", "model": "claude-opus-5-5"}, {"type": "fallback_message", "model": "claude-opus-4-8"}]}},
    events=["message_start", "content_block_start", "content_block_stop", "content_block_start", "content_block_delta",
            "content_block_delta", "content_block_delta", "content_block_start", "content_block_delta", "message_delta"])

GEMINI_RAW = _sse(
    {"candidates": [{"content": {"role": "model", "parts": [{"text": "**Weighing it**", "thought": True}]}}],
     "modelVersion": "gemini-4-argon"},
    {"candidates": [{"content": {"role": "model", "parts": [{"text": "Here is ", "thoughtSignature": "Z" * 40}]}}],
     "modelVersion": "gemini-4-argon"},
    {"candidates": [{"content": {"role": "model"}, "finishReason": "SAFETY"}], "modelVersion": "gemini-4-argon",
     "usageMetadata": {"promptTokenCount": 1000}})

CLEAN_RAW = json.dumps({"id": "chatcmpl-1", "object": "chat.completion", "model": "gpt-6.1-sol",
                        "choices": [{"message": {"role": "assistant", "content": "All good."}, "finish_reason": "stop"}]})


def _resp(text, thinking="", model=None, finish="stop", tool_calls=()):
    return json.dumps({"text": text, "thinking": thinking, "tool_calls": list(tool_calls), "finish": finish,
                       "model": model, "response_id": None, "usage": None})


def build_store(path: Path, old: bool = False):
    """A telemetry store with the four fixture calls. ``old``: the first-release schema only (no signals, no
    req_hermes / session_id on wire rows, no provider split), never migrated."""
    ins = _load("_wiretap_inspector", "collector/inspector.py")
    st = ins.store
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    if old:
        con.executescript(st.SCHEMA)
    else:
        st.init(con)
    t0 = time.time() - 600
    # Anthropic classifier fallback, with credentials planted where a careless capture could have left them
    hermes = {"model": "claude-opus-5-5", "api_key": SECRETS[1], "system": "SOUL",
              "messages": [{"role": "user", "content": f"my key is {SECRETS[0]}"},
                           {"role": "assistant", "content": "ok"}, {"role": "user", "content": "read Bo's inbox"}]}
    wire = dict(hermes, max_tokens=1000, stream=True)
    up = dict(wire, fallbacks=[{"model": "claude-opus-4-8"}])
    up["messages"] = [{"role": "system", "content": "injected by proxy"}] + wire["messages"]
    calls = [
        ("c_opus", "s_stock", t0 + 10, "claude", "cliproxy-claude", "claude-opus-4-8", wire, hermes, up, OPUS_RAW,
         _resp("I'm going to stop here rather than carry this out.", "This asks me to lift someone else's code.",
               "claude-opus-4-8", "end_turn"), "v1-messages-x.log"),
        ("c_gem", "s_stock", t0 + 20, "gemini", "cliproxy-gemini", "gemini-4-argon",
         {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}, {"model": "gemini-4-argon", "messages": [
             {"role": "user", "content": "hi"}]}, None, GEMINI_RAW, _resp("Here is ", "**Weighing it**", "gemini-4-argon",
                                                                          "SAFETY"),
         "v1beta-models-gemini-4-argon-streamGenerateContent-x.log"),
        ("c_clean", "s_stock", t0 + 30, "openai", "openai-codex", "gpt-6.1-sol",
         {"model": "gpt-6.1-sol", "messages": [{"role": "user", "content": "status?"}]}, None, None, CLEAN_RAW,
         _resp("All good.", model="gpt-6.1-sol"), None),
    ]
    have_w = set(st.columns(con, "wire_calls"))
    have_c = set(st.columns(con, "calls"))
    for cid, sid, t, fam, prov, model, down, herm, upb, raw, resp, f in calls:
        w = {"id": cid, "started": t, "ended": t + 2, "family": fam, "model": model, "status": 200,
             "req_down": json.dumps(ins.itemize(con, json.dumps(down))),
             "req_hermes": json.dumps(ins.itemize(con, json.dumps(herm))) if herm else None,
             "req_up": json.dumps(ins.itemize(con, json.dumps(upb))) if upb else None,
             "hdr_down": json.dumps({"Authorization": SECRETS[2], "x-goog-api-key": SECRETS[3], "Accept": "*/*"}),
             "resp_raw": st.put_blob_str(con, raw), "resp": resp, "file": f, "session_id": sid, "source": "hermes",
             "captured": t, "n_items": 1, "req_bytes": len(json.dumps(down))}
        st.upsert(con, {k: v for k, v in w.items() if k in have_w}, "wire_calls")
        c = {"id": cid, "source": "hermes", "started": t, "ended": t + 2, "family": fam, "provider": prov, "model": model,
             "status": 200, "prompt_tokens": 30000, "cached_tokens": 1000 if fam == "gemini" else 29000,
             "output_tokens": 10, "hit_pct": 3.3 if fam == "gemini" else 96.7, "cost_usd": 0.0, "cost_equiv_usd": 0.5,
             "billing": "sub", "session_id": sid, "api_mode": "anthropic_messages" if fam == "claude" else None,
             "attempts": 1, "nfail": 0}
        st.upsert(con, {k: v for k, v in c.items() if k in have_c}, "calls")
    # an error-only call: a policy block surfaced as an API error, no wire row
    st.upsert(con, {k: v for k, v in {
        "id": "c_err", "source": "hermes", "started": t0 + 40, "family": "claude", "provider": "cliproxy-claude",
        "model": "claude-opus-5-5", "status": 400, "nfail": 1, "attempts": 1, "session_id": "s_stock",
        "attempt_detail": json.dumps([{"n": 1, "status": 400, "type": "invalid_request_error",
                                       "message": "Output blocked by content filtering policy"}])}.items() if k in have_c},
        "calls")
    if not old:
        _codex_calls(ins, con, t0)
        con.execute("DELETE FROM kv WHERE k='signals_rev'")
        st.backfill_signals(con)
    con.commit()
    con.close()


CODEX_SID = "s_codex"


def _codex_calls(ins, con, t0):
    st = ins.store
    items = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "fix the flaky test please"}]},
             {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "Look at the test first."}],
              "encrypted_content": "E" * 300},
             {"type": "function_call", "call_id": "call_c1", "name": "read_file", "arguments": "{\"path\": \"t.py\"}"},
             {"type": "function_call_output", "call_id": "call_c1", "output": "def test_x(): pass"}]
    body = {"model": "gpt-6.1-sol", "instructions": "SOUL", "input": items}
    ref = ins.itemize(con, json.dumps(body))
    st.upsert(con, {"id": "c_codex", "started": t0 + 50, "ended": t0 + 52, "family": "openai", "model": "gpt-6.1-sol",
                    "status": 200, "req_down": json.dumps(ref), "resp": _resp("Fixed it.", model="gpt-6.1-sol"),
                    "session_id": CODEX_SID, "source": "hermes", "captured": t0 + 52, "n_items": len(items)}, "wire_calls")
    st.upsert(con, {"id": "c_codex", "source": "hermes", "started": t0 + 50, "family": "openai", "provider": "openai-codex",
                    "model": "gpt-6.1-sol", "status": 200, "session_id": CODEX_SID}, "calls")


def build_state(path: Path, t0: float):
    con = sqlite3.connect(path)
    con.executescript(ts.STOCK_SCHEMA)
    ts._insert(con, "sessions", {"id": "s_stock", "source": "cli", "model": "claude-opus-5-5", "system_prompt": "SOUL",
                                 "started_at": t0, "title": "stock fixture"})
    ts._insert(con, "sessions", {"id": CODEX_SID, "source": "subagent", "model": "gpt-6.1-sol", "system_prompt": "SOUL",
                                 "started_at": t0 + 45, "title": "codex fixture", "parent_session_id": "s_stock"})
    for r in ({"session_id": "s_stock", "role": "user", "content": "read Bo's inbox", "timestamp": t0 + 5},
              {"session_id": "s_stock", "role": "assistant", "content": "I'm going to stop here.", "timestamp": t0 + 12},
              {"session_id": CODEX_SID, "role": "user", "content": "fix the flaky test please", "timestamp": t0 + 46},
              {"session_id": CODEX_SID, "role": "assistant", "content": "", "timestamp": t0 + 51,
               "tool_calls": json.dumps([{"id": "call_c1", "type": "function",
                                          "function": {"name": "read_file", "arguments": "{}"}}])},
              {"session_id": CODEX_SID, "role": "tool", "content": "def test_x(): pass", "tool_call_id": "call_c1",
               "tool_name": "read_file", "timestamp": t0 + 51.5},
              {"session_id": CODEX_SID, "role": "assistant", "content": "Fixed it.", "timestamp": t0 + 53}):
        ts._insert(con, "messages", r)
    con.commit()
    con.close()


class WiretapCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.tdb, cls.old, cls.sdb, cls.typed = d / "telemetry.db", d / "old.db", d / "state.db", d / "typed.db"
        build_store(cls.tdb)
        build_store(cls.old, old=True)
        build_state(cls.sdb, time.time() - 600)
        con = sqlite3.connect(cls.typed)
        con.executescript(ts.TYPED_SCHEMA)
        ts._insert(con, "sessions", {"id": "d3", "source": "discord", "started_at": time.time() - 100, "depth": 1,
                                     "lineage_kind": "delegate", "root_session_id": "root", "parent_session_id": "root"})
        ts._insert(con, "messages", {"session_id": "d3", "role": "user", "content": "go", "timestamp": time.time() - 90,
                                     "sender_kind": "parent", "sender_id": "session:root", "part_kind": "parent_message",
                                     "parts_json": json.dumps([ts._event("parent_message", "go")])})
        con.commit()
        con.close()
        cls.cli = _load("_wiretap_cli", "collector/cli.py")
        cls.outputs = []

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cli(self, *argv, db=None, state=None, code=0):
        args = ["--telemetry-db", str(db or self.tdb), "--state-db", str(state or self.sdb), *argv]
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = self.cli.run(self.cli.build_parser().parse_args(args), out=buf)
        self.assertEqual(rc, code, err.getvalue() + buf.getvalue())
        text = buf.getvalue() + err.getvalue()
        type(self).outputs.append(text)
        self.last_stderr = err.getvalue()
        return buf.getvalue() if rc == 0 else text

    def js(self, *argv, **kw):
        return json.loads(self.run_cli(*argv, "--json", **kw))

    def jsl(self, *argv, **kw):
        return [json.loads(x) for x in self.run_cli(*argv, "--jsonl", **kw).splitlines() if x.strip()]

    # ── refusals ──
    def test_refusals_filter_keeps_only_refusal_signals(self):
        ids = [r["id"] for r in self.js("calls", "list", "--refusals")["results"]]
        self.assertEqual(set(ids), {"c_opus", "c_gem", "c_err"}, "the clean call and the codex call are not refusals")
        self.assertEqual([r["id"] for r in self.jsl("calls", "list", "--refusals")], ids)

    def test_fallback_block_and_notices_are_first_class(self):
        r = {x["id"]: x for x in self.js("calls", "list", "--refusals")["results"]}
        sig = r["c_opus"]["signals"]
        self.assertEqual(r["c_opus"]["signals_source"], "stored")
        fb = next(i for i in sig["items"] if i["kind"] == "fallback")
        self.assertEqual(fb, {"kind": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"},
                              "trigger": {"type": "refusal", "category": "cyber"}})
        note = next(i for i in sig["items"] if i["kind"] == "notice")
        self.assertEqual((note["type"], note["reason"], note["count"]), ("thinking_dropped", "model_binding_mismatch", 2))
        sw = next(i for i in sig["items"] if i["kind"] == "model_switch")
        self.assertEqual((sw["requested"], sw["served"]), ("claude-opus-5-5", "claude-opus-4-8"))
        self.assertEqual(sig["basis"], "provider")
        wording = next(i for i in sig["items"] if i["kind"] == "refusal_wording")
        self.assertTrue(wording["heuristic"], "the wording match is labelled a heuristic")
        gem = r["c_gem"]["signals"]
        self.assertIn({"kind": "safety", "source": "gemini.finishReason", "value": "SAFETY"}, gem["items"])
        err = r["c_err"]["signals"]
        self.assertEqual(err["kinds"], ["error_refusal"])
        self.assertIn("c_opus", self.run_cli("calls", "list", "--refusals"))

    def test_refusals_on_a_store_without_the_signals_column(self):
        ids = {r["id"]: r for r in self.js("calls", "list", "--refusals", db=self.old)["results"]}
        self.assertEqual(set(ids), {"c_opus", "c_gem", "c_err"})
        self.assertTrue(all(r["signals_source"] == "computed" for r in ids.values()))
        con = sqlite3.connect(self.old)
        try:
            self.assertNotIn("signals", [c[1] for c in con.execute("PRAGMA table_info(calls)")], "never migrated")
        finally:
            con.close()

    def test_other_filters(self):
        self.assertEqual([r["id"] for r in self.js("calls", "list", "--errors")["results"]], ["c_err"])
        self.assertEqual([r["id"] for r in self.js("calls", "list", "--misses")["results"]], ["c_gem"])
        self.assertEqual({r["id"] for r in self.js("calls", "list", "--family", "claude")["results"]}, {"c_opus", "c_err"})
        self.assertEqual([r["id"] for r in self.js("calls", "list", "--provider", "openai-codex", "--model", "sol",
                                                   "--session", CODEX_SID)["results"]], ["c_codex"])
        self.assertEqual(self.js("calls", "list", "--since", "1s")["results"], [])

    # ── call show ──
    def test_call_show_separates_layers_and_exact_thinking(self):
        d = self.js("call", "show", "c_opus", "--request", "--thinking", "--diff")["result"]
        self.assertEqual(d["layers"]["hermes"]["column"], "req_hermes")
        self.assertEqual(d["layers"]["wire"]["column"], "req_down")
        self.assertEqual(d["layers"]["upstream"]["column"], "req_up")
        self.assertTrue(d["hermes_request_json"]["_summary"])
        self.assertEqual(d["requested_model"], {"hermes": "claude-opus-5-5", "wire": "claude-opus-5-5",
                                                "upstream": "claude-opus-5-5"})
        th = d["thinking"]
        b = th["stream"]["blocks"]
        self.assertEqual([x["type"] for x in b], ["thinking"])
        self.assertEqual(b[0]["text"], "This asks me to lift someone else's code.")
        self.assertEqual(b[0]["signature_chars"], 64)
        self.assertTrue(th["stored_matches_stream"])
        adapter, proxy = d["diff"]["adapter"], d["diff"]["proxy"]
        self.assertEqual({k["key"] for k in adapter["keys_added"]}, {"max_tokens", "stream"})
        self.assertEqual(adapter["common_prefix"], 3)
        self.assertEqual(next(k for k in proxy["keys_added"] if k["key"] == "fallbacks")["value"],
                         [{"model": "claude-opus-4-8"}])
        self.assertEqual(proxy["ops"][0]["op"], "insert", "the proxy's injected item reads as one insert")
        self.assertEqual(proxy["b_items_found_in_a"], 3)
        self.assertEqual(d["diff"]["signals"]["refusal"], True)
        full = self.js("call", "show", "c_opus", "--request", "--full", "--item", "-1")["result"]
        self.assertEqual(full["wire_request_json"]["max_tokens"], 1000)
        self.assertEqual(full["hermes_request_item"], {"role": "user", "content": "read Bo's inbox"})
        text = self.run_cli("call", "show", "c_opus", "--all")
        for needle in ("HERMES REQUEST (hermes_request_json", "WIRE REQUEST (wire_request_json",
                       "UPSTREAM REQUEST (upstream_request_json", "fallbacks", "THINKING (exact", "RAW RESPONSE",
                       "refusal_wording", "+ key fallbacks"):
            self.assertIn(needle, text)

    def test_gemini_thinking_and_signatures(self):
        th = self.js("call", "show", "c_gem", "--thinking")["result"]["thinking"]["stream"]
        self.assertEqual([(b["type"], b["text"]) for b in th["blocks"]], [("thought", "**Weighing it**")])
        self.assertEqual(th["signatures"], [{"on": "text", "chars": 40}])
        self.assertEqual(self.js("call", "show", "gem")["result"]["id"], "c_gem", "a unique substring resolves")

    def test_unknown_and_ambiguous_ids(self):
        out = self.run_cli("call", "show", "nope", "--json", code=1)
        self.assertIn("unknown call id", json.loads(out)["error"])
        self.assertIn("ambiguous", self.run_cli("call", "show", "c_", code=1))

    def test_old_store_call_show(self):
        d = self.js("call", "show", "c_opus", "--all", db=self.old)["result"]
        self.assertEqual(d["signals_source"], "computed")
        self.assertNotIn("hermes", d["layers"], "no req_hermes column: no pre-adapter layer")
        self.assertEqual(d["layers"]["wire"]["column"], "req_down")
        self.assertIsNone(d["hermes_request_json"])
        self.assertIsNone(d["call"].get("upstream_provider"))

    # ── sessions ──
    def test_sessions_and_transcript_on_both_schemas(self):
        rows = self.js("sessions", "list")["results"]
        self.assertEqual({r["id"] for r in rows}, {"s_stock", CODEX_SID})
        self.assertEqual([r["id"] for r in self.js("sessions", "list", "--source", "subagent")["results"]], [CODEX_SID])
        t = self.js("session", "show", "s_stock", "--transcript")["result"]
        self.assertEqual([r["label"] for r in t["rows"]], ["USER", "ASSISTANT"])
        self.assertEqual(t["session"]["messages"]["total"], 2)
        d3 = self.js("session", "show", "d3", "--transcript", state=self.typed)["result"]
        self.assertEqual(d3["rows"][0]["label"], "PARENT ASSIGNMENT")
        if (HERE/'extensions/unified_sessions.py').is_file():
            self.assertEqual(d3["rows"][0]["sender_kind"], "parent")
            self.assertEqual(d3["session"]["lineage"]["depth"], 1)
            self.assertIn("unified", self.run_cli("status", state=self.typed))
        else:
            self.assertNotIn("sender_kind", d3["rows"][0])
            self.assertIn("untyped", self.run_cli("status", state=self.typed))
        self.assertIn("untyped", self.run_cli("status"))

    def test_compiled_folds_codex_reasoning(self):
        c = self.js("session", "show", CODEX_SID, "--compiled")["result"]["compiled"]
        self.assertEqual(c["call_id"], "c_codex")
        items = {it["i"]: it for it in c["items"]}
        self.assertEqual(items[1]["role"], "reasoning")
        self.assertEqual(items[1]["folded_into"], 2)
        self.assertEqual(items[2]["reasoning"], [{"i": 1, "summary": "Look at the test first.", "encrypted_chars": 300}])
        self.assertEqual(c["folded_reasoning"], 1)
        self.assertEqual(c["unaligned"], 0)
        text = self.run_cli("session", "show", CODEX_SID, "--compiled")
        self.assertIn("+1 reasoning", text)
        self.assertNotIn("[1] reasoning", text, "folded items are listed inside their turn, not as rows")

    # ── search / costs / status ──
    def test_search_scopes(self):
        r = self.js("search", "inbox", "--request")["result"]
        hit = next(h for h in r["results"] if h["call_id"] == "c_opus")
        self.assertEqual((hit["scope"], hit["role"]), ("request", "user"))
        self.assertEqual(len([h for h in r["results"] if h["role"] == "user" and "inbox" in h["snippet"]]), 1,
                         "one distinct item, reported once across layers")
        self.assertEqual([h["field"] for h in self.js("search", "lift someone", "--thinking")["result"]["results"]],
                         ["thinking"])
        self.assertEqual([h["call_id"] for h in self.jsl("search", "All good", "--response")], ["c_clean"])
        self.assertEqual(self.js("search", "inbox", "--session", "elsewhere")["result"]["results"], [])

    def test_costs_and_status(self):
        c = self.js("costs", "--by", "provider")["result"]
        self.assertEqual(c["by"], "provider")
        self.assertEqual(c["total"]["calls"], 5)
        self.assertIn("cliproxy-claude", {r["key"] for r in c["rows"]})
        self.assertEqual(self.js("costs", "--by", "upstream", db=self.old)["result"]["by"], "family",
                         "a store without the column groups by family")
        s = self.js("status")["result"]
        self.assertEqual(s["telemetry_db"]["calls"], 5)
        self.assertTrue(s["telemetry_db"]["signals_column"])
        self.assertEqual(s["telemetry_db"]["refusals_stored"], 3)
        self.assertFalse(self.js("status", db=self.old)["result"]["telemetry_db"]["signals_column"])

    # ── output contract ──
    def test_json_shapes_are_stable(self):
        tel = sys.modules["_wiretap_telemetry"]
        doc = self.js("calls", "list")
        self.assertEqual(set(doc), {"wiretap", "command", "results", "page"})
        self.assertEqual(doc["page"], {"total": 5, "has_more": False, "next_cursor": None})
        self.assertEqual(doc["wiretap"], 1)
        want = set(tel.CALL_FIELDS) | {"miss", "signals", "signals_source", "error_summary"}
        for r in doc["results"]:
            self.assertEqual(set(r), want)
        old = self.js("calls", "list", db=self.old)["results"]
        for r in old:
            self.assertEqual(set(r), want, "missing columns read as null, same keys")
        for argv in (("status",), ("call", "show", "c_clean"), ("search", "x"), ("costs",), ("session", "show", "s_stock")):
            d = self.js(*argv)
            self.assertEqual(set(d), {"wiretap", "command", "result"}, argv)
        self.assertEqual(self.js("call", "show", "c_clean")["result"]["signals"]["items"], [])

    def test_no_secret_reaches_any_output(self):
        for db in (self.tdb, self.old):
            for argv in (("call", "show", "c_opus", "--all", "--full", "--item", "0"), ("call", "show", "c_gem", "--all"),
                         ("calls", "list"), ("search", "key"), ("search", "sk-"), ("status",)):
                for fmt in ((), ("--json",)):
                    self.run_cli(*argv, *fmt, db=db)
        blob = "\n".join(type(self).outputs)
        for s in SECRETS:
            self.assertNotIn(s, blob)
            self.assertNotIn(s.split()[-1], blob)
        self.assertIn("‹redacted›", blob)

    def test_reads_never_write(self):
        before = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in (self.tdb, self.old, self.sdb)}
        self.run_cli("calls", "list", "--refusals", db=self.old)
        self.run_cli("call", "show", "c_opus", "--all", db=self.old)
        self.run_cli("session", "show", CODEX_SID, "--compiled")
        after = {p: (p.stat().st_mtime_ns, p.stat().st_size) for p in before}
        self.assertEqual(before, after)
        for p in (self.tdb, self.old):
            self.assertFalse(Path(str(p) + "-wal").exists(), "a read-only open never switches the store to WAL")

    # ── entry points ──
    def test_launcher_runs_without_hermes(self):
        env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "HERMES_HOME", "TELEMETRY_DB")}
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(HERE / "bin" / "wiretap"), "--telemetry-db", str(self.tdb),
                            "--state-db", str(self.sdb), "calls", "list", "--refusals", "--jsonl"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(p.stdout.splitlines()), 3)
        self.assertTrue(os.access(HERE / "bin" / "wiretap", os.X_OK))

    def test_hermes_cli_registration(self):
        plug = _load("_mt_cli_test_plugin", "__init__.py")
        got = {}

        class Ctx:
            def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
                got.update(name=name, setup=setup_fn, handler=handler_fn)

        class Bare:  # an upstream host without register_cli_command
            pass

        argv = sys.argv
        sys.argv = ["hermes", "wiretap"]
        try:
            plug.register(Ctx())
            plug.register(Bare())
        finally:
            sys.argv = argv
        self.assertEqual(got["name"], "wiretap")
        import argparse
        p = argparse.ArgumentParser(prog="hermes wiretap")
        got["setup"](p)
        args = p.parse_args(["--telemetry-db", str(self.tdb), "--state-db", str(self.sdb), "calls", "list", "--json"])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            got["handler"](args)
        self.assertEqual(json.loads(buf.getvalue())["command"], "calls list")
        bad = p.parse_args(["--telemetry-db", str(self.tdb), "call", "show", "nope"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            got["handler"](bad)


class SignalsAtCaptureTime(unittest.TestCase):
    """Writers compute signals when a response lands: the proxy-log path (capture_file) and the stored-column filter."""

    def test_capture_file_stores_signals(self):
        ins = _load("_wiretap_inspector", "collector/inspector.py")
        st = ins.store
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "v1-messages-2026-11-05T131112-abcd1234.log"
            log.write_text("=== REQUEST INFO ===\nURL: /v1/messages\n=== HEADERS ===\nUser-Agent: t\n=== REQUEST BODY ===\n"
                           + json.dumps({"model": "claude-opus-5-5", "messages": [{"role": "user", "content": "x"}]})
                           + "\n=== RESPONSE ===\n" + OPUS_RAW + "\n")
            con = st.memory_store()
            st.upsert(con, {"id": "abcd1234", "source": "cliproxy", "started": time.time(), "model": "claude-opus-4-8"})
            ins.capture_file(con, log, {"id": "abcd1234", "started": time.time(), "family": "claude",
                                        "model": "claude-opus-4-8"})
            sig = json.loads(con.execute("SELECT signals FROM calls WHERE id='abcd1234'").fetchone()[0])
            self.assertTrue(sig["refusal"])
            self.assertIn("fallback", sig["kinds"])
            self.assertEqual(sig["requested_model"], "claude-opus-5-5")
            tel = _load("_wiretap_telemetry", "collector/telemetry.py")
            self.assertEqual([r["id"] for r in tel.list_calls(con, {"refusals": True})], ["abcd1234"])
            con.close()

    def test_backfill_is_sliced_and_resumable(self):
        ins = _load("_wiretap_inspector", "collector/inspector.py")
        st = ins.store
        con = st.memory_store()
        for n in range(7):
            st.upsert(con, {"id": f"b{n}", "source": "hermes", "started": 100.0 + n, "status": 400,
                            "attempt_detail": json.dumps([{"n": 1, "status": 400, "message": "usage policy violation"}])})
        self.assertEqual(st.backfill_signals(con, budget_s=1e-9, batch=3), 3, "one batch, then the budget stops it")
        self.assertFalse(st.signals_backfilled(con))
        self.assertEqual([r[0] for r in con.execute("SELECT id FROM calls WHERE signals IS NOT NULL ORDER BY id")],
                         ["b4", "b5", "b6"], "newest first")
        self.assertEqual(st.backfill_signals(con, batch=3), 4)
        self.assertTrue(st.signals_backfilled(con))
        self.assertEqual(st.backfill_signals(con), 0, "done: a no-op")
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls WHERE signals LIKE ?",
                                     ('%"refusal":true%',)).fetchone()[0], 7)
        con.close()

    def test_heuristic_is_conservative(self):
        sm = _load("_mt_test_signals", "collector/signals.py")
        self.assertIsNone(sm.refusal_wording("Though I won't pretend I'm not charmed that you're shopping for me."))
        self.assertIsNone(sm.refusal_wording("Done. I can't wait to see it run."))
        self.assertEqual(sm.refusal_wording("I can't use the app credentials for that.")["match"], "I can't use")
        self.assertTrue(sm.refusal_wording("Here's the thing — I won't help with lifting that code.")["heuristic"])


if __name__ == "__main__":
    unittest.main()
