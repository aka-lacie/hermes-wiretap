"""Hermes-side capture, end to end: synthetic hook kwargs -> telemetry.db -> inspector views -> dashboard API.

Covers the contracts that make the plugin work on stock Hermes with any provider and no proxy: the hooks never
raise, the compiled request is stored exactly (or reconstructed and flagged), credentials never reach disk,
retries / errors are accounted, consecutive calls dedupe, the Inspector's Compiled-now and Transcript views
work from Hermes-side data alone, and optional proxy logs merge into the same row instead of double-counting.
"""
import importlib.util
import json
import threading
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent.parent
SID = "20260101_120000_abc123"
SYSTEM = "You are a helpful agent."
TOOLS = [{"type": "function", "function": {"name": "terminal", "description": "run a command",
                                           "parameters": {"type": "object", "properties": {"cmd": {"type": "string"}}}}},
         {"type": "function", "function": {"name": "read_file", "parameters": {"type": "object"}}}]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class _Ctx:
    def __init__(self, cfg=None):
        self.cfg, self.hooks = cfg or {}, {}

    def get_config(self, key, default=None):
        return self.cfg.get(key, default)

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def _state_db(path: Path, rows: list, source: str = "telegram") -> None:
    con = sqlite3.connect(path)
    # deliberately an older, narrower schema: no api_content / display_* / compacted / message_uid columns
    con.executescript("""
    CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, title TEXT, started_at REAL,
      message_count INTEGER, model_config TEXT, system_prompt TEXT);
    CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, tool_call_id TEXT,
      tool_calls TEXT, tool_name TEXT, timestamp REAL, finish_reason TEXT, reasoning TEXT, platform_message_id TEXT,
      active INTEGER);
    """)
    con.execute("INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
                (SID, source, "gpt-5.5", "Bot Chat", time.time() - 100, len(rows), "{}", SYSTEM))
    for r in rows:
        r = {"session_id": SID, "active": 1, **r}
        con.execute(f"INSERT INTO messages ({','.join(r)}) VALUES ({','.join('?' * len(r))})", list(r.values()))
    con.commit()
    con.close()


def fire_pre(hook, api_kwargs, **kw):
    """Mimics agent/turn_api_request._fire_pre_api_request_hook: a local ``api_kwargs`` and shallow-copied
    ``request_messages`` (same item objects)."""
    lst = api_kwargs.get("messages") if isinstance(api_kwargs.get("messages"), list) else api_kwargs.get("input")
    hook(request_messages=list(lst), **kw)


class _HookBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.old_env = {k: os.environ.get(k) for k in ("HOME", "HERMES_HOME", "TELEMETRY_DB", "CLIPROXY_LOG_DIR", "MAIN_SESSION",
                                                        "MODEL_TELEMETRY_POLLER")}
        os.environ.update(HOME=str(self.home), HERMES_HOME=str(self.home), CLIPROXY_LOG_DIR=str(self.home / "no-proxy"), MAIN_SESSION="",
                          TELEMETRY_DB=str(self.home / "plugin-data/wiretap/telemetry.db"),
                          MODEL_TELEMETRY_POLLER="0")  # PollerTest starts its own threads
        self.mt = _load("_mt_test_plugin", HERE / "__init__.py")
        self.cap = self.mt._capture()
        self.cap._writer = self.cap.Writer()
        self.cap.SETTINGS.update(enabled=True, capture_payloads=True, retention_hours=72.0, max_request_mb=64.0)
        self.ctx = _Ctx()
        self.mt.register(self.ctx)
        self.t0 = time.time() - 60

    def tearDown(self):
        w = self.cap._writer
        w.stop(5)
        for k, v in self.old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()

    def db(self):
        self.cap._writer.flush(5)
        con = sqlite3.connect(os.environ["TELEMETRY_DB"])
        con.row_factory = sqlite3.Row
        return con

    def chat_call(self, n, messages, reply="", tool_calls=None, usage=None, extra=None, between=None, model="gpt-5.5", **over):
        """One chat-completions round trip through the plugin's hooks."""
        rid = f"turn1:api:{n}"
        api_kwargs = {"model": model, "messages": messages, "tools": TOOLS, "temperature": 1,
                      "api_key": "sk-SECRET-KEY", "timeout": 30,
                      "extra_headers": {"Authorization": "Bearer SECRET-TOKEN", "X-Title": "hermes"}, **(extra or {})}
        base = {**dict(session_id=SID, platform="telegram", model=model, provider="openrouter",
                       base_url="https://user:pw@openrouter.ai/api/v1?key=SECRET-QS", api_mode="chat_completions",
                       api_request_id=rid, turn_id="turn1", task_id="t", api_call_count=n), **over}
        started = self.t0 + n * 10
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, retry_count=0, system_prompt=SYSTEM,
                 message_count=len(messages), tool_count=len(TOOLS), started_at=started,
                 request={"method": "POST", "body": {"_truncated": True, "preview": "…"}}, **base)
        if between is not None:
            between()
        msg = SimpleNamespace(role="assistant", content=reply, tool_calls=tool_calls or [], reasoning="pondering")
        self.ctx.hooks["post_api_request"](
            api_duration=4.0, started_at=started, ended_at=started + 4.0, first_chunk_at=started + 1.25,
            finish_reason="tool_calls" if tool_calls else "stop", message_count=len(messages), response_model=model,
            response={"model": model, "assistant_message": {"content": reply}}, assistant_message=msg,
            usage=usage or {"input_tokens": 500, "cache_read_tokens": 1500, "cache_write_tokens": 0, "output_tokens": 40,
                            "reasoning_tokens": 12, "prompt_tokens": 2000},
            context_length=400000, assistant_content_chars=len(reply), assistant_tool_call_count=len(tool_calls or []),
            **base)
        return "h:" + rid


class HookCaptureTest(_HookBase):
    def test_exact_request_and_response_are_captured(self):
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "list files"}]
        tc = SimpleNamespace(id="call_9", type="function", function=SimpleNamespace(name="terminal", arguments='{"cmd": "ls"}'))
        cid = self.chat_call(1, msgs, "", [tc])
        con = self.db()
        w = dict(con.execute("SELECT * FROM wire_calls WHERE id=?", (cid,)).fetchone())
        self.assertEqual((w["source"], w["exact"], w["session_id"], w["status"], w["n_items"]), ("hermes", 1, SID, 200, 2))
        ins = self.cap.inspector
        req = ins.rebuild(con, json.loads(w["req_down"]))
        self.assertEqual(req["tools"], TOOLS, "exact envelope (tools) comes from the transport-ready api_kwargs")
        self.assertEqual(req["messages"], msgs)
        self.assertEqual(req["temperature"], 1)
        self.assertNotIn("timeout", req)
        resp = json.loads(w["resp"])
        self.assertEqual(resp["tool_calls"], [{"id": "call_9", "name": "terminal", "args": {"cmd": "ls"}}])
        self.assertEqual((resp["thinking"], resp["finish"]), ("pondering", "tool_calls"))
        self.assertEqual(json.loads(w["tc_ids"]), ["call_9"])
        c = dict(con.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone())
        self.assertEqual((c["source"], c["status"], c["family"], c["session_id"], c["platform"]), ("hermes", 200, "openai", SID, "telegram"))
        self.assertEqual((c["ttfb_s"], c["total_s"], c["gen_s"]), (1.25, 4.0, 2.75))
        self.assertEqual((c["prompt_tokens"], c["cached_tokens"], c["hit_pct"], c["thinking_tokens"]), (2000, 1500, 75.0, 12))
        self.assertEqual(c["context_length"], 400000)
        self.assertEqual(c["url"], "https://openrouter.ai/api/v1", "userinfo and query string are stripped")
        con.close()

    def test_credentials_never_reach_disk(self):
        self.chat_call(1, [{"role": "user", "content": "hi"}], "hello")
        self.cap._writer.flush(5)
        raw = b""
        for p in Path(os.environ["TELEMETRY_DB"]).parent.iterdir():
            raw += p.read_bytes()
        import zlib
        con = self.db()
        for (z,) in con.execute("SELECT z FROM wire_blobs"):
            raw += zlib.decompress(z)
        con.close()
        for secret in (b"sk-SECRET-KEY", b"SECRET-TOKEN", b"SECRET-QS", b"user:pw"):
            self.assertFalse(secret in raw, f"{secret!r} reached the store")
        self.assertEqual(os.stat(os.environ["TELEMETRY_DB"]).st_mode & 0o777, 0o600)

    def test_reconstructed_envelope_without_caller_frame(self):
        """Anthropic route, hook fired without an ``api_kwargs`` frame: documented kwargs only, flagged inexact."""
        msgs = [{"role": "user", "content": [{"type": "text", "text": "summarize"}]}]
        self.ctx.hooks["pre_api_request"](
            session_id=SID, platform="cli", model="claude-sonnet-4-6", provider="anthropic", base_url="https://api.anthropic.com",
            api_mode="anthropic_messages", api_request_id="t2:api:1", started_at=self.t0, request_messages=msgs,
            system_prompt=[{"type": "text", "text": SYSTEM}], retry_count=0,
            request={"method": "POST", "body": {"model": "claude-sonnet-4-6", "max_tokens": 4096, "api_key": "<redacted>",
                                                "tools": [{"name": "terminal"}], "messages": "[truncated]"}})
        con = self.db()
        w = dict(con.execute("SELECT * FROM wire_calls WHERE id='h:t2:api:1'").fetchone())
        self.assertEqual(w["exact"], 0)
        req = self.cap.inspector.rebuild(con, json.loads(w["req_down"]))
        self.assertEqual(req["messages"], msgs, "raw request_messages replace the sanitized copy")
        self.assertEqual(req["system"], [{"type": "text", "text": SYSTEM}])
        self.assertEqual(req["tools"], [{"name": "terminal"}])
        self.assertEqual(w["status"], None, "in-flight until post_api_request")
        self.assertEqual(con.execute("SELECT family FROM calls WHERE id='h:t2:api:1'").fetchone()[0], "claude")
        con.close()

    def test_responses_api_input_and_instructions(self):
        items = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "deploy?"}]}]
        api_kwargs = {"model": "gpt-5.5-codex", "instructions": SYSTEM, "input": items, "tools": [{"type": "function", "name": "terminal"}]}
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, session_id=SID, model="gpt-5.5-codex", provider="openai-codex",
                 api_mode="codex_responses", api_request_id="t3:api:1", started_at=self.t0, system_prompt=SYSTEM)
        con = self.db()
        ref = json.loads(con.execute("SELECT req_down FROM wire_calls WHERE id='h:t3:api:1'").fetchone()[0])
        self.assertEqual(ref["list_key"], "input")
        self.assertIn("instructions", ref["keys"])
        con.close()

    def test_retry_then_success_is_one_call_with_attempts(self):
        kw = dict(session_id=SID, model="gpt-5.5", provider="openrouter", api_mode="chat_completions", api_request_id="t4:api:1")
        api_kwargs = {"model": "gpt-5.5", "messages": [{"role": "user", "content": "x"}]}
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, retry_count=0, started_at=self.t0, **kw)
        self.ctx.hooks["api_request_error"](status_code=429, retry_count=0, max_retries=3, retryable=True, reason="rate_limit",
                                            error={"type": "RateLimitError", "message": "slow down " * 200},
                                            started_at=self.t0, ended_at=self.t0 + 1.5, api_duration=1.5, **kw)
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, retry_count=1, started_at=self.t0 + 3, **kw)
        self.ctx.hooks["post_api_request"](started_at=self.t0 + 3, api_duration=2.0, ended_at=self.t0 + 5,
                                           assistant_message=SimpleNamespace(content="ok", tool_calls=[]),
                                           usage={"prompt_tokens": 10, "input_tokens": 10, "output_tokens": 1}, **kw)
        con = self.db()
        c = dict(con.execute("SELECT * FROM calls WHERE id='h:t4:api:1'").fetchone())
        self.assertEqual((c["status"], c["attempts"], c["n429"], c["nfail"]), (200, 2, 1, 1))
        det = json.loads(c["attempt_detail"])
        self.assertEqual(det[0]["status"], 429)
        self.assertLessEqual(len(det[0]["message"]), self.cap._ERR_CHARS)
        self.assertEqual(con.execute("SELECT status FROM wire_calls WHERE id='h:t4:api:1'").fetchone()[0], 200)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls").fetchone()[0], 1)
        con.close()

    def test_consecutive_calls_share_history_blobs(self):
        hist = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "a" * 5000}]
        self.chat_call(1, hist, "first")
        self.chat_call(2, hist + [{"role": "assistant", "content": "first"}, {"role": "user", "content": "more"}], "second")
        con = self.db()
        a, b = (json.loads(r[0]) for r in con.execute("SELECT req_down FROM wire_calls ORDER BY started"))
        self.assertEqual(a["items"], b["items"][:2])
        self.assertEqual(a["keys"]["tools"], b["keys"]["tools"])
        n = con.execute("SELECT COUNT(*) FROM wire_blobs").fetchone()[0]
        self.assertLess(n, len(a["items"]) + len(b["items"]) + len(a["keys"]) + len(b["keys"]))
        con.close()

    def test_payload_capture_off_keeps_telemetry_only(self):
        self.cap.SETTINGS["capture_payloads"] = False
        cid = self.chat_call(1, [{"role": "user", "content": "PRIVATE-PROMPT"}], "PRIVATE-REPLY")
        con = self.db()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT status FROM calls WHERE id=?", (cid,)).fetchone()[0], 200)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_blobs").fetchone()[0], 0)
        con.close()

    def test_oversized_request_is_skipped_before_serializing(self):
        self.cap.SETTINGS["max_request_mb"] = 1.0
        api_kwargs = {"model": "gpt-5.5", "messages": [{"role": "user", "content": "x"}]}
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, session_id=SID, model="gpt-5.5", api_mode="chat_completions",
                 api_request_id="big:api:1", started_at=self.t0, request_char_count=5 * 1024 * 1024, message_count=1)
        con = self.db()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0], 0)
        self.assertIn("not captured", con.execute("SELECT diverge FROM calls WHERE id='h:big:api:1'").fetchone()[0])
        con.close()

    def test_hooks_never_raise(self):
        self.ctx.hooks["pre_api_request"](request_messages=object(), request=42, started_at="soon")
        self.ctx.hooks["post_api_request"](usage=object(), assistant_message=42, api_duration="x")
        self.ctx.hooks["api_request_error"](error=None, status_code="bad")
        os.environ["TELEMETRY_DB"] = "/proc/definitely-not-writable/t.db"
        self.cap._writer.stop(5)
        self.cap._writer = self.cap.Writer()
        self.chat_call(1, [{"role": "user", "content": "x"}], "y")  # must not raise
        self.cap._writer.flush(2)

    def test_retention_gc_drops_old_payloads(self):
        self.chat_call(1, [{"role": "user", "content": "old"}], "old reply")
        con = self.db()
        con.execute("UPDATE wire_calls SET ended = ended - 999999, started = started - 999999")
        con.commit()
        self.cap.store.gc(con, keep_s=3600, force=True)
        con.commit()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_blobs").fetchone()[0], 0)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls").fetchone()[0], 1, "telemetry rows are kept")
        con.close()

    def _session(self):
        """A two-call session captured only by the hooks, plus its state.db transcript."""
        u1 = "what is in this directory?"
        m1 = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": u1}]
        tc = SimpleNamespace(id="call_1", function=SimpleNamespace(name="terminal", arguments='{"cmd":"ls"}'))
        c1 = self.chat_call(1, m1, "", [tc])
        m2 = m1 + [{"role": "assistant", "content": "", "tool_calls": [{"id": "call_1", "type": "function",
                                                                       "function": {"name": "terminal", "arguments": '{"cmd":"ls"}'}}]},
                   {"role": "tool", "tool_call_id": "call_1", "content": "README.md\nsrc"}]
        reply = "There is a README and a src folder."
        c2 = self.chat_call(2, m2, reply)
        _state_db(self.home / "state.db", [
            {"id": 1, "role": "user", "content": u1, "timestamp": self.t0 + 5, "platform_message_id": "777"},
            {"id": 2, "role": "assistant", "content": "", "timestamp": self.t0 + 15, "finish_reason": "tool_calls",
             "tool_calls": json.dumps([{"id": "call_1", "function": {"name": "terminal", "arguments": "{}"}}])},
            {"id": 3, "role": "tool", "content": "README.md\nsrc", "tool_call_id": "call_1", "tool_name": "terminal",
             "timestamp": self.t0 + 16},
            {"id": 4, "role": "assistant", "content": reply, "timestamp": self.t0 + 25, "finish_reason": "stop"},
            {"id": 5, "role": "user", "content": "thanks!", "timestamp": self.t0 + 40, "platform_message_id": "778"},
        ])
        return c1, c2

    def test_compiled_and_transcript_views_from_hook_data_alone(self):
        c1, c2 = self._session()
        t = _load("_mt_test_telemetry_native", HERE / "collector" / "telemetry.py")
        con = self.db()
        ins = t.inspector
        view = ins.session_view(t.STATE_DB, con, SID, None, 100, False)
        rows = {r["id"]: r for r in view["rows"]}
        self.assertEqual(rows[1]["label"], "USER · telegram")
        self.assertEqual(rows[2]["wire"], c1, "assistant tool-call row -> its call by tool-call id")
        self.assertEqual(rows[4]["wire"], c2, "assistant text row -> its call by response text")
        self.assertEqual(rows[1]["framing"]["first"]["call"], c1)
        comp = ins.compiled_view(t.STATE_DB, con, SID)
        self.assertEqual(comp["call_id"], c2)
        self.assertEqual(comp["system"]["item"], 0, "chat-completions system prompt is messages[0]")
        self.assertTrue(comp["system"]["matches_stored"])
        self.assertEqual(comp["tool_names"], ["terminal", "read_file"])
        self.assertEqual([it.get("row_id") for it in comp["wire"]["items"]], [None, 1, 2, 3])
        self.assertEqual([r["id"] for r in comp["rows_after"]], [4, 5])
        self.assertFalse(comp["wire"]["has_upstream"])
        con.close()

    def test_dashboard_api_without_proxy_or_collector(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except Exception as e:  # pragma: no cover - plain-python runs
            self.skipTest(f"fastapi unavailable: {e}")
        api = _load("_mt_test_api_native", HERE / "dashboard" / "plugin_api.py")
        sys.modules.pop("_wiretap_dashboard_telemetry", None)
        api._MOD.clear()
        app = FastAPI()
        app.include_router(api.router, prefix="/p")
        c = TestClient(app)
        h = c.get("/p/health").json()
        self.assertTrue(h["no_data"])
        self.assertFalse(h["proxy"]["exists"])
        self.assertEqual(c.get("/p/calls").json()["rows"], [])
        c1, c2 = self._session()
        self.cap._writer.flush(5)
        h = c.get("/p/health").json()
        self.assertEqual((h["calls"], h["wire_calls"], h["no_data"]), (2, 2, False))
        self.assertEqual(h["sources"], {"hermes": 2})
        self.assertIsNotNone(h["last_capture"]["ts"])
        calls = c.get("/p/calls", params={"hours": 2}).json()["rows"]
        self.assertEqual({r["id"] for r in calls}, {c1, c2})
        self.assertEqual({r["lane"] for r in calls}, {"main"})
        g = c.get("/p/sessions").json()["main"]
        self.assertEqual((g["id"], g["ctx_window"], g["last_prompt_tokens"]), (SID, 400000, 2000))
        self.assertEqual(g["compressor_trigger"], 200000, "Hermes's default compression.threshold 0.50")
        self.assertEqual(g["hygiene_trigger"], 340000, "gateway session: 85 % hygiene safety net")
        comp = c.get("/p/inspector/compiled").json()
        self.assertEqual(comp["call_id"], c2)
        w = c.get("/p/inspector/wire", params={"id": c2, "which": "up"}).json()
        self.assertEqual((w["which"], w["has_upstream"]), ("down", False), "no proxy: upstream falls back to downstream")
        part = c.get("/p/inspector/wire/part", params={"id": c2, "part": "key", "key": "tools"}).json()
        self.assertEqual(part, TOOLS)
        self.assertEqual(c.get("/p/inspector/row", params={"id": 1}).json()["class"]["label"], "USER · telegram")


def _proxy_log(path: Path, t0: float, body: dict, up: dict, reply: str, tag: str | None = None) -> None:
    from datetime import datetime, timezone

    ts = lambda e: datetime.fromtimestamp(e, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000000+00:00")  # noqa: E731
    sse = "\n\n".join("data: " + json.dumps(x) for x in (
        {"id": "c1", "object": "chat.completion.chunk", "model": "gpt-5.5", "choices": [{"delta": {"content": reply}}]},
        {"id": "c1", "object": "chat.completion.chunk", "model": "gpt-5.5", "choices": [{"delta": {}, "finish_reason": "stop"}],
         "usage": {"prompt_tokens": 2000, "completion_tokens": 40, "prompt_tokens_details": {"cached_tokens": 1500}}}))
    path.write_text("\n".join([
        "=== REQUEST INFO ===", "URL: /v1/chat/completions", f"Timestamp: {ts(t0)}", "",
        "=== HEADERS ===", "User-Agent: OpenAI/Python", "Authorization: Bearer DOWN-SECRET", *([f"X-Wiretap-Call: {tag}"] if tag else []), "",
        "=== REQUEST BODY ===", json.dumps(body), "",
        "=== API REQUEST 1 ===", f"Timestamp: {ts(t0 + 0.1)}", "Upstream URL: https://api.example/v1/chat/completions",
        "Auth: provider=openai, auth_id=a1, label=team, type=oauth value=tok_abcd9876", "", "Headers:",
        "Authorization: Bearer UP-SECRET", "Content-Type: application/json", "", "Body:", json.dumps(up), "",
        "=== API RESPONSE 1 ===", f"Timestamp: {ts(t0 + 1)}", "", "Status: 200", "", "Body:", sse, "",
        "=== RESPONSE ===", "Status: 200", "", sse, ""]))
    os.utime(path, (t0 + 5, t0 + 5))


class ProxyEnrichmentTest(_HookBase):
    """With proxy logs present, the proxy call merges into the Hermes-side row (no double count)."""

    def test_sidecar_proxy_log_does_not_merge_into_the_conversation_call(self):
        logs = self.home / "proxy-logs"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello " * 400}]
        cid = self.chat_call(1, msgs, "hi there")
        started = self.t0 + 10
        body = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS, "stream": True}
        side = {"model": "gpt-5.5", "messages": [{"role": "user", "content": "The following command was flagged as: x"}]}
        # the sidecar's log is closer in time and finishes first
        _proxy_log(logs / "v1-chat-completions-2026-00aaside.log", started + 0.05, side, side, "SAFE")
        _proxy_log(logs / "v1-chat-completions-2026-00bbmain.log", started + 0.7, body, body, "hi there")
        os.utime(logs / "v1-chat-completions-2026-00bbmain.log", (started + 20, started + 20))
        t = _load("_mt_test_telemetry_side", HERE / "collector" / "telemetry.py")
        self.cap._writer.flush(5)
        t.init_db()
        t.ingest_once()
        con = self.db()
        self.assertEqual(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (cid,)).fetchone()[0], "00bbmain")
        self.assertEqual(con.execute("SELECT source FROM calls WHERE id='00aaside'").fetchone()[0], "cliproxy")
        self.assertEqual(len(self.cap.inspector.wire_summary(con, cid, "down")["items"]), 2)
        con.close()

    def test_tagged_proxy_log_joins_its_call_exactly(self):
        """A log carrying the tap's X-Wiretap-Call header lands on that call even when another same-model call is
        closer in time; a tagged log of another family (a failover's failed attempt) stays its own row."""
        logs = self.home / "proxy-logs"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello " * 50}]
        a = self.chat_call(1, msgs, "first")
        b = self.chat_call(2, msgs, "second")
        body = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS, "stream": True}
        self.cap._writer.flush(5)
        con = self.db()
        con.execute("UPDATE wire_calls SET tap_nonces=? WHERE id=?", (json.dumps(["n0nce"]), a))  # a validated capture
        con.commit()
        con.close()
        # timestamped next to call b, but tagged for call a's validated request
        _proxy_log(logs / "v1-chat-completions-2026-00ccaaaa.log", self.t0 + 20.1, body, body, "first", tag=a + "~n0nce")
        t = _load("_mt_test_telemetry_tag", HERE / "collector" / "telemetry.py")
        t.init_db()
        t.ingest_once()
        con = self.db()
        self.assertEqual(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (a,)).fetchone()[0], "00ccaaaa")
        self.assertIsNone(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (b,)).fetchone()[0])
        row = t.parse_request_log(logs / "v1-chat-completions-2026-00ccaaaa.log")
        self.assertEqual(row["_call"], a + "~n0nce")
        # never a heuristic fallback: an unvalidated nonce, an old-format tag, or a call that does not exist
        for tag in (a + "~other", a, "h:no-such-call~n0nce"):
            self.assertEqual(t.match_hermes_call(con, dict(row, _call=tag)), t.TAG_PENDING, tag)
        con.execute("UPDATE calls SET family='claude' WHERE id=?", (a,))
        self.assertIsNone(t.match_hermes_call(con, dict(row, family="openai")), "another family's attempt: no merge")
        con.close()

    def test_an_unvalidated_tag_becomes_its_own_row_after_the_wait_never_another_calls(self):
        logs = self.home / "proxy-logs"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello " * 50}]
        b = self.chat_call(2, msgs, "second")
        body = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS, "stream": True}
        f = logs / "v1-chat-completions-2026-00ddbbbb.log"
        _proxy_log(f, self.t0 + 20.1, body, body, "second", tag="h:missing:api:9~abc")
        t = _load("_mt_test_telemetry_tag2", HERE / "collector" / "telemetry.py")
        self.cap._writer.flush(5)
        t.init_db()
        os.utime(f, None)  # fresh: the scan waits for the capture to validate
        t.ingest_once()
        con = self.db()
        self.assertIsNone(con.execute("SELECT 1 FROM calls WHERE id='00ddbbbb'").fetchone(), "deferred, not joined")
        self.assertIsNone(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (b,)).fetchone()[0])
        con.close()
        old = time.time() - t.TAG_WAIT_S - 5
        os.utime(f, (old, old))
        t.ingest_once()
        con = self.db()
        self.assertEqual(con.execute("SELECT source FROM calls WHERE id='00ddbbbb'").fetchone()[0], "cliproxy")
        self.assertIsNone(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (b,)).fetchone()[0],
                          "the nearest same-model call is never a substitute for the tagged one")
        con.close()

    def test_repair_unmerges_a_sidecar_log_and_requeues_both(self):
        st = self.cap.store
        con = st.memory_store()
        items = [st.put_blob(con, {"role": "user", "content": f"m{i}"}) for i in range(20)]
        big = json.dumps({"order": ["messages"], "keys": {}, "list_key": "messages", "items": items})
        small = json.dumps({"order": ["messages"], "keys": {}, "list_key": "messages", "items": items[:1]})
        st.upsert(con, dict(id="h:1", source="hermes", model="m", started=100.0, prompt_tokens=5000, provider="p",
                            api_mode="chat_completions", proxy_rid="side", file="side.log", auth_key="k"), "calls")
        st.upsert(con, dict(id="h:1", source="hermes", req_down=small, req_hermes=big, file="side.log", n_items=1), "wire_calls")
        st.upsert(con, dict(id="main", source="cliproxy", model="m", started=100.6, prompt_tokens=5000, file="main.log",
                            auth_key="real-key", upstream_provider="claude"), "calls")
        st.upsert(con, dict(id="main", source="cliproxy", req_down=big, file="main.log", n_items=20, req_bytes=9000), "wire_calls")
        con.execute("INSERT INTO seen_files VALUES ('side.log', 1, 1), ('main.log', 1, 1)")
        con.execute("DELETE FROM kv WHERE k='merge_rev'")
        self.assertEqual(self.cap._sibling("telemetry")._proxy_extension().repair_sidecar_merges(con), 1)
        w = con.execute("SELECT req_down, req_hermes, file, n_items FROM wire_calls WHERE id='h:1'").fetchone()
        self.assertEqual((w[0], w[1], w[2], w[3]), (big, big, "main.log", 20), "the conversation's own proxy capture")
        self.assertEqual(con.execute("SELECT proxy_rid, auth_key, upstream_provider FROM calls WHERE id='h:1'").fetchone()[:],
                         ("main", "real-key", "claude"))
        self.assertIsNone(con.execute("SELECT 1 FROM calls WHERE id='main'").fetchone(), "duplicate proxy-only row removed")
        self.assertEqual([r[0] for r in con.execute("SELECT name FROM seen_files")], ["main.log"],
                         "only the sidecar's log is re-ingested (as its own proxy-only call)")
        self.assertEqual(self.cap._sibling("telemetry")._proxy_extension().repair_sidecar_merges(con), 0, "once")
        con.close()

    def test_proxy_log_merges_into_hermes_capture(self):
        logs = self.home / "proxy-logs"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]
        cid = self.chat_call(1, msgs, "hi there")
        started = self.t0 + 10
        body = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS, "stream": True}
        up = dict(body, messages=[{"role": "developer", "content": SYSTEM}, msgs[1]])
        _proxy_log(logs / "v1-chat-completions-2026-0001abcd.log", started + 0.2, body, up, "hi there")
        t = _load("_mt_test_telemetry_proxy", HERE / "collector" / "telemetry.py")
        self.cap._writer.flush(5)
        t.init_db()
        self.assertEqual(t.ingest_once()[0], 1)
        con = self.db()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls").fetchone()[0], 1, "merged, not double-counted")
        c = dict(con.execute("SELECT * FROM calls WHERE id=?", (cid,)).fetchone())
        self.assertEqual((c["proxy_rid"], c["auth_key"], c["auth_type"], c["billing"], c["attempts"]),
                         ("0001abcd", "9876", "oauth", "sub", 1))
        self.assertEqual(c["ttfb_s"], 1.25, "Hermes-side TTFB is kept")
        self.assertEqual(con.execute("SELECT COUNT(*) FROM wire_calls").fetchone()[0], 1)
        w = t.inspector.wire_summary(con, cid, "up")
        self.assertTrue(w["has_upstream"] and w["upstream_differs"])
        self.assertEqual((w["which"], w["items"][0]["role"]), ("up", "developer"))
        self.assertEqual(w["headers_up"]["Authorization"], "‹redacted›")
        self.assertEqual(t.inspector.wire_summary(con, cid, "down")["items"][0]["role"], "system")
        con.close()

    def test_adapter_rewritten_proxy_body_becomes_the_wire_layer(self):
        """A provider adapter changes the shape (and item count) between Hermes and the HTTP body; the proxy's
        received body must still merge, become the default (post-adapter) layer, and keep Hermes's copy."""
        logs = self.home / "proxy-logs-2"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]
        cid = self.chat_call(1, msgs, "hi there")
        started = self.t0 + 10
        wire = {"model": "gpt-5.5", "stream": True, "tools": TOOLS, "messages": [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": "<USER_REQUEST>\nhello\n</USER_REQUEST>"},
            {"role": "user", "content": "<SYSTEM_MESSAGE>\nturn context\n</SYSTEM_MESSAGE>"}]}
        _proxy_log(logs / "v1-chat-completions-2026-0002abcd.log", started + 0.2, wire, wire, "hi there")
        t = _load("_mt_test_telemetry_proxy2", HERE / "collector" / "telemetry.py")
        self.cap._writer.flush(5)
        t.init_db()
        t.ingest_once()
        con = self.db()
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls").fetchone()[0], 1, "merged despite a different item count")
        down = t.inspector.wire_summary(con, cid, "down")
        self.assertEqual((down["layer"], len(down["items"])), ("wire", 3))
        self.assertIn("USER_REQUEST", down["items"][1]["head"])
        pre = t.inspector.wire_summary(con, cid, "hermes")
        self.assertEqual((pre["which"], len(pre["items"])), ("hermes", 2))
        self.assertEqual(t.inspector.wire_part(con, cid, "item", "hermes", 1)["content"], "hello")
        t.inspector.gc(con, force=True)
        self.assertEqual(t.inspector.wire_part(con, cid, "item", "hermes", 1)["content"], "hello", "GC keeps the pre-adapter blobs")
        con.close()




class FamilyTabsTest(_HookBase):
    """Model family is who made the model, not the route; /calls returns the window's families for the tabs."""

    def test_family_of(self):
        f = self.cap.store.family_of
        cases = {
            ("claude-opus-5-5", None, "cliproxy-claude"): "claude", ("gemini-4-argon", None, None): "gemini",
            ("gemma-3-27b", None, None): "gemini", ("gpt-6.1-sol", "codex_responses", "openai-codex"): "openai",
            ("o3-mini", None, None): "openai", ("o4", None, None): "openai", ("o5-preview", None, None): "other",
            ("ollama-thing", None, None): "ollama", ("deepseek/deepseek-chat-v4", None, "openrouter"): "deepseek",
            ("z-ai/glm-5", None, "openrouter"): "glm", ("MiniMax-M3", "anthropic_messages", "minimax"): "minimax",
            ("qwen/qwen3-coder", None, "openrouter"): "qwen", ("nousresearch/hermes-5-405b", None, None): "nous",
            ("meta-llama/llama-5-70b", None, None): "llama", ("moonshotai/kimi-k3", None, None): "kimi",
            ("zeta-system1-v2", None, None): "zeta", ("x-ai/grok-5", None, "openrouter"): "grok",
            ("acme-labs/zeta-9", None, "openrouter"): "acme-labs", ("", "anthropic_messages", None): "claude",
            ("", None, "openrouter"): "other", ("custom-model", None, "deepseek"): "deepseek",
        }
        for (m, mode, prov), want in cases.items():
            self.assertEqual(f(m, mode, prov), want, (m, mode, prov))
        self.assertEqual(self.cap.store.family_label("acme-labs"), "Acme Labs")
        self.assertEqual(self.cap.store.family_label("deepseek"), "DeepSeek")

    def test_calls_lists_families_and_filters_by_provider_and_other(self):
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hi"}]
        self.chat_call(1, msgs, "a")                                         # gpt-5.5 via openrouter
        self.chat_call(2, msgs, "b", model="deepseek/deepseek-chat")
        self.chat_call(3, msgs, "c", model="deepseek/deepseek-chat",
                       provider="deepseek")
        self.db().close()
        tel = self.mt_telemetry()
        q = lambda **kw: {k: [str(v)] for k, v in kw.items()}  # noqa: E731
        d = tel.api_calls(q(hours=6, family="all"))
        self.assertEqual([(x["family"], x["label"], x["n"]) for x in d["families"]], [("deepseek", "DeepSeek", 2), ("openai", "OpenAI", 1)])
        self.assertEqual({x["provider"]: x["n"] for x in d["providers"]}, {"openrouter": 2, "deepseek": 1})
        self.assertEqual(len(tel.api_calls(q(hours=6, family="deepseek"))["rows"]), 2)
        self.assertEqual([r["family"] for r in tel.api_calls(q(hours=6, family="!deepseek"))["rows"]], ["openai"])
        pg = tel.api_calls(q(hours=6, family="all", limit=2))
        self.assertEqual((len(pg["rows"]), pg["has_more"], pg["total"], pg["summary"]["deepseek"]["n"]), (2, True, 3, 2),
                         "head page, summary over the whole window")
        nxt = tel.api_calls(q(hours=6, family="all", limit=2, offset=2, page=1))
        self.assertEqual((len(nxt["rows"]), nxt["has_more"], "summary" in nxt), (1, False, False))
        self.assertEqual({r["id"] for r in pg["rows"]} & {r["id"] for r in nxt["rows"]}, set())
        d = tel.api_calls(q(hours=6, family="all", provider="openrouter"))
        self.assertEqual(len(d["rows"]), 2)
        self.assertEqual({x["family"]: x["n"] for x in d["families"]}, {"deepseek": 1, "openai": 1}, "tabs follow the provider filter")

    def test_proxy_only_rows_take_the_hermes_provider_of_their_upstream(self):
        st = self.cap.store
        con = st.memory_store()
        now = time.time()
        rows = [  # merged (both sides) rows teach the mapping; proxy-only rows carry only the upstream name
            dict(id="h:1", source="hermes", provider="cliproxy-claude", upstream_provider="claude", family="claude", started=now),
            dict(id="h:2", source="hermes", provider="cliproxy-gemini", upstream_provider="vertex", family="gemini", started=now),
            dict(id="p:1", source="cliproxy", provider="claude", family="claude", started=now),
            dict(id="p:2", source="cliproxy", provider="vertex", family="gemini", started=now),
            dict(id="p:3", source="cliproxy", provider="antigravity", family="gemini", started=now),
        ]
        for r in rows:
            st.upsert(con, r, "calls")
        con.execute("DELETE FROM kv WHERE k='provider_rev'")
        self.cap._sibling("telemetry")._proxy_extension().backfill_providers(con)
        got = {r[0]: (r[1], r[2]) for r in con.execute("SELECT id, provider, upstream_provider FROM calls WHERE source='cliproxy'")}
        self.assertEqual(got, {"p:1": ("cliproxy-claude", "claude"), "p:2": ("cliproxy-gemini", "vertex"),
                               "p:3": ("cliproxy", "antigravity")})
        self.assertEqual(self.cap._sibling("telemetry")._proxy_extension().hermes_provider_for(con, "vertex", "gemini"), "cliproxy-gemini")
        con.close()

    def mt_telemetry(self):
        spec = importlib.util.spec_from_file_location("_mt_tel_fam", HERE / "collector" / "telemetry.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod


class MissForensicsTest(_HookBase):
    """Prefix comparisons only ever pair items of the same layer; item #0 that is the system prompt says so."""

    def _store(self):
        st, ins = self.cap.store, self.cap.inspector
        con = st.memory_store()
        put = lambda o: st.put_blob(con, o)  # noqa: E731

        def ref(items, keys=None):
            return json.dumps({"order": list((keys or {}).keys()) + ["messages"], "keys": keys or {}, "list_key": "messages",
                               "items": [put(x) for x in items]})
        return st, ins, con, put, ref

    def test_pre_vs_post_layers_are_never_compared(self):
        st, ins, con, put, ref = self._store()
        hist = [{"role": "user", "content": f"turn {i}"} for i in range(6)]
        pre = lambda n: ref([{"role": "system", "content": "SYS"}] + hist[:n])  # noqa: E731  Hermes: system in messages
        post = lambda n: ref([{"role": "user", "parts": [{"text": h["content"]}]} for h in hist[:n]],  # noqa: E731
                             {"systemInstruction": put({"parts": [{"text": "SYS"}]})})        # adapter: systemInstruction
        st.upsert(con, dict(id="a", session_id="s", started=1.0, status=200, source="hermes", req_down=post(4), req_hermes=pre(4), file="a.log"), "wire_calls")
        st.upsert(con, dict(id="b", session_id="s", started=2.0, status=200, source="hermes", req_down=pre(6)), "wire_calls")
        d = ins.explain_miss(con, "b", "s", 2.0, 50000, 0.0)
        self.assertEqual((d["layer"], d["common_items"]), ("pre", 5))
        self.assertTrue(d["why"].startswith("prefix intact"), d)
        # the old any-layer comparison is exactly the reported bug
        self.assertEqual(self.cap._explain_miss_any_layer(con, "b", {"session_id": "s", "started": 2.0, "prompt_tokens": 50000})["common_items"], 0)
        # after b's proxy merge it has both layers: compared post vs post
        st.upsert(con, dict(id="b", req_down=post(6), req_hermes=pre(6), file="b.log"), "wire_calls")
        self.assertEqual(ins.explain_miss(con, "b", "s", 2.0, 50000, 0.0)["layer"], "post")
        con.close()

    def test_system_item_zero_is_labelled_a_system_prompt_change(self):
        st, ins, con, put, ref = self._store()
        st.upsert(con, dict(id="a", session_id="s", started=1.0, status=200, source="hermes",
                            req_down=ref([{"role": "system", "content": "v1"}, {"role": "user", "content": "hi"}])), "wire_calls")
        st.upsert(con, dict(id="b", session_id="s", started=2.0, status=200, source="hermes",
                            req_down=ref([{"role": "system", "content": "v2"}, {"role": "user", "content": "hi"}])), "wire_calls")
        st.upsert(con, dict(id="c", session_id="s", started=3.0, status=200, source="hermes",
                            req_down=ref([{"role": "system", "content": "v2"}, {"role": "user", "content": "HI"}])), "wire_calls")
        self.assertEqual(ins.explain_miss(con, "b", "s", 2.0, 50000, 0.0)["why"], "system prompt changed")
        self.assertEqual(ins.explain_miss(con, "c", "s", 3.0, 50000, 0.0)["why"], "history item #0 rewritten", "counted after the system message")
        con.close()


class CostTest(_HookBase):
    """cost_usd and cost_equiv_usd come from one token split and one price, so cost never exceeds its equivalent."""

    def test_proxy_route_is_priced_at_the_model_makers_list_price(self):
        st = self.cap.store
        if st.price_call("gemini-4-argon", "gemini", 1000, 0, 0, 0, 1000)[0] is None:
            self.skipTest("no Hermes pricing table importable here")
        con = st.memory_store()
        base = dict(source="hermes", model="gemini-4-argon", family="gemini", provider="cliproxy-gemini",
                    url="http://127.0.0.1:8080/v1", prompt_tokens=100000, cached_tokens=90000, uncached_tokens=10000,
                    cache_write_tokens=0, output_tokens=500)
        st.upsert(con, dict(base, id="api", billing="api", auth_type="api_key", proxy_rid="p1", cost_usd=0.05, cost_equiv_usd=None), "calls")
        st.upsert(con, dict(base, id="sub", billing="api", auth_type="oauth", proxy_rid="p2", cost_usd=0.05, cost_equiv_usd=0.01), "calls")
        st.upsert(con, dict(base, id="unknown", billing="api", cost_usd=0.05, cost_equiv_usd=None), "calls")
        for cid in ("api", "sub", "unknown"):
            st.reprice(con, cid)
        api = con.execute("SELECT cost_usd, cost_equiv_usd FROM calls WHERE id='api'").fetchone()
        sub = con.execute("SELECT cost_usd, cost_equiv_usd, billing FROM calls WHERE id='sub'").fetchone()
        unk = con.execute("SELECT cost_usd, cost_equiv_usd FROM calls WHERE id='unknown'").fetchone()
        want = st.price_call("gemini-4-argon", "gemini", 10000, 90000, 0, 500, 100000)[0]
        self.assertEqual((api[0], api[1]), (want, want), "API key: cost == equivalent at Google's list price")
        self.assertEqual((sub[0], sub[1], sub[2]), (0.0, want, "sub"), "OAuth credential: $0 with the same equivalent")
        self.assertEqual((unk[0], unk[1]), (None, want), "route Hermes cannot bill-resolve and no credential seen: paid unknown")
        con.close()


class AuthLabelTest(_HookBase):
    """Account emails are masked on screen; a proxy log of one family never stays on a call of another."""

    def test_mask_email(self):
        m = self.cap.store.mask_email
        self.assertEqual(m("demo495@example.com"), "d***5@e***.com")
        self.assertEqual(m('[{"key": "ab@x.co.uk"}]'), '[{"key": "a***@x***.uk"}]')
        self.assertEqual(m("vertex-apikey"), "vertex-apikey")
        js = (HERE / "dashboard" / "dist" / "index.js").read_text()
        self.assertIn("var mk = function", js, "the web UI masks account emails on screen")

    def test_credential_fingerprint_without_a_proxy(self):
        fp = self.cap._credential_extension().credential_fingerprint
        self.assertEqual(fp({"Authorization": "Bearer sk-or-v1-abcdefgh1234"}), ("1234", "api_key"))
        self.assertEqual(fp({"x-api-key": "sk-ant-api03-zzzzWXYZ"}), ("WXYZ", "api_key"))
        self.assertEqual(fp({"authorization": "Bearer eyJhbGc.eyJzdWIi.sigQ9z8"}), ("Q9z8", "oauth"))
        self.assertIsNone(fp({"content-type": "application/json"}))

    def test_named_credential_resolves_to_its_pool_label(self):
        named, auto = "sk-or-v1-named-0000aaaa", "sk-or-v1-plain-0000bbbb"
        (self.home / "auth.json").write_text(json.dumps({"credential_pool": {"openrouter": [
            {"id": "a1", "label": "openrouter-work", "source": "manual", "auth_type": "api_key", "access_token": named},
            {"id": "a2", "label": "OPENROUTER_API_KEY", "source": "env:OPENROUTER_API_KEY", "auth_type": "api_key", "access_token": auto},
        ]}}))
        ci = self.cap.credential_identity
        self.assertEqual(ci({"Authorization": "Bearer " + named}), ("openrouter-work", "api_key"))
        self.assertEqual(ci({"Authorization": "Bearer " + auto}), ("bbbb", "api_key"), "unnamed: 4-char suffix")
        self.assertEqual(ci({"x-api-key": "sk-ant-api03-unknownZZZZ"}), ("ZZZZ", "api_key"))
        self.assertNotIn(named, json.dumps(self.cap._credential_extension()._NAMES["map"]), "digests only")

    def test_failover_to_another_family_detaches_the_first_familys_proxy_log(self):
        st = self.cap.store
        con = st.memory_store()
        # a Gemini call whose proxy log (two 429s on Vertex keys) merged in, then Hermes failed over to Codex
        st.upsert(con, dict(id="h:1", source="hermes", family="openai", model="gpt-5.6-sol", provider="openai-codex",
                            url="https://chatgpt.com/backend-api/codex", api_mode="codex_responses", proxy_rid="p1",
                            proxy_family="gemini", file="v1beta-models-gemini-x-p1.log", auth_key="x3XQ", auth_type="api_key",
                            project="705520657614", upstream_provider="vertex", billing="api", n429=2, attempts=2,
                            attempt_detail=json.dumps([{"n": 1, "status": 429, "key": "NyGg", "label": "vertex-apikey"},
                                                       {"n": 2, "status": 429, "key": "x3XQ", "label": "vertex-apikey"}])), "calls")
        st.upsert(con, dict(id="h:1", source="hermes", file="v1beta-models-gemini-x-p1.log", req_up="{}"), "wire_calls")
        con.execute("INSERT INTO seen_files VALUES ('v1beta-models-gemini-x-p1.log', 1, 1)")
        self.assertTrue(self.cap._sibling("telemetry")._proxy_extension().detach_cross_family(con, "h:1"))
        r = con.execute("SELECT proxy_rid, auth_key, auth_type, project, upstream_provider, auth_label, attempt_detail, n429 FROM calls WHERE id='h:1'").fetchone()
        self.assertEqual(tuple(r), (None, None, None, None, None, "openai-codex", None, 0))
        self.assertIsNone(con.execute("SELECT file FROM wire_calls WHERE id='h:1'").fetchone()[0])
        self.assertEqual(con.execute("SELECT COUNT(*) FROM seen_files").fetchone()[0], 0, "log requeued as its own call")
        self.assertFalse(self.cap._sibling("telemetry")._proxy_extension().detach_cross_family(con, "h:1"))
        con.close()


class PollerTest(_HookBase):
    """The in-plugin poller: one scanning process per machine (flock), file-at-a-time, cheap idle ticks."""

    class _FakeTel:
        def __init__(self, db):
            self.DB_PATH, self.calls = db, 0

        def poll_once(self, max_files=None):
            self.calls += 1
            return 0, 0, False

    def _poller_mod(self):
        return _load("_mt_test_poller", HERE / "collector" / "poller.py")

    def test_flock_elects_one_scanner_and_hands_over(self):
        pm = self._poller_mod()
        lock = self.home / "plugin-data" / "wiretap" / "poller.lock"
        a_tel, b_tel = self._FakeTel(lock.with_name("telemetry.db")), self._FakeTel(lock.with_name("telemetry.db"))
        a, b = pm.Poller(a_tel, lock_path=lock), pm.Poller(b_tel, lock_path=lock)
        a.tick(); b.tick()
        self.assertEqual((a.holder, b.holder, a_tel.calls, b_tel.calls), (True, False, 1, 0))
        a._release()  # the holder process exits: the kernel drops its lock
        b.tick()
        self.assertEqual((b.holder, b_tel.calls), (True, 1))
        b._release()

    def test_lock_held_by_another_process(self):
        pm = self._poller_mod()
        lock = self.home / "poller.lock"
        script = self.home / "hold.py"
        script.write_text("import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
                          "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(30)\n")
        proc = subprocess.Popen([sys.executable, str(script), str(lock)], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(proc.stdout.readline().strip(), "held")
            tel = self._FakeTel(self.home / "telemetry.db")
            p = pm.Poller(tel, lock_path=lock)
            self.assertEqual((p.tick(), p.holder, tel.calls), (0, False, 0))
        finally:
            proc.kill(); proc.wait(5); proc.stdout.close()
        self.assertEqual((p.tick(), p.holder, tel.calls), (0, True, 1), "takes over once the other process is gone")
        p._release()

    def test_thread_enriches_one_file_per_transaction_and_idles_cheaply(self):
        logs = self.home / "proxy-logs"
        logs.mkdir()
        os.environ["CLIPROXY_LOG_DIR"] = str(logs)
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]
        cid = self.chat_call(1, msgs, "hi there")
        body = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS, "stream": True}
        _proxy_log(logs / "v1-chat-completions-2026-0001abcd.log", self.t0 + 10.2, body, body, "hi there")
        _proxy_log(logs / "v1-chat-completions-2026-0002abcd.log", self.t0 + 30, body, body, "unrelated")
        self.cap._writer.flush(5)
        t = _load("_mt_test_telemetry_poll", HERE / "collector" / "telemetry.py")
        t.init_db()
        self.assertEqual(t.poll_once(1)[0::2], (1, True), "one file per call, more pending")
        self.assertEqual(t.poll_once(1)[0::2], (1, False))
        self.assertEqual(t.poll_once(1), (0, 0, False), "directory unchanged: no scan")
        con = self.db()
        self.assertEqual(con.execute("SELECT proxy_rid FROM calls WHERE id=?", (cid,)).fetchone()[0], "0001abcd")
        con.close()
        # and as the real thread, on a new file
        os.environ["MODEL_TELEMETRY_POLLER"] = "1"
        pm = self._poller_mod()
        _proxy_log(logs / "v1-chat-completions-2026-0003abcd.log", self.t0 + 45, body, body, "third")
        p = pm.start(t, interval=0.2)
        try:
            deadline = time.time() + 10
            while time.time() < deadline and p.files < 1:
                time.sleep(0.05)
            self.assertEqual((p.files, p.holder, p.last_error), (1, True, None))
            self.assertIs(pm.running(), p)
            q = pm.start(t, interval=0.2)  # a reload replaces the thread; the lock moves with it
            self.assertFalse(p.is_alive())
            deadline = time.time() + 5
            while time.time() < deadline and not q.holder:
                time.sleep(0.05)
            self.assertTrue(q.holder)
        finally:
            for x in (p, locals().get("q")):
                if x is not None:
                    x.stop(5)


class ModuleLifecycleTest(_HookBase):
    def test_a_lazily_loaded_sibling_does_not_retire_the_capture_module(self):
        """A sibling loaded after capture (signals, on the first refusal check) must not make the next hook reload
        capture.py — that dropped every armed call and reset the tap counters."""
        first = self.mt._capture()
        for k in [k for k in sys.modules if k == "_wiretap_signals"]:
            del sys.modules[k]
        spec = importlib.util.spec_from_file_location("_wiretap_signals", HERE / "collector" / "signals.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_wiretap_signals"] = mod
        spec.loader.exec_module(mod)  # loaded without a load stamp, as a lazy loader of an older version would
        self.assertIs(self.mt._capture(), first)
        self.assertIs(self.mt._capture(), first)


class HttpTapTest(_HookBase):
    """The stored request is the body that left the process, even when something rewrote it after the hooks."""

    def test_final_outbound_body_wins_over_the_hook_snapshot(self):
        try:
            import httpx
        except Exception as e:  # pragma: no cover
            self.skipTest(f"httpx unavailable: {e}")
        self.assertTrue(getattr(httpx.Client._send_single_request, "_wiretap_http_tap", False))
        ask = "hello, please check the wire framing today"
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": ask}]
        # Another plugin / provider adapter rewrites the request after pre_api_request, then sends it: it wraps the
        # newest message and inserts its own item before it (the newest message stays last — see SIG_ADAPTER_SLACK).
        rewritten = {"model": "gpt-5.5", "messages": [msgs[0], {"role": "user", "content": "injected by another plugin"},
                                                      {"role": "user", "content": "<USER_REQUEST>\n" + ask + "\n</USER_REQUEST>"}]}

        def send():
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True})))
            client.post("https://openrouter.ai/api/v1/chat/completions", json=rewritten,
                        headers={"Authorization": "Bearer SECRET-TOKEN"})
            client.post("https://elsewhere.example/telemetry", json={"unrelated": True})  # other host: ignored
            client.close()

        cid = self.chat_call(1, msgs, "hi", between=send)
        self.cap._writer.flush(5)
        con = self.db()
        ins = self.cap.inspector
        wire = ins.wire_summary(con, cid, "down")
        self.assertEqual((wire["layer"], len(wire["items"])), ("wire", 3))
        self.assertIn("injected by another plugin", wire["items"][1]["head"])
        self.assertNotIn("SECRET-TOKEN", json.dumps(wire["headers_down"]))
        pre = ins.wire_summary(con, cid, "hermes")
        self.assertEqual((pre["which"], len(pre["items"])), ("hermes", 2))
        self.assertIsNone(self.cap._ARMED.get(), "disarmed after the response")
        con.close()


    def test_a_local_proxy_token_is_never_a_credential_and_the_request_is_tagged(self):
        import httpx
        seen = []
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]

        def send():
            def handler(req):
                seen.append(dict(req.headers))
                return httpx.Response(200, json={"ok": True})
            client = httpx.Client(transport=httpx.MockTransport(handler))
            client.post("http://127.0.0.1:8080/v1/chat/completions", json={"model": "gpt-5.5", "messages": msgs},
                        headers={"Authorization": "Bearer sk-cliproxy-client-QF9S"})
            client.close()

        cid = self.chat_call(1, msgs, "hi", between=send, base_url="http://127.0.0.1:8080/v1", provider="cliproxy-claude")
        self.cap._writer.flush(5)
        con = self.db()
        self.assertEqual(seen[0].get("x-wiretap-call", "").split("~")[0], cid, "the local hop carries the call id")
        nonce = seen[0]["x-wiretap-call"].split("~")[1]
        self.assertEqual(con.execute("SELECT auth_key, auth_type FROM calls WHERE id=?", (cid,)).fetchone()[:], (None, None))
        self.assertEqual(con.execute("SELECT tap_key, tap_kind FROM wire_calls WHERE id=?", (cid,)).fetchone()[:], (None, "proxy"))
        self.assertIn(nonce, json.loads(con.execute("SELECT tap_nonces FROM wire_calls WHERE id=?", (cid,)).fetchone()[0]),
                      "the request's tag is blessed only by its validated capture")
        con.close()

    def test_the_final_request_credential_wins(self):
        """A retry/failover's later request replaces an earlier attempt's credential (it used to keep the first)."""
        import httpx
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]

        def send():
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True})))
            for key in ("sk-or-first-attempt-AAAA", "sk-or-second-attempt-BBBB"):
                client.post("https://openrouter.ai/api/v1/chat/completions", json={"model": "gpt-5.5", "messages": msgs},
                            headers={"Authorization": "Bearer " + key})
            client.close()

        cid = self.chat_call(1, msgs, "hi", between=send)
        self.cap._writer.flush(5)
        con = self.db()
        self.assertEqual(con.execute("SELECT auth_key, auth_type FROM calls WHERE id=?", (cid,)).fetchone()[:], ("BBBB", "api_key"))
        con.close()

    def test_repair_clears_proxy_client_tokens(self):
        st = self.cap.store
        con = st.memory_store()
        st.upsert(con, dict(id="h:p", source="hermes", provider="cliproxy-claude", auth_key="QF9S", auth_type="api_key"), "calls")
        st.upsert(con, dict(id="h:p", source="hermes", url="http://127.0.0.1:8080/v1/messages"), "wire_calls")
        st.upsert(con, dict(id="h:f", source="hermes", provider="openai-codex", auth_key="QF9S", auth_type="api_key"), "calls")
        st.upsert(con, dict(id="h:f", source="hermes", url="https://chatgpt.com/backend-api/codex/responses"), "wire_calls")
        st.upsert(con, dict(id="h:d", source="hermes", provider="openrouter", auth_key="1234", auth_type="api_key"), "calls")
        st.upsert(con, dict(id="h:d", source="hermes", url="https://openrouter.ai/api/v1/chat/completions"), "wire_calls")
        st.upsert(con, dict(id="h:m", source="hermes", provider="cliproxy-claude", auth_key="9876", auth_type="oauth", proxy_rid="r"), "calls")
        st.upsert(con, dict(id="h:m", source="hermes", url="http://127.0.0.1:8080/v1/messages"), "wire_calls")
        con.execute("DELETE FROM kv WHERE k='proxy_token_rev'")
        self.assertEqual(self.cap._sibling("telemetry")._proxy_extension().repair_proxy_tokens(con), 2)
        keys = dict(con.execute("SELECT id, auth_key FROM calls").fetchall())
        self.assertEqual(keys, {"h:p": None, "h:f": None, "h:d": "1234", "h:m": "9876"}, "merged upstream keys are kept")
        self.assertEqual(self.cap._sibling("telemetry")._proxy_extension().repair_proxy_tokens(con), 0, "once")
        con.close()

    def test_sidecar_calls_never_land_on_the_armed_call(self):
        """An approval classifier / auxiliary client call made while a conversation call is armed — before it, or
        after it in the same turn — is not that call's wire."""
        import contextvars
        import httpx
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello " * 200}]
        real = {"model": "gpt-5.5", "messages": msgs, "tools": TOOLS}
        side = {"model": "gpt-5.5", "messages": [{"role": "user", "content": "The following command was flagged as: x"}]}

        def post(obj):
            client = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"ok": True})))
            client.post("https://openrouter.ai/api/v1/chat/completions", json=obj)
            client.close()

        def between():
            post(side)   # a sidecar call fires first while this call is armed
            post(real)   # the conversation request
            post(side)   # and another sidecar before the response hook
        chars = sum(len(m["content"]) for m in msgs)
        cid = self.chat_call(1, msgs, "hi", between=between, request_char_count=chars)
        # after post_api_request — fired here in a copied context, as Hermes's API worker does — the arm is dead even
        # in this context, so a classifier call later in the turn is ignored too
        post(side)
        self.cap._writer.flush(5)
        con = self.db()
        wire = self.cap.inspector.wire_summary(con, cid, "down")
        self.assertEqual(len(wire["items"]), 2, "the conversation request, not a 1-message sidecar")
        con.close()
        arm = {"id": "x", "host": None, "t": 0, "done": False, "got": None, "expect": None}
        tok = self.cap._ARMED.set(arm)
        contextvars.copy_context().run(self.cap._disarm, "x")
        self.assertIsNone(self.cap._armed_for("openrouter.ai"), "disarmed from another context")
        self.cap._ARMED.reset(tok)


try:  # real-runtime contract: drive the plugin through Hermes's own hook call sites when importable
    import agent.turn_api_request as _tar  # type: ignore
    import agent.turn_response_intake as _tri  # type: ignore
    from agent.api_request_hooks import ApiRequestHooksMixin  # type: ignore
except Exception as _e:  # pragma: no cover - plugin tests run without a Hermes checkout on sys.path
    _TAR_ERR = repr(_e)
    _tar = None


@unittest.skipIf(_tar is None, "Hermes runtime not importable (set PYTHONPATH to a Hermes checkout): " + globals().get("_TAR_ERR", ""))
def _jwt(claims: dict) -> str:
    import base64
    enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")  # noqa: E731
    return enc({"alg": "RS256"}) + "." + enc(claims) + "." + "sig" + str(abs(hash(json.dumps(claims))) % 10 ** 8)


def _acct(a: str) -> dict:
    return {"https://api.openai.com/auth": {"chatgpt_account_id": a}, "exp": 9999999999}


class TapCorrelationTest(_HookBase):
    """Hermes fires pre/post_api_request on bounded workers under a *copy* of the caller's context, so an arm set in
    the hook never reaches the send. These run the hooks that way and send from context-free threads, as live."""

    def _hook(self, name, **kw):
        import contextvars
        t = threading.Thread(target=contextvars.copy_context().run, args=(lambda: self.ctx.hooks[name](**kw),))
        t.start()
        t.join(10)

    def _pre(self, n, msgs, session, base_url="http://127.0.0.1:8080/v1", provider="cliproxy-claude",
             model="claude-opus-5-5", retry=0, mode="chat_completions", list_key="messages"):
        rid = f"{session}:api:{n}"
        base = dict(session_id=session, platform="cli", model=model, provider=provider, base_url=base_url, api_mode=mode,
                    api_request_id=rid, turn_id="t", task_id="t", api_call_count=n)
        self._hook("pre_api_request", request_messages=list(msgs), retry_count=retry, system_prompt=SYSTEM,
                   message_count=len(msgs), tool_count=0, started_at=self.t0 + n,
                   request_char_count=sum(len(json.dumps(m)) for m in msgs),
                   request={"method": "POST", "body": {"_truncated": True}}, **base)
        return "h:" + rid, base

    def _post(self, base, n, msgs):
        msg = SimpleNamespace(role="assistant", content="ok", tool_calls=[], reasoning=None)
        self._hook("post_api_request", api_duration=1.0, started_at=self.t0 + n, ended_at=self.t0 + n + 1,
                   first_chunk_at=None, finish_reason="stop", message_count=len(msgs), response_model=base["model"],
                   response={"model": base["model"]}, assistant_message=msg,
                   usage={"input_tokens": 10, "output_tokens": 2, "prompt_tokens": 10}, context_length=1000,
                   assistant_content_chars=2, assistant_tool_call_count=0, **base)

    def _send(self, url, body=None, headers=None, raw=None):
        """POST from a fresh thread with an empty context (no arm can be inherited); returns the sent headers."""
        import contextvars
        import httpx
        sent: dict = {}

        def go():
            def handler(req):
                sent.update({k.lower(): v for k, v in req.headers.items()})
                return httpx.Response(200, json={"ok": True})
            c = httpx.Client(transport=httpx.MockTransport(handler))
            if raw is not None:
                c.post(url, content=raw, headers=headers or {})
            else:
                c.post(url, json=body, headers=headers or {})
            c.close()
        t = threading.Thread(target=contextvars.Context().run, args=(go,))
        t.start()
        t.join(10)
        return sent

    def _req(self, con, cid):
        return con.execute("SELECT w.req_bytes, w.n_items, w.url, w.exact, c.auth_key, c.auth_type FROM wire_calls w "
                           "JOIN calls c ON c.id=w.id WHERE w.id=?", (cid,)).fetchone()

    def test_signature_is_the_newest_messages_id_or_a_plain_text_run(self):
        sig = self.cap.call_signature
        self.assertEqual(sig([{"role": "user", "content": "x"}, {"role": "tool", "tool_call_id": "call_abc12345", "content": "r"}]),
                         b'"call_abc12345"')
        self.assertEqual(sig([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01XYZabc", "content": "r"}]}]),
                         b'"toolu_01XYZabc"')
        self.assertEqual(sig([{"type": "function_call_output", "call_id": "call_codexQQ99", "output": "{}"}]), b'"call_codexQQ99"')
        t = sig([{"role": "user", "content": 'Please "quote" this: summarize the quarterly shipping report in two lines'}])
        self.assertTrue(t and len(t) <= 48 and b'"' not in t and t in b"summarize the quarterly shipping report in two lines")
        self.assertIsNone(sig([]))

    def test_concurrent_calls_to_one_host_land_on_their_own_rows(self):
        a_msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "refactor the parser please"},
                  {"role": "assistant", "content": "", "tool_calls": [{"id": "call_parserAAAA1111", "type": "function",
                                                                       "function": {"name": "read", "arguments": "{}"}}]},
                  {"role": "tool", "tool_call_id": "call_parserAAAA1111", "content": "file body " * 40}]
        b_msgs = [{"role": "system", "content": SYSTEM},
                  {"role": "user", "content": "Summarize the quarterly shipping report for the account in two lines " * 3}]
        a, ab = self._pre(1, a_msgs, "sa-A")
        b, bb = self._pre(2, b_msgs, "sa-B")
        url, auth = "http://127.0.0.1:8080/v1/chat/completions", {"Authorization": "Bearer sk-proxy-client-QF9S"}
        hb = self._send(url, {"model": "claude-opus-5-5", "messages": b_msgs}, auth)  # b first, from another thread
        ha = self._send(url, {"model": "claude-opus-5-5", "messages": a_msgs}, auth)
        side = self._send(url, {"model": "claude-opus-5-5", "messages": [{"role": "user", "content": "The following command was flagged as: rm"}]}, auth)
        self._post(ab, 1, a_msgs)
        self._post(bb, 2, b_msgs)
        con = self.db()
        tagof = lambda h: (h.get("x-wiretap-call") or "").split("~")[0] or None  # noqa: E731
        self.assertEqual((tagof(ha), tagof(hb), tagof(side)), (a, b, None),
                         "each request tagged with its own call; the sidecar with none")
        ra, rb = self._req(con, a), self._req(con, b)
        self.assertEqual((ra[1], ra[3], rb[1], rb[3]), (4, 1, 2, 1))
        self.assertEqual((ra[4], rb[4]), (None, None), "a proxy hop records no credential")
        self.assertGreaterEqual(self.cap.TAP_STATS["sig"], 2)
        con.close()

    def test_a_lone_text_signature_miss_never_takes_the_armed_call(self):
        msgs = [{"role": "user", "content": "Summarize the quarterly shipping report for the account in two lines please"}]
        cid, base = self._pre(1, msgs, "sa-T")
        # an unrelated, similarly sized classifier request while this is the only armed call
        self._send("http://127.0.0.1:8080/v1/chat/completions",
                   {"model": "m", "messages": [{"role": "user", "content": "classify this command for safety: " + "x " * 40}]})
        self._post(base, 1, msgs)
        con = self.db()
        r = con.execute("SELECT exact, tap_miss FROM wire_calls WHERE id=?", (cid,)).fetchone()
        self.assertNotEqual(r[0], 1, "no exact wire from someone else's request")
        self.assertTrue(r[1], "the miss is recorded on the call with its reason")
        con.close()

    def test_a_sidecar_carrying_an_older_copy_is_rejected_and_the_real_request_still_lands(self):
        tail = {"role": "tool", "tool_call_id": "call_histQQQQ1234", "content": "result " * 30}
        msgs = [{"role": "user", "content": "go"}, {"role": "assistant", "content": "", "tool_calls": [
            {"id": "call_histQQQQ1234", "type": "function", "function": {"name": "f", "arguments": "{}"}}]}, tail]
        cid, base = self._pre(1, msgs, "sa-H")
        url = "http://127.0.0.1:8080/v1/chat/completions"
        # a compressor-like request: the whole conversation (with the id, structured) and then its own instruction
        sidecar = msgs + [{"role": "user", "content": "Summarize everything above for a handoff, keep every detail " * 3}]
        self._send(url, {"model": "m", "messages": sidecar})
        self.cap._writer.flush(5)
        con = self.db()
        self.assertNotEqual(con.execute("SELECT exact FROM wire_calls WHERE id=?", (cid,)).fetchone()[0], 1)
        self.assertIn("last", con.execute("SELECT tap_miss FROM wire_calls WHERE id=?", (cid,)).fetchone()[0])
        con.close()
        self._send(url, {"model": "m", "messages": msgs})  # the call's own request
        self._post(base, 1, msgs)
        con = self.db()
        r = con.execute("SELECT exact, n_items, tap_miss FROM wire_calls WHERE id=?", (cid,)).fetchone()
        self.assertEqual((r[0], r[1], r[2]), (1, 3, None))
        con.close()

    def test_a_forked_childs_text_in_the_parents_history_does_not_make_the_parent_ambiguous(self):
        assignment = "Audit the retention sweep for concurrent writers and report every race you can reproduce"
        parent = [{"role": "user", "content": "review it"},
                  {"role": "assistant", "content": "", "tool_calls": [{"id": "call_delegAAAA0001", "type": "function",
                   "function": {"name": "delegate_task", "arguments": json.dumps({"goal": assignment})}}]},
                  {"role": "tool", "tool_call_id": "call_delegAAAA0001", "content": "dispatched"}]
        child = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": assignment}]
        p, pb = self._pre(1, parent, "sa-P")
        c, cb = self._pre(1, child, "sa-C")
        url = "http://127.0.0.1:8080/v1/chat/completions"
        self._send(url, {"model": "m", "messages": parent})  # carries the child's text inside an earlier item
        self._post(pb, 1, parent)
        self._post(cb, 1, child)
        con = self.db()
        self.assertEqual(con.execute("SELECT exact FROM wire_calls WHERE id=?", (p,)).fetchone()[0], 1)
        self.assertNotEqual(con.execute("SELECT exact FROM wire_calls WHERE id=?", (c,)).fetchone()[0], 1)
        con.close()

    def test_an_id_inside_a_non_conversation_sidecar_body_is_not_the_call(self):
        """The review's fixture: a classifier body that quotes the call's newest tool-result id in its own history."""
        msgs = [{"role": "tool", "tool_call_id": "call_main_abcdefgh", "content": "a tool result " * 10}]
        cid, base = self._pre(1, msgs, "sa-I")
        self._send("http://127.0.0.1:8080/v1/chat/completions",
                   {"instruction": "classify historical call", "history": [{"tool_call_id": "call_main_abcdefgh", "content": "x" * 800}]})
        self._post(base, 1, msgs)
        con = self.db()
        r = con.execute("SELECT exact, tap_miss FROM wire_calls WHERE id=?", (cid,)).fetchone()
        self.assertNotEqual(r[0], 1)
        self.assertIn("message list", r[1])
        con.close()

    def test_decompression_is_bounded_by_the_capture_budget(self):
        import gzip
        bomb = gzip.compress(b'{"messages":[' + b" " * 3_000_000 + b"]}")
        self.assertIsNone(self.cap.decode_body(bomb, "gzip", 1024 * 1024), "would expand past the budget: refused")
        self.assertIsNotNone(self.cap.decode_body(bomb, "gzip", 4 * 1024 * 1024))
        self.assertIsNone(self.cap.decode_body(bomb[:-20], "gzip", 4 * 1024 * 1024), "truncated: refused")
        self.assertIsNone(self.cap.decode_body(b"xx", "br", 1024), "no bounded decoder: refused")

    def test_a_lone_armed_call_rejects_a_request_without_its_tool_id(self):
        msgs = [{"role": "user", "content": "go"}, {"role": "tool", "tool_call_id": "call_loneZZZZ9999", "content": "x " * 200}]
        cid, base = self._pre(1, msgs, "sa-L")
        url = "http://127.0.0.1:8080/v1/chat/completions"
        # a compressor-sized sidecar while this call is armed: large enough for the size check, but not this call
        self._send(url, {"model": "m", "messages": [{"role": "user", "content": "summarize: " + "x " * 400}]})
        self._send(url, {"model": "m", "messages": msgs})
        self._post(base, 1, msgs)
        con = self.db()
        self.assertEqual(self._req(con, cid)[1], 2, "the call's own request, not the sidecar")
        self.assertGreaterEqual(self.cap.TAP_STATS["sig_miss"], 1)
        con.close()

    def test_retry_then_cross_family_fallback_keeps_one_row_with_the_answering_credential(self):
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "Plan the migration of the billing tables carefully " * 4}]
        cid, base = self._pre(1, msgs, "sa-R")
        other, ob = self._pre(1, [{"role": "user", "content": "an unrelated concurrent call on the same proxy " * 3}], "sa-O")
        url, auth = "http://127.0.0.1:8080/v1/messages", {"x-api-key": "sk-proxy-client-QF9S"}
        h1 = self._send(url, {"model": "claude-opus-5-5", "messages": msgs}, auth)
        h2 = self._send(url, {"model": "claude-opus-5-5", "messages": msgs}, auth)  # SDK retry, same body
        # the Claude attempt fails; Hermes falls back to Codex: pre fires again for the same request id
        tok = _jwt(_acct("acct-direct-7Q2Z"))
        cid2, base2 = self._pre(1, msgs, "sa-R", base_url="https://chatgpt.com/backend-api/codex", provider="openai-codex",
                                model="gpt-5.6-sol", retry=1, mode="codex_responses")
        h3 = self._send("https://chatgpt.com/backend-api/codex/responses", {"model": "gpt-5.6-sol", "input": msgs},
                        {"Authorization": "Bearer " + tok, "ChatGPT-Account-ID": "acct-direct-7Q2Z"})
        self._post(base2, 1, msgs)
        self._post(ob, 1, [])
        con = self.db()
        self.assertEqual(cid2, cid)
        self.assertEqual((h1.get("x-wiretap-call", "").split("~")[0], h2.get("x-wiretap-call", "").split("~")[0]), (cid, cid))
        self.assertNotEqual(h1["x-wiretap-call"], h2["x-wiretap-call"], "each request has its own nonce")
        self.assertNotIn("x-wiretap-call", h3, "never sent to a provider")
        r = self._req(con, cid)
        self.assertEqual((r[2], r[3], r[4], r[5]), ("https://chatgpt.com/backend-api/codex/responses", 1, "7Q2Z", "oauth"),
                         "the answering request's credential: the account, stable across token refreshes")
        self.assertEqual(con.execute("SELECT COUNT(*) FROM calls WHERE id LIKE 'h:sa-R%'").fetchone()[0], 1)
        con.close()

    def _codex_call(self, n, session, token, acct, encoding):
        msgs = [{"role": "user", "content": f"codex request number {n} for the credential check, padded " * 3}]
        cid, base = self._pre(n, msgs, session, base_url="https://chatgpt.com/backend-api/codex", provider="openai-codex",
                              model="gpt-5.6-sol", mode="codex_responses")
        raw = json.dumps({"model": "gpt-5.6-sol", "input": msgs, "stream": True}).encode()
        if encoding == "zstd":
            try:
                from compression import zstd
            except ImportError:
                import zstandard as zstd_mod  # type: ignore
                packed = zstd_mod.ZstdCompressor().compress(raw)
            else:
                packed = zstd.compress(raw)
        else:
            import gzip
            packed = gzip.compress(raw)
        self._send("https://chatgpt.com/backend-api/codex/responses", raw=packed,
                   headers={"Authorization": "Bearer " + token, "ChatGPT-Account-ID": acct, "Content-Encoding": encoding,
                            "Content-Type": "application/json"})
        self._post(base, n, msgs)
        return cid

    def test_codex_compressed_bodies_and_several_named_codex_credentials(self):
        ta, tb = _jwt(_acct("acct-main-AAAA")), _jwt(_acct("acct-work-BBBB"))
        (self.home / "auth.json").write_text(json.dumps({"credential_pool": {"openai-codex": [
            {"id": "c1", "label": "codex-main", "source": "device_code", "auth_type": "oauth", "access_token": ta},
            {"id": "c2", "label": "codex-work", "source": "device_code", "auth_type": "oauth", "access_token": tb},
        ]}}))
        try:
            from compression import zstd  # noqa: F401
            enc = "zstd"
        except ImportError:
            try:
                import zstandard  # noqa: F401
                enc = "zstd"
            except ImportError:
                enc = "gzip"  # this interpreter cannot make zstd; the decode path is the same function
        refreshed = _jwt(dict(_acct("acct-main-AAAA"), exp=1))  # a token refreshed since auth.json was written
        cids = [self._codex_call(1, "cx1", tb, "acct-work-BBBB", enc),
                self._codex_call(2, "cx2", refreshed, "acct-main-AAAA", "gzip"),
                self._codex_call(3, "cx3", _jwt(_acct("acct-other-CCCC")), "acct-other-CCCC", enc)]
        con = self.db()
        got = [self._req(con, c) for c in cids]
        self.assertEqual([(r[3], r[1]) for r in got], [(1, 1)] * 3, f"{enc}/gzip bodies decoded and captured")
        self.assertEqual([(r[4], r[5]) for r in got], [("codex-work", "oauth"), ("codex-main", "oauth"), ("CCCC", "oauth")])
        self.assertNotIn(ta, json.dumps(self.cap._credential_extension()._NAMES), "digests only")
        con.close()


class HermesRuntimeContractTest(unittest.TestCase):
    """The kwargs and frame shape of Hermes's real ``_fire_pre/post_api_request_hook`` reach the store intact."""

    def test_real_call_sites(self):
        import hermes_cli.lifecycle as lc  # type: ignore
        from agent.api_request_hooks import ApiRequestHooksMixin
        from agent import turn_api_request as _tar, turn_response_intake as _tri
        import types

        # The two helpers the call sites import lazily from agent.conversation_loop; importing that module cold
        # boots a full runtime, so a stub stands in unless a real one is already loaded.
        stubbed = "agent.conversation_loop" not in sys.modules
        if stubbed:
            cl = types.ModuleType("agent.conversation_loop")
            cl._system_prompt_for_hooks = lambda kw, msgs: kw.get("system") or kw.get("instructions")
            cl._moa_reference_metrics_for_hook = lambda agent: None
            sys.modules["agent.conversation_loop"] = cl

        with tempfile.TemporaryDirectory() as tmp:
            old = {k: os.environ.get(k) for k in ("HERMES_HOME", "TELEMETRY_DB")}
            os.environ.update(HERMES_HOME=tmp, TELEMETRY_DB=str(Path(tmp) / "t.db"))
            mt = _load("_mt_test_plugin_rt", HERE / "__init__.py")
            cap = mt._capture()
            cap._writer = cap.Writer()
            ctx = _Ctx()
            mt.register(ctx)
            saved = (lc.has_hook, lc.invoke_hook)
            lc.has_hook = lambda name: name in ctx.hooks
            lc.invoke_hook = lambda name, **kw: [ctx.hooks[name](**kw)]
            try:
                class Agent(ApiRequestHooksMixin):
                    session_id, platform, model, provider = SID, "cli", "claude-sonnet-4-6", "anthropic"
                    base_url, api_mode, max_tokens = "https://api.anthropic.com", "anthropic_messages", 4096
                    tools = [{"name": "terminal"}] * 3
                    _last_api_first_chunk_at = None
                    context_compressor = SimpleNamespace(context_length=200000)

                ag = Agent()
                msgs = [{"role": "user", "content": [{"type": "text", "text": "x" * 30000}]}]  # > hook payload cap
                api_kwargs = {"model": ag.model, "system": [{"type": "text", "text": SYSTEM}], "messages": msgs,
                              "tools": [{"name": "terminal", "input_schema": {"type": "object"}}], "max_tokens": 4096,
                              "api_key": "sk-ant-SECRET"}
                t0 = time.time()
                _tar._fire_pre_api_request_hook(
                    ag, api_kwargs, msgs, [], messages=msgs, original_user_message="x", approx_tokens=8000,
                    total_chars=30000, retry_count=0, api_call_count=1, api_request_id="rt:api:1", api_start_time=t0,
                    effective_task_id="task", turn_id="rt")
                ag._invoke_api_request_error_hook(
                    task_id="task", turn_id="rt", api_request_id="rt:api:1", api_call_count=1,
                    api_start_time=t0, api_kwargs=api_kwargs, error_type="RateLimitError",
                    error_message="synthetic retry", status_code=429, retry_count=0,
                    max_retries=3, retryable=True, reason="rate_limit")
                ag._last_api_first_chunk_at = t0 + 0.5
                resp = SimpleNamespace(model=ag.model, usage=SimpleNamespace(input_tokens=10, output_tokens=5,
                                                                             cache_read_input_tokens=7990,
                                                                             cache_creation_input_tokens=0))
                am = SimpleNamespace(role="assistant", content="done", tool_calls=[], reasoning=None)
                _tri._fire_post_api_request_hook(
                    ag, resp, am, "stop", api_messages=msgs, api_call_count=1, api_duration=2.0, api_start_time=t0,
                    api_request_id="rt:api:1", effective_task_id="task", turn_id="rt")
                cap._writer.flush(5)
                con = sqlite3.connect(os.environ["TELEMETRY_DB"])
                w = con.execute("SELECT exact, req_down, resp, status FROM wire_calls WHERE id='h:rt:api:1'").fetchone()
                self.assertIsNotNone(w, "pre/post_api_request reached the store")
                self.assertEqual((w[0], w[3]), (1, 200), "exact envelope located through the real call site")
                req = cap.inspector.rebuild(con, json.loads(w[1]))
                self.assertEqual(req["messages"], msgs)
                self.assertEqual(req["api_key"], "‹redacted›")
                self.assertEqual(json.loads(w[2])["text"], "done")
                c = con.execute("SELECT ttfb_s, context_length, cached_tokens FROM calls WHERE id='h:rt:api:1'").fetchone()
                self.assertEqual(c[0], 0.5)
                self.assertEqual(c[1], 200000)
                self.assertEqual(con.execute("SELECT n429, nfail FROM calls WHERE id='h:rt:api:1'").fetchone(), (1, 1))
                con.close()
            finally:
                lc.has_hook, lc.invoke_hook = saved
                if stubbed:
                    sys.modules.pop("agent.conversation_loop", None)
                cap._writer.stop(5)
                for k, v in old.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
