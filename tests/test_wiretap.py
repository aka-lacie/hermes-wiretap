"""Hermes-side capture, end to end: synthetic hook kwargs -> telemetry.db -> inspector views -> dashboard API.

Covers the contracts that make the plugin work on stock Hermes with any provider: the hooks never raise, the
request is stored from the hook arguments (raw messages and system prompt, the envelope from Hermes's sanitized
copy, flagged as such), credentials never reach disk, retries / errors are accounted, consecutive calls dedupe,
and the Inspector's Compiled-now and Transcript views work from that data alone.
"""
import importlib.util
import json
import os
import sqlite3
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


def hook_request(api_kwargs):
    """The ``request`` argument as Hermes builds it: its own sanitizer and size cap over the provider kwargs."""
    from agent.api_request_hooks import ApiRequestHooksMixin
    return ApiRequestHooksMixin()._api_request_payload_for_hook(api_kwargs)


def proposed_hook_args(api_kwargs):
    """``request_tools`` and ``request_params`` as proposed upstream; no Hermes release passes them yet. The tools
    are the provider-client list itself; the parameters are every other non-message, non-transport kwarg,
    JSON-normalized and key-redacted by Hermes but outside its size cap."""
    from agent.api_request_hooks import ApiRequestHooksMixin
    owned = {"messages", "input", "system", "instructions", "tools", "timeout", "http_client", "extra_headers",
             "default_headers", "extra_query"}
    return {"request_tools": list(api_kwargs.get("tools") or []),
            "request_params": ApiRequestHooksMixin._hook_jsonable({k: v for k, v in api_kwargs.items() if k not in owned})}


PROPOSED = ("request_tools", "request_params")


def fire_pre(hook, api_kwargs, patched=(), **kw):
    """Mimics agent/turn_api_request._fire_pre_api_request_hook: shallow-copied ``request_messages`` (same item
    objects) and Hermes's sanitized ``request`` copy. Nothing else of ``api_kwargs`` reaches the hook, unless
    ``patched`` names proposed arguments, standing in for a Hermes that passes them."""
    lst = api_kwargs.get("messages") if isinstance(api_kwargs.get("messages"), list) else api_kwargs.get("input")
    kw.setdefault("request", hook_request(api_kwargs))
    kw.update({k: v for k, v in proposed_hook_args(api_kwargs).items() if k in patched})
    hook(request_messages=list(lst), **kw)


class _HookBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.old_env = {k: os.environ.get(k) for k in ("HOME", "HERMES_HOME", "TELEMETRY_DB", "MAIN_SESSION")}
        os.environ.update(HOME=str(self.home), HERMES_HOME=str(self.home), MAIN_SESSION="",
                          TELEMETRY_DB=str(self.home / "plugin-data/wiretap/telemetry.db"))
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

    def chat_call(self, n, messages, reply="", tool_calls=None, usage=None, extra=None, between=None, model="gpt-5.5",
                  patched=(), **over):
        """One chat-completions round trip through the plugin's hooks."""
        rid = f"turn1:api:{n}"
        api_kwargs = {"model": model, "messages": messages, "tools": TOOLS, "temperature": 1,
                      "api_key": "sk-SECRET-KEY", "timeout": 30,
                      "extra_headers": {"Authorization": "Bearer SECRET-TOKEN", "X-Title": "hermes"}, **(extra or {})}
        base = {**dict(session_id=SID, platform="telegram", model=model, provider="openrouter",
                       base_url="https://user:pw@openrouter.ai/api/v1?key=SECRET-QS", api_mode="chat_completions",
                       api_request_id=rid, turn_id="turn1", task_id="t", api_call_count=n), **over}
        started = self.t0 + n * 10
        fire_pre(self.ctx.hooks["pre_api_request"], api_kwargs, patched=patched, retry_count=0, system_prompt=SYSTEM,
                 message_count=len(messages), tool_count=len(TOOLS), started_at=started, **base)
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
    def test_request_and_response_are_captured_from_the_hook_arguments(self):
        msgs = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "list files"}]
        tc = SimpleNamespace(id="call_9", type="function", function=SimpleNamespace(name="terminal", arguments='{"cmd": "ls"}'))
        cid = self.chat_call(1, msgs, "", [tc])
        con = self.db()
        w = dict(con.execute("SELECT * FROM wire_calls WHERE id=?", (cid,)).fetchone())
        self.assertEqual((w["source"], w["exact"], w["session_id"], w["status"], w["n_items"]), ("hermes", 0, SID, 200, 2),
                         "a hook capture is never marked exact: its envelope is Hermes's sanitized copy")
        ins = self.cap.inspector
        req = ins.rebuild(con, json.loads(w["req_down"]))
        self.assertEqual(req["tools"], TOOLS, "a request under Hermes's cap carries its tools whole in that copy")
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
        self.chat_call(1, [{"role": "user", "content": "hi"}], "hello",
                       extra={"metadata": {"client_secret": "SECRET-CLIENT"}})  # a key Hermes's sanitizer keeps
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
        self.assertNotIn(b"SECRET-CLIENT", raw, "the plugin redacts secret-named keys itself")
        self.assertIn(b"metadata", raw, "the envelope key that carried it was stored")
        self.assertEqual(os.stat(os.environ["TELEMETRY_DB"]).st_mode & 0o777, 0o600)

    def test_a_capped_hook_copy_still_stores_raw_messages_and_system_prompt(self):
        """Anthropic route. Hermes's ``request`` copy is size-capped: under the cap it carries the envelope (with the
        message list cut down), over it the whole argument is a preview. Messages and system prompt come from the
        raw arguments."""
        msgs = [{"role": "user", "content": [{"type": "text", "text": "summarize"}]}]
        system = [{"type": "text", "text": SYSTEM}]
        partial = {"method": "POST", "body": {"model": "claude-sonnet-4-6", "max_tokens": 4096, "api_key": "<redacted>",
                                              "tools": [{"name": "terminal"}], "messages": "[truncated]"}}
        overflow = {"_truncated": True, "original_type": "dict", "preview": '{"method": "POST", "body": {"model"'}
        for n, (request, tools) in enumerate([(partial, [{"name": "terminal"}]), (overflow, None)], 1):
            with self.subTest(request=sorted(request)):
                cid = f"h:t2:api:{n}"
                self.ctx.hooks["pre_api_request"](
                    session_id=SID, platform="cli", model="claude-sonnet-4-6", provider="anthropic",
                    base_url="https://api.anthropic.com", api_mode="anthropic_messages", api_request_id=cid[2:],
                    started_at=self.t0, request_messages=msgs, system_prompt=system, retry_count=0, request=request)
                con = self.db()
                w = dict(con.execute("SELECT * FROM wire_calls WHERE id=?", (cid,)).fetchone())
                self.assertEqual(w["exact"], 0)
                req = self.cap.inspector.rebuild(con, json.loads(w["req_down"]))
                self.assertEqual(req["messages"], msgs, "raw request_messages replace the sanitized copy")
                self.assertEqual(req["system"], system)
                self.assertEqual(req.get("tools"), tools, "tools exist only as far as Hermes's copy carried them")
                self.assertEqual(req["model"], "claude-sonnet-4-6")
                self.assertNotIn("preview", req, "a truncation preview is not an envelope key")
                self.assertEqual(w["status"], None, "in-flight until post_api_request")
                self.assertEqual(con.execute("SELECT family FROM calls WHERE id=?", (cid,)).fetchone()[0], "claude")
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


class FamilyTabsTest(_HookBase):
    """Model family is who made the model, not the route; /calls returns the window's families for the tabs."""

    def test_family_of(self):
        f = self.cap.store.family_of
        cases = {
            ("claude-opus-5-5", None, "relay-claude"): "claude", ("gemini-4-argon", None, None): "gemini",
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


class HookCopyForensicsTest(_HookBase):
    """Hermes caps its hook copy by the size of the whole request, so one session's unchanged tools are stored whole,
    truncated or not at all from call to call. Comparing those copies would report a tool change that never happened."""

    def test_tools_from_the_hook_copy_are_not_compared_and_exact_ones_still_are(self):
        st, ins = self.cap.store, self.cap.inspector
        con = st.memory_store()
        put = lambda o: st.put_blob(con, o)  # noqa: E731
        hist = [{"role": "system", "content": "SYS"}] + [{"role": "user", "content": f"turn {i}"} for i in range(4)]
        whole, cut = [{"name": "patch", "description": "d" * 9000}], [{"name": "patch", "description": "d" * 1000 + "…"}]

        def call(cid, started, n, tools, exact):
            keys = {"tools": put(tools)} if tools is not None else {}
            ref = {"order": [*keys, "messages"], "keys": keys, "list_key": "messages", "items": [put(m) for m in hist[:n]]}
            st.upsert(con, dict(id=cid, session_id="s", started=started, status=200, source="hermes", exact=exact,
                                req_down=json.dumps(ref)), "wire_calls")

        cases = [  # earlier call's tools, later call's tools, exact, history shared, expected verdict, tools compared
            (whole, cut, 0, 3, "system prompt and messages unchanged", False),   # same tools, cut by the size cap
            (whole, None, 0, 3, "system prompt and messages unchanged", False),  # same tools, copy over the cap
            (whole, whole, 0, 2, "history item #1 rewritten", False),            # a real history change is still found
            (whole, cut, 1, 3, "tool declarations changed", None),               # exact captures compare tools
        ]
        for i, (before, after, exact, shared, verdict, compared) in enumerate(cases):
            with self.subTest(case=i):
                a, b = f"a{i}", f"b{i}"
                con.execute("DELETE FROM wire_calls")
                call(a, 1.0, 3, before, exact)
                if shared < 3:  # the later call rewrote an item the earlier one had sent
                    hist[shared] = {"role": "user", "content": "rewritten"}
                call(b, 2.0, 4, after, exact)
                d = ins.explain_miss(con, b, "s", 2.0, 50000, 0.0)
                self.assertTrue(d["why"].startswith(verdict), d)
                self.assertEqual(d.get("tools_compared"), compared, d)
                self.assertEqual(d["prev_id"], a)
        con.close()


class RequestToolsIntakeTest(_HookBase):
    """Through the hooks: a miss is blamed on the tools only when Hermes handed the hook the tool list itself."""

    MISS = {"input_tokens": 50000, "cache_read_tokens": 0, "cache_write_tokens": 0, "output_tokens": 5, "prompt_tokens": 50000}
    EDITED = [dict(TOOLS[0], function=dict(TOOLS[0]["function"], description="run a shell command")), TOOLS[1]]

    def test_tool_verdicts_with_and_without_the_proposed_arguments(self):
        short = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "first question"}]
        # long enough that Hermes replaces its ``request`` copy with a preview: no tools reach an unpatched hook
        long = short + [{"role": "assistant" if i % 2 == 0 else "user", "content": f"{i} " + "y" * 2000} for i in range(60)]
        cases = [  # proposed arguments Hermes passes, tools of the later call, verdict, change path
            ((), TOOLS, "system prompt and messages unchanged", None),        # same tools, one copy whole, one absent
            ((), self.EDITED, "system prompt and messages unchanged", None),  # a real change is not guessed at either
            (PROPOSED, TOOLS, "prefix intact", None),
            (PROPOSED, self.EDITED, "tool declarations changed", "tools[0].function.description"),
            (PROPOSED, [], "tool declarations removed", None),
            (PROPOSED[:1], self.EDITED, "tool declarations changed", "tools[0].function.description"),  # tools alone suffice
        ]
        for i, (patched, later_tools, verdict, path) in enumerate(cases):
            exact, tools_exact = int(patched == PROPOSED), int("request_tools" in patched)
            with self.subTest(patched=patched, verdict=verdict):
                sid = f"{SID}_{i}"
                a = self.chat_call(10 * i + 1, short, "ok", usage=self.MISS, patched=patched, session_id=sid)
                b = self.chat_call(10 * i + 2, long, "ok", usage=self.MISS, patched=patched, session_id=sid,
                                   extra={"tools": later_tools})
                con = self.db()
                stored = {cid: dict(con.execute("SELECT exact, tools_exact, req_down FROM wire_calls WHERE id=?", (cid,)).fetchone())
                          for cid in (a, b)}
                self.assertEqual({(w["exact"], w["tools_exact"]) for w in stored.values()}, {(exact, tools_exact)})
                tools = [self.cap.inspector.rebuild(con, json.loads(stored[cid]["req_down"])).get("tools") for cid in (a, b)]
                self.assertEqual(tools, [TOOLS, later_tools or None] if tools_exact else [TOOLS, None],
                                 "an unpatched Hermes hands the hook no tools once the request is over its cap")
                miss = json.loads(con.execute("SELECT diverge FROM calls WHERE id=?", (b,)).fetchone()[0])
                self.assertTrue(miss["why"].startswith(verdict), miss)
                self.assertEqual(miss["prev_id"], a)
                self.assertEqual((miss.get("change") or {}).get("path"), path)
                con.close()

    def test_proposed_arguments_replace_the_capped_copy_and_stay_redacted(self):
        msgs = [{"role": "user", "content": "hi"}]
        cid = self.chat_call(1, msgs, "ok", patched=PROPOSED, extra={"tool_choice": "auto", "metadata": {"client_secret": "SECRET-CLIENT"}},
                             request={"_truncated": True, "original_type": "dict", "preview": "{"})
        con = self.db()
        w = dict(con.execute("SELECT exact, tools_exact, req_down FROM wire_calls WHERE id=?", (cid,)).fetchone())
        req = self.cap.inspector.rebuild(con, json.loads(w["req_down"]))
        self.assertEqual((w["exact"], w["tools_exact"]), (1, 1))
        self.assertEqual((req["tools"], req["tool_choice"], req["temperature"], req["messages"]), (TOOLS, "auto", 1, msgs))
        self.assertEqual((req["api_key"], req["metadata"]), ("‹redacted›", {"client_secret": "‹redacted›"}))
        self.assertFalse({"timeout", "extra_headers"} & set(req))
        con.close()


class CostTest(_HookBase):
    """cost_usd and cost_equiv_usd come from one token split and one price, so cost never exceeds its equivalent."""

    def test_proxy_route_is_priced_at_the_model_makers_list_price(self):
        st = self.cap.store
        if st.price_call("gemini-4-argon", "gemini", 1000, 0, 0, 0, 1000)[0] is None:
            self.skipTest("no Hermes pricing table importable here")
        con = st.memory_store()
        base = dict(source="hermes", model="gemini-4-argon", family="gemini", provider="relay-gemini",
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

class ModuleLifecycleTest(_HookBase):
    def test_a_lazily_loaded_sibling_does_not_retire_the_capture_module(self):
        """A sibling loaded after capture (signals, on the first refusal check) must not make the next hook reload
        capture.py — that restarted the writer thread and dropped what it had queued."""
        first = self.mt._capture()
        for k in [k for k in sys.modules if k == "_wiretap_signals"]:
            del sys.modules[k]
        spec = importlib.util.spec_from_file_location("_wiretap_signals", HERE / "collector" / "signals.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_wiretap_signals"] = mod
        spec.loader.exec_module(mod)  # loaded without a load stamp, as a lazy loader of an older version would
        self.assertIs(self.mt._capture(), first)
        self.assertIs(self.mt._capture(), first)


class HermesRuntimeContractTest(unittest.TestCase):
    """What Hermes's real ``_fire_pre/post_api_request_hook`` and error hook pass reaches the store intact."""

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
                msgs = [{"role": "user", "content": [{"type": "text", "text": "x" * 30000}]}]  # cut in the hook copy
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
                self.assertEqual((w[0], w[3]), (0, 200), "captured from the hook arguments alone")
                req = cap.inspector.rebuild(con, json.loads(w[1]))
                self.assertEqual(req["messages"], msgs, "the raw message, not the copy Hermes cut to 8,000 characters")
                self.assertEqual(req["system"], api_kwargs["system"])
                self.assertEqual(req["tools"], api_kwargs["tools"])
                self.assertEqual(req["api_key"], "‹redacted›")
                self.assertEqual(json.loads(w[2])["text"], "done")
                c = con.execute("SELECT ttfb_s, context_length, cached_tokens FROM calls WHERE id='h:rt:api:1'").fetchone()
                self.assertEqual(c[0], 0.5)
                self.assertEqual(c[1], 200000)
                self.assertEqual(con.execute("SELECT n429, nfail FROM calls WHERE id='h:rt:api:1'").fetchone(), (1, 1))
                con.close()

                # A request over Hermes's hook payload cap: its copy is a preview, so only what the raw
                # arguments carry (messages, system prompt) is stored.
                big = [{"role": "user" if i % 2 == 0 else "assistant", "content": f"{i} " + "y" * 2000} for i in range(60)]
                _tar._fire_pre_api_request_hook(
                    ag, dict(api_kwargs, messages=big), big, [], messages=big, original_user_message="y",
                    approx_tokens=30000, total_chars=120000, retry_count=0, api_call_count=2,
                    api_request_id="rt:api:2", api_start_time=t0, effective_task_id="task", turn_id="rt")
                cap._writer.flush(5)
                con = sqlite3.connect(os.environ["TELEMETRY_DB"])
                w = con.execute("SELECT exact, req_down, n_items FROM wire_calls WHERE id='h:rt:api:2'").fetchone()
                req = cap.inspector.rebuild(con, json.loads(w[1]))
                self.assertEqual((w[0], w[2], req["messages"]), (0, 60, big))
                self.assertEqual(req["system"], api_kwargs["system"])
                self.assertNotIn("tools", req, "Hermes passed no usable copy of the tools for this request")
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
