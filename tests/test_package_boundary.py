"""Package boundary: the plugin executes no Python file but its own, and reads no credential store.

One scenario runs in a fresh interpreter under an audit hook: register the plugin, fire the three API-request
hooks, read the dashboard routes and run the CLI. The hook records every source file whose code was executed and
every file that was opened, by any mechanism (import, ``exec_module``, ``exec(compile(...))``).
"""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zlib

HERE = Path(__file__).resolve().parent.parent
SHIPPED = {"__init__.py", "dashboard/plugin_api.py",
           *(f"collector/{name}.py" for name in ("capture", "cli", "forensics", "inspector", "signals", "store",
                                                 "telemetry"))}
FAKE_SECRET = "demo-secret-not-a-real-token-1234"
# A module nobody reviewed, as it could be dropped into an installed plugin directory.
TRAP = "from pathlib import Path\nPath(__file__).with_suffix('.ran').write_text('executed')\n"

SCENARIO = r'''
import importlib.util, io, json, os, sys, time
from pathlib import Path

plugin, secret = Path(sys.argv[1]), sys.argv[2]
executed, opened = set(), set()


def audit(event, args):
    if event == "exec":
        name = getattr(args[0], "co_filename", None)
        if isinstance(name, str):
            executed.add(name)
    elif event == "open" and isinstance(args[0], (str, bytes, os.PathLike)):
        opened.add(os.fsdecode(args[0]))


sys.addaudithook(audit)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class Ctx:
    def __init__(self):
        self.hooks = {}

    def get_config(self, key, default=None):
        return default

    def register_hook(self, name, fn):
        self.hooks[name] = fn

    def register_cli_command(self, *a, **kw):
        pass


plugin_module = load("wiretap_boundary_plugin", plugin / "__init__.py")
ctx = Ctx()
plugin_module.register(ctx)
kw = dict(session_id="boundary-session", model="example-model", provider="example-provider",
          base_url="https://fixture.example/v1", api_mode="chat_completions", api_request_id="boundary:1",
          started_at=time.time() - 5)
messages = [{"role": "user", "content": "a completely synthetic request"}]
ctx.hooks["pre_api_request"](
    request_messages=messages, retry_count=0, request={"method": "POST", "body": {
        "model": "example-model", "messages": messages, "extra_headers": {"Authorization": "Bearer " + secret},
        "metadata": {"access_token": secret}}}, **kw)
ctx.hooks["api_request_error"](status_code=429, retry_count=0, error={"type": "RateLimitError", "message": "slow"}, **kw)
ctx.hooks["post_api_request"](api_duration=1.0, ended_at=time.time(), assistant_message={"content": "ok"},
                              usage={"prompt_tokens": 5, "input_tokens": 5, "output_tokens": 1}, **kw)
plugin_module._capture()._writer.stop(5)

from fastapi import FastAPI
from fastapi.testclient import TestClient

api = load("wiretap_boundary_api", plugin / "dashboard" / "plugin_api.py")
app = FastAPI()
app.include_router(api.router)
with TestClient(app) as client:
    routes = {path: client.get(path).status_code for path in ("/health", "/calls", "/sessions")}
    health = client.get("/health").json()

cli = load("wiretap_boundary_cli", plugin / "collector" / "cli.py")
stdout, sys.stdout = sys.stdout, io.StringIO()
try:
    cli_status = cli.main(["status", "--json"])
finally:
    sys.stdout = stdout

root = str(plugin) + os.sep
print(json.dumps({
    "executed": sorted(Path(name).relative_to(plugin).as_posix() for name in executed if name.startswith(root)),
    "opened": sorted(opened), "routes": routes, "calls": health["calls"], "cli_status": cli_status,
}))
'''


class PackageBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        cls.root = Path(tmp.name).resolve()
        cls.plugin, cls.home = cls.root / "plugin", cls.root / "profile"
        cls.plugin.mkdir()
        cls.home.mkdir()
        shutil.copyfile(HERE / "__init__.py", cls.plugin / "__init__.py")
        for directory in ("collector", "dashboard"):
            shutil.copytree(HERE / directory, cls.plugin / directory, ignore=shutil.ignore_patterns("__pycache__"))
        cls.traps = [cls.plugin / rel for rel in ("extensions/credentials.py", "extensions/unified_sessions.py",
                                                  "extensions/enrichment.py", "collector/poller.py")]
        for trap in cls.traps:
            trap.parent.mkdir(exist_ok=True)
            trap.write_text(TRAP)
        # A pool-shaped credential file with a fake token: any read of it is a regression.
        (cls.home / "auth.json").write_text(json.dumps({"credential_pool": {"example-provider": [
            {"label": "private-demo-label", "access_token": FAKE_SECRET}]}}))
        state = sqlite3.connect(cls.home / "state.db")
        state.executescript("""
        CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT, model TEXT, title TEXT, started_at REAL,
          message_count INTEGER, model_config TEXT, system_prompt TEXT);
        CREATE TABLE messages (id INTEGER PRIMARY KEY, session_id TEXT, role TEXT, content TEXT, timestamp REAL);
        """)
        state.close()
        env = dict(os.environ, HERMES_HOME=str(cls.home), HOME=str(cls.root), MAIN_SESSION="",
                   TELEMETRY_DB=str(cls.home / "wiretap.db"), WIRETAP_STATE_DB=str(cls.home / "state.db"),
                   PYTHONDONTWRITEBYTECODE="1")
        done = subprocess.run([sys.executable, "-c", SCENARIO, str(cls.plugin), FAKE_SECRET], env=env,
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr[-4000:]
        cls.seen = json.loads(done.stdout.strip().splitlines()[-1])

    def test_only_the_packages_own_modules_are_executed(self):
        executed = set(self.seen["executed"])
        self.assertEqual(executed - SHIPPED, set(), "code outside the shipped modules was executed")
        self.assertLessEqual({"__init__.py", "collector/capture.py", "collector/telemetry.py", "collector/cli.py",
                              "dashboard/plugin_api.py"}, executed, "the scenario did not exercise the package")
        self.assertEqual([str(t) for t in self.traps if t.with_suffix(".ran").exists()], [])
        self.assertEqual(self.seen["routes"], {"/health": 200, "/calls": 200, "/sessions": 200})
        self.assertEqual((self.seen["calls"], self.seen["cli_status"]), (1, 0))

    def test_no_credential_store_is_read_and_no_secret_is_stored(self):
        self.assertEqual([p for p in self.seen["opened"] if Path(p).name == "auth.json"], [])
        con = sqlite3.connect(self.home / "wiretap.db")
        self.addCleanup(con.close)
        con.row_factory = sqlite3.Row
        row = dict(con.execute("SELECT * FROM calls WHERE id='h:boundary:1'").fetchone())
        self.assertEqual((row["provider"], row["model"], row["auth_label"]),
                         ("example-provider", "example-model", "example-provider"))
        self.assertIsNone(row["auth_key"], "a call is identified by Hermes's provider name, never a credential")
        stored = b"".join(p.read_bytes() for p in self.home.iterdir() if p.name.startswith("wiretap.db"))
        stored += b"".join(zlib.decompress(z) for (z,) in con.execute("SELECT z FROM wire_blobs"))
        self.assertNotIn(FAKE_SECRET.encode(), stored)
        self.assertIn(b"metadata", stored, "the envelope that carried the secret-named key was captured")


if __name__ == "__main__":
    unittest.main()
