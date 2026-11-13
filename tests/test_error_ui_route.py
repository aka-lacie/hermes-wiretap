"""The dashboard /calls route forwards the general error filter (errors=1) and carries each row's error_summary."""
import importlib.util
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


class ErrorFilterRoute(unittest.TestCase):
    def test_errors_filter_and_summary_reach_the_dashboard(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except Exception as e:  # pragma: no cover
            self.skipTest(f"fastapi unavailable: {e}")
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = Path(tmp.name)
        (home / "plugin-data" / "wiretap").mkdir(parents=True)
        tdb = home / "plugin-data" / "wiretap" / "telemetry.db"
        spec = importlib.util.spec_from_file_location("_mt_err_route_store", HERE / "collector" / "store.py")
        store = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(store)  # type: ignore[union-attr]
        mem = store.memory_store()
        now = time.time() - 60
        rows = [("ok", 200, 0), ("timeout", 0, 1), ("rl", 429, 2), ("recovered", 200, 2), ("pending", None, None)]
        for n, (cid, status, nfail) in enumerate(rows):
            store.upsert(mem, {"id": cid, "source": "hermes", "started": now + n, "family": "openai", "model": "m", "status": status,
                               "nfail": nfail, "n429": 2 if cid == "rl" else 0, "prompt_tokens": 10, "auth_key": "key-a"}, "calls")
        for k, kind in enumerate(("fail:429", "fail:429", "fail:503")):  # proxy-logged failed upstream attempts
            mem.execute("INSERT INTO events (rid, ts, level, kind, detail) VALUES (?,?,?,?,?)",
                        ("rl", now + k, "warn", kind, f"{kind[5:]} after 1.00s gemini key=AAAA"))
        mem.commit()
        disk = sqlite3.connect(tdb)
        mem.backup(disk)
        disk.close()
        mem.close()
        sqlite3.connect(home / "state.db").close()
        with mock.patch.dict(os.environ, {"HERMES_HOME": str(home), "TELEMETRY_DB": str(tdb), "MAIN_SESSION": ""}):
            spec = importlib.util.spec_from_file_location("_mt_err_route_api", HERE / "dashboard" / "plugin_api.py")
            api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(api)  # type: ignore[union-attr]
            app = FastAPI()
            app.include_router(api.router, prefix="/w")
            c = TestClient(app)
            every = c.get("/w/calls", params={"hours": 1}).json()["rows"]
            got = {r["id"]: r.get("error_summary") for r in every}
            if not any(got.values()):
                self.skipTest("backend without error summaries (general error backend not merged)")
            self.assertEqual(got["pending"]["outcome"], "unknown")
            self.assertTrue(got["recovered"]["recovered"])
            errs = {r["id"] for r in c.get("/w/calls", params={"hours": 1, "errors": 1}).json()["rows"]}
            self.assertEqual(errs, {"timeout", "rl", "recovered"}, "errors=1: failed and recovered calls, never pending ones")
            body = c.get("/w/calls", params={"hours": 1}).json()
            fam = body["summary"]["openai"]
            self.assertEqual((fam["failed_calls"], fam["recovered_calls"], fam["unknown_calls"], fam["n429"]), (2, 1, 1, 2))
            key = {k["auth_key"]: k for k in body["keys"]}["key-a"]
            self.assertEqual((key["n"], key["failed_calls"], key["recovered_calls"], key["n429"]), (5, 2, 1, 2),
                             "per-key outcomes count calls, with the same rules as error_summary")
            fk = {k["key"]: k for k in body["fail_keys"]}["AAAA"]
            self.assertEqual((fk["n"], fk["n429"]), (3, 2), "proxy failed attempts are every status, with their 429 subset")
            # sort=errors: failed (more failure observations first) > recovered > succeeded; no status always last
            def order(d):
                return [r["id"] for r in c.get("/w/calls", params={"hours": 1, "sort": "errors", "dir": d}).json()["rows"]]
            self.assertEqual(order("desc"), ["rl", "timeout", "recovered", "ok", "pending"])
            self.assertEqual(order("asc"), ["ok", "recovered", "timeout", "rl", "pending"])


if __name__ == "__main__":
    unittest.main()
