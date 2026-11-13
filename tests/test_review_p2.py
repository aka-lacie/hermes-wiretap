"""Regression tests for the performance / SQL review of 819ed83 (REVIEW.md, P2 findings): cached views and polls
never keep stale provenance, retention GC never holds the writer lock through its reachability mark, the calls
revision follows the sliding window, and the dashboard drops stale responses (jsdom harness)."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    for k in [k for k in sys.modules if k.startswith("_wiretap")]:
        del sys.modules[k]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class _Env(unittest.TestCase):
    KEYS = ("HERMES_HOME", "TELEMETRY_DB", "MAIN_SESSION")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home = root / "home"
        self.home.mkdir()
        self.old = {k: os.environ.get(k) for k in self.KEYS}
        os.environ.update(HERMES_HOME=str(self.home), MAIN_SESSION="",
                          TELEMETRY_DB=str(self.home / "plugin-data/wiretap/telemetry.db"))

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()


class RetentionGcTest(unittest.TestCase):
    def _store(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        st = _load("_mt_rv_store", HERE / "collector" / "store.py")
        con = st.connect(Path(tmp.name) / "t.db")
        self.addCleanup(con.close)
        st.init(con)
        con.commit()
        return st, con

    def _call(self, st, con, cid, ended, *items):
        hs = [st.put_blob(con, {"role": "user", "content": x}) for x in items]
        st.upsert(con, {"id": cid, "ended": ended, "req_down": json.dumps({"items": hs, "keys": {}})}, "wire_calls")
        return hs

    def test_a_writer_pending_before_the_mark_and_committed_after_it_keeps_its_blob(self):
        """REREVIEW P1: the writer stamps its rev before GC starts, commits after GC's mark snapshot — two
        connections, real interleaving. The re-referenced orphan must survive."""
        st, con = self._store()
        orphan = st.put_blob(con, {"user": "orphan until the pending writer commits"})
        st.upsert(con, {"id": "survivor", "ended": time.time(), "req_down": json.dumps({"items": []})}, "wire_calls")
        con.commit()
        path = con.execute("PRAGMA database_list").fetchone()[2]
        w = st.connect(path)
        self.addCleanup(w.close)
        st.upsert(w, {"id": "survivor", "ended": time.time(), "req_down": json.dumps({"items": [orphan]})}, "wire_calls")
        self.assertTrue(w.in_transaction, "pending, uncommitted, rev already stamped")
        st._GC_AFTER_MARK = w.commit  # commits after GC's snapshot finished, before it takes the writer lock
        try:
            with con:
                res = st.gc(con, force=True)
        finally:
            st._GC_AFTER_MARK = None
        refs = json.loads(con.execute("SELECT req_down FROM wire_calls WHERE id='survivor'").fetchone()[0])["items"]
        self.assertIn(orphan, refs)
        self.assertTrue(con.execute("SELECT 1 FROM wire_blobs WHERE h=?", (orphan,)).fetchone(), f"blob deleted: {res}")
        self.assertGreaterEqual(res["rechecked"], 1)

    def test_a_direct_update_of_refs_changes_rev(self):
        st, con = self._store()
        st.upsert(con, {"id": "x", "ended": time.time(), "req_down": json.dumps({"items": []})}, "wire_calls")
        r0 = con.execute("SELECT rev FROM wire_calls WHERE id='x'").fetchone()[0]
        con.execute("UPDATE wire_calls SET req_down=? WHERE id='x'", (json.dumps({"items": ["h"]}),))
        self.assertNotEqual(con.execute("SELECT rev FROM wire_calls WHERE id='x'").fetchone()[0], r0)

    def test_mark_runs_outside_the_write_transaction_and_concurrent_captures_keep_their_blobs(self):
        st, con = self._store()
        now = time.time()
        old = self._call(st, con, "old", now - 10 * 86400, "expired only", "shared")
        live = self._call(st, con, "live", now, "live only", "shared")
        orphan = st.put_blob(con, {"role": "user", "content": "orphan, re-referenced during the mark"})
        con.commit()
        real, seen = st._mark_refs, {}

        def mark(rows, out):
            if not seen:
                # another writer commits a capture mid-mark — it can, because the mark holds no writer lock (a short
                # busy timeout would fail if it did): a new blob, and a re-reference of an orphan
                w = st.connect(con.execute("PRAGMA database_list").fetchone()[2], timeout=0.2)
                seen["writer_ok"] = True
                st.upsert(w, {"id": "new", "ended": time.time(),
                              "req_down": json.dumps({"items": [st.put_blob(w, {"c": "added during mark"}), orphan], "keys": {}})},
                          "wire_calls")
                w.commit()
                w.close()
            return real(rows, out)

        with mock.patch.object(st, "_mark_refs", mark):
            with con:
                res = st.gc(con, keep_s=86400, force=True)
        self.assertTrue(seen.get("writer_ok"), "the reachability mark holds no write lock")
        have = {h for (h,) in con.execute("SELECT h FROM wire_blobs")}
        self.assertEqual(have & {old[0]}, set(), "the expired call's own blob is swept")
        self.assertTrue({live[0], live[1], orphan} <= have, "live, shared and re-referenced blobs survive")
        new_items = json.loads(con.execute("SELECT req_down FROM wire_calls WHERE id='new'").fetchone()[0])["items"]
        self.assertTrue(set(new_items) <= have, "a blob a concurrent capture added is never lost")
        self.assertEqual(res["expired"], 1)

    def test_nothing_expired_is_a_no_op(self):
        st, con = self._store()
        self._call(st, con, "live", time.time(), "x")
        con.commit()
        st._last_gc[:] = [0.0, time.time()]
        with con:
            self.assertEqual(st.gc(con, keep_s=86400), {"skipped": "nothing expired"})


class CallsRevisionAndJoinTest(_Env):
    def setUp(self):
        super().setUp()
        self.t = _load("_mt_rv_tel2", HERE / "collector" / "telemetry.py")
        self.t.init_db()
        self.st = self.t.store

    def test_a_row_ageing_out_of_the_window_changes_the_revision(self):
        now = time.time()
        with self.t._con() as con:
            self.st.upsert(con, {"id": "h:1", "source": "hermes", "started": now - 3599, "model": "m", "family": "claude"})
            self.st.bump_calls_rev(con)
        q = {"hours": ["1"], "family": ["all"], "limit": ["100"]}
        d1 = self.t.api_calls(q)
        self.assertEqual(d1["total"], 1)
        with mock.patch.object(self.t.time, "time", return_value=now + 5):
            d2 = self.t.api_calls(dict(q, rev=[d1["rev"]]))
        self.assertNotIn("unchanged", d2, "the window moved past the only row")
        self.assertEqual(d2["total"], 0)

    def test_an_event_alone_changes_the_revision_and_freshness_rides_the_unchanged_reply(self):
        now = time.time()
        with self.t._con() as con:
            self.st.upsert(con, {"id": "p1", "source": "proxy", "started": now - 60, "model": "m", "family": "claude"})
            self.st.bump_calls_rev(con)
        q = {"hours": ["6"], "family": ["all"], "limit": ["100"]}
        d1 = self.t.api_calls(q)
        same = self.t.api_calls(dict(q, rev=[d1["rev"]]))
        self.assertTrue(same.get("unchanged"))
        self.assertIn("last_scan", same)
        with self.t._con() as con:
            con.execute("INSERT INTO events (rid, ts, kind, detail) VALUES ('p1', ?, 'LCP cache hit', '')", (now,))
        self.assertNotIn("unchanged", self.t.api_calls(dict(q, rev=[d1["rev"]])))

def _jsdom_dir() -> Path | None:
    for d in (os.environ.get("WIRETAP_JSDOM_DIR"), Path.home() / ".hermes" / "hermes-agent",
              HERE.parent.parent):
        if d and (Path(d) / "node_modules" / "jsdom").is_dir():
            return Path(d)
    return None


class DashboardJsTest(unittest.TestCase):
    """The real bundle under jsdom: out-of-order responses, stale older pages, the wire-part cache key."""

    def test_dashboard_drops_stale_responses(self):
        node, jd = shutil.which("node"), _jsdom_dir()
        if not node or not jd:
            self.skipTest("node or jsdom unavailable")
        p = subprocess.run([node, str(HERE / "tests" / "test_dashboard.mjs"), str(HERE / "dashboard" / "dist" / "index.js"), str(jd)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


if __name__ == "__main__":
    unittest.main()
