"""Regression tests for the performance / SQL review of 819ed83 (REVIEW.md, P2 findings): cached views and polls
never keep stale provenance, alignment reruns only when its inputs change, retention GC never holds the writer lock
through its reachability mark, the calls revision follows the sliding window, untapped proxy-log joins filter for
compatibility before their LIMIT, and the dashboard drops stale responses (jsdom harness)."""
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_inspector import SESSION, _gemini_log, _state_db  # noqa: E402  (fixture builders only)


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
    KEYS = ("HERMES_HOME", "TELEMETRY_DB", "CLIPROXY_LOG_DIR", "MAIN_SESSION", "MODEL_TELEMETRY_POLLER")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.home, self.logs = root / "home", root / "logs"
        self.home.mkdir()
        self.logs.mkdir()
        self.old = {k: os.environ.get(k) for k in self.KEYS}
        os.environ.update(HERMES_HOME=str(self.home), CLIPROXY_LOG_DIR=str(self.logs), MAIN_SESSION="",
                          TELEMETRY_DB=str(self.home / "plugin-data/wiretap/telemetry.db"), MODEL_TELEMETRY_POLLER="0")

    def tearDown(self):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self.tmp.cleanup()


class ViewProvenanceTest(_Env):
    """Views and their alignment are keyed on what they display, not on ids and counts."""

    def setUp(self):
        super().setUp()
        now = time.time() - 600
        user = "can you check the wire framing please?"
        hist = [{"role": "user", "parts": [{"text": "<USER_REQUEST>\n" + user + "\n</USER_REQUEST>"}]}]
        _gemini_log(self.logs / "v1beta-models-gemini-2.5-pro-streamGenerateContent-a-1111aaaa.log", now + 2, hist,
                    [{"text": "Framing is fine and the worker is done."}], 50000, 1000)
        _state_db(self.home / "state.db", [
            {"id": 1, "role": "user", "content": user, "timestamp": now},
            {"id": 2, "role": "assistant", "content": "Framing is fine and the worker is done.", "timestamp": now + 5,
             "finish_reason": "stop"},
        ])
        self.t = _load("_mt_rv_tel", HERE / "collector" / "telemetry.py")
        self.t.init_db()
        self.t.ingest_once()
        self.con = self.t.db()
        self.ins = self.t.inspector

    def tearDown(self):
        self.con.close()
        super().tearDown()

    def _state(self, sql, args=()):
        s = sqlite3.connect(self.home / "state.db")
        s.execute(sql, args)
        s.commit()
        s.close()

    def test_an_in_place_rewrite_reaches_the_views_without_waiting_for_the_ttl(self):
        v1 = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, False)
        self.assertEqual({r["id"]: r["content"] for r in v1["rows"]}[1], "can you check the wire framing please?")
        self._state("UPDATE messages SET content=? WHERE id=1", ("REDACTED by a later pass, same id and count",))
        v2 = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, False)
        self.assertEqual({r["id"]: r["content"] for r in v2["rows"]}[1], "REDACTED by a later pass, same id and count")
        # the archived-history transcript (length sums over every row) sees a rewrite that changes the length
        a1 = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, True)
        self._state("UPDATE messages SET api_content='late envelope' WHERE id=2")
        a2 = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, True)
        self.assertIsNot(a1["rows"], a2["rows"], "rebuilt, not served from the memo")

    def test_display_kind_reasoning_and_archived_same_length_edits_reach_the_views(self):
        self._state("UPDATE messages SET reasoning_content='old thought' WHERE id=2")
        self._state("INSERT INTO messages (id, session_id, role, content, timestamp, active) VALUES (3, ?, 'user', 'aaaa', 3, 0)",
                    (SESSION,))
        a = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, False)
        self._state("UPDATE messages SET display_kind='internal_notification' WHERE id=1")
        self._state("UPDATE messages SET reasoning_content='new thought' WHERE id=2")
        b = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, False)
        fresh = self.ins._session_view(self.t.STATE_DB, self.con, SESSION, None, 250, False)
        self.assertEqual([(r["kind"], r.get("reasoning")) for r in b["rows"]], [(r["kind"], r.get("reasoning")) for r in fresh["rows"]])
        self.assertNotEqual([r["kind"] for r in a["rows"]], [r["kind"] for r in b["rows"]])
        self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, True)
        self._state("UPDATE messages SET content='bbbb' WHERE id=3")  # same length, archived row
        c = self.ins.session_view(self.t.STATE_DB, self.con, SESSION, None, 250, True)
        self.assertEqual({r["id"]: r["content"] for r in c["rows"]}[3], "bbbb")

    def test_alignment_is_reused_when_only_the_call_status_changed_and_rerun_when_a_row_changes(self):
        st = self.ins.ALIGN_STATS
        c1 = self.ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertTrue(c1.get("wire", {}).get("items"), c1.get("error"))
        base = dict(st)
        # a status-only write to the call (the request's refs are unchanged): the view rebuilds, alignment does not
        self.t.store.upsert(self.con, {"id": c1["call_id"], "status": 200}, "wire_calls")
        self.t.store.bump_wire_rev(self.con)  # as the proxy-capture writer does (this fixture's call has no session id)
        self.con.commit()
        c2 = self.ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertEqual((st["run"] - base["run"], st["hit"] - base["hit"]), (0, 1))
        self.assertEqual([i.get("row_id") for i in c1["wire"]["items"]], [i.get("row_id") for i in c2["wire"]["items"]])
        # an existing row rewritten: alignment reruns
        self._state("UPDATE messages SET content='a different question entirely now' WHERE id=1")
        self.ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertEqual(st["run"] - base["run"], 1)

    def test_appended_rows_reuse_only_a_complete_alignment(self):
        st = self.ins.ALIGN_STATS
        c1 = self.ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        complete = all(i.get("row_id") or i.get("row_ids") for i in c1["wire"]["items"] if self.ins._alignable(i))
        base = dict(st)
        self._state("INSERT INTO messages (id, session_id, role, content, timestamp, active) VALUES (3, ?, 'user', ?, ?, 1)",
                    (SESSION, "a follow-up after the request", time.time()))
        self.ins.compiled_view(self.t.STATE_DB, self.con, SESSION)
        self.assertEqual((st["append_reuse"] - base["append_reuse"], st["run"] - base["run"]), (1, 0) if complete else (0, 1))

    def test_the_server_revision_covers_alignment_not_just_counts(self):
        try:
            import fastapi  # noqa: F401
        except Exception as e:  # pragma: no cover
            self.skipTest(f"fastapi unavailable: {e}")
        import threading
        api = _load("_mt_rv_api", HERE / "dashboard" / "plugin_api.py")
        for th in threading.enumerate():  # the module boots its poller on a thread: let it settle before cleanup
            if th.name == "wiretap-poller-boot":
                th.join(10)
        view = {"call_id": "c", "wire": {"items": [{"i": 0, "row_id": None}]}, "rows_unmapped": 1, "now": 1.0}
        r1 = json.loads(api._json_rev(view).body)
        moved = json.loads(api._json_rev(dict(view, wire={"items": [{"i": 0, "row_id": 7}]}, now=2.0)).body)
        self.assertNotEqual(r1["rev"], moved["rev"], "only a row_id changed")
        self.assertEqual(json.loads(api._json_rev(dict(view, now=9.0), r1["rev"]).body).get("unchanged"), True,
                         "the clock alone is not a change")
        self.assertNotIn("unchanged", json.loads(api._json_rev(dict(view, wire={"items": [{"i": 0, "row_id": 7}]}), r1["rev"]).body))


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
            self.st.upsert(con, {"id": "p1", "source": "cliproxy", "started": now - 60, "model": "m", "family": "claude"})
            self.st.bump_calls_rev(con)
        q = {"hours": ["6"], "family": ["all"], "limit": ["100"]}
        d1 = self.t.api_calls(q)
        same = self.t.api_calls(dict(q, rev=[d1["rev"]]))
        self.assertTrue(same.get("unchanged"))
        self.assertIn("last_scan", same)
        with self.t._con() as con:
            con.execute("INSERT INTO events (rid, ts, kind, detail) VALUES ('p1', ?, 'LCP cache hit', '')", (now,))
        self.assertNotIn("unchanged", self.t.api_calls(dict(q, rev=[d1["rev"]])))

    def test_nearer_same_family_calls_of_another_model_do_not_crowd_out_the_compatible_one(self):
        t0 = time.time() - 100
        with self.t._con() as con:
            for i in range(25):
                self.st.upsert(con, {"id": f"h:{i}", "source": "hermes", "started": t0 + 0.01 * i, "family": "openai",
                                     "model": "gpt-target" if i == 24 else "gpt-other", "prompt_tokens": 100})
            got = self.t.match_hermes_call(con, {"id": "log", "started": t0, "family": "openai", "model": "gpt-target",
                                                 "prompt_tokens": 100})
        self.assertEqual(got, "h:24")

    def test_nearer_calls_of_another_family_do_not_crowd_out_the_compatible_one(self):
        t0 = time.time() - 100
        with self.t._con() as con:
            for i in range(6):
                self.st.upsert(con, {"id": f"h:c{i}", "source": "hermes", "started": t0 + 0.01 * i, "model": "claude-opus-5-5",
                                     "family": "claude"})
            self.st.upsert(con, {"id": "h:o", "source": "hermes", "started": t0 + 0.6, "model": "gpt-5.6-sol", "family": "openai"})
            got = self.t.match_hermes_call(con, {"id": "log1", "started": t0, "model": "gpt-5.6-sol", "family": "openai"})
        self.assertEqual(got, "h:o")


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
