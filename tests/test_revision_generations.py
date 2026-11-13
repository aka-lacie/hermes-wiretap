"""Capture revisions are DB-assigned generations (FINAL_REVIEW conditional P1, revision ABA).

``wire_calls.rev`` must never return to a value a reader has already seen for that row: retention GC's lock-time
recheck trusts equality with the rev it saw at its mark, and ``session_wire_rev`` keys cached views on MAX(rev). These
tests hold or roll back ``time.time_ns`` deliberately and replay, against the real store and SQLite triggers, the
shapes that used to restore an old token: two upserts in one transaction under a held clock (the reviewed ABA), direct
UPDATEs that set a stale rev explicitly, delete + reinsert and INSERT OR REPLACE of the same id. They also cover the
install/migration of the persistent sequence over a store with existing (timestamp) revisions, a legacy trigger
recreated by an older process, and read-only access to a legacy store."""
import hashlib
import importlib.util
import json
import os
import random
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent.parent

# The trigger shipped before generations (for building legacy stores and simulating an older process's init).
LEGACY_TRIGGER_SQL = (
    "CREATE TRIGGER IF NOT EXISTS wire_calls_refs_rev AFTER UPDATE OF req_down, req_up, resp_raw, req_hermes ON wire_calls "
    "WHEN NEW.rev IS OLD.rev BEGIN UPDATE wire_calls SET rev = COALESCE(OLD.rev, 0) + 1 WHERE rowid = NEW.rowid; END")


def _load_store():
    name = "_mt_revgen_store"
    spec = importlib.util.spec_from_file_location(name, HERE / "collector" / "store.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def ref(*hs):
    return json.dumps({"items": list(hs), "keys": {}})


class _Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.path = self.dir / "t.db"
        old = os.environ.get("TELEMETRY_DB")
        os.environ["TELEMETRY_DB"] = str(self.path)  # init's secure_files() touches only this fixture
        self.addCleanup(lambda: os.environ.pop("TELEMETRY_DB", None) if old is None else os.environ.update(TELEMETRY_DB=old))
        self.st = _load_store()
        self.addCleanup(setattr, self.st, "_GC_AFTER_MARK", None)

    def open(self, init=True):
        con = self.st.connect(self.path)
        self.addCleanup(con.close)
        if init:
            self.st.init(con)
            con.commit()
        return con

    def frozen(self, t):
        return mock.patch.object(self.st.time, "time_ns", return_value=t)

    @staticmethod
    def rev(con, cid):
        r = con.execute("SELECT rev FROM wire_calls WHERE id=?", (cid,)).fetchone()
        return r[0] if r else None

    @staticmethod
    def seq(con):
        return con.execute("SELECT n FROM wire_rev_seq WHERE k=0").fetchone()[0]

    def blob_present(self, con, h):
        return con.execute("SELECT 1 FROM wire_blobs WHERE h=?", (h,)).fetchone() is not None


class GcRevisionAbaTest(_Base):
    """Actual ``store.gc`` with a writer committing between its read-snapshot mark and its writer lock."""

    def _fixture(self):
        con = self.open()
        st = self.st
        a = st.put_blob(con, {"payload": "initial live"})
        b = st.put_blob(con, {"payload": "orphan re-referenced after the snapshot"})
        d = st.put_blob(con, {"payload": "intermediate"})
        T = time.time_ns()
        with self.frozen(T):
            st.upsert(con, {"id": "live", "ended": time.time(), "req_down": ref(a)}, "wire_calls")
        con.commit()
        return con, a, b, d, T, self.rev(con, "live")

    def _gc_with(self, con, after_mark):
        self.st._GC_AFTER_MARK = after_mark
        with con:
            return self.st.gc(con, force=True)

    def _assert_survives(self, con, b, res, r0, revs):
        refs = json.loads(con.execute("SELECT req_down FROM wire_calls WHERE id='live'").fetchone()[0])["items"]
        self.assertEqual(refs, [b])
        self.assertTrue(self.blob_present(con, b), f"a live capture's blob was swept: {res}, revs {r0} -> {revs}")
        self.assertGreaterEqual(res["rechecked"], 1, res)
        self.assertNotIn(r0, revs, "a committed rev token came back")
        self.assertEqual(revs, sorted(set(revs)), "generations strictly increase")
        self.assertGreater(revs[0], r0)

    def test_held_clock_two_upserts_in_one_transaction_cannot_restore_the_snapshot_rev(self):
        """The reviewed counterexample (edge_probe.py): T, T+1 by the old trigger, then T again — GC skipped the row."""
        con, a, b, d, T, r0 = self._fixture()
        revs = []

        def after_mark():
            w = self.st.connect(self.path)
            w.execute("BEGIN IMMEDIATE")
            with self.frozen(T):
                self.st.upsert(w, {"id": "live", "req_down": ref(d)}, "wire_calls")
                revs.append(self.rev(w, "live"))
                self.st.upsert(w, {"id": "live", "req_down": ref(b), "rev": r0}, "wire_calls")  # even a stale proposal
                revs.append(self.rev(w, "live"))
            w.commit()
            w.close()

        res = self._gc_with(con, after_mark)
        self._assert_survives(con, b, res, r0, revs)
        self.assertFalse(self.blob_present(con, d), "the transient, never-committed reference is still swept")
        self.assertTrue(self.blob_present(con, a), "the snapshot-marked old blob is kept (conservative; next pass)")

    def test_direct_updates_that_set_a_stale_rev_explicitly_get_a_fresh_generation(self):
        con, a, b, d, T, r0 = self._fixture()
        revs = []

        def after_mark():
            w = self.st.connect(self.path)
            with self.frozen(T):
                w.execute("UPDATE wire_calls SET req_down=? WHERE id='live'", (ref(d),))
                revs.append(self.rev(w, "live"))
                w.execute("UPDATE wire_calls SET req_down=?, rev=? WHERE id='live'", (ref(b), r0))
                revs.append(self.rev(w, "live"))
            w.commit()
            w.close()

        res = self._gc_with(con, after_mark)
        self._assert_survives(con, b, res, r0, revs)

    def test_delete_and_reinsert_of_the_same_id_under_a_held_clock(self):
        for how in ("upsert", "explicit-rev-insert", "insert-or-replace"):
            with self.subTest(how=how):
                self.setUp()
                con, a, b, d, T, r0 = self._fixture()
                revs = []

                def after_mark():
                    w = self.st.connect(self.path)
                    with self.frozen(T):
                        if how == "insert-or-replace":
                            w.execute("INSERT OR REPLACE INTO wire_calls (id, ended, req_down, rev) VALUES ('live', ?, ?, ?)",
                                      (time.time(), ref(b), r0))
                        else:
                            w.execute("DELETE FROM wire_calls WHERE id='live'")
                            if how == "upsert":
                                self.st.upsert(w, {"id": "live", "ended": time.time(), "req_down": ref(b)}, "wire_calls")
                            else:
                                w.execute("INSERT INTO wire_calls (id, ended, req_down, rev) VALUES ('live', ?, ?, ?)",
                                          (time.time(), ref(b), r0))
                        revs.append(self.rev(w, "live"))
                    w.commit()
                    w.close()

                res = self._gc_with(con, after_mark)
                self._assert_survives(con, b, res, r0, revs)

    def test_randomized_writers_between_mark_and_lock_never_lose_a_live_blob(self):
        """Bounded exploration of the snapshot-diff protocol: held clock, stale explicit revs, deletes, reinserts."""
        for seed in range(20):
            with self.subTest(seed=seed):
                self.setUp()
                rnd = random.Random(seed)
                con = self.open()
                st = self.st
                pool = [st.put_blob(con, {"p": i}) for i in range(8)]
                ids = [f"c{i}" for i in range(4)]
                T = time.time_ns()
                with self.frozen(T):
                    for cid in ids:
                        st.upsert(con, {"id": cid, "ended": time.time(), "req_down": ref(rnd.choice(pool))}, "wire_calls")
                con.commit()
                old = {cid: self.rev(con, cid) for cid in ids}

                def after_mark():
                    w = st.connect(self.path)
                    with self.frozen(T):
                        for _ in range(rnd.randint(1, 6)):
                            cid, h, op = rnd.choice(ids), rnd.choice(pool), rnd.randrange(5)
                            stale = rnd.choice(list(old.values()))
                            if op == 0:
                                st.upsert(w, {"id": cid, "ended": time.time(), "req_down": ref(h)}, "wire_calls")
                            elif op == 1:
                                w.execute("UPDATE wire_calls SET req_down=?, rev=? WHERE id=?", (ref(h), stale, cid))
                            elif op == 2:
                                w.execute("DELETE FROM wire_calls WHERE id=?", (cid,))
                            elif op == 3:
                                w.execute("INSERT OR REPLACE INTO wire_calls (id, ended, req_down, rev) VALUES (?, ?, ?, ?)",
                                          (cid, time.time(), ref(h), stale))
                            else:
                                w.execute("UPDATE wire_calls SET status=200 WHERE id=?", (cid,))
                    w.commit()
                    w.close()

                self._gc_with(con, after_mark)
                for (down,) in con.execute("SELECT req_down FROM wire_calls"):
                    for h in json.loads(down)["items"]:
                        self.assertTrue(self.blob_present(con, h), f"seed {seed}: live blob {h} swept")


class GenerationSequenceTest(_Base):
    def test_held_and_rolled_back_clocks_still_give_strictly_increasing_generations(self):
        con = self.open()
        st = self.st
        T = time.time_ns()
        clock = iter([T - k * 10**9 for k in range(200)])  # every reading earlier than the one before
        revs, wire, calls = [], [], []

        def note(cid):
            revs.append(self.rev(con, cid))
            wire.append(int(con.execute("SELECT v FROM kv WHERE k='wire_rev'").fetchone()[0]))

        with mock.patch.object(st.time, "time_ns", side_effect=lambda: next(clock)):
            st.upsert(con, {"id": "x", "ended": 1.0, "req_down": ref("a")}, "wire_calls"); note("x")
            st.upsert(con, {"id": "x", "req_down": ref("b")}, "wire_calls"); note("x")
            st.upsert(con, {"id": "y", "ended": 1.0}, "wire_calls"); note("y")
            con.execute("UPDATE wire_calls SET status=500 WHERE id='x'"); revs.append(self.rev(con, "x"))
            con.execute("UPDATE wire_calls SET rev=? WHERE id='y'", (2 ** 62,)); revs.append(self.rev(con, "y"))
            st.upsert(con, {"id": "y", "status": 200}, "wire_calls"); note("y")
            for i in range(3):
                st.upsert(con, {"id": f"c{i}", "source": "hermes"}, "calls")
                calls.append(int(con.execute("SELECT v FROM kv WHERE k='calls_rev'").fetchone()[0]))
        con.commit()
        self.assertEqual(revs, sorted(set(revs)), f"rows' generations strictly increase: {revs}")
        self.assertLess(revs[-1], 2 ** 62, "a caller-proposed rev is never absorbed into the sequence")
        self.assertEqual(wire, sorted(set(wire)), "wire_rev never repeats or goes back")
        self.assertEqual(calls, sorted(set(calls)), "calls_rev never repeats or goes back")
        self.assertEqual(self.seq(con), revs[-1])

    def test_generations_are_global_persistent_and_shared_by_connections(self):
        con = self.open()
        st = self.st
        T = time.time_ns()
        with self.frozen(T):
            st.upsert(con, {"id": "a", "ended": 1.0}, "wire_calls")
            con.commit()
            w = self.open()
            st.upsert(w, {"id": "b", "ended": 1.0}, "wire_calls")
            w.commit()
            st.upsert(con, {"id": "a", "status": 1}, "wire_calls")
            con.commit()
        ra, rb = self.rev(con, "a"), self.rev(con, "b")
        self.assertGreater(rb, 0)
        self.assertGreater(ra, rb, "one sequence for every connection, in commit order")
        # a rolled-back write is never visible; the next committed write still moves past every committed value
        st.upsert(con, {"id": "a", "status": 2}, "wire_calls")
        con.rollback()
        self.assertEqual(self.rev(con, "a"), ra)
        con.close()
        again = self.open()  # reopen + init: install is a no-op and the sequence persisted
        self.assertFalse(self.st.install_rev_generations(again))
        with self.frozen(T - 10**12):
            st.upsert(again, {"id": "b", "status": 3}, "wire_calls")
        again.commit()
        self.assertGreater(self.rev(again, "b"), ra)

    def test_every_column_and_every_row_of_a_multirow_update_is_stamped(self):
        con = self.open()
        st = self.st
        for i in range(3):
            st.upsert(con, {"id": f"r{i}", "ended": 1.0, "model": "m"}, "wire_calls")
        before = max(self.rev(con, f"r{i}") for i in range(3))
        con.execute("UPDATE wire_calls SET family='z'")
        after = sorted(self.rev(con, f"r{i}") for i in range(3))
        self.assertEqual(len(set(after)), 3)
        self.assertGreater(after[0], before)
        con.execute("UPDATE wire_calls SET url='k' WHERE id='r0'")  # a non-reference column (capture.py does this)
        self.assertGreater(self.rev(con, "r0"), after[-1])

    def test_a_legacy_trigger_recreated_by_an_older_process_coexists_even_with_recursive_triggers(self):
        con = self.open()
        st = self.st
        con.execute(LEGACY_TRIGGER_SQL)  # an older process's init recreates it
        con.commit()
        T = time.time_ns()
        revs = []
        for recursive in (0, 1):
            con.execute(f"PRAGMA recursive_triggers={recursive}")
            with self.frozen(T):
                st.upsert(con, {"id": "x", "ended": 1.0, "req_down": ref("a")}, "wire_calls"); revs.append(self.rev(con, "x"))
                st.upsert(con, {"id": "x", "req_down": ref("b")}, "wire_calls"); revs.append(self.rev(con, "x"))
                con.execute("UPDATE wire_calls SET req_down=? WHERE id='x'", (ref("c"),)); revs.append(self.rev(con, "x"))
                con.execute("UPDATE wire_calls SET req_down=?, rev=? WHERE id='x'", (ref("d"), revs[0])); revs.append(self.rev(con, "x"))
                con.execute("UPDATE wire_calls SET status=1 WHERE id='x'"); revs.append(self.rev(con, "x"))
            con.commit()
        self.assertEqual(revs, sorted(set(revs)), revs)
        self.assertEqual(self.seq(con), revs[-1])
        con.execute("PRAGMA recursive_triggers=0")
        self.assertTrue(st.install_rev_generations(con), "a newer init drops the legacy trigger again")
        self.assertTrue(st.rev_generations_installed(con))

    def test_the_memory_store_assigns_generations_too(self):
        con = self.st.memory_store()
        self.addCleanup(con.close)
        with self.frozen(5):
            self.st.upsert(con, {"id": "m", "ended": 1.0}, "wire_calls")
            r1 = self.rev(con, "m")
            self.st.upsert(con, {"id": "m", "status": 200}, "wire_calls")
        self.assertIsNotNone(r1)
        self.assertGreater(self.rev(con, "m"), r1)


def _legacy_store(st, path, rows, kv_wire_rev=None):
    """A store as the previous release left it: columns migrated, timestamp revs, the old trigger, no sequence."""
    con = sqlite3.connect(path)
    con.executescript(st.SCHEMA)
    for table, col, typ in st.MIGRATIONS:
        if col not in st.columns(con, table):
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
    con.executescript(st.POST_MIGRATION)
    con.execute(LEGACY_TRIGGER_SQL)
    for cid, sid, rev in rows:
        con.execute("INSERT INTO wire_calls (id, session_id, ended, rev) VALUES (?, ?, 1.0, ?)", (cid, sid, rev))
    if kv_wire_rev is not None:
        con.execute("INSERT OR REPLACE INTO kv VALUES ('wire_rev', ?)", (str(kv_wire_rev),))
    con.commit()
    con.close()


class MigrationTest(_Base):
    def test_install_seeds_the_sequence_above_existing_revisions_deleted_stamps_and_the_clock(self):
        st = self.st
        now = time.time_ns()
        ahead = now + 10**15                  # rows stamped by a clock that later went back
        _legacy_store(st, self.path, [("old_max", "s", ahead), ("small", "s", 5), ("null", "s", None)],
                      kv_wire_rev=ahead + 10**12)  # a deleted row's stamp, above every surviving rev
        con = st.connect(self.path)
        self.addCleanup(con.close)
        with self.frozen(now - 10**15):       # and install itself runs on a clock behind them
            st.init(con)
            con.commit()
            self.assertTrue(st.rev_generations_installed(con))
            names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='trigger'")}
            self.assertNotIn("wire_calls_refs_rev", names)
            self.assertGreaterEqual(self.seq(con), ahead + 10**12)
            self.assertEqual((self.rev(con, "old_max"), self.rev(con, "small"), self.rev(con, "null")), (ahead, 5, None),
                             "install rewrites no row")
            st.upsert(con, {"id": "new", "ended": 1.0}, "wire_calls")
            con.execute("UPDATE wire_calls SET status=1 WHERE id='null'")
            con.commit()
        self.assertGreater(self.rev(con, "new"), ahead + 10**12)
        self.assertGreater(self.rev(con, "null"), self.rev(con, "new"))
        n = self.seq(con)
        self.assertFalse(st.install_rev_generations(con), "idempotent")
        self.assertEqual(self.seq(con), n)

    def test_reinstall_after_the_triggers_were_lost_only_raises_the_sequence(self):
        con = self.open()
        st = self.st
        st.upsert(con, {"id": "x", "ended": 1.0}, "wire_calls")
        con.commit()
        for name, _ in st.REV_TRIGGERS:
            con.execute(f"DROP TRIGGER {name}")
        con.execute("UPDATE wire_calls SET rev=? WHERE id='x'", (time.time_ns() + 10**15,))  # a timestamp write meanwhile
        con.commit()
        legacy_max = self.rev(con, "x")
        self.assertTrue(st.install_rev_generations(con))
        self.assertGreaterEqual(self.seq(con), legacy_max)
        con.execute("UPDATE wire_calls SET status=1 WHERE id='x'")
        self.assertGreater(self.rev(con, "x"), legacy_max)

    def test_a_removed_sequence_row_is_reseeded_from_the_surviving_maximum_not_reset(self):
        con = self.open()
        st = self.st
        st.upsert(con, {"id": "x", "ended": 1.0}, "wire_calls")
        r = self.rev(con, "x")
        con.execute("DELETE FROM wire_rev_seq")
        st.upsert(con, {"id": "y", "ended": 1.0}, "wire_calls")
        self.assertGreater(self.rev(con, "y"), r)

    def test_a_legacy_store_reads_read_only_without_any_write(self):
        st = self.st
        _legacy_store(st, self.path, [("a", "s", 100), ("b", "s", 200), ("c", "t", None)], kv_wire_rev=300)
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        ro = st.connect_ro(self.path)
        try:
            self.assertEqual(st.session_wire_rev(ro, "s"), "200:2:2")
            self.assertEqual(st.session_wire_rev(ro, "t"), "None:1:3")
            self.assertEqual(st.wire_rev(ro), "300:3")
            self.assertFalse(st.rev_generations_installed(ro))
            with self.assertRaises(sqlite3.OperationalError):
                st.install_rev_generations(ro)  # a reader cannot (and need not) install
        finally:
            ro.close()
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), digest, "the legacy file is untouched")
        self.assertFalse(Path(str(self.path) + "-wal").exists())


class SessionRevisionTest(_Base):
    def _key(self, con, sid):
        return self.st.session_wire_rev(con, sid)

    def _content(self, con, sid):
        cols = [c for c in self.st.columns(con, "wire_calls") if c != "rev"]
        return tuple(sorted(tuple(r) for r in con.execute(f"SELECT {','.join(cols)} FROM wire_calls WHERE session_id=?", (sid,))))

    def test_a_session_key_recurs_only_for_identical_rows_and_ignores_other_sessions(self):
        """Bounded random history under a held clock: key -> content must be a function (no stale cache hit), and a
        write that touches only another session leaves the key alone (no needless invalidation)."""
        con = self.open()
        st = self.st
        rnd = random.Random(7)
        seen: dict = {}
        T = time.time_ns()
        ids = [f"w{i}" for i in range(5)]
        with self.frozen(T):
            for step in range(300):
                cid, sid, op = rnd.choice(ids), rnd.choice(("s", "o")), rnd.randrange(6)
                cur = con.execute("SELECT session_id FROM wire_calls WHERE id=?", (cid,)).fetchone()
                touches_s = sid == "s" or (cur is not None and cur[0] == "s")
                before = self._key(con, "s")
                stale = rnd.choice([v for (v,) in con.execute("SELECT rev FROM wire_calls")] or [None])
                if op == 0:
                    st.upsert(con, {"id": cid, "session_id": sid, "ended": 1.0, "req_down": ref(str(rnd.random()))}, "wire_calls")
                elif op == 1:
                    st.upsert(con, {"id": cid, "session_id": sid, "status": rnd.randrange(3)}, "wire_calls")
                elif op == 2:
                    con.execute("UPDATE wire_calls SET req_down=?, rev=?, session_id=? WHERE id=?",
                                (ref(str(rnd.randrange(3))), stale, sid, cid))
                elif op == 3:
                    con.execute("DELETE FROM wire_calls WHERE id=?", (cid,))
                    touches_s = cur is not None and cur[0] == "s"
                elif op == 4:
                    con.execute("DELETE FROM wire_calls WHERE id=?", (cid,))
                    con.execute("INSERT INTO wire_calls (id, session_id, ended, rev) VALUES (?, ?, 1.0, ?)", (cid, sid, stale))
                else:
                    con.execute("INSERT OR REPLACE INTO wire_calls (id, session_id, ended, status, rev) VALUES (?, ?, 1.0, ?, ?)",
                                (cid, sid, rnd.randrange(3), stale))
                con.commit()
                key, content = self._key(con, "s"), self._content(con, "s")
                if not touches_s and content:  # (a session with no captures keys on every write, by design)
                    self.assertEqual(key, before, f"step {step}: another session's write changed this session's key")
                if key in seen:
                    self.assertEqual(seen[key], content, f"step {step}: key {key} recurred for different rows")
                seen[key] = content
        self.assertGreater(len(seen), 50, "the history exercised many distinct states")


if __name__ == "__main__":
    unittest.main()
