"""Real capture-writer idle backfill, rollback/retry and queued-job fairness."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE / relative)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class IdleMaintenance(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'telemetry.db'
        self.environment = mock.patch.dict(os.environ, {'HOME': self.tmp.name, 'HERMES_HOME': self.tmp.name,
            'TELEMETRY_DB': str(self.path), 'CLIPROXY_LOG_DIR': '', 'WIRETAP_PROXY_POLLER': '0',
            'WIRETAP_POLLER': '0', 'MODEL_TELEMETRY_POLLER': '0'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.saved = {k: v for k, v in sys.modules.items() if k.startswith('_wiretap')}
        for key in self.saved:
            sys.modules.pop(key)
        self.addCleanup(self.restore_modules)
        self.cap = load('_wiretap_idle_capture', 'collector/capture.py')
        self.store = self.cap.store
        self.writers = []
        self.addCleanup(self.stop_writers)
        self.backfill = self.store.backfill_signals

    def restore_modules(self):
        for key in list(sys.modules):
            if key.startswith('_wiretap'):
                sys.modules.pop(key)
        sys.modules.update(self.saved)

    def stop_writers(self):
        for writer in self.writers:
            writer.stop(5)
            self.assertFalse(writer.thread and writer.thread.is_alive(), 'test writer must terminate')

    def writer(self):
        writer = self.cap.Writer(self.path)
        self.writers.append(writer)
        return writer

    def seed(self, count=5):
        con = self.store.connect(self.path)
        try:
            self.store.init(con)
            for i in range(count):
                self.store.upsert(con, {'id': f'history:{i}', 'source': 'hermes', 'started': i,
                    'attempt_detail': json.dumps([{'status': 400, 'message': 'Blocked by safety policy'}])})
            con.execute("DELETE FROM kv WHERE k='signals_rev'")
            con.commit()
        finally:
            con.close()

    def slice(self, con, budget_s=None, batch=50):
        # Real parsing and SQL; force one-row slices so a small fixture exercises
        # multiple idle timeouts without spending seconds inside each slice.
        return self.backfill(con, budget_s=1e-12, batch=1)

    def read(self, sql, params=()):
        con = self.store.connect_ro(self.path)
        try:
            return con.execute(sql, params).fetchall()
        finally:
            con.close()

    def wait_until(self, predicate, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.02)
        self.fail('writer did not reach the required persisted state')

    def finished(self):
        rows = self.read("SELECT v FROM kv WHERE k='signals_rev'")
        return bool(rows and rows[0][0] == self.store.SIGNALS_REV)

    def test_backfill_finishes_across_idle_timeouts_without_traffic_or_poller(self):
        self.seed()
        writer = self.writer()
        with mock.patch.object(self.store, 'backfill_signals', side_effect=self.slice):
            self.assertTrue(writer.submit(lambda con: con.execute("INSERT INTO kv VALUES ('job', 'committed')")))
            writer.flush(3)
            capture = self.read("SELECT v FROM kv WHERE k='last_capture'")[0][0]
            self.assertLess(self.read('SELECT COUNT(*) FROM calls WHERE signals IS NOT NULL')[0][0], 5)
            self.wait_until(self.finished)
            signals = [json.loads(row[0]) for row in self.read('SELECT signals FROM calls')]
            self.assertEqual(len(signals), 5)
            self.assertTrue(all(sig['v'] == 1 and sig['refusal'] for sig in signals))
            self.assertEqual(self.read("SELECT v FROM kv WHERE k='last_capture'")[0][0], capture,
                             'backfill must finish without another submitted capture')
            self.assertFalse(any(t.name == 'wiretap-poller' and t.is_alive() for t in threading.enumerate()))
            self.assertFalse(any('/extensions/cliproxy' in str(getattr(mod, '__file__', ''))
                                 for mod in list(sys.modules.values()) if mod is not None))
            writer.stop(3)

    def test_maintenance_error_rolls_back_then_retries_even_if_logging_fails(self):
        self.seed(4)
        writer = self.writer()
        failed = threading.Event()
        retry_entered = threading.Event()
        allow_retry = threading.Event()
        idle_attempts = 0

        def faulty_slice(con, budget_s=None, batch=50):
            nonlocal idle_attempts
            if budget_s == 0.25:
                idle_attempts += 1
                if idle_attempts == 1:
                    self.slice(con, budget_s, batch)
                    con.execute("INSERT INTO kv VALUES ('must-rollback', 'partial')")
                    failed.set()
                    raise sqlite3.OperationalError('synthetic maintenance failure')
                if idle_attempts == 2:
                    retry_entered.set()
                    if not allow_retry.wait(3):
                        raise RuntimeError('test did not release retry')
            return self.slice(con, budget_s, batch)

        self.addCleanup(allow_retry.set)
        with mock.patch.object(self.store, 'backfill_signals', side_effect=faulty_slice), \
             mock.patch.object(self.cap.logger, 'debug', side_effect=OSError('log sink unavailable')):
            self.assertTrue(writer.submit(lambda con: con.execute("INSERT INTO kv VALUES ('job', 'healthy')")))
            self.assertTrue(failed.wait(3))
            self.assertTrue(retry_entered.wait(3), 'idle timeout must retry without new traffic')
            self.assertEqual(self.read("SELECT v FROM kv WHERE k='must-rollback'"), [])
            self.assertEqual(self.read('SELECT COUNT(*) FROM calls WHERE signals IS NOT NULL')[0][0], 1,
                             'the failed idle slice must roll back its signals write too')
            allow_retry.set()
            self.wait_until(self.finished)
            self.assertEqual(self.read('SELECT COUNT(*) FROM calls WHERE signals IS NOT NULL')[0][0], 4)
            self.assertTrue(writer.thread.is_alive())
            writer.stop(3)

    def test_queued_jobs_and_new_traffic_are_not_starved_by_pending_backfill(self):
        self.seed(5)
        writer = self.writer()
        blocker_started = threading.Event()
        release_blocker = threading.Event()
        idle_started = threading.Event()
        release_idle = threading.Event()
        urgent_done = threading.Event()
        observed_counts = []

        def blocker(con):
            blocker_started.set()
            if not release_blocker.wait(3):
                raise RuntimeError('test did not release initial job')

        def gated_slice(con, budget_s=None, batch=50):
            if budget_s == 0.25 and not idle_started.is_set():
                observed_counts.append(con.execute("SELECT COUNT(*) FROM kv WHERE k LIKE 'queued:%'").fetchone()[0])
                idle_started.set()
                if not release_idle.wait(3):
                    raise RuntimeError('test did not release idle slice')
            return self.slice(con, budget_s, batch)

        self.addCleanup(release_blocker.set)
        self.addCleanup(release_idle.set)
        with mock.patch.object(self.store, 'backfill_signals', side_effect=gated_slice):
            self.assertTrue(writer.submit(blocker))
            self.assertTrue(blocker_started.wait(3))
            for i in range(70):
                self.assertTrue(writer.submit(lambda con, i=i: con.execute('INSERT INTO kv VALUES (?, ?)',
                                                                          (f'queued:{i}', str(i)))))
            release_blocker.set()
            self.assertTrue(idle_started.wait(3))
            self.assertEqual(observed_counts, [70], 'all queued jobs must commit before an idle slice starts')
            self.assertTrue(writer.submit(lambda con: (con.execute("INSERT INTO kv VALUES ('urgent', 'done')"), urgent_done.set())))
            release_idle.set()
            self.assertTrue(urgent_done.wait(2), 'traffic arriving during maintenance must run before backfill completes')
            writer.flush(3)
            self.assertEqual(self.read("SELECT v FROM kv WHERE k='urgent'")[0][0], 'done')
            self.wait_until(self.finished)
            self.assertEqual(writer.dropped, 0)
            writer.stop(3)

    def test_reopened_writer_resumes_new_historical_backlog(self):
        writer = self.writer()
        self.assertTrue(writer.submit(lambda con: con.execute("INSERT INTO kv VALUES ('first', 'done')")))
        writer.flush(3)
        self.wait_until(self.finished)
        writer.stop(3)
        self.seed(3)
        with mock.patch.object(self.store, 'backfill_signals', side_effect=self.slice):
            self.assertTrue(writer.submit(lambda con: con.execute("INSERT INTO kv VALUES ('reopened', 'done')")))
            writer.flush(3)
            self.wait_until(self.finished)
            self.assertEqual(self.read('SELECT COUNT(*) FROM calls WHERE signals IS NOT NULL')[0][0], 3)
            writer.stop(3)


if __name__ == '__main__':
    unittest.main()
