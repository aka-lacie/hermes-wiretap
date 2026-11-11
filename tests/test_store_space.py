"""Writer tuning, read-only page accounting and all-pages retention reclamation."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


class StoreSpace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'telemetry?#.db'
        patcher = mock.patch.dict(os.environ, {'HERMES_HOME': self.tmp.name, 'TELEMETRY_DB': str(self.path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        spec = importlib.util.spec_from_file_location('_store_space_test', HERE / 'collector/store.py')
        assert spec is not None and spec.loader is not None
        self.store = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.store
        self.addCleanup(sys.modules.pop, spec.name, None)
        spec.loader.exec_module(self.store)

    def test_writer_tuning_applies_to_each_connection_and_empty_store_is_incremental(self):
        for _ in range(2):
            con = self.store.connect(self.path, timeout=0.25)
            try:
                self.store.init(con)
                self.assertEqual(con.execute('PRAGMA synchronous').fetchone()[0], 1)
                self.assertEqual(con.execute('PRAGMA journal_size_limit').fetchone()[0], 67108864)
                self.assertEqual(con.execute('PRAGMA busy_timeout').fetchone()[0], 250)
                self.assertEqual(con.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
                self.assertEqual(self.store.space(con)['vacuum'], 'incremental')
            finally:
                con.close()

    def test_space_on_readonly_legacy_store_never_migrates_reclaims_or_writes(self):
        con = sqlite3.connect(self.path)
        con.execute('PRAGMA page_size=1024')
        con.execute('CREATE TABLE payload(body)')
        con.execute('INSERT INTO payload VALUES (zeroblob(65536))')
        con.commit()
        con.execute('DELETE FROM payload')
        con.commit()
        pages = con.execute('PRAGMA page_count').fetchone()[0]
        free = con.execute('PRAGMA freelist_count').fetchone()[0]
        con.close()
        before = self.path.read_bytes()
        reader = self.store.connect_ro(self.path)
        try:
            self.assertGreater(free, 0)
            self.assertEqual(self.store.space(reader), {'page_size': 1024, 'pages': pages, 'free_pages': free,
                                                        'bytes': 1024 * pages, 'free_bytes': 1024 * free, 'vacuum': 'none'})
            self.assertFalse(reader.in_transaction)
            self.assertEqual(reader.execute('PRAGMA query_only').fetchone()[0], 1)
            with self.assertRaises(sqlite3.OperationalError):
                reader.execute('CREATE TABLE forbidden(x)')
        finally:
            reader.close()
        self.assertEqual(self.path.read_bytes(), before)
        writer = self.store.connect(self.path)
        try:
            self.store.init(writer)
            self.assertEqual(self.store.space(writer)['vacuum'], 'none')
        finally:
            writer.close()

    def test_retention_drains_more_than_one_vacuum_slice_and_reader_sees_live_pages(self):
        con = self.store.connect(self.path)
        self.addCleanup(con.close)
        self.store.init(con)
        live = self.store.put_blob(con, {'kept': True})
        self.store.upsert(con, {'id': 'live', 'started': time.time(), 'resp_raw': live}, 'wire_calls')
        # An orphan larger than a bounded 2,048-page pass; no decompression or
        # random data generation is needed to exercise page reclamation.
        size = 12 * 1024 * 1024
        con.execute("INSERT INTO wire_blobs VALUES ('expired', zeroblob(?), ?)", (size, size))
        self.store.upsert(con, {'id': 'expired', 'started': 1, 'resp_raw': 'expired'}, 'wire_calls')
        con.commit()
        before = self.store.space(con)
        self.assertGreater(before['pages'], 2048)
        with con:
            result = self.store.gc(con, keep_s=3600, force=True)
        after = self.store.space(con)
        self.assertEqual((result['expired'], result['dead_blobs']), (1, 1))
        self.assertEqual(after['free_pages'], 0)
        self.assertLess(after['pages'], before['pages'] // 2)
        self.assertEqual(self.store.get_blob(con, live), {'kept': True})
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        self.assertEqual(self.path.stat().st_size, after['bytes'])
        reader = self.store.connect_ro(self.path)
        try:
            self.assertEqual(self.store.space(reader), after)
            self.assertEqual(reader.execute('SELECT id FROM wire_calls').fetchone()[0], 'live')
        finally:
            reader.close()

    def test_space_reads_full_vacuum_mode_without_schema(self):
        con = sqlite3.connect(':memory:')
        self.addCleanup(con.close)
        con.execute('PRAGMA auto_vacuum=FULL')
        con.execute('CREATE TABLE payload(x)')
        self.assertEqual(self.store.space(con)['vacuum'], 'full')


if __name__ == '__main__':
    unittest.main()
