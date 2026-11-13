"""Migration and fail-open storage regressions using isolated SQLite databases."""
import errno
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from test_wiretap import _HookBase, _Ctx, _load, HERE


class SettingsCompatibility(unittest.TestCase):
    def test_default_store_resolution_does_not_split_legacy_data(self):
        store = _load('_wiretap_paths_test', HERE / 'collector/store.py')
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {'TELEMETRY_DB': ''}):
            home = Path(tmp)
            old = home / 'plugin-data/model-telemetry/telemetry.db'
            new = home / 'plugin-data/wiretap/telemetry.db'
            with patch.object(store, 'hermes_home', return_value=home):
                self.assertEqual(store.db_path(), new)
                old.parent.mkdir(parents=True)
                old.touch()
                new.parent.mkdir(parents=True)
                self.assertEqual(store.data_dir(), old.parent)
                self.assertEqual(store.db_path(), old)
                new.touch()
                self.assertEqual(store.data_dir(), new.parent)
                self.assertEqual(store.db_path(), new)
                with patch.dict(os.environ, {'TELEMETRY_DB': str(home / 'override.db')}):
                    self.assertEqual(store.db_path(), home / 'override.db')

    def test_setting_precedence_and_registration(self):
        plugin = _load('_wiretap_settings_test', HERE / '__init__.py')
        cap = plugin._capture()
        cfg = {'plugins': {'entries': {
            'wiretap': {'settings': {'enabled': False}, 'config': {'max_request_mb': 8}},
            'model-telemetry': {'settings': {'enabled': True, 'capture_payloads': False},
                                'config': {'retention_hours': 12}}}}}
        old = dict(cap.SETTINGS)
        try:
            with patch.object(cap.store, 'hermes_config', return_value=cfg):
                plugin.register(_Ctx())
                self.assertFalse(cap.SETTINGS['enabled'])
                self.assertFalse(cap.SETTINGS['capture_payloads'])
                self.assertEqual(cap.SETTINGS['retention_hours'], 12)
                self.assertEqual(cap.SETTINGS['max_request_mb'], 8)
                self.assertEqual(cap.store.plugin_setting('unknown', 'fallback'), 'fallback')
        finally:
            cap.SETTINGS.clear()
            cap.SETTINGS.update(old)


class HookStorageSafety(_HookBase):
    def test_all_hook_boundaries_swallow_storage_and_log_sink_errors(self):
        for failure in (sqlite3.OperationalError('database is locked'),
                        sqlite3.OperationalError('database or disk is full'),
                        OSError(errno.ENOSPC, 'No space left on device')):
            for event, method in [('pre_api_request', 'on_pre'),
                                  ('post_api_request', 'on_post'),
                                  ('api_request_error', 'on_error')]:
                with self.subTest(event=event, failure=str(failure)), \
                     patch.object(self.cap, method, side_effect=failure), \
                     patch.object(self.mt.logger, 'debug', side_effect=OSError(errno.ENOSPC, 'log full')):
                    self.assertIsNone(self.ctx.hooks[event](api_request_id='failure'))
        with patch.object(self.mt, '_capture', side_effect=OSError(errno.ENOSPC, 'full')):
            self.assertIsNone(self.ctx.hooks['pre_api_request']())

    def test_locked_writer_drops_capture_and_recovers(self):
        store = self.cap.store
        con = store.connect()
        store.init(con)
        con.execute('BEGIN IMMEDIATE')
        connect = store.connect
        try:
            with patch.object(store, 'connect', side_effect=lambda path=None, timeout=0: connect(path, timeout=.01)):
                # All three hooks return without waiting for SQLite's writer lock.
                self.chat_call(701, [{'role': 'user', 'content': 'locked request'}], 'answer')
                self.ctx.hooks['api_request_error'](api_request_id='lock-error', status_code=429)
                self.cap._writer.flush(3)
                self.assertEqual(self.cap._writer.q.unfinished_tasks, 0)
                self.assertEqual(con.execute('SELECT COUNT(*) FROM calls').fetchone()[0], 0)
        finally:
            con.rollback()
            con.close()
        cid = self.chat_call(702, [{'role': 'user', 'content': 'recovered request'}], 'answer')
        con = self.db()
        try:
            self.assertEqual(con.execute('SELECT status FROM calls WHERE id=?', (cid,)).fetchone()[0], 200)
        finally:
            con.close()

    def test_real_sqlite_full_does_not_kill_writer(self):
        # SQLite's page limit produces SQLITE_FULL without filling the shared host disk.
        failures = []
        def fill(con):
            pages = con.execute('PRAGMA page_count').fetchone()[0]
            con.execute(f'PRAGMA max_page_count={pages}')
            try:
                con.execute("INSERT INTO wire_blobs VALUES ('full', randomblob(2097152), 2097152)")
            except sqlite3.OperationalError as exc:
                failures.append(exc.sqlite_errorcode)
                raise
            finally:
                con.execute('PRAGMA max_page_count=2147483646')
        self.cap._writer.submit(fill)
        self.cap._writer.flush(3)
        self.assertEqual(failures, [sqlite3.SQLITE_FULL])
        cid = self.chat_call(703, [{'role': 'user', 'content': 'after full'}], 'healthy')
        con = self.db()
        try:
            self.assertEqual(con.execute('SELECT status FROM calls WHERE id=?', (cid,)).fetchone()[0], 200)
        finally:
            con.close()


class RetentionAndReadOnly(unittest.TestCase):
    def setUp(self):
        self.store = _load('_wiretap_hygiene_store', HERE / 'collector/store.py')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'telemetry.db'

    def test_retention_reclaims_pages_and_keeps_shared_live_blobs(self):
        con = self.store.connect(self.path)
        self.addCleanup(con.close)
        self.store.init(con)
        self.assertEqual(con.execute('PRAGMA auto_vacuum').fetchone()[0], 2)
        now = time.time()
        expired = self.store.put_blob_str(con, os.urandom(2 * 1024 * 1024).hex())
        shared = self.store.put_blob_str(con, 'still referenced')
        for cid, started, refs in [('old', now - 73 * 3600, [expired, shared]),
                                   ('live', now, [shared])]:
            self.store.upsert(con, {'id': cid, 'started': started,
                                   'req_down': json.dumps({'items': refs})}, 'wire_calls')
        con.commit()
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        before = self.path.stat().st_size
        pages_before = con.execute('PRAGMA page_count').fetchone()[0]
        with con:
            result = self.store.gc(con, keep_s=72 * 3600, force=True)
        con.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchall()
        self.assertEqual(result['expired'], 1)
        self.assertEqual(result['dead_blobs'], 1)
        self.assertEqual(con.execute('SELECT id FROM wire_calls').fetchone()[0], 'live')
        self.assertEqual(self.store.get_blob_str(con, shared), 'still referenced')
        self.assertLess(con.execute('PRAGMA page_count').fetchone()[0], pages_before)
        self.assertLess(self.path.stat().st_size, before // 2)
        self.assertEqual(con.execute('PRAGMA freelist_count').fetchone()[0], 0)

    def test_existing_none_mode_database_is_not_rewritten(self):
        con = sqlite3.connect(self.path)
        self.addCleanup(con.close)
        con.execute('CREATE TABLE preserved(value)')
        con.execute('INSERT INTO preserved VALUES (123)')
        con.commit()
        self.store.init(con)
        self.assertEqual(con.execute('PRAGMA auto_vacuum').fetchone()[0], 0)
        self.assertEqual(con.execute('SELECT value FROM preserved').fetchone()[0], 123)

    def test_state_store_is_read_only_even_with_uri_characters(self):
        state = Path(self.tmp.name) / 'state?#.db'
        con = sqlite3.connect(state)
        con.execute('CREATE TABLE sessions(id)')
        con.commit()
        con.close()
        before = state.read_bytes()
        ins = _load('_wiretap_hygiene_inspector', HERE / 'collector/inspector.py')
        con = ins.state_con(state)
        try:
            self.assertEqual(con.execute('SELECT COUNT(*) FROM sessions').fetchone()[0], 0)
            with self.assertRaises(sqlite3.OperationalError):
                con.execute('INSERT INTO sessions VALUES (1)')
        finally:
            con.close()
        self.assertEqual(state.read_bytes(), before)
        with self.assertRaises(sqlite3.OperationalError):
            ins.state_con(Path(self.tmp.name) / 'absent.db')
        self.assertFalse((Path(self.tmp.name) / 'absent.db').exists())
