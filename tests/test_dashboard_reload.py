"""Dashboard source reload changes observable readers without replacing capture modules."""
import importlib.util
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent.parent


class DashboardReaderReload(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        shutil.copytree(HERE/'collector', self.root/'collector', ignore=shutil.ignore_patterns('__pycache__'))
        spec = importlib.util.spec_from_file_location('_reload_dashboard_api', HERE/'dashboard/plugin_api.py')
        assert spec and spec.loader
        self.api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.api)
        self.prefix = '_wiretap_reload_test_' + self.root.name.replace('-', '_') + '_'
        setattr(self.api, '_READER_PREFIX', self.prefix)
        setattr(self.api, '_PRIVATE', self.prefix+'telemetry')
        setattr(self.api, '_COLLECTOR', self.root/'collector')
        self.addCleanup(self._clear_modules)

    def _clear_modules(self):
        for key in tuple(sys.modules):
            if key.startswith(self.prefix):
                sys.modules.pop(key, None)

    def test_each_watched_source_hot_reloads_same_size_rapid_edits(self):
        capture_modules = {k:sys.modules.get(k) for k in ('_wiretap_store','_wiretap_inspector','_wiretap_capture')}
        for name, path, select in [
            ('telemetry', self.root/'collector/telemetry.py', lambda t:t),
            ('inspector', self.root/'collector/inspector.py', lambda t:t.inspector),
            ('store', self.root/'collector/store.py', lambda t:t.store),
        ]:
            with self.subTest(module=name):
                original = path.read_text()
                first_source = original + "\ndef reload_probe(): return 'one'\n"
                path.write_text(first_source)
                first = self.api._telemetry()
                self.assertEqual(select(first).reload_probe(), 'one')
                self.assertIs(self.api._telemetry(), first)
                stat = path.stat()
                path.write_text(first_source.replace("return 'one'", "return 'two'"))
                os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns+1))
                second = self.api._telemetry()
                self.assertEqual(select(second).reload_probe(), 'two')
                self.assertIsNot(first, second)
                self.assertEqual(select(first).reload_probe(), 'one', 'in-flight old readers stay usable')
        for key, original in capture_modules.items():
            self.assertIs(sys.modules.get(key), original, 'reader reload must not replace capture-owned modules')

    def test_next_http_request_observes_changed_source_without_restarting_app(self):
        app = FastAPI()
        app.include_router(self.api.router)
        path = self.root/'collector/inspector.py'
        original = path.read_text()
        source = original + "\ndef sessions_list(*a, **kw): return [{'id':'before'}]\n"
        path.write_text(source)
        with patch.object(self.api, '_need_state'), patch.dict(os.environ, {'MAIN_SESSION':'test'}):
            with TestClient(app) as client:
                self.assertEqual(client.get('/inspector/sessions').json()['sessions'], [{'id':'before'}])
                path.write_text(source.replace("'before'", "'after!'"))
                self.assertEqual(client.get('/inspector/sessions').json()['sessions'], [{'id':'after!'}])

    def test_concurrent_requests_share_one_fresh_reader(self):
        first = self.api._telemetry()
        path = self.root/'collector/inspector.py'
        path.write_text(path.read_text()+"\ndef reload_probe(): return 'fresh'\n")
        with ThreadPoolExecutor(max_workers=8) as pool:
            readers = list(pool.map(lambda _:self.api._telemetry(), range(16)))
        self.assertTrue(all(r is readers[0] for r in readers))
        self.assertIsNot(readers[0], first)
        self.assertEqual(readers[0].inspector.reload_probe(), 'fresh')

    def test_broken_edit_keeps_last_good_reader_and_recovers_on_next_edit(self):
        first = self.api._telemetry()
        path = self.root/'collector/inspector.py'
        original = path.read_text()
        path.write_text(original+'\ninvalid python ]\n')
        with self.assertLogs(self.api._LOG, level='WARNING'):
            self.assertIs(self.api._telemetry(), first)
        self.assertIs(sys.modules[self.api._PRIVATE], first)
        path.write_text(original+"\ndef reload_probe(): return 'recovered'\n")
        self.assertEqual(self.api._telemetry().inspector.reload_probe(), 'recovered')
