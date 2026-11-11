"""Core-only privacy, missing enrichment and concurrent dashboard cold starts."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from hermes_constants import set_hermes_home_override, reset_hermes_home_override

HERE = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CoreDistribution(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.plugin = self.root / 'plugin'
        for directory in ('collector', 'dashboard'):
            shutil.copytree(HERE / directory, self.plugin / directory, ignore=shutil.ignore_patterns('__pycache__'))
        self.home = self.root / 'profile'
        self.home.mkdir()
        self.token = set_hermes_home_override(str(self.home))
        self.addCleanup(reset_hermes_home_override, self.token)
        env = patch.dict(os.environ, HERMES_HOME=str(self.home), TELEMETRY_DB=str(self.home/'wiretap.db'),
                         WIRETAP_STATE_DB=str(self.home/'state.db'), CLIPROXY_LOG_DIR=str(self.root/'configured-logs'),
                         WIRETAP_PROXY_POLLER='1', MAIN_SESSION='')
        env.start()
        self.addCleanup(env.stop)
        self.api = load('_wiretap_core_distribution_api', self.plugin/'dashboard/plugin_api.py')
        self.api._READER_PREFIX = '_wiretap_core_' + self.root.name.replace('-', '_') + '_'
        self.t = self.api._telemetry()
        con = self.t.store.connect(self.t.DB_PATH)
        self.t.store.init(con)
        self.t.store.upsert(con, dict(id='core-call', source='hermes', provider='example-provider', model='example-model'), 'calls')
        con.commit()
        con.close()
        self.app = FastAPI()
        self.app.include_router(self.api.router)

    def test_missing_extensions_ignore_configured_and_detected_proxy_logs(self):
        default_logs = self.root / '.cli-proxy-api' / 'logs'
        default_logs.mkdir(parents=True)
        with patch('pathlib.Path.home', return_value=self.root), TestClient(self.app) as client:
            for value in (str(self.root/'configured-logs'), ''):
                with self.subTest(log_setting=value), patch.dict(os.environ, CLIPROXY_LOG_DIR=value):
                    health = client.get('/health')
                    self.assertEqual(health.status_code, 200, health.text)
                    self.assertEqual(health.json()['proxy']['configured'], False)
                    self.assertEqual(client.get('/calls').status_code, 200)
                    self.assertIsNone(self.t._proxy_extension())
                    self.assertIsNone(self.api._poller_adapter().maybe_start(self.t, force=True))
                    self.t.main()  # explicit legacy scanner command is harmless without a scanner

    def test_core_capture_does_not_resolve_or_store_credentials(self):
        cap = load('_wiretap_core_privacy_capture', self.plugin/'collector/capture.py')
        self.addCleanup(cap._writer.stop)
        fake_secret = 'demo-secret-not-a-real-token-1234'
        # Any attempted credential-file read is a regression, even if its result
        # would later be hashed. Use a real pool-shaped file, never real credentials.
        (self.home/'auth.json').write_text(json.dumps({'credential_pool': {'example-provider': [
            {'label': 'private-demo-label', 'access_token': fake_secret}]}}))
        actual_read = Path.read_text
        def guarded_read(path, *args, **kw):
            if path.name == 'auth.json':
                raise AssertionError('Core attempted to read a credential store')
            return actual_read(path, *args, **kw)
        with patch.object(Path, 'read_text', guarded_read):
            self.assertIsNone(cap.credential_identity({'Authorization': 'Bearer ' + fake_secret}))
        import httpx
        messages = [{'role':'user','content':'Please analyze this completely synthetic request carefully.'}]
        cap._arm('privacy-call', {'base_url':'https://fixture.example/v1', 'request_messages':messages,
                                 'request_char_count':150, 'tool_count':0})
        con = cap.store.memory_store()
        self.addCleanup(con.close)
        cap.store.upsert(con, dict(id='privacy-call', source='hermes',provider='example-provider',model='example-model'), 'calls')
        writer = SimpleNamespace(submit=lambda job: job(con))
        with patch.object(cap, '_writer', writer), patch.object(Path, 'read_text', guarded_read):
            cap.on_http_request(httpx.Request('POST','https://fixture.example/v1/chat/completions',
                headers={'Authorization':'Bearer ' + fake_secret},json={'model':'example-model','messages':messages}))
        row = dict(con.execute("SELECT * FROM calls WHERE id='privacy-call'").fetchone())
        self.assertEqual((row['provider'],row['model']),('example-provider','example-model'))
        self.assertIsNone(row['auth_key'])
        self.assertIsNone(row['auth_label'])
        wire = dict(con.execute("SELECT * FROM wire_calls WHERE id='privacy-call'").fetchone())
        self.assertEqual(wire['exact'],1)
        self.assertNotIn(fake_secret,wire['hdr_down'])
        self.assertIsNone(wire['tap_key'])

    def test_concurrent_http_health_waits_for_complete_poller_import(self):
        prior = sys.modules.pop('_wiretap_poller', None)
        self.addCleanup(lambda: sys.modules.__setitem__('_wiretap_poller',prior) if prior is not None else sys.modules.pop('_wiretap_poller',None))
        entered, release = threading.Event(), threading.Event()
        original = importlib.util.spec_from_file_location
        def delayed_spec(name, path, *args, **kw):
            spec = original(name, path, *args, **kw)
            if name == '_wiretap_poller':
                real_exec = spec.loader.exec_module
                def delayed_exec(mod):
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError('test did not release import')
                    return real_exec(mod)
                spec.loader.exec_module = delayed_exec
            return spec
        second_entered = threading.Event()
        original_adapter = self.api._poller_adapter
        def observed_adapter():
            if entered.is_set():
                second_entered.set()
            return original_adapter()
        with TestClient(self.app) as client, patch.object(self.api.importlib.util,'spec_from_file_location',side_effect=delayed_spec), patch.object(self.api,'_poller_adapter',side_effect=observed_adapter):
            with ThreadPoolExecutor(max_workers=2) as pool:
                first = pool.submit(client.get,'/health')
                try:
                    self.assertTrue(entered.wait(5))
                    second = pool.submit(client.get,'/health')
                    self.assertTrue(second_entered.wait(5))
                    # The import is deliberately blocked. A concurrent HTTP read
                    # must wait, not return or crash on a half-initialized module.
                    from concurrent.futures import TimeoutError
                    with self.assertRaises(TimeoutError):
                        second.result(timeout=.1)
                finally:
                    release.set()
                responses = [first.result(timeout=5), second.result(timeout=5)]
        self.assertTrue(all(r.status_code==200 for r in responses),[r.text for r in responses])
        self.assertTrue(all(r.json()['proxy']['configured'] is False for r in responses))
