"""Page accounting through the real CLI and FastAPI health boundary, without writes."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

HERE = Path(__file__).resolve().parent.parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE / relative)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


class StatusSpace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.path = self.home / 'plugin-data/model-telemetry/telemetry.db'
        self.environment = mock.patch.dict(os.environ, {'HOME': str(self.home), 'HERMES_HOME': str(self.home),
            'TELEMETRY_DB': '', 'WIRETAP_STATE_DB': '', 'CLIPROXY_LOG_DIR': '', 'MAIN_SESSION': '',
            'WIRETAP_PROXY_POLLER': '0', 'WIRETAP_POLLER': '0', 'MODEL_TELEMETRY_POLLER': '0'})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.saved = {k: v for k, v in sys.modules.items() if k.startswith('_wiretap')}
        for key in self.saved:
            sys.modules.pop(key)
        self.addCleanup(self.restore_modules)
        self.store = load('_wiretap_store', 'collector/store.py')

    def restore_modules(self):
        for key in list(sys.modules):
            if key.startswith('_wiretap'):
                sys.modules.pop(key)
        sys.modules.update(self.saved)

    def seed(self, current=False):
        self.path.parent.mkdir(parents=True)
        if current:
            con = self.store.connect(self.path)
            self.store.init(con)
        else:
            con = sqlite3.connect(self.path)
            con.execute('PRAGMA auto_vacuum=INCREMENTAL')
            con.executescript(self.store.SCHEMA)  # genuine old schema: no additive migrations or derived backfills
        con.execute("INSERT INTO calls (id, source, started) VALUES ('synthetic', 'hermes', 1)")
        con.execute("INSERT INTO wire_calls (id, source, started) VALUES ('expired', 'hermes', 1)")
        con.execute("INSERT INTO wire_blobs VALUES ('unreferenced', zeroblob(1024), 1024)")
        con.execute('CREATE TABLE freed_payload(body)')
        con.execute('INSERT INTO freed_payload VALUES (zeroblob(131072))')
        con.execute('DELETE FROM freed_payload')
        con.commit()
        expected = self.store.space(con)
        con.close()
        self.assertGreater(expected['free_pages'], 0, 'fixture must make unintended reclamation observable')
        return expected

    def snapshot(self):
        con = self.store.connect_ro(self.path)
        try:
            return {'sha256': hashlib.sha256(self.path.read_bytes()).hexdigest(), 'space': self.store.space(con),
                    'schema': [tuple(r) for r in con.execute('SELECT type, name, sql FROM sqlite_master ORDER BY type, name')],
                    'kv': [tuple(r) for r in con.execute('SELECT * FROM kv ORDER BY k')],
                    'calls': [tuple(r) for r in con.execute('SELECT * FROM calls')],
                    'wire': [tuple(r) for r in con.execute('SELECT * FROM wire_calls')],
                    'blobs': [tuple(r) for r in con.execute('SELECT h, n FROM wire_blobs')]}
        finally:
            con.close()

    def cli(self, *args, environment=None):
        proc = subprocess.run([sys.executable, str(HERE / 'bin/wiretap'), *map(str, args)],
                              env=environment, capture_output=True, text=True, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stderr, '')
        return json.loads(proc.stdout)

    def test_cli_home_and_environment_preserve_legacy_fallback_and_report_space_without_migration(self):
        expected = self.seed()
        before = self.snapshot()
        env = dict(os.environ)
        commands = [(['--home', self.home, 'status', '--json'], env),
                    (['status', '--json'], env)]
        # An explicit home also wins over an otherwise valid environment store.
        explicit = dict(env, HERMES_HOME=str(self.home / 'other-profile'), TELEMETRY_DB=str(self.home / 'wrong.db'))
        commands.append((['--home', self.home, 'status', '--json'], explicit))
        for argv, command_env in commands:
            with self.subTest(argv=list(map(str, argv)), home=command_env['HERMES_HOME']):
                doc = self.cli(*argv, environment=command_env)
                self.assertEqual((doc['wiretap'], doc['command']), (1, 'status'))
                telemetry = doc['result']['telemetry_db']
                self.assertEqual(telemetry['path'], str(self.path))
                self.assertEqual(telemetry['space'], expected)
                self.assertEqual((telemetry['calls'], telemetry['wire_calls'], telemetry['blobs']), (1, 1, 1))
                self.assertFalse(telemetry['signals_column'], 'status must not migrate the old store')
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.home / 'plugin-data/wiretap').exists(), 'legacy reads must not split the store')
        self.assertFalse((self.home / 'wrong.db').exists())

    def test_health_returns_space_without_migrating_or_reclaiming_a_legacy_store(self):
        expected = self.seed()
        before = self.snapshot()
        api = load('_wiretap_status_health', 'dashboard/plugin_api.py')
        app = FastAPI()
        app.include_router(api.router, prefix='/api/plugins/wiretap')
        with TestClient(app) as client:
            response = client.get('/api/plugins/wiretap/health')
        self.assertEqual(response.status_code, 200, response.text)
        doc = response.json()
        self.assertEqual(doc['db'], str(self.path))
        self.assertEqual(doc['space'], expected)
        self.assertEqual((doc['calls'], doc['wire_calls']), (1, 1))
        self.assertFalse(doc['no_data'])
        self.assertEqual(self.snapshot(), before, '/health must not perform schema/data migrations or retention')

    def test_health_reports_current_store_pages_without_reclaiming_existing_free_pages(self):
        expected = self.seed(current=True)
        before = self.snapshot()
        api = load('_wiretap_status_health', 'dashboard/plugin_api.py')
        app = FastAPI()
        app.include_router(api.router)
        with TestClient(app) as client:
            first = client.get('/health')
            second = client.get('/health')
        self.assertEqual((first.status_code, second.status_code), (200, 200))
        self.assertEqual(first.json()['space'], expected)
        self.assertEqual(second.json()['space'], expected)
        after = self.snapshot()
        self.assertEqual(after['kv'], before['kv'], '/health must not initialize backfill revision markers')
        self.assertEqual(after, before)

    def test_missing_store_status_and_health_do_not_create_it(self):
        doc = self.cli('status', '--json', environment=dict(os.environ))
        self.assertFalse(doc['result']['telemetry_db']['exists'])
        self.assertNotIn('space', doc['result']['telemetry_db'])
        api = load('_wiretap_status_health', 'dashboard/plugin_api.py')
        app = FastAPI()
        app.include_router(api.router)
        with TestClient(app) as client:
            response = client.get('/health')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['db_exists'])
        self.assertNotIn('space', response.json())
        self.assertFalse((self.home / 'plugin-data').exists())


if __name__ == '__main__':
    unittest.main()
