"""Archived stores remain useful through real dashboard routes without migration."""
import hashlib
import importlib.util
import json
import os
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
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


def snapshot(path):
    con = sqlite3.connect(path)
    try:
        return (hashlib.sha256(path.read_bytes()).hexdigest(), list(con.iterdump()),
                con.execute('PRAGMA journal_mode').fetchone(),
                con.execute('PRAGMA freelist_count').fetchone())
    finally:
        con.close()


class LegacyDashboard(unittest.TestCase):
    @contextmanager
    def fixture(self, *, upstream=False, signals=False, wire_migrations=False):
        saved = {k: v for k, v in sys.modules.items() if k.startswith('_wiretap')}
        for key in saved:
            sys.modules.pop(key)
        try:
            with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {
                'HOME': tmp, 'HERMES_HOME': tmp, 'TELEMETRY_DB': '', 'WIRETAP_STATE_DB': '',
                'MAIN_SESSION': '', 'CLIPROXY_LOG_DIR': '', 'WIRETAP_POLLER': '0',
                'WIRETAP_PROXY_POLLER': '0', 'MODEL_TELEMETRY_POLLER': '0',
            }):
                home = Path(tmp)
                path = home / 'plugin-data/model-telemetry/telemetry.db'
                path.parent.mkdir(parents=True)
                store = load('_wiretap_store', 'collector/store.py')
                now = time.time()
                con = sqlite3.connect(path)
                con.executescript(store.SCHEMA)
                for table, col, typ in store.MIGRATIONS:
                    wanted = (table == 'wire_calls' and wire_migrations or
                              table == 'calls' and (col == 'upstream_provider' and upstream or col == 'signals' and signals))
                    if wanted and col not in store.columns(con, table):
                        con.execute(f'ALTER TABLE {table} ADD COLUMN {col} {typ}')
                for cid, age, family, provider, key, p, c, out, cost, duration in (
                    ('recent', 10, 'fixture', 'router-a', 'K001', 30000, 6000, 30, .5, 40),
                    ('second', 20, 'fixture', 'router-a', 'K001', 100, 90, 10, .25, 10),
                    ('other', 30, 'other', 'router-b', None, 50, 0, 5, .125, 5),
                    ('old', 172800, 'fixture', 'router-a', 'K001', 999, 0, 1, 99, 1),
                ):
                    row = dict(id=cid, source='hermes', started=now-age, ended=now-age+duration,
                               family=family, provider=provider, model='fixture-v1', session_id='chat',
                               auth_label='fixture-key' if key else None, auth_key=key, auth_type='api_key',
                               project='project-a', prompt_tokens=p, cached_tokens=c, output_tokens=out,
                               thinking_tokens=0, cache_write_tokens=0, hit_pct=100*c/p,
                               cost_usd=cost, cost_equiv_usd=cost*2, total_s=duration, ttfb_s=1,
                               status=200, nfail=0, n429=1 if cid == 'recent' else 0,
                               attempts=2 if cid == 'recent' else 1, retry_s=2 if cid == 'recent' else 0,
                               context_length=100000, message_count=3, proxy_rid='proxy-1' if cid == 'recent' else None)
                    if upstream:
                        row['upstream_provider'] = 'vendor-a' if cid == 'recent' else 'vendor-b'
                    if signals:
                        row['signals'] = json.dumps({'v': 1, 'refusal': cid == 'recent'}, separators=(',', ':'))
                    con.execute(f"INSERT INTO calls ({','.join(row)}) VALUES ({','.join('?' for _ in row)})", list(row.values()))
                con.execute("INSERT INTO events VALUES ('proxy-1', ?, 'info', 'bound to new auth', 'fixture')", (now-9,))
                con.execute("INSERT INTO events VALUES ('proxy-1', ?, 'error', 'fail:request', 'key=K001 fixture')", (now-8,))
                con.execute('CREATE TABLE freed_payload(body)')
                con.execute('INSERT INTO freed_payload VALUES (zeroblob(131072))')
                con.execute('DELETE FROM freed_payload')
                con.commit()
                con.close()
                state = home / 'state.db'
                con = sqlite3.connect(state)
                con.execute('CREATE TABLE sessions (id TEXT, source TEXT, started_at REAL, model TEXT, message_count INTEGER, model_config TEXT)')
                con.execute("INSERT INTO sessions VALUES ('chat', 'cli', ?, 'fixture-v1', 3, '{}')", (now,))
                con.commit()
                con.close()
                before, state_before = snapshot(path), snapshot(state)
                api = load('_wiretap_legacy_api', 'dashboard/plugin_api.py')
                app = FastAPI()
                app.include_router(api.router)
                try:
                    with TestClient(app, raise_server_exceptions=False) as client:
                        yield client, api, path
                finally:
                    self.assertEqual(snapshot(path), before, 'dashboard reads must not migrate, reprice, reclaim or change journal mode')
                    self.assertEqual(snapshot(state), state_before)
                    self.assertFalse((home / 'plugin-data/wiretap').exists())
        finally:
            for key in list(sys.modules):
                if key.startswith('_wiretap'):
                    sys.modules.pop(key)
            sys.modules.update(saved)

    def get(self, client, route, **params):
        response = client.get(route, params=params)
        self.assertEqual(response.status_code, 200, f'{route}: {response.text}')
        return response.json()

    def test_health_and_calls_keep_old_rows_aggregates_and_key_groups(self):
        for upstream, signals, wire_migrations in ((False, False, False), (True, False, False),
                                                  (False, True, True), (True, True, True)):
            with self.subTest(upstream=upstream, signals=signals, wire_migrations=wire_migrations):
                with self.fixture(upstream=upstream, signals=signals, wire_migrations=wire_migrations) as (client, api, path):
                    health = self.get(client, '/health')
                    self.assertEqual(health['calls'], 4)
                    self.assertGreater(health['space']['free_pages'], 0)
                    doc = self.get(client, '/calls', limit=1)
                    self.assertEqual((doc['total'], doc['has_more']), (3, True))
                    row = doc['rows'][0]
                    self.assertEqual((row['id'], row['prompt_tokens'], row['cost_usd']), ('recent', 30000, .5))
                    self.assertEqual((row['aff'], row['lane']), ('rebound', None))
                    self.assertEqual(len(row['events']), 2)
                    self.assertEqual(bool(row.get('refusal')), signals)
                    summary = doc['summary']['fixture']
                    self.assertEqual((summary['n'], summary['p'], summary['c'], summary['cost'], summary['eq']),
                                     (2, 30100, 6090, .75, 1.5))
                    agg = next(r for r in doc['agg'] if r['family'] == 'fixture')
                    self.assertEqual((agg['n'], agg['prompt'], agg['n429'], agg['retried'], agg['misses']), (2, 30100, 1, 1, 1))
                    self.assertEqual({r['provider']: r['n'] for r in doc['providers']}, {'router-a': 2, 'router-b': 1})
                    keys = doc['keys']
                    self.assertEqual(sum(r['n'] for r in keys), 2)
                    if upstream:
                        self.assertEqual({r['upstream_provider'] for r in keys}, {'vendor-a', 'vendor-b'})
                        self.assertEqual(len(keys), 2)
                    else:
                        self.assertEqual(len(keys), 1)
                        self.assertIsNone(keys[0]['upstream_provider'])
                    self.assertEqual(doc['fail_keys'][0]['key'], 'K001')
                    next_page = self.get(client, '/calls', limit=1, offset=1, page=1)
                    self.assertEqual([r['id'] for r in next_page['rows']], ['second'])
                    self.assertTrue(next_page['has_more'])
                    last_page = self.get(client, '/calls', limit=1, offset=2, page=1)
                    self.assertEqual([r['id'] for r in last_page['rows']], ['other'])
                    self.assertFalse(last_page['has_more'])
                    unchanged = self.get(client, '/calls', limit=1, rev=doc['rev'])
                    self.assertTrue(unchanged['unchanged'])
                    for query, expected in (({'provider': 'router-a'}, ['recent', 'second']),
                                            ({'family': '!fixture'}, ['other']), ({'family': 'fixture'}, ['recent', 'second']),
                                            ({'misses': 1}, ['recent']), ({'slow': 1}, ['recent']),
                                            ({'session': 'absent'}, []), ({'sort': 'cost_usd', 'dir': 'asc'}, ['other', 'second', 'recent'])):
                        filtered = self.get(client, '/calls', **query)
                        self.assertEqual([r['id'] for r in filtered['rows']], expected)
                        self.assertEqual(filtered['total'], len(expected))
                    sessions = self.get(client, '/sessions')
                    self.assertNotIn('error', sessions)
                    self.assertEqual(sessions['sessions'][0]['id'], 'chat')
                    self.assertIsNone(sessions['main']['id'], 'legacy archive without Bot Chat must not pin a random root')
                    self.assertEqual(api._telemetry().context_gauge('chat', 'cli', None, 3)['ctx_window'], 100000)
                    # There is no dashboard /costs route: exercise the shared CLI costs boundary instead.
                    proc = subprocess.run([sys.executable, str(HERE / 'bin/wiretap'), 'costs', '--since', '1h',
                                           '--group-by', 'credential', '--json'], capture_output=True, text=True, timeout=20)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    costs = json.loads(proc.stdout)['result']
                    self.assertEqual((costs['total']['calls'], costs['total']['prompt_tokens'], costs['total']['cost_usd']),
                                     (3, 30150, .875))
                    self.assertEqual(next(r for r in costs['rows'] if r['auth_key'] == 'K001')['calls'], 2)
                    tel = api._telemetry()
                    con = tel.store.connect_ro(path)
                    try:
                        for by in tel.COST_GROUPS:
                            report = tel.costs(con, {'since': time.time()-3600}, by=by)
                            self.assertEqual(report['total']['calls'], 3)
                            self.assertEqual(report['total']['cost_usd'], .875)
                        upstream_page = tel.list_calls_page(con, {'since': time.time()-3600, 'upstream': 'vendor-a'})
                        self.assertEqual(upstream_page['total'], 1 if upstream else 0)
                        for filters, expected in (({'credential': 'K001', 'project': 'project-a', 'status': 200}, ['recent', 'second']),
                                                  ({'model': 'fixture', 'misses': True}, ['recent']),
                                                  ({'errors': True}, []), ({'credential': 'absent'}, [])):
                            filters = dict(filters, since=time.time()-3600)
                            self.assertEqual([r['id'] for r in tel.list_calls(con, filters)], expected)
                            page = tel.list_calls_page(con, filters, limit=1)
                            self.assertEqual(page['total'], len(expected))
                            self.assertEqual([r['id'] for r in page['results']], expected[:1])
                        # Without stored signals or responses, do not invent a
                        # refusal. Partial migration can supply a stored one.
                        refusal = tel.list_calls_page(con, {'since': time.time()-3600, 'refusals': True})
                        self.assertEqual([r['id'] for r in refusal['results']], ['recent'] if signals else [])
                    finally:
                        con.close()


if __name__ == '__main__':
    unittest.main()
