"""Bot Chat identity, session-local gauges and multiplexed profile isolation."""
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from hermes_constants import set_hermes_home_override, reset_hermes_home_override
import test_schemas as fixtures

HERE = Path(__file__).resolve().parent.parent


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE/file)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class SelectedSessionContext(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        environment = patch.dict(os.environ, {'MAIN_SESSION':'', 'TELEMETRY_DB':'', 'WIRETAP_STATE_DB':''})
        environment.start()
        self.addCleanup(environment.stop)
        self.api = load('_selected_context_api', 'dashboard/plugin_api.py')
        self.api._MOD.clear()
        self.homes = {}
        self.addCleanup(self.api._MOD.clear)
        for profile, window, prompt, count, threshold in [('a',1000,100,11,.5), ('b',4000,1200,22,.25)]:
            home = self.root/profile
            home.mkdir()
            (home/'config.yaml').write_text(json.dumps({'compression':{'enabled':True,'threshold':threshold,'hygiene_hard_message_limit':40}}))
            self.homes[profile] = home
            with sqlite3.connect(home/'state.db') as con:
                con.executescript(fixtures.STOCK_SCHEMA)
                for sid, title in [('same-session','Bot Chat'), (profile+'-only',profile+' conversation')]:
                    fixtures._insert(con,'sessions',dict(id=sid,source='discord',model='test',title=title,
                        started_at=time.time(),message_count=count,model_config='{}'))
                    fixtures._insert(con,'messages',dict(session_id=sid,role='user',content='synthetic input',timestamp=time.time()))
            token = set_hermes_home_override(str(home))
            try:
                with patch.dict(os.environ,{'MAIN_SESSION':''}):
                    t = self.api._telemetry()
                con = t.store.connect(t.DB_PATH)
                try:
                    t.store.init(con)
                    t.store.upsert(con,dict(id='same-call',session_id='same-session',started=time.time(),source='hermes',
                        provider='test',model='test',context_length=window,prompt_tokens=prompt),'calls')
                    con.commit()
                finally:
                    con.close()
            finally:
                reset_hermes_home_override(token)
        self.app = FastAPI()
        self.app.include_router(self.api.router)
        @self.app.middleware('http')
        async def profile_scope(request: Request, call_next):
            token = set_hermes_home_override(str(self.homes[request.query_params.get('profile','a')]))
            try:
                return await call_next(request)
            finally:
                reset_hermes_home_override(token)

    def test_one_server_keeps_profiles_paths_badges_cache_and_gauges_separate(self):
        with TestClient(self.app) as client:
            def read(profile):
                context = client.get('/inspector/session',params={'profile':profile,'id':'same-session','limit':1}).json()['context']
                sessions = client.get('/inspector/sessions',params={'profile':profile}).json()
                health = client.get('/health',params={'profile':profile}).json()
                return profile,context,sessions,health
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(read,['a','b','a','b','b','a']))
        for profile,context,sessions,health in results:
            with self.subTest(profile=profile):
                expected = (1000,100,11,500,850) if profile=='a' else (4000,1200,22,1000,3400)
                self.assertEqual(tuple(context[k] for k in ('ctx_window','last_prompt_tokens','message_count','compressor_trigger','hygiene_trigger')),expected)
                self.assertEqual(sessions['main'],'same-session')
                self.assertEqual({s['id'] for s in sessions['sessions']},{'same-session',profile+'-only'})
                self.assertEqual(Path(health['state_db']),self.homes[profile]/'state.db')
                self.assertTrue(str(health['db']).startswith(str(self.homes[profile])))

    def test_compiled_and_uncaptured_sessions_use_selected_identity(self):
        with TestClient(self.app) as client:
            compiled = client.get('/inspector/compiled',params={'profile':'b','id':'same-session'}).json()
            self.assertEqual(compiled['context']['ctx_window'],4000)
            unknown = client.get('/inspector/session',params={'profile':'b','id':'b-only','limit':1}).json()['context']
            self.assertEqual(unknown['id'],'b-only')
            self.assertNotIn('ctx_window',unknown)

    def test_main_is_only_bot_chat_or_explicit_override(self):
        t = load('_selected_main_test','collector/telemetry.py')
        db = self.homes['a']/'state.db'
        self.assertEqual(t.main_session(db),'same-session')
        with sqlite3.connect(db) as con:
            con.execute("UPDATE sessions SET title='Regular chat' WHERE id='same-session'")
        self.assertIsNone(t.main_session(db))
        with patch.object(t,'MAIN_SESSION_ENV','explicit-session'):
            self.assertEqual(t.main_session(db),'explicit-session')
        with sqlite3.connect(db) as con:
            fixtures._insert(con,'sessions',dict(id='fake-child',source='subagent',title='Bot Chat',started_at=time.time()+100))
        self.assertIsNone(t.main_session(db))
