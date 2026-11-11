"""Session picker contracts: metadata search, useful titles, and no-op admissions."""
import importlib.util
import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import test_schemas as fixtures

HERE = Path(__file__).resolve().parent.parent


class SessionPicker(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / 'state.db'
        self.ins = fixtures._load_inspector()
        self.now = time.time() - 30
        con = sqlite3.connect(self.db)
        self.addCleanup(con.close)
        con.executescript(fixtures.TYPED_SCHEMA)
        con.executescript('ALTER TABLE sessions ADD COLUMN api_call_count INTEGER DEFAULT 0;'
                          'CREATE INDEX activity_order ON sessions(COALESCE(last_activity_at,started_at));'
                          'CREATE INDEX message_lookup ON messages(session_id,id);')
        rows = [
            dict(id='main', source='discord', model='gemini-4-argon', title='Bot Chat', depth=0, lineage_kind='root', message_count=2),
            dict(id='child-sol', source='subagent', model='gpt-6.1-sol', billing_provider='openai-codex', depth=1,
                 title='Subagent: <latest_user_message sent_at="2026… #35', role='orchestrator',
                 parent_session_id='main', root_session_id='main', group_id='deleg_alpha', lineage_kind='delegate',
                 session_key='agent:research'),
            dict(id='child-argon', source='subagent', model='gemini-4-argon', message_count=2, depth=1,
                 title='Subagent: [Parent assignment at yesterday]', parent_session_id='main', lineage_kind='delegate'),
            dict(id='leaf', source='subagent', model='gpt-6.1-sol', message_count=3, depth=2, role='leaf',
                 parent_session_id='child-sol', root_session_id='main', group_id='deleg_beta', lineage_kind='delegate',
                 title='Review bandwidth measurements'),
            dict(id='calls-only', source='cron', api_call_count=1, model='probe-model', model_config=json.dumps({'provider':'alternate-provider'})),
            dict(id='stale-counters', source='cli', model='fallback-model'),
            dict(id='local-deadbeef', source='cron', model='gemini-4-argon'),
        ]
        for i, row in enumerate(rows):
            fixtures._insert(con, 'sessions', dict(started_at=self.now+i, last_activity_at=self.now+i, **row))
        for sid, text in [('child-sol', '<latest_user_message>Unrelated question</latest_user_message>\n<parent_message sent_at="now">Audit the credential routing and verify the serving account.</parent_message>'),
                          ('child-argon', '[Parent assignment at yesterday]\nCheck cache prefix stability across turns.'),
                          ('stale-counters', 'A real message despite counters not updated yet.')]:
            fixtures._insert(con, 'messages', dict(session_id=sid, role='user', content=text, timestamp=self.now))
        con.commit()

    def ids(self, query='', limit=100, main='main', **kwargs):
        return [r['id'] for r in self.ins.sessions_list(self.db, query, limit, main, **kwargs)]

    def test_search_all_tokens_across_metadata_without_pinning_unmatched_main(self):
        for query, expected in [
            ('SOL subagent', {'child-sol','leaf'}), ('argon d1', {'child-argon'}),
            ('codex', {'child-sol'}), ('discord d0', {'main'}), ('agent:research', {'child-sol'}),
            ('deleg_alpha', {'child-sol'}), ('delegate d2', {'leaf'}), ('alternate-provider', {'calls-only'}),
            ('main d1', {'child-sol','child-argon'}), ('child-sol d2', {'leaf'}),
            ('sol nonexistent', set()), ('%', set()), ('no_such_session', set()),
        ]:
            with self.subTest(query=query):
                self.assertEqual(set(self.ids(query)), expected)
        self.assertEqual(self.ids('sol', source='cron'), [])
        with self.assertRaises(ValueError):
            self.ids('word ' * 17)

    def test_empty_sessions_are_filtered_before_limit_but_real_activity_survives(self):
        ids = self.ids()
        self.assertNotIn('local-deadbeef', ids)
        self.assertIn('calls-only', ids)
        self.assertIn('stale-counters', ids)
        self.assertEqual(self.ids(limit=1, main=''), ['stale-counters'])
        self.assertEqual(self.ids(main='local-deadbeef').count('local-deadbeef'), 0)

    def test_titles_use_assignment_not_forwarded_headers_without_mutating_store(self):
        rows = {r['id']:r for r in self.ins.sessions_list(self.db, '', 100, 'main')}
        self.assertEqual(rows['child-sol']['display_title'], 'Subagent: Audit the credential routing and verify the serving account.')
        self.assertEqual(rows['child-argon']['display_title'], 'Subagent: Check cache prefix stability across turns.')
        self.assertEqual(rows['leaf']['display_title'], 'Review bandwidth measurements')
        self.assertTrue(rows['child-sol']['title'].startswith('Subagent: <latest_user_message'))

    def test_title_fallback_does_not_mistake_forked_human_text_for_assignment(self):
        con = sqlite3.connect(self.db)
        self.addCleanup(con.close)
        for sender, expected in [('human', 'Subagent · child-sol'), ('parent', 'Subagent: Audit the response parser for the serving provider.')]:
            with self.subTest(sender=sender):
                con.execute("UPDATE messages SET content=?, sender_kind=? WHERE session_id='child-sol'",
                            ('Audit the response parser for the serving provider.', sender))
                con.commit()
                row = self.ins.sessions_list(self.db, 'deleg_alpha', 10, '')[0]
                self.assertEqual(row['display_title'], expected)

    def test_telemetry_sessions_also_excludes_noops(self):
        spec = importlib.util.spec_from_file_location('_picker_telemetry', HERE/'collector/telemetry.py')
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with patch.object(mod, 'STATE_DB', self.db), patch.object(mod, 'main_session', return_value='main'), patch.object(mod, 'context_gauge', return_value=None):
            response = mod.api_sessions({'hours':['24']})
        self.assertNotIn('error', response)
        ids = {r['id'] for r in response['sessions']}
        self.assertNotIn('local-deadbeef', ids)
        self.assertTrue({'calls-only','stale-counters','child-sol'} <= ids)

    def test_stock_schema_has_same_search_and_empty_filter_semantics(self):
        stock = self.db.with_name('stock.db')
        con = sqlite3.connect(stock)
        self.addCleanup(con.close)
        con.executescript(fixtures.STOCK_SCHEMA)
        fixtures._insert(con, 'sessions', dict(id='old', source='cli', model='gpt-6.1-sol', started_at=self.now))
        fixtures._insert(con, 'sessions', dict(id='empty', source='cron', started_at=self.now))
        fixtures._insert(con, 'messages', dict(session_id='old', role='user', content='real input', timestamp=self.now))
        con.commit()
        self.assertEqual([r['id'] for r in self.ins.sessions_list(stock,'sol cli d0',10,'')], ['old'])
        self.assertEqual([r['id'] for r in self.ins.sessions_list(stock,'',10,'')], ['old'])
