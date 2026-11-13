"""Execution forks share cache identity, never ownership of the primary wire."""
import contextvars
import json
import sqlite3
import sys
from types import ModuleType
from unittest.mock import patch

from test_wiretap import _HookBase, _state_db, SID, SYSTEM

REVIEW = ("Review the conversation above and consider saving to memory if appropriate.\n\n"
          "Personal memory maintenance.\n\nYou can only call memory and skill management tools. "
          "Other tools will be denied at runtime — do not attempt them. "
          "Exception — these configured tools are also allowed: goal_manage, memory_notes.")
BASE = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "hello"}]
USAGE = {"prompt_tokens": 50000, "input_tokens": 49000, "cache_read_tokens": 1000, "output_tokens": 10}


class ReviewLanes(_HookBase):
    def test_runtime_context_survives_hook_worker_and_keeps_payload_identity(self):
        origin = contextvars.ContextVar('test_origin', default='assistant_tool')
        module = ModuleType('tools.skill_provenance')
        setattr(module, 'get_current_write_origin', origin.get)
        with patch.dict(sys.modules, {'tools.skill_provenance': module}):
            main = self.chat_call(1, BASE)
            token = origin.set('background_review')
            try:
                # Same context-copy boundary as Hermes's bounded hook worker.
                review = contextvars.copy_context().run(self.chat_call, 2, BASE)
            finally:
                origin.reset(token)
            again = self.chat_call(3, BASE)
        with self.db() as con:
            rows = {r['id']: dict(r) for r in con.execute('SELECT * FROM calls')}
            self.assertEqual(rows[review]['lane'], 'review')
            self.assertEqual(rows[main]['lane'], rows[again]['lane'])
            self.assertEqual(rows[review]['session_id'], SID)
            refs = [r[0] for r in con.execute('SELECT req_down FROM wire_calls ORDER BY started')]
            self.assertEqual(len(set(refs)), 1, 'classification must not mutate prompts, tools or affinity')
        con.close()

    def test_compiled_default_and_explicit_review_and_no_primary_fallback(self):
        _state_db(self.home/'state.db', [])
        review = self.chat_call(1, BASE+[{'role':'user','content':REVIEW}], execution_origin='background_review')
        with self.db() as con:
            ins = self.cap.inspector
            self.assertIn('error', ins.compiled_view(self.home/'state.db', con, SID))
            self.assertEqual(ins.compiled_view(self.home/'state.db', con, SID, lane='review')['call_id'], review)
        con.close()
        main = self.chat_call(2, BASE, execution_origin='assistant_tool')
        newest_review = self.chat_call(3, BASE+[{'role':'user','content':REVIEW}], execution_origin='background_review', usage=USAGE)
        with self.db() as con:
            self.assertEqual(ins.context_gauge(con,SID,'telegram',None,2,{})['last_prompt_tokens'],2000)
            for lane, expected in [('main',main),('review',newest_review),('all',newest_review),('main',main)]:
                self.assertEqual(ins.compiled_view(self.home/'state.db',con,SID,lane=lane)['call_id'],expected)
            with self.assertRaises(ValueError):
                ins.compiled_view(self.home/'state.db',con,SID,lane='typo')
            self.assertEqual(ins.newest_extension(con,main),main)
        con.close()

    def test_miss_candidates_filtered_before_budget_and_legacy_verdict_repaired_readonly(self):
        main = self.chat_call(1, BASE, execution_origin='assistant_tool', usage=USAGE)
        for n in range(2,18):
            review = self.chat_call(n,BASE+[{'role':'user','content':REVIEW}],execution_origin='background_review',usage=USAGE)
        # A newer unrelated model family must not be the comparison either.
        self.chat_call(18,BASE,execution_origin='assistant_tool',usage=USAGE,model='claude-sonnet-4')
        current = self.chat_call(19,BASE+[{'role':'user','content':'next turn'}],execution_origin='assistant_tool',usage=USAGE)
        with self.db() as con:
            ins = self.cap.inspector
            miss = ins.explain_miss(con,current,SID,self.t0+190,50000,2)
            self.assertEqual(miss['prev_id'],main)
            self.assertIn('system prompt and messages unchanged',miss['why'])
            first_review = ins.explain_miss(con,'h:turn1:api:2',SID,self.t0+20,50000,2)
            self.assertNotIn('prev_id',first_review)
            wrong = {'prev_id':review,'why':'history rewritten','at':2,'change':{'v':2}}
            con.execute('UPDATE calls SET diverge=? WHERE id=?',(json.dumps(wrong),current))
            con.commit()
            detail = ins.call_detail(con,current,want=('diff',))
            self.assertEqual(detail['diff']['miss']['prev_id'],main)
            self.assertEqual(json.loads(con.execute('SELECT diverge FROM calls WHERE id=?',(current,)).fetchone()[0]),wrong)
        con.close()

    def test_legacy_harness_detection_and_foreground_override(self):
        main = self.chat_call(1,BASE+[{'role':'user','content':'Please inspect memory_notes and goal_manage.'}])
        review = self.chat_call(2,BASE+[{'role':'user','content':REVIEW},{'role':'assistant','content':'done'}])
        quoted = self.chat_call(3,BASE+[{'role':'user','content':'Debug this prompt: '+REVIEW}])
        explicit = self.chat_call(4,BASE+[{'role':'user','content':REVIEW}],execution_origin='assistant_tool')
        with self.db() as con:
            con.execute('UPDATE calls SET execution_origin=NULL WHERE id IN (?,?,?)',(main,review,quoted))
            self.assertEqual(self.cap.inspector.call_lane(con,review),'review')
            for cid in (main,quoted,explicit):
                self.assertNotEqual(self.cap.inspector.call_lane(con,cid),'review')
            tel = self.mt._private('_wiretap_telemetry','telemetry.py')
            rows = [dict(r) for r in con.execute('SELECT * FROM calls')]
            with patch.object(tel,'main_session',return_value=SID):
                tel._decorate(con,rows)
            by_id = {r['id']:r for r in rows}
            self.assertEqual(by_id[review]['lane'],'review')
            self.assertEqual(by_id[main]['lane'],'main')
            self.assertEqual(tel._call_out(con,dict(con.execute('SELECT * FROM calls WHERE id=?',(review,)).fetchone()))['lane'],'review')
        con.close()

    def test_real_hermes_bounded_hook_propagates_origin(self):
        try:
            from hermes_cli.plugins import PluginManager
            from tools.skill_provenance import set_current_write_origin, reset_current_write_origin
        except ImportError:
            self.skipTest('Hermes runtime required for bounded-hook integration')
        manager = PluginManager()
        token = set_current_write_origin('background_review')
        try:
            row = manager._run_hook_callback_bounded(
                'pre_api_request', lambda **kw: self.cap.base_row(kw),
                {'session_id': SID, 'platform': 'discord', 'api_request_id': 'context-check'}, 2.0)
        finally:
            reset_current_write_origin(token)
        self.assertEqual(row['lane'], 'review')
        self.assertEqual(row['execution_origin'], 'background_review')

    def test_api_and_cli_select_reviews_without_changing_default(self):
        from test_wiretap import _load, HERE
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest('FastAPI unavailable')
        import io
        from contextlib import redirect_stdout
        _state_db(self.home/'state.db', [])
        main = self.chat_call(1,BASE,execution_origin='assistant_tool')
        review = self.chat_call(2,BASE+[{'role':'user','content':REVIEW}],execution_origin='background_review')
        self.cap._writer.flush(5)
        api = _load('_review_api', HERE/'dashboard/plugin_api.py')
        app = FastAPI()
        app.include_router(api.router)
        with TestClient(app) as client:
            for lane, expected in [('main',main),('review',review),('all',review)]:
                result = client.get('/inspector/compiled',params={'id':SID,'lane':lane})
                self.assertEqual(result.status_code,200,result.text)
                self.assertEqual(result.json()['call_id'],expected)
            self.assertEqual(client.get('/inspector/compiled',params={'id':SID}).json()['call_id'],main)
            self.assertEqual(client.get('/inspector/compiled',params={'id':SID,'lane':'typo'}).status_code,400)
            rows = client.get('/calls').json()['rows']
            self.assertEqual(next(r for r in rows if r['id']==review)['lane'],'review')
        cli = _load('_review_cli', HERE/'collector/cli.py')
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(['--home',str(self.home),'session','show',SID,'--compiled','--lane','review','--json'])
        self.assertEqual(rc,0)
        self.assertEqual(json.loads(buf.getvalue())['result']['compiled']['call_id'],review)

    def test_telemetry_only_legacy_listing_preserves_stored_comparison_readonly(self):
        cid = self.chat_call(1, BASE, usage=USAGE)
        original = {'prev_id': 'old-call', 'why': 'old diagnostic', 'at': 1}
        with self.db() as con:
            con.execute('UPDATE calls SET diverge=? WHERE id=?', (json.dumps(original), cid))
            con.execute('DROP TABLE wire_calls')
            con.commit()
            con.execute('PRAGMA query_only=ON')
            before = con.total_changes
            schema = list(con.execute('SELECT name, sql FROM sqlite_master ORDER BY name'))
            tel = self.mt._private('_wiretap_telemetry', 'telemetry.py')
            rows = tel.list_calls(con, {}, limit=10)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['id'], cid)
            self.assertEqual(rows[0]['prompt_tokens'], USAGE['prompt_tokens'])
            self.assertEqual(rows[0]['miss'], original['why'])
            self.assertEqual(self.cap.inspector.enrich_miss(con, cid, original), original)
            self.assertEqual(json.loads(con.execute('SELECT diverge FROM calls WHERE id=?', (cid,)).fetchone()[0]), original)
            self.assertEqual(con.total_changes, before)
            self.assertEqual(list(con.execute('SELECT name, sql FROM sqlite_master ORDER BY name')), schema)
        con.close()

    def test_review_classified_with_payload_capture_disabled(self):
        self.cap.SETTINGS['capture_payloads'] = False
        review = self.chat_call(1,BASE,execution_origin='background_review')
        with self.db() as con:
            self.assertEqual(self.cap.inspector.call_lane(con,review),'review')
            self.assertEqual(con.execute('SELECT COUNT(*) FROM wire_calls').fetchone()[0],0)
        con.close()
