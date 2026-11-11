"""Divergence-centred evidence: real request blobs, bounded windows, no base64 dumps."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent.parent


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE/relative)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class FirstDivergence(unittest.TestCase):
    def test_late_text_edit_insert_delete_and_unicode_are_centered(self):
        f = load('_wiretap_window_test','collector/forensics.py')
        for old,new,expected in [('shared '*90+'old tail','shared '*90+'new tail','new'),
                                  ('same description','same description plus metadata',' plus metadata'),
                                  ('same description plus metadata','same description',''),
                                  ('first\n雪☃ old','first\n雪☃ new','new')]:
            with self.subTest(current=new[-30:]):
                result=f.describe({'content':old},{'content':new},'messages[26]')
                self.assertEqual(result['path'],'messages[26].content')
                self.assertEqual(result['after']['change'],expected)
                self.assertLessEqual(len(result['before']['prefix']),80)
                self.assertLessEqual(len(result['after']['suffix']),80)
                self.assertLess(len(json.dumps(result)),1800)
        late=f.describe('identical '*100+'before','identical '*100+'after','value')
        self.assertGreater(late['offset'],240)
        self.assertGreater(late['before']['omitted_prefix'],0)
        self.assertEqual(late['before']['change'],'before')
        self.assertEqual(late['after']['change'],'after')

    def test_image_eviction_is_structural_and_never_exposes_encoded_payload(self):
        f = load('_wiretap_media_test','collector/forensics.py')
        payload='ABCD'*106000
        old={'role':'user','content':[{'type':'tool_result','content':[
            {'type':'text','text':'Image loaded into your context. Same boilerplate.'},
            {'type':'image','source':{'type':'base64','media_type':'image/png','data':payload}}]}]}
        new={'role':'user','content':[{'type':'tool_result','content':[
            {'type':'text','text':'Image loaded into your context. Same boilerplate.'}]}]}
        result=f.describe(old,new,'messages[26]')
        self.assertEqual(result['path'],'messages[26].content[0].content[1]')
        self.assertIn('1 image removed',result['summary'])
        self.assertIn('424,000 encoded payload chars removed',result['summary'])
        encoded=json.dumps(result)
        self.assertNotIn('ABCD'*8,encoded)
        self.assertLess(len(encoded),1800)
        self.assertEqual(result['after']['change'],'[absent]')

    def test_actual_legacy_call_api_upgrades_identical_heads_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'wiretap.db'
            tel=load('_wiretap_forensic_api_test','collector/telemetry.py')
            st,ins=tel.store,tel.inspector
            con=st.connect(path)
            st.init(con)
            before='Stable public tool description. '*12
            after=before+' Runtime serial: 7.'
            now=time.time()
            for cid,description,ts in [('previous',before,now-5),('current',after,now-2)]:
                body={'model':'demo-model','tools':[{'type':'function','function':{'name':'read_file','description':description}}],
                      'messages':[{'role':'user','content':'Compare the request.'}]}
                ref=ins.itemize(con,json.dumps(body))
                st.upsert(con,dict(id=cid,session_id='demo-session',started=ts,status=200,source='hermes',req_down=json.dumps(ref)),'wire_calls')
                st.upsert(con,dict(id=cid,session_id='demo-session',started=ts,status=200,source='hermes',
                                  provider='demo-provider',model='demo-model',prompt_tokens=50000,hit_pct=2),'calls')
            miss=ins.explain_miss(con,'current','demo-session',now-2,50000,2)
            self.assertEqual(miss['change']['path'],'tools[0].function.description')
            self.assertIn('Runtime serial',miss['change']['after']['change'])
            legacy={k:v for k,v in miss.items() if k!='change'}
            legacy['prev_head']=legacy['cur_head']=before[:240]
            st.upsert(con,dict(id='current',diverge=json.dumps(legacy)),'calls')
            con.commit()
            try:
                with patch.object(tel,'DB_PATH',path), patch.object(tel,'STATE_DB',Path(tmp)/'absent.db'):
                    result=tel.api_calls({'hours':['24']})
                row=next(r for r in result['rows'] if r['id']=='current')
                upgraded=json.loads(row['diverge'])
                self.assertEqual(upgraded['change']['after']['change'],' Runtime serial: 7.')
                self.assertEqual(json.loads(con.execute("SELECT diverge FROM calls WHERE id='current'").fetchone()[0]),legacy)
                detail=ins.call_detail(con,'current',want=('diff',))
                self.assertEqual(detail['diff']['miss']['change'],upgraded['change'])
            finally:
                con.close()
