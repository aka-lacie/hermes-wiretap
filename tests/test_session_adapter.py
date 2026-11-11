"""Behavior boundaries for optional session enrichment and legacy home discovery."""
import importlib.util
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_schemas as fixtures

HERE = Path(__file__).resolve().parent.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SessionAdapter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ins = fixtures._load_inspector()
        self.wire = self.ins.store.memory_store()
        self.addCleanup(self.wire.close)

    def state(self, message_columns=(), session_columns=(), row=None, session=None):
        path = self.root / 'state.db'
        con = sqlite3.connect(path)
        con.executescript(fixtures.STOCK_SCHEMA)
        for name, sql_type in message_columns:
            con.execute(f'ALTER TABLE messages ADD COLUMN {name} {sql_type}')
        for name, sql_type in session_columns:
            con.execute(f'ALTER TABLE sessions ADD COLUMN {name} {sql_type}')
        fixtures._insert(con, 'sessions', {'id': 's', 'source': 'cli', 'started_at': 1, **(session or {})})
        fixtures._insert(con, 'messages', {'id': 1, 'session_id': 's', 'role': 'user', 'timestamp': 2,
                                         'content': 'ordinary user words', **(row or {})})
        con.commit()
        con.close()
        return path

    def view(self, path, inspector=None):
        return (inspector or self.ins).session_view(path, self.wire, 's', None, 20, False)

    def test_stock_install_without_adapter_imports_and_reads(self):
        # A physically absent extensions directory, not merely an enabled=False branch.
        collector = self.root / 'stock-only' / 'collector'
        collector.mkdir(parents=True)
        shutil.copyfile(HERE / 'collector' / 'inspector.py', collector / 'inspector.py')
        ins = load('_wiretap_no_session_extension', collector / 'inspector.py')
        path = self.state(session={'parent_session_id': 'parent'})
        before = path.read_bytes()
        result = self.view(path, ins)
        self.assertEqual(result['rows'][0]['kind'], 'parent')
        self.assertEqual(result['session']['lineage']['parent'], 'parent')
        self.assertNotIn('typed', result['rows'][0])
        self.assertEqual(ins.full_row(path, self.wire, 1)['row']['content'], 'ordinary user words')
        self.assertEqual(path.read_bytes(), before, 'read-only inspection must not migrate the state store')

    def test_sender_only_partial_schema_overrides_misleading_text(self):
        path = self.state(message_columns=[('sender_kind', 'TEXT')],
                          row={'sender_kind': 'human', 'content': '[ASYNC DELEGATION BATCH COMPLETE — deleg_deadbeef] not a completion'})
        result = self.view(path)['rows'][0]
        self.assertEqual(result['kind'], 'user')
        self.assertTrue(result['typed'])
        self.assertNotIn('parts', result)

    def test_parts_only_partial_schema_supplies_authorship_and_identity(self):
        parts = [fixtures._human('only the authored text', '1567000000000000999'),
                 {'type': 'injection', 'kind': 'context', 'text': 'added context'}]
        path = self.state(message_columns=[('parts_json', 'TEXT')], row={'content': '', 'parts_json': json.dumps(parts)})
        row = self.view(path)['rows'][0]
        self.assertEqual((row['kind'], row['content'], row['ref']), ('user', 'only the authored text', '1567000000000000999'))
        self.assertEqual(row['injections'], [{'kind': 'context', 'len': 13}])
        detail = self.ins.full_row(path, self.wire, 1)
        self.assertEqual(detail['plain'], 'only the authored text')
        self.assertEqual(detail['row']['parts_json'], parts)

    def test_lineage_only_partial_schema_labels_child_assignment(self):
        path = self.state(session_columns=[('lineage_kind', 'TEXT'), ('depth', 'INTEGER'), ('root_session_id', 'TEXT')],
                          session={'lineage_kind': 'delegate', 'depth': 2, 'root_session_id': 'root'})
        view = self.view(path)
        self.assertEqual(view['rows'][0]['kind'], 'parent')
        self.assertEqual(view['session']['lineage'], {'kind': 'delegate', 'depth': 2, 'root': 'root', 'parent': None, 'typed': True})
        self.assertEqual(self.ins.sessions_list(path, '', 20, '')[0]['lineage'], view['session']['lineage'])

    def test_malformed_parts_fall_back_to_stock_heuristics(self):
        path = self.state(message_columns=[('parts_json', 'TEXT')],
                          row={'content': '[ASYNC DELEGATION BATCH COMPLETE — deleg_deadbeef] finished', 'parts_json': '[broken'})
        row = self.view(path)['rows'][0]
        self.assertEqual((row['kind'], row['ref']), ('subagent', 'deleg_deadbeef'))
        self.assertNotIn('typed', row)
        self.assertNotIn('parts', row)

    def test_invalid_part_entries_are_ignored(self):
        parts = [None, 'invalid', {'type': 'future_part', 'text': 'not authored'}, fixtures._human('real authored text', '123456789012345678')]
        path = self.state(message_columns=[('parts_json', 'TEXT')], row={'content': '', 'parts_json': json.dumps(parts)})
        detail = self.ins.full_row(path, self.wire, 1)
        self.assertEqual(detail['plain'], 'real authored text')
        self.assertEqual(len(detail['parts']), 1)

    def test_actual_hermes_session_store_is_read_without_mutation(self):
        path = self.root / 'actual-state.db'
        with mock.patch.dict(os.environ, {'HERMES_HOME': str(self.root / 'isolated-profile')}):
            try:
                from hermes_state import SessionDB
            except ImportError as exc:
                self.skipTest(f'Hermes source/dependency unavailable: {exc}')
            db = SessionDB(db_path=path)
            try:
                db.create_session('s', 'cli')
                db.append_message('s', 'user', 'read this actual stock transcript')
            finally:
                db.close()
        before = path.read_bytes()
        view = self.view(path)
        self.assertEqual(view['rows'][0]['content'], 'read this actual stock transcript')
        self.assertEqual(view['session']['source'], 'cli')
        self.assertNotIn('typed', view['rows'][0])
        self.assertEqual(path.read_bytes(), before)


class LegacyHomeDiscovery(unittest.TestCase):
    def test_cli_home_fallback_and_explicit_database_precedence(self):
        cli = load('_wiretap_adapter_cli_test', HERE / 'collector' / 'cli.py')
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            legacy = home / 'plugin-data' / 'model-telemetry' / 'telemetry.db'
            current = home / 'plugin-data' / 'wiretap' / 'telemetry.db'
            legacy.parent.mkdir(parents=True)
            legacy.touch()
            # Resolve only: opening or changing either telemetry DB is not part of discovery.
            with mock.patch.dict(os.environ, {'TELEMETRY_DB': str(home / 'wrong.db')}, clear=False):
                for explicit, expected in ((None, legacy), (str(home / 'explicit.db'), home / 'explicit.db')):
                    args = cli.build_parser().parse_args(['--home', str(home), 'status'])
                    args.wt_telemetry_db = explicit
                    ctx = cli.Ctx(args)
                    self.assertEqual(ctx.tdb, expected)
                    self.assertFalse(current.exists())
                    ctx.close()
                current.parent.mkdir(parents=True)
                current.touch()
                ctx = cli.Ctx(cli.build_parser().parse_args(['--home', str(home), 'status']))
                self.assertEqual(ctx.tdb, current, 'new slug wins once its DB exists')
                ctx.close()


if __name__ == '__main__':
    unittest.main()
