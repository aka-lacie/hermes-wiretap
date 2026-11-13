"""Agent-facing budgets, cursor/output contracts and routing CLI integration (isolated stores only)."""
import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cli as fixtures


class WiretapAX(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tdb, self.sdb = Path(self.tmp.name) / "telemetry.db", Path(self.tmp.name) / "state.db"
        fixtures.build_store(self.tdb)
        fixtures.build_state(self.sdb, time.time() - 600)
        self.cli = fixtures._load("_mt_ax_cli", "collector/cli.py")

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--telemetry-db", str(self.tdb), "--state-db", str(self.sdb), *args]
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code = self.cli.main(argv)
            except SystemExit as e:
                code = e.code
        return code, stdout.getvalue(), stderr.getvalue()

    def js(self, *args):
        code, text, err = self.invoke(*args, "--json")
        self.assertEqual(code, 0, text + err)
        self.assertEqual(err, "")
        return json.loads(text)

    def long_request(self, count=500):
        ins = self.cli._sibling("inspector")
        con = sqlite3.connect(self.tdb)
        con.row_factory = sqlite3.Row
        body = {"model": "claude-opus-5-5", "system": "SOUL", "messages": [
            {"role": "user", "content": f"message {i}: " + "long context " * 30} for i in range(count)]}
        ref = json.dumps(ins.itemize(con, json.dumps(body)))
        con.execute("UPDATE wire_calls SET req_down=?, req_hermes=?, req_up=? WHERE id='c_opus'", (ref, ref, ref))
        con.commit()
        con.close()
        return body

    def test_request_budget_slice_full_and_raw_item(self):
        body = self.long_request()
        doc = self.js("call", "show", "c_opus", "--request", "--diff")
        self.assertLess(len(json.dumps(doc)), 18000)
        for layer in ("hermes", "wire", "upstream"):
            r = doc["result"][layer + "_request_json"]
            self.assertEqual(r["total"], 500)
            self.assertEqual([i["i"] for i in r["items"]], [0, 497, 498, 499])
            self.assertTrue(r["truncated"])
            self.assertEqual(r["next_items"], "1:5")
            self.assertEqual(r["n_items"], 500)
        doc = self.js("call", "show", "c_opus", "--request", "--items", "5:8", "--item", "5")["result"]
        self.assertEqual([i["i"] for i in doc["wire_request_json"]["items"]], [5, 6, 7])
        self.assertEqual(doc["wire_request_item"], body["messages"][5])
        full = self.js("call", "show", "c_opus", "--request", "--full")["result"]
        self.assertEqual(full["wire_request_json"], body)
        tail = self.js("call", "show", "c_opus", "--request", "--items=-2:")["result"]
        self.assertEqual([i["i"] for i in tail["wire_request_json"]["items"]], [498, 499])
        text = self.invoke("call", "show", "c_opus", "--request")[1]
        self.assertIn("showing 4 of 500", text)
        self.assertIn("next --items 1:5", text)

    def test_compiled_limit_continuation_and_full(self):
        first = self.js("session", "show", fixtures.CODEX_SID, "--compiled", "--limit", "2")["result"]["compiled"]
        self.assertEqual(len(first["items"]), 2)
        self.assertEqual(first["total"], 4)
        self.assertTrue(first["truncated"])
        self.assertEqual(first["next_items"], "2:4")
        second = self.js("session", "show", fixtures.CODEX_SID, "--compiled", "--cursor", first["next_cursor"])["result"]["compiled"]
        self.assertEqual([i["i"] for i in second["items"]], [2, 3])
        self.assertFalse(second["has_more"])
        full = self.js("session", "show", fixtures.CODEX_SID, "--compiled", "--full")["result"]["compiled"]
        self.assertEqual(len(full["items"]), 4)
        self.assertFalse(full["truncated"])

    def test_compiled_large_session_is_bounded(self):
        self.long_request()
        # Explicitly make the long request newest before the first compiled read (memoization follows capture revisions).
        con = sqlite3.connect(self.tdb)
        con.execute("UPDATE wire_calls SET started=? WHERE id='c_opus'", (time.time(),))
        con.execute("UPDATE calls SET started=? WHERE id='c_opus'", (time.time(),))
        con.commit()
        con.close()
        compiled = self.js("session", "show", "s_stock", "--compiled", "--limit", "2")["result"]["compiled"]
        self.assertEqual(compiled["total"], 500)
        self.assertEqual(len(compiled["items"]), 2)
        self.assertLess(len(json.dumps(compiled)), 12000)

    def test_calls_cursor_total_and_jsonl_stderr_metadata(self):
        first = self.js("calls", "list", "--limit", "2")
        self.assertEqual(len(first["results"]), 2)
        self.assertEqual(first["page"]["total"], 5)
        self.assertTrue(first["page"]["has_more"])
        ids = [r["id"] for r in first["results"]]
        cursor = first["page"]["next_cursor"]
        while cursor:
            page = self.js("calls", "list", "--limit", "2", "--cursor", cursor)
            ids.extend(r["id"] for r in page["results"])
            self.assertEqual(page["page"]["total"], 5)
            cursor = page["page"]["next_cursor"]
        self.assertEqual(len(ids), 5)
        self.assertEqual(len(set(ids)), 5)
        code, out, err = self.invoke("calls", "list", "--limit", "2", "--jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 2)
        self.assertTrue(all("id" in json.loads(line) for line in out.splitlines()))
        self.assertEqual(json.loads(err)["page"], first["page"])
        code, out, err = self.invoke("calls", "list", "--provider", "absent", "--jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(out, "")
        self.assertEqual(json.loads(err)["page"]["total"], 0)

    def test_routing_filters_and_credential_cost_breakdown(self):
        con = sqlite3.connect(self.tdb)
        con.execute("UPDATE calls SET auth_label='account-A',auth_key='fp1234',project='project-A',upstream_provider='claude' WHERE id='c_opus'")
        con.commit()
        con.close()
        args = ("--provider", "relay-claude", "--credential", "account-A", "--project", "project-A", "--upstream", "claude", "--status", "200")
        rows = self.js("calls", "list", *args)["results"]
        self.assertEqual([r["id"] for r in rows], ["c_opus"])
        self.assertEqual(self.js("calls", "list", "--credential", "fp1234")["results"][0]["id"], "c_opus")
        self.assertEqual(self.js("calls", "list", "--status", "429")["results"], [])
        cost = self.js("costs", *args, "--group-by", "credential")["result"]
        self.assertEqual(cost["total"]["calls"], 1)
        self.assertEqual(cost["rows"][0]["auth_label"], "account-A")
        self.assertEqual(cost["rows"][0]["auth_key"], "fp1234")

    def test_search_keyset_pagination_and_jsonl_metadata(self):
        all_hits = self.js("search", "i", "--request", "--limit", "100")["result"]
        first = self.js("search", "i", "--request", "--limit", "1")["result"]
        self.assertGreater(first["total"], 1)
        hits = list(first["results"])
        cursor = first["next_cursor"]
        while cursor:
            page = self.js("search", "i", "--request", "--limit", "1", "--cursor", cursor)["result"]
            hits.extend(page["results"])
            self.assertEqual(page["total"], first["total"])
            cursor = page["next_cursor"]
        self.assertEqual(hits, all_hits["results"])
        code, out, err = self.invoke("search", "i", "--request", "--limit", "1", "--jsonl")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertEqual(json.loads(err)["page"]["next_cursor"], first["next_cursor"])
        self.assertIn("scanned", json.loads(err)["page"])

    def test_fields_projection_and_invalid_paths(self):
        result = self.js("call", "show", "c_opus", "--request", "--diff", "--fields", "id,requested_model.wire,diff.miss")["result"]
        self.assertEqual(set(result), {"id", "requested_model", "diff"})
        self.assertEqual(result["requested_model"], {"wire": "claude-opus-5-5"})
        rows = self.js("calls", "list", "--fields", "id,model")["results"]
        self.assertTrue(all(set(r) == {"id", "model"} for r in rows))
        for args in [("call", "show", "c_opus", "--fields", "typo"),
                     ("calls", "list", "--fields", "id,missing"),
                     ("calls", "list", "--provider", "absent", "--fields", "id..model"),
                     ("calls", "list", "--fields", ""),
                     ("call", "show", "c_opus", "--fields", "id..model")]:
            code, out, err = self.invoke(*args, "--json")
            self.assertEqual(code, 1)
            self.assertIn("--fields", json.loads(out)["error"])
        self.assertEqual(self.invoke("calls", "list", "--fields", "id")[0], 1)

    def test_argument_errors_are_json_and_nonzero(self):
        for args in [("calls", "list", "--limit", "-1"), ("calls", "list", "--limit", "oops"),
                     ("call", "show"), ("nonsense",), ("calls", "list", "--typo"),
                     ("call", "show", "c_opus", "--request", "--items", "foo"),
                     ("session", "show", "s_stock", "--layer", "bad")]:
            code, out, err = self.invoke(*args, "--json")
            self.assertEqual(code, 2, out + err)
            self.assertEqual(err, "")
            self.assertEqual(json.loads(out)["error_type"], "argument")
        for args in [("calls", "list", "--cursor", "not-base64"),
                     ("search", "i", "--cursor", "not-base64"),
                     ("call", "show", "c_opus", "--request", "--items", "8:2"),
                     ("session", "show", "s_stock", "--items", "1:2"),
                     ("call", "show", "c_opus", "--request", "--full", "--items", "1:2")]:
            code, out, err = self.invoke(*args, "--json")
            self.assertEqual(code, 1, out + err)
            self.assertIn("error", json.loads(out))
        code, out, err = self.invoke("calls", "list", "--limit", "bad", "--jsonl")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error_type"], "argument")

    def test_standalone_parser_error_and_no_hermes_dependency(self):
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(HERE / "bin/wiretap"),
                            "calls", "list", "--limit", "bad", "--json"], capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 2)
        self.assertEqual(p.stderr, "")
        self.assertEqual(json.loads(p.stdout)["error_type"], "argument")

    def test_registered_parent_parser_errors_and_host_isolation(self):
        import argparse
        root = argparse.ArgumentParser(prog="hermes")
        sub = root.add_subparsers(dest="command", required=True)
        wt = sub.add_parser("wiretap")
        self.cli.build_parser(wt)
        sub.add_parser("other")
        for argv in [["wiretap", "--json"], ["wiretap", "calls", "list", "--typo", "--json"],
                     ["wiretap", "--json", "calls", "list", "--typo"],
                     ["wiretap", "calls", "list", "--limit", "bad", "--json"]]:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
                root.parse_args(argv)
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(json.loads(out.getvalue())["error_type"], "argument")
        # Other host routes keep their existing human parser/error behavior.
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
            root.parse_args(["other", "--typo", "--json"])
        self.assertEqual(out.getvalue(), "")
        self.assertIn("unrecognized arguments", err.getvalue())

    def test_parser_errors_scrub_entire_document(self):
        secret = "sk-proj-" + "synthetic1234567890" * 3
        code, out, err = self.invoke("call", secret, "--json")
        self.assertEqual(code, 2)
        self.assertNotIn(secret, out + err)
        self.assertNotIn("synthetic1234567890", out + err)
        self.assertEqual(json.loads(out)["command"], "call")

    def test_search_cursor_keeps_repeated_same_name_tool_calls(self):
        con = sqlite3.connect(self.tdb)
        resp = json.loads(con.execute("SELECT resp FROM wire_calls WHERE id='c_clean'").fetchone()[0])
        resp["tool_calls"] = [{"name": "read_file", "id": str(i), "args": {"path": "needle.py"}} for i in range(3)]
        con.execute("UPDATE wire_calls SET resp=? WHERE id='c_clean'", (json.dumps(resp),))
        con.commit()
        con.close()
        hits, cursor = [], None
        for i in range(3):
            args = ("--cursor", cursor) if cursor else ()
            page = self.js("search", "needle.py", "--response", "--limit", "1", *args)["result"]
            hits.extend(page["results"])
            self.assertEqual(page["total"], 3)
            cursor = page["next_cursor"]
        self.assertEqual(len(hits), 3)
        self.assertEqual(len({h["match_index"] for h in hits}), 3)
        self.assertIsNone(cursor)

    def test_empty_search_and_item_selection_edges(self):
        r = self.js("search", "")["result"]
        self.assertEqual(r["total"], 0)
        self.assertFalse(r["has_more"])
        self.assertIsNone(r["next_cursor"])
        ins = self.cli._sibling("inspector")
        self.assertEqual(ins.item_selection(0, 4)[1]["shown"], 0)
        self.assertEqual(ins.item_selection(10, 4, (20, None))[0], [])
        self.assertEqual(ins.item_selection(10, 4, (-2, None))[0], [8, 9])
        self.assertEqual(ins.item_selection(10, 4, (None, 2))[0], [0, 1])


if __name__ == "__main__":
    unittest.main()
