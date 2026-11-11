"""Routing filters, credential grouping and bounded/keyset CLI calls pages (stdlib only)."""
import base64
import importlib.util
import json
import sqlite3
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

HERE = Path(__file__).resolve().parent.parent


def load_telemetry():
    name = "_wiretap_ax_test"
    spec = importlib.util.spec_from_file_location(name, HERE / "collector/telemetry.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def cursor_for(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


class TelemetryAX(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tel = load_telemetry()

    def make_db(self, *, routing=("auth_label", "auth_key", "upstream_provider", "project"), signals=True):
        con = sqlite3.connect(":memory:")
        con.row_factory = sqlite3.Row
        self.addCleanup(con.close)
        columns = ["id TEXT PRIMARY KEY", "started REAL", "family TEXT", "provider TEXT", "model TEXT",
                   "session_id TEXT", "status INTEGER", "nfail INTEGER", "hit_pct REAL", "prompt_tokens INTEGER",
                   "cached_tokens INTEGER", "cache_write_tokens INTEGER", "output_tokens INTEGER",
                   "thinking_tokens INTEGER", "cost_usd REAL", "cost_equiv_usd REAL", "attempt_detail TEXT"]
        columns += [x + " TEXT" for x in routing]
        if signals:
            columns.append("signals TEXT")
        con.execute("CREATE TABLE calls (" + ", ".join(columns) + ")")
        con.execute("CREATE INDEX calls_started ON calls(started)")
        return con

    def put(self, con, cid, started: float | None = 1, **kw: Any):
        row = dict(id=cid, started=started, family="claude", provider="router", model="model-a", session_id="s1",
                   status=200, nfail=0, hit_pct=90, prompt_tokens=100, cached_tokens=90, cache_write_tokens=0,
                   output_tokens=10, thinking_tokens=0, cost_usd=0.25, cost_equiv_usd=0.5)
        row.update(kw)
        if "signals" in self.tel.store.columns(con, "calls") and "signals" not in kw:
            row["signals"] = '{"v":1,"refusal":false}'
        con.execute(f"INSERT INTO calls ({','.join(row)}) VALUES ({','.join('?' for _ in row)})", list(row.values()))

    def ids(self, con, f):
        return [r["id"] for r in self.tel.list_calls(con, f)]

    def test_routing_filters_are_exact_and_combined(self):
        con = self.make_db()
        self.put(con, "a", auth_label="work", auth_key="A123", upstream_provider="vertex", project="p1", status=429)
        self.put(con, "b", auth_label="work-extra", auth_key="A1234", upstream_provider="vertex-extra", project="p10")
        self.put(con, "c", auth_label="work", auth_key="B456", upstream_provider="claude", project="p1")
        self.assertEqual(set(self.ids(con, {"credential": "work"})), {"a", "c"})
        for f in ({"credential": "A123"}, {"upstream": "vertex"}, {"status": 429},
                  {"credential": "work", "project": "p1", "upstream": "vertex", "status": "429"}):
            with self.subTest(f=f):
                self.assertEqual(self.ids(con, f), ["a"])
        self.assertEqual(set(self.ids(con, {"project": "p1"})), {"a", "c"})
        self.assertEqual(self.ids(con, {"credential": "work", "status": 400}), [])

    def test_filters_parameterize_untrusted_values(self):
        con = self.make_db()
        token = "x' OR 1=1 --"
        self.put(con, "literal", auth_label=token, auth_key=token, project=token, upstream_provider=token)
        self.put(con, "other", auth_label="other")
        for field in ("credential", "project", "upstream"):
            f = {field: token}
            where, args = self.tel.call_filters(f, set(self.tel.store.columns(con, "calls")))
            self.assertNotIn(token, " ".join(where))
            self.assertIn(token, args)
            self.assertEqual(self.ids(con, f), ["literal"])
        for bad in ("200 OR 1=1", 200.5, True, ""):
            with self.subTest(status=bad), self.assertRaisesRegex(ValueError, "status.*integer"):
                self.tel.call_filters({"status": bad}, {"status"})
        self.put(con, "zero", status=0)
        self.assertEqual(self.ids(con, {"status": 0}), ["zero"])

    def test_missing_routing_columns_do_not_broaden_filters(self):
        con = self.make_db(routing=())
        self.put(con, "a")
        for field in ("credential", "upstream", "project"):
            self.assertEqual(self.ids(con, {field: "missing"}), [])
        con = self.make_db(routing=("auth_key",))
        self.put(con, "fingerprint", auth_key="A123")
        self.assertEqual(self.ids(con, {"credential": "A123"}), ["fingerprint"])

    def test_credential_costs_group_real_label_fingerprint_pairs(self):
        con = self.make_db()
        self.put(con, "a", auth_label="work", auth_key="A123")
        self.put(con, "b", auth_label="work", auth_key="A123")
        self.put(con, "c", auth_label="work", auth_key="B456")
        self.put(con, "d", auth_label="", auth_key="C789")
        self.put(con, "e")
        result = self.tel.costs(con, {}, by="credential")
        self.assertEqual(result["by"], "credential")
        rows = {(r["auth_label"], r["auth_key"]): r for r in result["rows"]}
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows["work", "A123"]["calls"], 2)
        self.assertEqual(rows["work", "A123"]["cost_usd"], 0.5)
        self.assertEqual(rows["work", "A123"]["hit_pct"], 90)
        self.assertEqual(rows["", "C789"]["key"], "C789")
        self.assertEqual(rows["", ""]["key"], "")
        self.assertEqual(result["total"]["calls"], 5)
        result = self.tel.costs(con, {"credential": "B456"}, by="credential")
        self.assertEqual(result["total"]["calls"], 1)
        self.assertEqual(result["rows"][0]["auth_key"], "B456")

    def test_credential_costs_support_each_missing_column_combination(self):
        for fields in ((), ("auth_label",), ("auth_key",)):
            with self.subTest(fields=fields):
                con = self.make_db(routing=fields)
                values: dict[str, Any] = {x: "work" for x in fields}
                self.put(con, "a", **values)
                self.put(con, "b", **values)
                result = self.tel.costs(con, {}, by="credential")
                self.assertEqual(result["by"], "credential")
                self.assertEqual(len(result["rows"]), 1)
                self.assertEqual(result["rows"][0]["calls"], 2)
                self.assertEqual(result["rows"][0]["key"], "work" if fields else "")

    def test_pages_cover_ties_zero_negative_and_null_timestamps(self):
        con = self.make_db()
        for cid, started in (("a", 20), ("z", 20), ("b", 10), ("c", 0), ("d", -1), ("n1", None), ("n2", None)):
            self.put(con, cid, started)
        seen, cursor = [], None
        expected = ["z", "a", "b", "c", "d", "n2", "n1"]
        for index in range(7):
            page = self.tel.list_calls_page(con, {}, limit=1, cursor=cursor)
            self.assertEqual(set(page), {"results", "total", "has_more", "next_cursor"})
            self.assertEqual(page["total"], 7)
            self.assertEqual(page["has_more"], index < 6)
            seen += [r["id"] for r in page["results"]]
            cursor = page["next_cursor"]
            if cursor:
                self.assertRegex(cursor, r"^[A-Za-z0-9_-]+$")
                self.assertEqual(self.tel._calls_cursor_decode(cursor)["id"], seen[-1])
        self.assertEqual(seen, expected)
        self.assertIsNone(cursor)
        self.assertIsInstance(self.tel.list_calls(con, {}), list)
        self.assertEqual(self.tel.list_calls_page(con, {}, 100)["has_more"], False)

    def test_total_is_filter_total_not_remaining_and_cursor_can_outlive_row(self):
        con = self.make_db()
        for n in range(6):
            self.put(con, str(n), n, auth_key="A123" if n % 2 else "B456")
        f = {"credential": "A123", "status": 200}
        first = self.tel.list_calls_page(con, f, 1)
        self.assertEqual(first["total"], 3)
        self.assertEqual(first["results"][0]["id"], "5")
        con.execute("DELETE FROM calls WHERE id='5'")
        self.put(con, "new", 10, auth_key="A123")
        second = self.tel.list_calls_page(con, f, 1, first["next_cursor"])
        self.assertEqual(second["total"], 3)
        self.assertEqual(second["results"][0]["id"], "3")
        final = self.tel.list_calls_page(con, f, 1, second["next_cursor"])
        self.assertEqual(final["total"], 3)
        self.assertEqual(final["results"][0]["id"], "1")
        self.assertFalse(final["has_more"])
        self.assertIsNone(final["next_cursor"])
        exhausted = self.tel.list_calls_page(con, f, cursor=cursor_for({"started": -100, "id": "missing"}))
        self.assertEqual(exhausted["total"], 3)
        self.assertEqual(exhausted["results"], [])
        self.assertIsNone(exhausted["next_cursor"])

    def test_empty_filtered_page(self):
        page = self.tel.list_calls_page(self.make_db(), {})
        self.assertEqual(page, {"results": [], "total": 0, "has_more": False, "next_cursor": None})

    def test_normal_page_only_formats_returned_rows_and_queries_limit_plus_one(self):
        con = self.make_db()
        for n in range(100):
            self.put(con, str(n), n)
        queries = []
        con.set_trace_callback(queries.append)
        with mock.patch.object(self.tel, "_call_out", wraps=self.tel._call_out) as output:
            page = self.tel.list_calls_page(con, {}, 2)
        self.assertEqual(output.call_count, 2)
        self.assertEqual(page["total"], 100)
        row_queries = [q for q in queries if q.startswith("SELECT * FROM calls")]
        self.assertEqual(len(row_queries), 1)
        self.assertIn("ORDER BY started DESC, id DESC LIMIT 3", row_queries[0])
        self.assertFalse(any("OFFSET" in q for q in queries))

    def test_invalid_cursors_and_limits_raise_descriptive_value_errors(self):
        con = self.make_db()
        malformed = ["", "not base64!", "a", "====", [], 123]
        malformed += [cursor_for(v) for v in (None, [], {}, {"started": 1}, {"started": 1, "id": "a", "extra": 1},
                      {"started": "1", "id": "a"}, {"started": True, "id": "a"}, {"started": [], "id": "a"},
                      {"started": float("nan"), "id": "a"}, {"started": float("inf"), "id": "a"},
                      {"started": 1, "id": ""}, {"started": 1, "id": 1})]
        malformed += [base64.urlsafe_b64encode(b"\xff").decode(), "A" * 17000]
        for cursor in malformed:
            with self.subTest(cursor=str(cursor)[:80]), self.assertRaisesRegex(ValueError, "invalid calls cursor"):
                self.tel.list_calls_page(con, {}, cursor=cursor)
        for limit in (0, -1, 1.5, "2", True, None):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "limit.*positive integer"):
                self.tel.list_calls_page(con, {}, limit=limit)

    def test_refusal_pages_match_existing_stored_and_computed_rules(self):
        con = self.make_db()
        self.put(con, "stored", 5, signals='{"v":1,"refusal":true}', auth_key="A123")
        self.put(con, "computed", 4, signals=None, auth_key="A123")
        self.put(con, "clean", 3, signals=None, auth_key="A123")
        self.put(con, "stored-clean", 2, signals='{"v":1,"refusal":false}', auth_key="A123")
        self.put(con, "null-time", None, signals=None, auth_key="A123")
        self.put(con, "other-key", 6, signals='{"v":1,"refusal":true}', auth_key="B456")
        f = {"refusals": True, "credential": "A123"}
        def compute(_con, cid):
            return {"v": 1, "refusal": cid in {"computed", "null-time", "stored-clean"}}
        with mock.patch.object(self.tel.store, "compute_signals", side_effect=compute) as computation:
            legacy_ids = self.ids(con, f)
            first = self.tel.list_calls_page(con, f, 1)
            second = self.tel.list_calls_page(con, f, 1, first["next_cursor"])
            third = self.tel.list_calls_page(con, f, 1, second["next_cursor"])
        self.assertEqual(legacy_ids, ["stored", "computed", "null-time"])
        self.assertEqual([p["results"][0]["id"] for p in (first, second, third)], legacy_ids)
        self.assertEqual([p["total"] for p in (first, second, third)], [3, 3, 3])
        self.assertEqual(first["results"][0]["signals_source"], "stored")
        self.assertEqual(second["results"][0]["signals_source"], "computed")
        self.assertFalse(third["has_more"])
        self.assertNotIn("stored-clean", [call.args[1] for call in computation.call_args_list])

    def test_refusal_pages_without_signals_column_compute_all_candidates(self):
        con = self.make_db(signals=False)
        self.put(con, "z", None)
        self.put(con, "y", None)
        self.put(con, "x", None)
        self.put(con, "clean", 1)
        with mock.patch.object(self.tel.store, "compute_signals", side_effect=lambda _con, cid: {"v": 1, "refusal": cid != "clean"}):
            page = self.tel.list_calls_page(con, {"refusals": True}, 2)
            self.assertEqual([r["id"] for r in page["results"]], ["z", "y"])
            self.assertEqual(page["total"], 3)
            last = self.tel.list_calls_page(con, {"refusals": True}, 2, page["next_cursor"])
            self.assertEqual([r["id"] for r in last["results"]], ["x"])
            self.assertEqual(last["total"], 3)
            self.assertFalse(last["has_more"])

    def test_real_refusal_signal_computation_for_unbackfilled_and_old_stores(self):
        for signals in (True, False):
            with self.subTest(signals_column=signals):
                con = self.make_db(signals=signals)
                con.execute("CREATE TABLE wire_calls (id TEXT PRIMARY KEY, resp_raw TEXT, resp TEXT)")
                self.put(con, "safety", 4, **({"signals": None} if signals else {}))
                self.put(con, "policy-error", 3, status=400, attempt_detail=json.dumps([
                    {"status": 400, "message": "Output blocked by content filtering policy"}]),
                    **({"signals": None} if signals else {}))
                self.put(con, "clean", 5, **({"signals": None} if signals else {}))
                con.execute("INSERT INTO wire_calls VALUES (?, NULL, ?)",
                            ("safety", json.dumps({"text": "", "finish": "SAFETY"})))
                con.execute("INSERT INTO wire_calls VALUES (?, NULL, ?)",
                            ("clean", json.dumps({"text": "All good.", "finish": "stop"})))
                first = self.tel.list_calls_page(con, {"refusals": True}, 1)
                self.assertEqual(first["total"], 2)
                self.assertEqual(first["results"][0]["id"], "safety")
                self.assertEqual(first["results"][0]["signals_source"], "computed")
                last = self.tel.list_calls_page(con, {"refusals": True}, 1, first["next_cursor"])
                self.assertEqual(last["total"], 2)
                self.assertEqual(last["results"][0]["id"], "policy-error")
                self.assertFalse(last["has_more"])
                if signals:
                    self.assertIsNone(con.execute("SELECT signals FROM calls WHERE id='safety'").fetchone()[0],
                                      "read API must not persist computed signals")


if __name__ == "__main__":
    unittest.main()
