"""General error accounting through real capture/read boundaries, without providers."""
import json
from types import SimpleNamespace

from test_wiretap import SID, _HookBase, fire_pre


class GeneralErrorsTest(_HookBase):
    def _pre(self, name):
        kw = dict(session_id=SID, model="synthetic", provider="synthetic", api_mode="chat_completions",
                  api_request_id=name, started_at=self.t0)
        fire_pre(self.ctx.hooks["pre_api_request"], {"messages": [{"role": "user", "content": "test"}]}, **kw)
        return kw

    def _error(self, kw, status, reason="test"):
        self.ctx.hooks["api_request_error"](
            status_code=status, retry_count=0, retryable=False, reason=reason,
            error={"type": "SyntheticError", "message": "private provider error"},
            ended_at=self.t0 + 1, api_duration=1, **kw)

    def test_general_errors_are_not_pending_and_recovered_is_not_failed(self):
        for name, status in (("auth", 401), ("permission", 403), ("rate", 429), ("server", 503),
                             ("timeout", None), ("invalid_response", None)):
            self._error(self._pre(name), status)
        self._pre("pending")
        recovered = self._pre("recovered")
        self._error(recovered, 503)
        self.ctx.hooks["post_api_request"](
            ended_at=self.t0 + 3, api_duration=2,
            assistant_message=SimpleNamespace(content="ok", tool_calls=[]),
            usage={"prompt_tokens": 1, "output_tokens": 1}, **recovered)
        con = self.db()
        try:
            tel = self.cap._sibling("telemetry")
            page = tel.list_calls_page(con, {"errors": True}, limit=20)
            self.assertEqual(page["total"], 7)
            self.assertNotIn("h:pending", {r["id"] for r in page["results"]})
            rows = {r["id"]: r for r in page["results"]}
            self.assertEqual(rows["h:timeout"]["error_summary"]["outcome"], "failed")
            self.assertEqual(rows["h:invalid_response"]["error_summary"]["category"], "transport_or_invalid_response")
            self.assertEqual(rows["h:auth"]["error_summary"]["category"], "authentication")
            self.assertEqual(rows["h:permission"]["error_summary"]["category"], "permission")
            self.assertEqual(rows["h:rate"]["error_summary"]["category"], "rate_limit")
            self.assertTrue(rows["h:recovered"]["error_summary"]["recovered"])
            self.assertEqual(rows["h:recovered"]["error_summary"]["outcome"], "succeeded")
            summary = tel.family_summary(con, ["1=1"], [])["synthetic"]
            self.assertEqual({k: summary[k] for k in ("err", "failed_calls", "affected_calls", "recovered_calls",
                                                    "unknown_calls", "recorded_failure_observations", "n429")},
                             dict(err=6, failed_calls=6, affected_calls=7, recovered_calls=1,
                                  unknown_calls=1, recorded_failure_observations=7, n429=1))
        finally:
            con.close()

    def test_dashboard_and_cli_share_summary_without_exposing_error_text(self):
        self._error(self._pre("auth"), 401)
        con = self.db()
        try:
            tel = self.cap._sibling("telemetry")
            dashboard = [dict(r) for r in con.execute("SELECT * FROM calls")]
            tel._decorate(con, dashboard)
            cli = tel.list_calls(con, {})
            self.assertEqual(dashboard[0]["error_summary"], cli[0]["error_summary"])
            encoded = json.dumps(cli[0]["error_summary"])
            self.assertNotIn("private provider error", encoded)
            self.assertNotIn("auth_key", encoded)
            self.assertEqual(cli[0]["error_summary"]["scope"], "call")
        finally:
            con.close()

    def test_semantic_provider_code_is_not_an_http_status(self):
        self._error(self._pre("soft_failure"), "insufficient_quota", "invalid_response")
        con = self.db()
        try:
            tel = self.cap._sibling("telemetry")
            rows = tel.list_calls(con, {"errors": True})
            self.assertEqual(len(rows), 1)
            summary = rows[0]["error_summary"]
            self.assertEqual(summary["outcome"], "unknown")
            self.assertTrue(summary["affected"])
            self.assertIsNone(summary["category"])
            self.assertEqual(tel.family_summary(con, ["1=1"], [])["synthetic"]["affected_calls"], 1)
        finally:
            con.close()

    def test_all_http_success_statuses_and_legacy_unknown(self):
        self._pre("pending")
        con = self.db()
        try:
            tel = self.cap._sibling("telemetry")
            for status, expected in ((200, "succeeded"), (204, "succeeded"), (299, "succeeded"),
                                     (300, "failed"), (400, "failed"), (499, "failed"), (500, "failed"),
                                     (0, "failed"), (None, "unknown")):
                with self.subTest(status=status):
                    summary = tel.error_summary({"status": status})
                    self.assertEqual(summary["outcome"], expected)
                    self.assertIsNone(summary["recorded_failure_observations"])
            self.assertEqual(tel.error_summary({})["outcome"], "unknown")
        finally:
            con.close()
