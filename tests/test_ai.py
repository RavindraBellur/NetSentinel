"""Claude diagnosis with a fake API client: no network, no cost."""
import json
import threading
import types
import unittest

from tests import _env  # noqa: F401
from netscan import ai, settings


class FakeClient:
    def __init__(self, reply=None, stop="end_turn", error=None):
        self.reply, self.stop, self.error, self.requests = reply, stop, error, []
        self.beta = types.SimpleNamespace(messages=types.SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.requests.append(kw)
        if self.error:
            raise self.error
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return types.SimpleNamespace(stop_reason=self.stop,
                                     content=[types.SimpleNamespace(type="text", text=text)])


GOOD = {"title": "ISP link down at reception", "severity": "high", "category": "isp_wan",
        "root_cause": "Gateway answers but both internet targets fail.", "confidence": 140,
        "evidence": ["8.8.8.8 down", "gateway 2 ms"], "alternative_causes": ["DNS"],
        "user_impact": "No internet", "recommended_actions": ["Call the ISP"],
        "needs_onsite_visit": False, "data_gaps": ["no syslog"]}


def diagnoser(client):
    return ai.Diagnoser(log=lambda m: None, client_factory=lambda key: client)


class ClaudeDiagnosis(unittest.TestCase):
    def setUp(self):
        settings.reset()
        settings.save({"ai": {"enabled": True, "api_key": "sk-test", "max_per_hour": 20}})

    def test_off_by_default_sends_nothing(self):
        settings.reset()
        client = FakeClient(GOOD)
        self.assertIsNone(diagnoser(client).diagnose({"device": {}}))
        self.assertEqual(client.requests, [])

    def test_no_key_sends_nothing(self):
        settings.save({"ai": {"api_key": ""}})
        client = FakeClient(GOOD)
        self.assertIsNone(diagnoser(client).diagnose({}))
        self.assertEqual(client.requests, [])

    def test_good_answer_is_used(self):
        client = FakeClient(GOOD)
        diag = diagnoser(client).diagnose({"device": {"ip": "10.0.0.1"}}, {"title": "rules say ISP"})
        self.assertEqual(diag["engine"], "claude")
        self.assertEqual(diag["confidence"], 100)          # clamped
        req = client.requests[0]
        self.assertEqual(req["model"], "claude-opus-5-5")
        self.assertEqual(req["output_config"]["format"]["type"], "json_schema")
        self.assertIn("rules say ISP", req["messages"][0]["content"])  # rule verdict included

    def test_refusal_truncation_garbage_and_errors_fall_back(self):
        for client in (FakeClient(GOOD, stop="refusal"), FakeClient(GOOD, stop="max_tokens"),
                       FakeClient("not json"), FakeClient(error=ConnectionError("offline"))):
            self.assertIsNone(diagnoser(client).diagnose({}))

    def test_hourly_budget(self):
        settings.save({"ai": {"max_per_hour": 2}})
        dz = diagnoser(FakeClient(GOOD))
        results = [dz.diagnose({}) for _ in range(3)]
        self.assertIsNotNone(results[0])
        self.assertIsNotNone(results[1])
        self.assertIsNone(results[2])
        self.assertIn("limit", dz.last_error)

    def test_background_refine_updates_incident(self):
        ai._instance = diagnoser(FakeClient(GOOD))
        inc = {"id": "INC-1", "title": "rules title", "diagnosis": {"engine": "rules"}, "timeline": []}
        saved = []
        t = ai.refine_in_background(inc, {"device": {}}, saved.append, log=lambda m: None)
        t.join(5)
        self.assertEqual(inc["diagnosis"]["engine"], "claude")
        self.assertEqual(inc["title"], GOOD["title"])
        self.assertTrue(any("Claude diagnosis" in x["text"] for x in inc["timeline"]))
        self.assertEqual(saved, [inc])

    def test_failed_refine_keeps_rules(self):
        ai._instance = diagnoser(FakeClient(error=RuntimeError("boom")))
        inc = {"id": "INC-2", "title": "rules title", "diagnosis": {"engine": "rules"}, "timeline": []}
        t = ai.refine_in_background(inc, {}, lambda i: None, log=lambda m: None)
        t.join(5)
        self.assertEqual(inc["diagnosis"]["engine"], "rules")

    def test_ask_uses_snapshot_and_history(self):
        client = FakeClient("Reception AP is down since 10:02.")
        answer, source = diagnoser(client).ask("what is down?", {"devices": [{"ip": "10.0.0.9"}]},
                                               [{"role": "user", "content": "hi"},
                                                {"role": "assistant", "content": "hello"}])
        self.assertEqual(source, "claude")
        self.assertIn("Reception", answer)
        msgs = client.requests[0]["messages"]
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant", "user"])
        self.assertIn("10.0.0.9", msgs[-1]["content"])

    def test_compact_snapshot_has_no_settings(self):
        snap = {"settings": {"ai": {"api_key": "sk-secret"}}, "devices": [{"ip": "1"}], "incidents": []}
        self.assertNotIn("sk-secret", json.dumps(ai.compact_snapshot(snap)))


if __name__ == "__main__":
    unittest.main()
