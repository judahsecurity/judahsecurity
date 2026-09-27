"""Decision persistence, concurrent writes, changed evidence, and capture scope."""
from copy import deepcopy
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest

from pydantic import ValidationError
# These modules are pure; avoid unrelated eager DNS/database imports in package __init__.
def load_unit(name, relative):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

FindingTriageWrite = load_unit('triage_schema_under_test', 'app/schemas/finding_triage.py').FindingTriageWrite
service = load_unit('triage_service_under_test', 'app/services/finding_triage.py')
TASKS, asset_mentions, record_decision, triage_state, validate_capture_url = (
    service.TASKS, service.asset_mentions, service.record_decision, service.triage_state, service.validate_capture_url,
)


class FindingTriageTests(unittest.TestCase):
    def setUp(self):
        self.finding = SimpleNamespace(
            asset_id=7, title="Database exposure", description="Endpoints: 192.0.2.1, 192.0.2.2",
            evidence="port open", status="open", severity="high", last_detected="2026-09-20",
            metadata_={"oracle": {"opes_score": 8.5}, "unrelated": {"keep": True}},
        )
        self.user = SimpleNamespace(id=3, full_name="Analyst", email="analyst@example.test", username="analyst")

    def payload(self, task="evidence", **changes):
        state = triage_state(self.finding)
        data = dict(task_id=task, expected_revision=state["revision"],
                    evidence_version=state["evidence_version"], state="reviewed", decision="confirm",
                    rationale="Reviewed the recorded response", correction="", evidence_references=["capture #12"])
        data.update(changes)
        return FindingTriageWrite(**data).model_dump()

    def save(self, task="evidence", **changes):
        self.finding.metadata_ = record_decision(self.finding, self.payload(task, **changes), self.user)

    def test_review_is_persisted_without_resolving_finding_or_losing_metadata(self):
        original = deepcopy(self.finding.metadata_)
        self.save()
        state = triage_state(self.finding)
        self.assertEqual(state["pending"], 3)
        self.assertEqual(state["status"], "in_review")
        self.assertEqual(state["history"][0]["reviewer_id"], self.user.id)
        self.assertEqual(state["history"][0]["evidence_references"], ["capture #12"])
        self.assertEqual(self.finding.status, "open")
        for key in original:
            self.assertEqual(self.finding.metadata_[key], original[key])

    def test_drafts_and_missing_evidence_do_not_complete_review(self):
        self.save(state="draft", decision=None, rationale="", evidence_references=[])
        self.assertEqual(triage_state(self.finding)["pending"], 4)
        self.save(decision="needs_evidence", evidence_references=[])
        self.assertEqual(triage_state(self.finding)["pending"], 4)

    def test_completion_requires_each_current_evidence_decision(self):
        for task in TASKS:
            self.save(task["id"])
        state = triage_state(self.finding)
        self.assertEqual(state["status"], "reviewed")
        self.assertIsNotNone(state["last_reviewed_at"])
        self.finding.evidence = "new response"
        state = triage_state(self.finding)
        self.assertEqual(state["pending"], 4)
        self.assertTrue(all(item["stale"] for item in state["items"]))
        self.assertIsNone(state["last_reviewed_at"])
        self.assertEqual(len(state["history"]), 4)

    def test_changed_risk_ratings_and_business_context_reopen_review(self):
        for attribute, value in (("sev_score", 62.5), ("business_app_id", 18), ("sev_exploit_realism", "confirmed")):
            with self.subTest(attribute=attribute):
                self.save("priority")
                previous = self.payload("priority")
                setattr(self.finding, attribute, value)
                priority = next(item for item in triage_state(self.finding)["items"] if item["id"] == "priority")
                self.assertTrue(priority["stale"])
                with self.assertRaisesRegex(ValueError, "evidence changed"):
                    record_decision(self.finding, previous, self.user)

    def test_inherited_business_application_changes_reopen_review(self):
        self.finding.asset = SimpleNamespace(business_app_id=10)
        self.save("impact")
        previous = self.payload("impact")
        self.finding.asset.business_app_id = 11
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            record_decision(self.finding, previous, self.user)

    def test_concurrent_or_stale_evidence_writes_are_rejected(self):
        first = self.payload()
        self.save()
        with self.assertRaisesRegex(ValueError, "review changed"):
            record_decision(self.finding, first, self.user)
        current = self.payload()
        self.finding.metadata_["detection"] = {"response": "new packet"}
        with self.assertRaisesRegex(ValueError, "evidence changed"):
            record_decision(self.finding, current, self.user)

    def test_review_history_is_immutable_and_identity_cannot_be_spoofed(self):
        self.save()
        first = deepcopy(triage_state(self.finding)["history"][0])
        self.save(decision="correct", correction="Evidence supports medium severity")
        self.assertEqual(triage_state(self.finding)["history"][0], first)
        with self.assertRaises(ValidationError):
            FindingTriageWrite(**{**self.payload(), "reviewer_id": 999})

    def test_reviewed_decision_requires_real_content(self):
        for change in ({"rationale": "  "}, {"evidence_references": []},
                       {"decision": "correct", "correction": " "}, {"evidence_references": [" "]}):
            with self.subTest(change=change), self.assertRaises(ValidationError):
                self.payload(**change)

    def test_asset_mentions_are_unique_and_invalid_ips_are_ignored(self):
        self.finding.description += " 192.0.2.1 999.1.1.1"
        self.finding.metadata_["agent_detection"] = {"assets": ["https://app.example.test/path"]}
        self.assertEqual(asset_mentions(self.finding), ["https://app.example.test/path", "192.0.2.1", "192.0.2.2"])

    def test_capture_allows_exact_asset_paths_but_not_other_hosts_or_credentials(self):
        url = "https://app.example.test:8443/login?view=public"
        self.assertEqual(validate_capture_url(url, "app.example.test"), url)
        for url in ["https://other.example.test/", "file:///etc/passwd", "https://user:pass@app.example.test/",
                    "https://app.example.test.evil.test/", "https://app.example.test:99999/",
                    "https://app.example.test/\\@evil.test", "https://app.example.test/#fragment"]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_capture_url(url, "app.example.test")


if __name__ == "__main__":
    unittest.main()
