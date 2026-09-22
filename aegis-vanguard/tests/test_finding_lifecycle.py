import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.finding_lifecycle import (
    apply_validation_decisions,
    initialize_candidates,
    parse_validation_decisions,
    reportable_findings,
)


def test_structured_validation_is_required_for_reporting():
    findings = initialize_candidates([
        {"title": "SQLi", "vuln_type": "sqli", "url": "https://t/?id=1"},
        {"title": "Header", "vuln_type": "headers", "url": "https://t/"},
    ])
    text = "analysis prose\n```json\n" + json.dumps({"decisions": [
        {"finding_id": findings[0]["finding_id"], "decision": "PASS", "reason": "PoC"},
        {"finding_id": findings[1]["finding_id"], "decision": "KILL", "reason": "info"},
    ]}) + "\n```"
    assessed = apply_validation_decisions(findings, parse_validation_decisions(text))
    assert assessed[0]["lifecycle_state"] == "validated"
    assert assessed[1]["lifecycle_state"] == "rejected"
    assert [item["title"] for item in reportable_findings(assessed)] == ["SQLi"]


def test_unstructured_validator_prose_does_not_confirm_candidate():
    findings = initialize_candidates([
        {"title": "Potential issue", "url": "https://t/"},
    ])
    assessed = apply_validation_decisions(findings, parse_validation_decisions("PASS everything"))
    assert assessed[0]["validation_status"] == "needs_more_evidence"
    assert reportable_findings(assessed) == []
