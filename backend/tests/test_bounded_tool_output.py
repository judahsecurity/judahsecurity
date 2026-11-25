"""Tool output stays valid JSON when it exceeds the output budget."""

import json

from app.services.agent.tools import _bounded_json


def test_small_payload_is_unchanged():
    payload = {"verdict": "MUTANT_DENIED", "signals": []}
    assert json.loads(_bounded_json(payload, max_chars=1000)) == payload


def test_bulky_brain_is_dropped_before_verdict_is_lost():
    payload = {
        "verdict": "LIKELY_IMPACT",
        "engagement_brain": {"observations": ["x" * 500] * 100},
        "proof_escalation": {"id": "esc-1"},
        "next_action": "Complete the structured authorization proof",
    }
    out = json.loads(_bounded_json(payload, max_chars=2000))
    assert out["verdict"] == "LIKELY_IMPACT"
    assert out["proof_escalation"] == {"id": "esc-1"}
    assert out["next_action"].startswith("Complete")
    assert "engagement_brain" not in out
    assert "engagement_brain_omitted" in out


def test_compact_form_used_before_hard_cut():
    payload = {"rows": [{"k": i} for i in range(60)]}
    pretty = json.dumps(payload, indent=2)
    compact = json.dumps(payload)
    limit = (len(pretty) + len(compact)) // 2
    assert json.loads(_bounded_json(payload, max_chars=limit)) == payload
