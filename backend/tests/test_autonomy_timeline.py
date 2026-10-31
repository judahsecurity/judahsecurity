"""A run timeline links leads, branches, receipts, and spend without raw logs."""

from datetime import datetime, timezone
from types import SimpleNamespace

from app.services.agent.autonomy_timeline import build_timeline


def test_timeline_separates_lead_from_receipt_backed_finding():
    now = datetime.now(timezone.utc)
    work = SimpleNamespace(
        id="work-1", status="completed", turns=1, spent_usd=0.25,
        stop_reason="", finished_at=now, updated_at=now,
    )
    candidate = {
        "id": "c1", "status": "confirmed", "hypothesis_id": "h1",
        "verifier_run_id": "verify-1", "revision": "r1", "nonce": "n1",
    }
    snapshot = {"saved_at": now.timestamp(), "engagement_brain": {
        "recon_observations": [{
            "id": "o1", "dedupe_key": "o1", "kind": "dns_cname",
            "target": "https://docs.example.test", "value": "unused.github.io",
            "source": "execute_dnsx", "evidence_ref": "artifact:1",
            "scope": {"allowed_hosts": ["docs.example.test"]},
            "observed_at": now.isoformat(),
        }],
        "hypotheses": [{
            "id": "h1", "observation_id": "o1", "title": "Check CNAME",
            "target": "https://docs.example.test", "specialist": "takeover",
            "status": "proven", "created_at": now.isoformat(),
        }],
        "candidates": [candidate],
        "verification_receipts": {"c1": {
            "candidate_id": "c1", "verdict": "confirmed", "run_id": "verify-1",
            "revision": "r1", "nonce": "n1", "nonce_observed": True,
            "evidence_ids": ["e1"],
        }},
    }}
    run = SimpleNamespace(id="run-1", started_at=now, ended_at=now, status="completed", reason="")
    action = SimpleNamespace(
        run_id="run-1", action_id="a1", event="completed", created_at=now,
        tool_name="execute_dnsx", target="https://docs.example.test?secret=hidden",
        phase="takeover", detail="ok", evidence_ids=["e1"],
    )
    result = build_timeline(work, snapshot, [run], [action], [])
    assert result["lead_count"] == 1 and result["verified_count"] == 1
    kinds = {event["kind"] for event in result["events"]}
    assert kinds == {"observation", "hypothesis", "tool_attempt", "candidate", "run", "work"}
    assert next(event for event in result["events"] if event["kind"] == "hypothesis")["observation_id"] == "o1"
    verified_event = next(event for event in result["events"] if event["kind"] == "candidate")
    assert verified_event["verdict"] == "verified" and verified_event["evidence_ids"] == ["e1"]
    assert "hidden" not in str(result)


def test_confirmation_without_matching_receipt_remains_lead():
    now = datetime.now(timezone.utc)
    work = SimpleNamespace(
        id="work-1", status="blocked", turns=1, spent_usd=0.1,
        stop_reason="budget exhausted", finished_at=now, updated_at=now,
    )
    snapshot = {"engagement_brain": {
        "candidates": [{"id": "c1", "status": "confirmed", "verifier_run_id": "verify-1", "revision": "r1", "nonce": "n1"}],
        "verification_receipts": {"c1": {"candidate_id": "c1", "verdict": "confirmed", "run_id": "other"}},
    }}
    result = build_timeline(work, snapshot, [], [], [])
    assert result["verified_count"] == 0
    assert next(event for event in result["events"] if event["kind"] == "candidate")["verdict"] == "lead"
    assert result["events"][-1]["stop_reason"] == "budget exhausted"
