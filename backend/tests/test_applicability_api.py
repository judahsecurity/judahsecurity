from datetime import datetime, timedelta, timezone

import pytest

from test_severity_api import client  # noqa: F401 — isolated SQLite/API fixture
from app.api.routes import oracle
from app.models.vulnerability import Vulnerability
from app.services.oracle_enrichment_service import OracleUnavailable

SIGNAL = "components.mesop_ai_sandbox.enabled"


def _seed():
    from app.db.database import SessionLocal
    with SessionLocal() as db:
        v = db.get(Vulnerability, 100)
        v.cve_id = "CVE-2026-33057"
        v.detection_confidence = "version_only"
        v.metadata_ = {"oracle": {
            "mode": "full", "analysis_status": "complete", "opes_score": 8.0,
            "contextual_assessment": {
                "state": "conditions_met", "summary": "Previously verified",
                "preconditions": [{"precondition": {
                    "id": "sandbox-route", "description": "Sandbox execution route enabled",
                    "severity": "blocker", "verification_signal": SIGNAL,
                    "match_kind": "equals", "match_value": "true",
                    "verification_method": "Inspect the deployed entry point and route map",
                }, "status": "satisfied"}],
            },
        }}
        db.commit()


def _observation(**patch):
    data = {
        "signal_path": SIGNAL, "value": "false", "method": "deployment_config",
        "reference": "deployment revision abc123", "note": "Sandbox entry point is disabled in this image",
        "observed_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "valid_for_hours": 24,
    }
    return {**data, **patch}


def test_evidence_survives_outage_and_old_conclusions_are_withdrawn(client, monkeypatch):
    _seed()
    def offline(*args, **kwargs):
        raise OracleUnavailable("offline")
    monkeypatch.setattr(oracle, "enrich_vulnerability", offline)
    r = client.put("/oracle/applicability/100", json={"observations": [_observation()]})
    assert r.status_code == 200
    data = r.json()
    assert data["refresh_error"] == "offline"
    assert data["state"] == "needs_evidence"
    assert data["observations"][SIGNAL]["scope"] == "asm-10"
    assert data["observations"][SIGNAL]["collected_by"] == "a"
    assert "opes_score" not in data["oracle"]
    assert data["risk"]["exploit_realism"]["tier"] == "unverified"
    assert data["risk"]["score"] > 0
    assert client.get("/oracle/applicability/100").json()["observations"][SIGNAL]["value"] == "false"


def test_observations_reach_oracle_and_return_updated_risk(client, monkeypatch):
    _seed()
    from app.services import oracle_enrichment_service as bridge
    def analyze(cve, asset):
        assert cve == "CVE-2026-33057"
        assert asset["signals"]["observed_signals"][SIGNAL]["value"] == "false"
        assert asset["asset_id"] == "asm-10"
        return {
            "mode": "full", "analysis_status": "complete",
            "contextual_assessment": {
                "state": "documented_path_blocked", "summary": "Sandbox route disabled",
                "preconditions": [{"precondition": {"id": "sandbox-route", "severity": "blocker", "verification_signal": SIGNAL},
                                   "status": "unsatisfied", "evidence": [asset["signals"]["observed_signals"][SIGNAL]]}],
            },
        }
    monkeypatch.setattr(bridge, "_call_analyze", analyze)
    data = client.put("/oracle/applicability/100", json={"observations": [_observation()]}).json()
    assert data["refresh_error"] is None
    assert data["state"] == "documented_path_blocked"
    assert data["risk"]["score"] == 0
    assert data["valid_until"]


def test_concurrent_evidence_change_rejects_superseded_oracle_result(client, monkeypatch):
    from copy import deepcopy
    from app.db.database import SessionLocal
    from app.services import oracle_enrichment_service as bridge
    _seed()
    def analyze(cve, asset):
        with SessionLocal() as db:
            v = db.get(Vulnerability, 100)
            meta = deepcopy(v.metadata_)
            meta["applicability_evidence"]["signals"][SIGNAL]["value"] = "true"
            v.metadata_ = meta
            db.commit()
        return {"mode": "full", "analysis_status": "complete",
                "contextual_assessment": {"state": "documented_path_blocked"}}
    monkeypatch.setattr(bridge, "_call_analyze", analyze)
    data = client.put("/oracle/applicability/100", json={"observations": [_observation()]}).json()
    assert "changed during analysis" in data["refresh_error"]
    assert data["observations"][SIGNAL]["value"] == "true"
    assert data["state"] == "needs_evidence"
    assert data["risk"]["score"] > 0


def test_degraded_oracle_response_keeps_verification_plan(client, monkeypatch):
    from app.services import oracle_enrichment_service as bridge
    _seed()
    monkeypatch.setattr(bridge, "_call_analyze", lambda *args: {"analysis_status": "failed", "analysis_error": "provider timeout"})
    data = client.put("/oracle/applicability/100", json={"observations": [_observation()]}).json()
    assert data["refresh_error"] == "provider timeout"
    assert data["checks"][0]["signal_path"] == SIGNAL
    assert data["state"] == "needs_evidence"


@pytest.mark.parametrize("patch", [
    {"signal_path": "extra.unrelated"}, {"value": "unknown"}, {"reference": " "},
    {"observed_at": "2099-01-01T00:00:00Z"}, {"observed_at": "2000-01-01T00:00:00Z"},
    {"observed_at": "2026-01-01T00:00:00"}, {"valid_for_hours": 169},
])
def test_invalid_evidence_is_rejected_without_mutation(client, patch):
    _seed()
    before = client.get("/oracle/applicability/100").json()
    r = client.put("/oracle/applicability/100", json={"observations": [_observation(**patch)]})
    assert r.status_code == 422
    assert client.get("/oracle/applicability/100").json() == before


def test_cross_organization_and_viewer_writes_are_rejected(client):
    from app.db.database import SessionLocal
    from app.api import deps
    from app.models.user import User, UserRole
    _seed()
    with SessionLocal() as db:
        db.add(Vulnerability(id=200, title="Other org", asset_id=20, severity="high"))
        db.commit()
    assert client.get("/oracle/applicability/200").status_code == 403
    assert client.put("/oracle/applicability/200", json={"observations": [_observation()]}).status_code == 403
    # Remove the test's analyst bypass and exercise the real role dependency.
    del client.app.dependency_overrides[deps.require_analyst]
    viewer = User(id=2, username="viewer", email="v@acme.com", organization_id=1, role=UserRole.VIEWER, is_active=True)
    client.app.dependency_overrides[deps.get_current_active_user] = lambda: viewer
    assert client.put("/oracle/applicability/100", json={"observations": [_observation()]}).status_code == 403


def test_expired_block_is_revisited_by_worker_without_input_change(client):
    from app.db.database import SessionLocal
    from app.services.severity_evaluation import EVALUATOR_VERSION, run_dirty_batch
    _seed()
    expired = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    with SessionLocal() as db:
        v = db.get(Vulnerability, 100)
        meta = dict(v.metadata_)
        meta["oracle"]["contextual_assessment"]["state"] = "documented_path_blocked"
        meta["oracle"]["contextual_assessment"]["preconditions"][0]["evidence"] = [{"valid_until": expired}]
        meta["severity_eval"] = {"version": EVALUATOR_VERSION, "evidence_valid_until": expired}
        v.metadata_, v.sev_dirty, v.sev_score = meta, False, 0
        # Assignment from a fresh dict ensures SQLAlchemy sees the update.
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(v, "metadata_")
        db.commit()
    result = run_dirty_batch(SessionLocal)
    assert result["failed"] == 0
    with SessionLocal() as db:
        v = db.get(Vulnerability, 100)
        assert v.sev_score > 0
        assert v.sev_exploit_realism == "unverified"
        assert v.oracle_opes_score is None
        assert v.metadata_["severity_eval"]["evidence_valid_until"] is None
