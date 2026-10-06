"""NetBrain Cisco prerequisite evaluation and reversible finding status tests."""

from types import SimpleNamespace

from app.models.vulnerability import VulnerabilityStatus
from app.services.netbrain_service import apply_assessment, evaluate_cisco_ios_xe_web_ui


def finding(status=VulnerabilityStatus.OPEN, metadata=None):
    return SimpleNamespace(status=status, resolved_at=None, metadata_=metadata or {})


def test_web_ui_enabled_is_exploitable_prerequisite():
    result = evaluate_cisco_ios_xe_web_ui("ip http server\nip http secure-server\n")
    assert result["verdict"] == "prerequisite_present"
    assert result["exploitable_transports"] == ["http", "https"]


def test_disabled_servers_remove_prerequisite():
    result = evaluate_cisco_ios_xe_web_ui("no ip http server\nno ip http secure-server\n")
    assert result["verdict"] == "prerequisite_absent"
    assert result["exploitable_transports"] == []


def test_session_module_restrictions_are_evaluated_per_transport():
    result = evaluate_cisco_ios_xe_web_ui(
        "ip http server\nip http secure-server\nip http active-session-modules none\n"
    )
    assert result["verdict"] == "prerequisite_present"
    assert result["exploitable_transports"] == ["https"]
    result = evaluate_cisco_ios_xe_web_ui(
        "ip http server\nip http secure-server\nip http active-session-modules none\n"
        "ip http secure-active-session-modules none\n"
    )
    assert result["verdict"] == "prerequisite_absent"


def test_auto_mitigation_preserves_evidence_and_is_reversible():
    record = finding(metadata={"scanner": {"plugin_id": 123}})
    action = apply_assessment(record, {"verdict": "prerequisite_absent"}, auto_mitigate=True)
    assert action == "mitigated"
    assert record.status == VulnerabilityStatus.MITIGATED
    assert record.metadata_["scanner"] == {"plugin_id": 123}
    assert record.metadata_["netbrain_exposure"]["managed_status"] is True

    action = apply_assessment(record, {"verdict": "prerequisite_present"}, auto_mitigate=True)
    assert action == "reopened"
    assert record.status == VulnerabilityStatus.OPEN
    assert record.metadata_["netbrain_exposure"]["managed_status"] is False


def test_unknown_reopens_only_netbrain_managed_mitigation():
    managed = finding(VulnerabilityStatus.MITIGATED, {"netbrain_exposure": {
        "managed_status": True, "managed_integration_id": 10,
    }})
    assert apply_assessment(
        managed, {"verdict": "unknown", "integration_id": 10}, auto_mitigate=True
    ) == "reopened"
    assert managed.status == VulnerabilityStatus.OPEN

    analyst_managed = finding(VulnerabilityStatus.MITIGATED)
    assert apply_assessment(analyst_managed, {"verdict": "unknown"}, auto_mitigate=True) == "evidence_updated"
    assert analyst_managed.status == VulnerabilityStatus.MITIGATED


def test_unknown_from_another_connection_does_not_reopen_managed_mitigation():
    managed = finding(VulnerabilityStatus.MITIGATED, {"netbrain_exposure": {
        "managed_status": True, "managed_integration_id": 10,
    }})
    action = apply_assessment(
        managed, {"verdict": "unknown", "integration_id": 20}, auto_mitigate=True
    )
    assert action == "evidence_updated"
    assert managed.status == VulnerabilityStatus.MITIGATED
    assert managed.metadata_["netbrain_exposure"]["managed_integration_id"] == 10


def test_evidence_only_mode_never_changes_status():
    record = finding()
    assert apply_assessment(record, {"verdict": "prerequisite_absent"}, auto_mitigate=False) == "evidence_updated"
    assert record.status == VulnerabilityStatus.OPEN
