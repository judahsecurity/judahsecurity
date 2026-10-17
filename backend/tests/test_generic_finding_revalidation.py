"""A reachable endpoint is not proof of an imported vulnerability claim."""

from app.services.finding_revalidation_service import _verdict_from_probes


def test_reachable_manual_endpoint_remains_inconclusive():
    finding = {"severity": "high", "source_kind": "manual", "title": "SQL injection"}
    probes = [{"kind": "url", "url": "https://example.test/search", "reachable": True}]

    result = _verdict_from_probes(finding, probes, method="steps_replay")

    assert result["verdict"] == "needs_more_evidence"
    assert result["still_open"] is None
    assert result["is_false_positive"] is False
    assert result["recommended_severity"] == "high"
    assert "Reachability alone" in result["reasoning"]


def test_unreachable_agent_endpoint_does_not_refute_claim():
    finding = {"severity": "medium", "detected_by": "agent", "title": "Stored XSS"}
    probes = [{"kind": "url", "url": "https://example.test/posts/1", "reachable": False}]

    result = _verdict_from_probes(finding, probes, method="agent_steps_replay")

    assert result["verdict"] == "needs_more_evidence"
    assert result["still_open"] is None
    assert result["is_false_positive"] is False
    assert result["recommended_severity"] == "medium"
