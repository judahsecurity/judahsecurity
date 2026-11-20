"""Reachability alone must not re-confirm an agent-found application bug."""

import asyncio

from app.services import finding_revalidation_service as svc


def _run(monkeypatch, detected_by, reachable=True):
    monkeypatch.setattr(svc, "revalidate_port_exposure", lambda finding: _none())
    monkeypatch.setattr(svc, "_probe_endpoints", lambda endpoints: [
        {**(e if isinstance(e, dict) else {"url": e}), "reachable": reachable} for e in endpoints])
    finding = {
        "detected_by": detected_by, "source_kind": "web", "severity": "high",
        "steps_to_reproduce": "GET https://app.example.com/api/orders/1002 as user B",
    }
    return asyncio.run(svc.revalidate_finding(finding))


async def _none():
    return None


def test_agent_finding_reachable_is_not_confirmed(monkeypatch):
    verdict = _run(monkeypatch, "agent")
    assert verdict["verdict"] == "needs_more_evidence"
    assert verdict["still_open"] is None
    assert "does not re-prove" in verdict["reasoning"]


def test_scanner_exposure_reachable_stays_confirmed(monkeypatch):
    assert _run(monkeypatch, "httpx")["verdict"] == "confirmed"


def test_agent_finding_unreachable_is_still_reported(monkeypatch):
    assert _run(monkeypatch, "agent", reachable=False)["verdict"] == "false_positive"
