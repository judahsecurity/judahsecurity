"""CI gate: a bounded hunt fails a pipeline only on confirmed findings."""

import pytest

from app.services.agent import scheduled_hunt as sched


def test_finding_severity_counts_scopes_to_session():
    findings = [
        {"severity": "high", "session_id": "s1"},
        {"severity": "high", "session_id": "s1"},
        {"severity": "low", "session_id": "s1"},
        {"severity": "critical", "session_id": "other"},
    ]
    assert sched.finding_severity_counts(findings, "s1") == {"high": 2, "low": 1}
    assert sched.finding_severity_counts(findings, "none") == {}


def test_ci_gate_exit_code_threshold():
    assert sched.ci_gate_exit_code({}, "medium") == 0
    assert sched.ci_gate_exit_code({"low": 3}, "medium") == 0
    assert sched.ci_gate_exit_code({"medium": 1}, "medium") == 1
    assert sched.ci_gate_exit_code({"high": 1}, "medium") == 1


def test_ci_gate_exit_code_respects_fail_on():
    assert sched.ci_gate_exit_code({"medium": 5}, "high") == 0
    assert sched.ci_gate_exit_code({"high": 1}, "high") == 1
    assert sched.ci_gate_exit_code({"critical": 1}, "critical") == 1
    assert sched.ci_gate_exit_code({"high": 9}, "critical") == 0


@pytest.mark.asyncio
async def test_run_ci_gate_fails_on_confirmed_finding(monkeypatch):
    captured = {}

    async def fake_hunt(**kwargs):
        captured.update(kwargs)
        return {
            "results": [
                {"target": "https://a.example.test", "session_id": "s1", "complete": True},
                {"target": "https://b.example.test", "session_id": "s2", "complete": True},
            ],
            "digest": "hunt digest",
        }

    def fake_findings(org, session_id, since):
        if session_id == "s1":
            return [{"severity": "high", "session_id": "s1"}]
        return []

    monkeypatch.setattr(sched, "run_tester_process_targets", fake_hunt)
    monkeypatch.setattr(sched, "collect_confirmed_findings", fake_findings)

    out = await sched.run_ci_gate(
        organization_id=1, user_id="7",
        targets=["https://a.example.test", "https://b.example.test"],
        fail_on="medium", scope_note="focus on /api/orders touched by this PR",
    )

    assert out["exit_code"] == 1
    assert out["gate"] == "fail"
    rows = {r["target"]: r for r in out["results"]}
    assert rows["https://a.example.test"]["gate"] == "fail"
    assert rows["https://a.example.test"]["confirmed_findings"] == {"high": 1}
    assert rows["https://b.example.test"]["gate"] == "pass"
    assert "CI gate: FAIL" in out["digest"]
    # scope_note is forwarded as advisory focus
    assert captured["extra_instructions"] == "focus on /api/orders touched by this PR"


@pytest.mark.asyncio
async def test_run_ci_gate_passes_when_quiet(monkeypatch):
    async def fake_hunt(**kwargs):
        return {"results": [{"target": "https://a.example.test", "session_id": "s1"}],
                "digest": "d"}

    monkeypatch.setattr(sched, "run_tester_process_targets", fake_hunt)
    monkeypatch.setattr(sched, "collect_confirmed_findings", lambda *a, **k: [])

    out = await sched.run_ci_gate(organization_id=1, user_id="7",
                                  targets=["https://a.example.test"])
    assert out["exit_code"] == 0
    assert out["gate"] == "pass"
    assert "CI gate: PASS" in out["digest"]


@pytest.mark.asyncio
async def test_run_ci_gate_below_threshold_does_not_fail(monkeypatch):
    async def fake_hunt(**kwargs):
        return {"results": [{"target": "https://a.example.test", "session_id": "s1"}],
                "digest": "d"}

    monkeypatch.setattr(sched, "run_tester_process_targets", fake_hunt)
    monkeypatch.setattr(
        sched, "collect_confirmed_findings",
        lambda *a, **k: [{"severity": "low", "session_id": "s1"}],
    )

    out = await sched.run_ci_gate(organization_id=1, user_id="7",
                                  targets=["https://a.example.test"], fail_on="high")
    assert out["exit_code"] == 0
    assert out["results"][0]["confirmed_findings"] == {"low": 1}
