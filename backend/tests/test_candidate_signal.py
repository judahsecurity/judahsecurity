"""Candidates appear in the run ledger immediately, marked unverified."""

from types import SimpleNamespace

from app.services.agent import action_ledger
from app.services.agent.candidate_signal import signal


def test_submission_and_verdict_reach_the_ledger(monkeypatch):
    calls = []
    monkeypatch.setattr(action_ledger, "append_action",
                        lambda run_id, action_id, event, name, **kw: calls.append((name, kw)))
    token = action_ledger.active_run_id.set("run-1")
    try:
        cand = SimpleNamespace(title="IDOR on /api/invoices/{id}", severity="high",
                               target="https://app.test", evidence_ids=["a" * 32])
        signal(cand, "submitted")
        signal(cand, "confirmed")
    finally:
        action_ledger.active_run_id.reset(token)
    (first, first_kw), (second, second_kw) = calls
    assert first == "unverified_candidate"
    assert first_kw["detail"].startswith("UNVERIFIED")
    assert "HIGH IDOR on /api/invoices/{id} @ https://app.test" in first_kw["detail"]
    assert first_kw["evidence_ids"] == ["a" * 32]
    assert second == "candidate_verdict" and "CONFIRMED" in second_kw["detail"]


def test_ledger_failure_never_breaks_the_caller(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(action_ledger, "append_action", boom)
    signal(SimpleNamespace(title="t"), "submitted")  # no exception
