"""The pipeline starts the hunt engine by itself once the first pass has signals."""

from app.core.config import settings
from app.services.agent import tester_loop
from app.services.agent.fireteam_service import SpecialistReport, _fill_summary_contract
from app.services.agent.model_led import always_forced

TARGET = "https://shop.test/"


def _state(*outcomes):
    cells = [{"id": f"c{i}", "method": "GET", "path": "/catalog", "parameter": f"p{i}",
              "test_type": "sqli", "first_pass_outcome": outcome}
             for i, outcome in enumerate(outcomes)]
    return {"mode": "agent", "engagement_brain": {"coverage_cells": cells}}


def test_starts_on_signals_only_when_enabled(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", False, raising=False)
    assert tester_loop._hunt_engine_step(_state("proof_signal"), [], TARGET) is None

    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    assert tester_loop._hunt_engine_step(_state("tested_clean"), [], TARGET) is None
    step = tester_loop._hunt_engine_step(_state("proof_signal", "inconclusive"), [], TARGET)
    assert step["tool_name"] == "run_hunt_engine"
    assert step["tool_args"]["signal_count"] == 2 and step["tool_args"]["target"] == TARGET
    # Advisory steering must not defer it back to the model.
    assert always_forced(step)


def test_not_repeated_for_the_same_signals_and_capped(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    state = _state("proof_signal")
    step = tester_loop._hunt_engine_step(state, [], TARGET)
    trace = [{"tool_name": "run_hunt_engine", "tool_args": step["tool_args"], "success": True}]
    assert tester_loop._hunt_engine_step(state, trace, TARGET) is None

    # A new signal set gets one more run, up to the cap.
    grown = _state("proof_signal", "proof_signal")
    second = tester_loop._hunt_engine_step(grown, trace, TARGET)
    assert second is not None
    trace.append({"tool_name": "run_hunt_engine", "tool_args": second["tool_args"]})
    assert tester_loop._hunt_engine_step(_state("proof_signal", "proof_signal", "inconclusive"),
                                         trace, TARGET) is None


def test_skipped_in_pilot_and_when_the_budget_is_spent(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_HUNT_ENGINE", True, raising=False)
    pilot = dict(_state("proof_signal"), mode="pilot")
    assert tester_loop._hunt_engine_step(pilot, [], TARGET) is None

    class Spent:
        exhausted = True

    from app.services.agent import request_budget
    monkeypatch.setattr(request_budget, "active", lambda: Spent())
    assert tester_loop._hunt_engine_step(_state("proof_signal"), [], TARGET) is None


def test_specialist_done_payload_keeps_facts():
    report = SpecialistReport(specialist="sqli", role="r", mission="m", summary="")
    _fill_summary_contract(report, {"verdict": "killed", "facts": [
        {"summary": "category not injectable with A, B, C", "negative": True,
         "confidence": "observed"}, {"no": "summary"}, "junk"]})
    assert [f["summary"] for f in report.facts] == ["category not injectable with A, B, C"]
