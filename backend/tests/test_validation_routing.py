"""VALIDATE_FINDING validator chain: native, then Prowl."""

import asyncio

import pytest

from app.workers import scanner_worker
from app.workers.scanner_worker import route_finding_validation

INCONCLUSIVE = {"verdict": "needs_more_evidence", "method": "agent_steps_replay", "reasoning": "r"}
CONFIRMED = {"verdict": "confirmed", "method": "nuclei_template_replay"}


def _route(mode, *, native=INCONCLUSIVE, prowl=None, prowl_enabled=True):
    calls = []

    async def run_native():
        calls.append("native")
        return dict(native)

    async def run_prowl():
        calls.append("prowl")
        return dict(prowl) if prowl else None

    verdict = asyncio.run(route_finding_validation(
        mode, run_native=run_native, run_prowl=run_prowl, prowl_enabled=prowl_enabled))
    return verdict, calls


def test_conclusive_native_verdict_stops_the_chain():
    for mode in ("native", "auto", "prowl"):
        verdict, calls = _route(mode, native=CONFIRMED)
        assert verdict["method"] == "nuclei_template_replay" and calls == ["native"]


def test_native_mode_never_escalates():
    assert _route("native")[1] == ["native"]


def test_auto_uses_prowl_and_keeps_native_context():
    verdict, calls = _route("auto", prowl={"verdict": "false_positive", "method": "prowl_independent_verify"})
    assert calls == ["native", "prowl"]
    assert verdict["method"] == "prowl_independent_verify"
    assert verdict["native_verdict"]["method"] == "agent_steps_replay"


def test_inconclusive_native_verdict_is_final_when_prowl_cannot_take_it():
    verdict, calls = _route("auto", prowl=None)
    assert calls == ["native", "prowl"] and verdict["verdict"] == "needs_more_evidence"


def test_auto_with_prowl_disabled_stops_at_native():
    assert _route("auto", prowl_enabled=False)[1] == ["native"]


def test_prowl_mode_ignores_the_disable_flag():
    assert _route("prowl", prowl_enabled=False)[1] == ["native", "prowl"]


@pytest.mark.parametrize("mode", ["docker", "subprocess", "weird"])
def test_removed_vanguard_modes_run_as_auto(mode, monkeypatch):
    monkeypatch.setattr(scanner_worker, "_legacy_mode_warned", False)
    verdict, calls = _route(mode, prowl={"verdict": "confirmed", "method": "prowl_independent_verify"})
    assert calls == ["native", "prowl"] and verdict["method"] == "prowl_independent_verify"
