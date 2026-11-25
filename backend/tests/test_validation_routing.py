"""VALIDATE_FINDING validator chain: native, Prowl, Vanguard fallback."""

import asyncio

import pytest

from app.workers.scanner_worker import route_finding_validation

INCONCLUSIVE = {"verdict": "needs_more_evidence", "method": "agent_steps_replay", "reasoning": "r"}
CONFIRMED = {"verdict": "confirmed", "method": "nuclei_template_replay"}


def _route(mode, *, native=INCONCLUSIVE, prowl=None, prowl_enabled=True, fallback="docker",
           vanguard_error=None):
    calls = []

    async def run_native():
        calls.append("native")
        return dict(native)

    async def run_prowl():
        calls.append("prowl")
        return dict(prowl) if prowl else None

    async def run_vanguard(kind):
        calls.append(f"vanguard:{kind}")
        if vanguard_error:
            raise vanguard_error
        return {"verdict": "confirmed", "method": "vanguard"}

    verdict = asyncio.run(route_finding_validation(
        mode, run_native=run_native, run_prowl=run_prowl, run_vanguard=run_vanguard,
        prowl_enabled=prowl_enabled, vanguard_fallback=fallback))
    return verdict, calls


def test_conclusive_native_verdict_stops_the_chain():
    for mode in ("native", "auto", "prowl"):
        verdict, calls = _route(mode, native=CONFIRMED)
        assert verdict["method"] == "nuclei_template_replay" and calls == ["native"]


def test_native_mode_never_escalates():
    assert _route("native")[1] == ["native"]


def test_auto_prefers_prowl_and_keeps_native_context():
    verdict, calls = _route("auto", prowl={"verdict": "false_positive", "method": "prowl_independent_verify"})
    assert calls == ["native", "prowl"]
    assert verdict["method"] == "prowl_independent_verify"
    assert verdict["native_verdict"]["method"] == "agent_steps_replay"


def test_auto_falls_back_to_vanguard_only_when_prowl_cannot_take_it():
    verdict, calls = _route("auto", prowl=None)
    assert calls == ["native", "prowl", "vanguard:docker"] and verdict["method"] == "vanguard"
    verdict, calls = _route("auto", prowl=None, fallback=None)
    assert calls == ["native", "prowl"] and verdict["verdict"] == "needs_more_evidence"


def test_auto_with_prowl_disabled_keeps_the_old_vanguard_escalation():
    assert _route("auto", prowl_enabled=False)[1] == ["native", "vanguard:docker"]


def test_prowl_mode_never_uses_vanguard():
    verdict, calls = _route("prowl", prowl=None, prowl_enabled=False)
    assert calls == ["native", "prowl"] and verdict["verdict"] == "needs_more_evidence"


def test_vanguard_failure_in_auto_keeps_native_verdict():
    verdict, calls = _route("auto", vanguard_error=RuntimeError("boom"))
    assert verdict["verdict"] == "needs_more_evidence" and calls[-1] == "vanguard:docker"


@pytest.mark.parametrize("mode, kind", [("subprocess", "subprocess"), ("docker", "docker"),
                                        ("weird", "docker")])
def test_explicit_vanguard_modes(mode, kind):
    assert _route(mode)[1] == [f"vanguard:{kind}"]
