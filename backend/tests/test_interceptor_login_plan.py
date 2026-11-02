"""Recorded login plans: allowlisted verbs, in-scope URLs, host-local storage."""

import asyncio

import pytest

from app.services.interceptor_recon import ReconResult, parse_login_plan, replay_login_plan

PLAN = """# exported by interceptor monitor export --plan
interceptor open "https://app.example.com/login"
interceptor find "Email" --role textbox
interceptor act e7 "analyst@example.com"
"$INTC" act e9 "hunter2"
act e11
"""


class FakeCLI:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on = [], fail_on

    async def run(self, *args, timeout=0):
        self.calls.append(args)
        if self.fail_on and args[0] == self.fail_on:
            return "__error__ exit 1: element e9 typed hunter2 not found"
        return "ok"


def test_parse_strips_prefixes_and_keeps_steps():
    steps = parse_login_plan(PLAN, "example.com")
    assert steps[0] == ["open", "https://app.example.com/login"]
    assert steps[3] == ["act", "e9", "hunter2"]
    assert len(steps) == 5


@pytest.mark.parametrize("bad", [
    'open "https://evil.test/login"',
    'open "https://app.example.com/"\neval "fetch(1)"',
    'open "https://app.example.com/"\noverride "*api*" admin=1',
    'open "https://app.example.com/"\nact e5 --os',
    'open "https://app.example.com/"\nmacos click 1,1 --app Mail',
    'act e1',
    'open "javascript:alert(1)"',
])
def test_parse_rejects_unsafe_plans(bad):
    with pytest.raises(ValueError):
        parse_login_plan(bad, "example.com")


def _result():
    return ReconResult(target="https://app.example.com/", scope="example.com")


def test_replay_runs_steps(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERCEPTOR_LOGIN_PLAN_DIR", str(tmp_path))
    (tmp_path / "acme.plan").write_text(PLAN)
    cli, result = FakeCLI(), _result()
    assert asyncio.run(replay_login_plan(cli, "acme", result)) is True
    assert result.login_plan == "acme"
    assert cli.calls[0][0] == "open" and cli.calls[-1][0] == "wait-stable"


def test_replay_failure_is_noted_without_leaking_output(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERCEPTOR_LOGIN_PLAN_DIR", str(tmp_path))
    (tmp_path / "acme.plan").write_text(PLAN)
    result = _result()
    assert asyncio.run(replay_login_plan(FakeCLI(fail_on="act"), "acme", result)) is False
    assert result.login_plan is None
    assert "stopped at step 3/5" in result.errors[0]
    assert "hunter2" not in " ".join(result.errors)


def test_replay_rejects_traversal_and_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("INTERCEPTOR_LOGIN_PLAN_DIR", str(tmp_path))
    result = _result()
    assert asyncio.run(replay_login_plan(FakeCLI(), "../etc/passwd", result)) is False
    assert asyncio.run(replay_login_plan(FakeCLI(), "missing", result)) is False
    assert "invalid name" in result.errors[0] and "not found" in result.errors[1]
