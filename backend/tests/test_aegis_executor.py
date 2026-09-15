from __future__ import annotations

import sys

import pytest
from aegis_executor import (
    ExecutionPolicy,
    ExecutionPolicyError,
    build_environment,
    run_process,
)


def test_environment_is_allowlisted_and_secret_extras_require_authorization() -> None:
    policy = ExecutionPolicy(
        allowed_extra_environment=frozenset({"WORKFLOW_IN", "SERVICE_TOKEN"})
    )
    env = build_environment(
        policy,
        base={"PATH": "/usr/bin", "OPENAI_API_KEY": "do-not-leak", "OTHER": "drop"},
        extra={"WORKFLOW_IN": "/tmp/in"},
    )
    assert env == {"PATH": "/usr/bin", "WORKFLOW_IN": "/tmp/in"}
    with pytest.raises(ExecutionPolicyError, match="explicit authorization"):
        build_environment(policy, base={}, extra={"SERVICE_TOKEN": "secret"})
    with pytest.raises(ExecutionPolicyError, match="not authorized"):
        build_environment(policy, base={}, extra={"LD_PRELOAD": "/tmp/evil.so"})


@pytest.mark.asyncio
async def test_subprocess_receives_only_explicit_environment(tmp_path) -> None:
    result = await run_process(
        [
            sys.executable,
            "-c",
            "import os; print(os.getenv('VISIBLE')); print(os.getenv('OPENAI_API_KEY'))",
        ],
        workdir=tmp_path,
        environment={"VISIBLE": "yes"},
        policy=ExecutionPolicy(allowed_extra_environment=frozenset({"VISIBLE"})),
    )
    assert result.exit_code == 0
    assert result.stdout.splitlines() == ["yes", "None"]


@pytest.mark.asyncio
async def test_subprocess_output_is_bounded(tmp_path) -> None:
    result = await run_process(
        [sys.executable, "-c", "print('x' * 5000)"],
        workdir=tmp_path,
        policy=ExecutionPolicy(max_output_bytes=1024),
    )
    assert result.exit_code == 0
    assert result.output_truncated is True
    assert len(result.stdout.encode()) == 1024
