from __future__ import annotations

import pytest
from app.services.workflow.script_runner import run_script


@pytest.mark.asyncio
async def test_workflow_script_does_not_inherit_backend_secrets(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak")
    code, stdout, stderr, _outputs = await run_script(
        language="python",
        source=(
            "import os\n"
            "print(os.getenv('OPENAI_API_KEY'))\n"
            "print(os.getenv('INPUT_VISIBLE'))\n"
        ),
        workdir=tmp_path / "run",
        env_extra={"INPUT_VISIBLE": "allowed"},
        timeout=10,
    )
    assert code == 0
    assert stderr == ""
    assert stdout.splitlines() == ["None", "allowed"]


@pytest.mark.asyncio
async def test_workflow_secret_like_input_is_not_injected_into_environment(tmp_path) -> None:
    with pytest.raises(RuntimeError, match="explicit authorization"):
        await run_script(
            language="python",
            source="print('should not execute')",
            workdir=tmp_path / "run",
            env_extra={"INPUT_SERVICE_TOKEN": "secret"},
            timeout=10,
        )
