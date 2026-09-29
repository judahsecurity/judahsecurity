"""A cancelled agent tool must not leave its scanner process running."""

import asyncio
import sys

import pytest

from app.services.mcp.server import MCPServer


@pytest.mark.asyncio
async def test_cancelled_command_reaps_process(monkeypatch):
    launched = []
    real_create = asyncio.create_subprocess_exec

    async def capture(*args, **kwargs):
        process = await real_create(*args, **kwargs)
        launched.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    task = asyncio.create_task(MCPServer._run_command(
        None, [sys.executable, "-c", "import time; time.sleep(30)"], timeout=30,
    ))
    try:
        for _ in range(100):
            if launched:
                break
            await asyncio.sleep(0.01)
        assert launched
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert launched[0].returncode is not None
    finally:
        if launched and launched[0].returncode is None:
            launched[0].kill()
            await launched[0].wait()


@pytest.mark.asyncio
async def test_discovery_observation_survives_output_cap():
    source = (
        "import sys; "
        "sys.stdout.write('x' * 12000 + '\\nhttps://lab.example/late\\n')"
    )
    result = await MCPServer._run_command(
        None, [sys.executable, "-c", source], timeout=5,
        max_output_chars=100, capture_discovery_urls=True,
    )
    assert result["success"] is True
    assert "https://lab.example/late" not in result["output"]
    assert any(
        item["target"] == "https://lab.example/late"
        for item in result["observations"]
    )
