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


@pytest.mark.asyncio
async def test_timed_out_scanner_keeps_bounded_partial_output_and_reaps_process(monkeypatch):
    launched = []
    real_create = asyncio.create_subprocess_exec

    async def capture(*args, **kwargs):
        process = await real_create(*args, **kwargs)
        launched.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture)
    source = (
        "import sys,time; "
        "sys.stdout.write('lead:' + 'x' * 200); sys.stdout.flush(); "
        "sys.stderr.write('progress'); sys.stderr.flush(); time.sleep(30)"
    )
    result = await MCPServer._run_command(
        None, [sys.executable, "-c", source], timeout=1,
        max_output_chars=30, capture_partial_on_timeout=True,
    )
    assert result["success"] is False
    assert result["timed_out"] is True
    assert result["partial_output"] is True
    assert result["output"] == "lead:" + "x" * 25
    assert result["stderr"] == "progress"
    assert launched[0].returncode is not None


@pytest.mark.asyncio
async def test_xsstrike_uses_assessment_proxy_only_in_child_environment(monkeypatch, tmp_path):
    ca = tmp_path / "ca.crt"
    ca.write_text("test certificate")
    monkeypatch.setenv("AEGIS_ASSESSMENT_PROXY_URL", "http://caido-assessment:8082")
    monkeypatch.setenv("AEGIS_ASSESSMENT_CA_BUNDLE", str(ca))
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    observed = {}

    async def run_command(self, command, **kwargs):
        observed.update(command=command, **kwargs)
        return {"success": True, "output": "lead only"}

    monkeypatch.setattr(MCPServer, "_run_command", run_command)
    server = MCPServer.__new__(MCPServer)
    await server._execute_xsstrike('-u "https://example.com/search?q=a&x=b" --skip-dom')
    assert observed["command"][-1] == "--skip"
    assert observed["env"]["HTTPS_PROXY"] == "http://caido-assessment:8082"
    assert observed["env"]["NO_PROXY"] == ""
    assert observed["capture_partial_on_timeout"] is True
    assert "HTTP_PROXY" not in __import__("os").environ

    # XSStrike passes proxies={} to Requests when --proxy is absent. Requests
    # fills that empty mapping from these child-process environment values.
    import requests
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        monkeypatch.setenv(key, observed["env"][key])
    merged = requests.Session().merge_environment_settings(
        "https://example.com/search", {}, None, False, None,
    )
    assert merged["proxies"]["https"] == "http://caido-assessment:8082"
