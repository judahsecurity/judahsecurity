"""Regression checks for the legacy bounded Python probe."""

import json

import pytest

from app.services.agent.custom_probe import run_custom_probe, validate_probe_source
from app.services.agent.assessment_scope import register_scope
from app.services.agent.tools import ASMToolsManager


def test_rejects_eval_and_os():
    assert any("eval" in e for e in validate_probe_source("print(eval('1'))"))
    assert any("os" in e for e in validate_probe_source("import os\nprint(os.getcwd())"))
    assert any("subprocess" in e or "not allowed" in e for e in validate_probe_source(
        "import subprocess\nsubprocess.run(['id'])"
    ))


def test_allows_json_re_httpx():
    src = "import json, re, httpx\nprint(json.dumps({'ok': True}))\n"
    assert validate_probe_source(src) == []


def test_requires_hosts():
    out = run_custom_probe("print('hi')", allowed_hosts=[])
    assert out["ok"] is False
    assert "in-scope" in out["error"].lower() or "hosts" in out["error"].lower()


def test_runs_print_only_probe():
    out = run_custom_probe("print('probe-ok')", allowed_hosts=["example.com"], timeout_sec=8)
    assert out["ok"] is True
    assert "probe-ok" in out.get("stdout", "")


def test_blocks_out_of_scope_http():
    src = (
        "import httpx\n"
        "raised = False\n"
        "try:\n"
        "    httpx.get('https://evil.invalid/')\n"
        "except PermissionError:\n"
        "    raised = True\n"
        "print('blocked' if raised else 'not-blocked')\n"
    )
    out = run_custom_probe(src, allowed_hosts=["example.com"], timeout_sec=8)
    assert out["ok"] is True
    assert "blocked" in (out.get("stdout") or "")


def test_oob_host_is_disabled_by_default():
    src = (
        "raised = False\n"
        "try:\n"
        "    httpx.get('https://abc123.oast.fun/', timeout=1)\n"
        "except PermissionError:\n"
        "    raised = True\n"
        "except Exception:\n"
        "    raised = False\n"
        "print('oob-blocked' if raised else 'oob-ok')\n"
    )
    out = run_custom_probe(src, allowed_hosts=["example.com"], timeout_sec=8)
    assert out["ok"] is True, out
    assert "oob-blocked" in (out.get("stdout") or "")


def test_urllib_request_cannot_bypass_httpx_scope():
    assert any("urllib.request" in error for error in validate_probe_source(
        "from urllib.request import urlopen\nurlopen('https://evil.invalid')"
    ))
    assert validate_probe_source("import httpx._client")
    assert validate_probe_source("httpx.AsyncClient()")
    assert validate_probe_source("httpx.Client()._transport")


@pytest.mark.asyncio
async def test_agent_cannot_add_custom_probe_hosts(monkeypatch):
    manager = ASMToolsManager()
    manager._fallback_target = "https://app.example.test"
    register_scope(manager, "app.example.test")
    called = []

    async def fake_run(source, **kwargs):
        called.append(kwargs)
        return {"ok": True, "allowed_hosts": kwargs["allowed_hosts"]}

    monkeypatch.setattr("app.services.agent.custom_probe.run_custom_probe_async", fake_run)
    with pytest.raises(ValueError, match="Out-of-scope"):
        await manager.run_custom_probe("print('test')", allowed_hosts="attacker.test")
    assert called == []
    result = json.loads(await manager.run_custom_probe("print('test')"))
    assert result["allowed_hosts"] == ["app.example.test"]
    assert called[0]["oob_allowed"] is False
