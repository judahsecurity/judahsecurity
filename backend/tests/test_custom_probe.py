"""Bounded CodeAgent sandbox — no shell, no os, in-scope hosts only."""

from app.services.agent.custom_probe import run_custom_probe, validate_probe_source


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


def test_allows_interactsh_oob_host():
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
    assert "oob-ok" in (out.get("stdout") or "")
