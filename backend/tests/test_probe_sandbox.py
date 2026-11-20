"""Custom-probe execution modes and the probe-egress scope checks."""

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.services.agent.custom_probe import custom_probe_mode, run_custom_probe_isolated

_EGRESS_PATH = Path(__file__).resolve().parents[1] / "probe_sandbox" / "egress.py"
_spec = importlib.util.spec_from_file_location("probe_egress", _EGRESS_PATH)
egress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress)


def test_probe_mode_defaults_off_and_fails_closed(monkeypatch):
    assert settings.AGENT_CUSTOM_PROBE_MODE == "off"
    assert custom_probe_mode() == "off"
    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "sandbox-please")
    assert custom_probe_mode() == "off"
    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "Isolated")
    assert custom_probe_mode() == "isolated"


def test_disabled_tool_refuses_without_running(monkeypatch):
    from app.services.agent import custom_probe
    from app.services.agent.tools import ASMToolsManager

    def boom(*_args, **_kwargs):
        raise AssertionError("probe must not run while disabled")

    monkeypatch.setattr(custom_probe, "run_custom_probe_async", boom)
    monkeypatch.setattr(custom_probe, "run_custom_probe_isolated", boom)
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._scoped_policy_applied = False
    out = json.loads(asyncio.run(manager.run_custom_probe("print(1)", allowed_hosts="example.com")))
    assert out["error"] == "custom_probe_disabled"


def test_isolated_client_requires_configuration(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_TOKEN", "")
    out = asyncio.run(run_custom_probe_isolated("print(1)", allowed_hosts=["example.com"]))
    assert out["ok"] is False and "not configured" in out["error"]


def test_isolated_client_still_applies_source_checks(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_TOKEN", "t" * 30)
    out = asyncio.run(run_custom_probe_isolated("import os", allowed_hosts=["example.com"]))
    assert out["error"] == "Sandbox rejected source"


def test_specialists_lose_probe_tools_when_off():
    from app.services.agent import fireteam_service

    source = Path(fireteam_service.__file__).read_text()
    assert 'if custom_probe_mode() == "off":' in source


@pytest.mark.parametrize("host,expected", [
    ("app.example.com", True),
    ("deep.app.example.com", True),
    ("APP.EXAMPLE.COM.", True),
    ("example.com", False),
    ("evil-app.example.com", False),
    ("abc.oast.fun", True),
    ("localhost", False),
    ("", False),
])
def test_egress_host_scope(host, expected):
    assert egress.host_in_scope(host, ["app.example.com"], ["oast.fun"]) is expected


def test_egress_blocks_private_and_unlisted_ips(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", False)
    assert egress.resolve_checked("10.0.0.5", 80, ["app.example.com"])[0] is None
    assert egress.resolve_checked("169.254.169.254", 80, ["169.254.169.254"])[0] is None
    assert egress.resolve_checked("127.0.0.1", 80, ["127.0.0.1"])[0] is None
    assert egress.resolve_checked("8.8.8.8", 443, ["8.8.8.8"]) == ("8.8.8.8", "")


def test_egress_rejects_names_resolving_only_private(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", False)
    monkeypatch.setattr(egress.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.10", 80))])
    ip, reason = egress.resolve_checked("app.example.com", 80, ["app.example.com"])
    assert ip is None and "non-public" in reason


def test_egress_job_credential_lookup():
    egress._jobs["tok123"] = {"allowed": ["a.example"], "oob": [], "log": []}
    try:
        import base64

        good = "Basic " + base64.b64encode(b"job:tok123").decode()
        bad = "Basic " + base64.b64encode(b"job:nope").decode()
        assert egress._job_for(good)[1] is egress._jobs["tok123"]
        assert egress._job_for(bad) == (None, None)
        assert egress._job_for(None) == (None, None)
    finally:
        egress._jobs.pop("tok123", None)
