"""Offline script sandbox: useful computation works, escapes do not."""

import json

import pytest

from app.services.agent import script_sandbox
from app.services.agent.script_sandbox import jail_available, run_python
from app.services.agent.tools import ASMToolsManager, current_organization_id, current_session_id

needs_jail = pytest.mark.skipif(not jail_available(), reason="unshare/chroot jail unavailable")


@needs_jail
def test_offline_computation_works():
    result = run_python(
        "import base64, hmac, json, sys, urllib.parse as up\n"
        "data = sys.stdin.read()\n"
        "print(base64.b64decode(data).decode(), hmac.new(b'k', b'm', 'sha256').hexdigest()[:8],"
        " up.quote('a b'))\n"
        "open('scratch.txt', 'w').write('ok'); print(open('scratch.txt').read())",
        stdin="aGk=",
    )
    assert result["isolation"] == "jail+netns+audit"
    assert result["exit_code"] == 0
    assert result["stdout"].splitlines() == ["hi b60090e3 a%20b", "ok"]


@needs_jail
@pytest.mark.parametrize("code,fragment", [
    ("import socket", "import socket"),
    ("import urllib.request; urllib.request.urlopen('http://example.com')", "not allowed"),
    ("print(open('/etc/passwd').read())", "outside the run folder"),
    ("import os; os.system('id')", "os.system"),
    ("import os; os.fork()", "os.fork"),
    ("import _posixsubprocess", "_posixsubprocess"),
    ("import ctypes", "ctypes"),
    ("open('/tmp/x', 'w').write('x')", "outside the run folder"),
    ("import os; os.chdir('/')", "os.chdir"),
    ("open('evil.py','w').write('print(1)')\nimport sys; sys.path.insert(0, '.'); import evil",
     "run folder"),
])
def test_escapes_are_blocked(code, fragment):
    result = run_python(code, timeout=5)
    assert result["exit_code"] != 0
    assert fragment in result["stderr"]


@needs_jail
def test_the_jail_hides_host_files_and_bounds_time():
    view = run_python("import posix; print(sorted(posix.listdir('/work')), posix.getcwd())")
    assert view["stdout"].strip() == "['main.py'] /work"
    spin = run_python("while True: pass", timeout=1)
    assert spin["exit_code"] != 0


def test_refused_without_isolation(monkeypatch):
    monkeypatch.setattr(script_sandbox, "jail_available", lambda: False)
    with pytest.raises(RuntimeError, match="isolation"):
        run_python("print(1)")
    with pytest.raises(ValueError):
        run_python("x" * (script_sandbox.MAX_CODE_BYTES + 1))


@needs_jail
@pytest.mark.asyncio
async def test_tool_records_evidence_and_enforces_a_run_limit(monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "AGENT_SCRIPT_SANDBOX_MAX_RUNS", 2, raising=False)
    org = current_organization_id.set(1)
    session = current_session_id.set("sandbox-test")
    try:
        manager = ASMToolsManager()
        first = json.loads(await manager.run_sandboxed_script("print(6*7)"))
        assert first["success"] and first["stdout"] == "42\n" and first["evidence_id"]
        failed = json.loads(await manager.run_sandboxed_script("import socket"))
        assert failed["success"] is False and failed["evidence_id"]
        limited = json.loads(await manager.run_sandboxed_script("print(1)"))
        assert "limit" in limited["error"]
    finally:
        current_session_id.reset(session)
        current_organization_id.reset(org)
