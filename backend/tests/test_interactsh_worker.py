import importlib.util
import json
import signal
import sys
from pathlib import Path

from app.workers import interactsh_worker


class _FakeRedis:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.deleted = None

    def rpush(self, key, request):
        self.request = (key, json.loads(request))

    def blpop(self, key, timeout):
        if self.response is None:
            return None
        return key, json.dumps(self.response)

    def delete(self, key):
        self.deleted = key


def test_rpc_healthcheck_requires_successful_worker_response(monkeypatch):
    fake = _FakeRedis({"success": True})
    monkeypatch.setattr(
        interactsh_worker.redis.Redis,
        "from_url",
        lambda *args, **kwargs: fake,
    )

    assert interactsh_worker.rpc_healthcheck() is True
    assert fake.request[0] == interactsh_worker.REQUEST_QUEUE
    assert fake.request[1]["operation"] == "health"
    assert fake.deleted == fake.request[1]["response_key"]


def test_rpc_healthcheck_rejects_missing_worker_response(monkeypatch):
    fake = _FakeRedis(None)
    monkeypatch.setattr(
        interactsh_worker.redis.Redis,
        "from_url",
        lambda *args, **kwargs: fake,
    )

    assert interactsh_worker.rpc_healthcheck() is False


def test_register_checkpoints_session_before_return(monkeypatch, tmp_path):
    ish = interactsh_worker.interactsh_service
    processes = []
    session_path = None

    class _Process:
        def __init__(self, command, first):
            nonlocal session_path
            session_path = command[command.index("-sf") + 1]
            self.stdout = iter(
                ["[INF] abc123def45678901234.oast.fun\n"] if first else []
            )
            self.returncode = None
            self.signal = None

        def poll(self):
            return self.returncode

        def send_signal(self, sent):
            self.signal = sent
            Path(session_path).write_text("saved-session", encoding="utf-8")
            self.returncode = 1

        def wait(self, timeout=None):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def kill(self):
            self.returncode = -9

    def _popen(command, **_kwargs):
        process = _Process(command, first=not processes)
        processes.append(process)
        return process

    monkeypatch.setenv("AEGIS_INTERACTSH_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(ish, "_binary", lambda: "/usr/local/bin/interactsh-client")
    monkeypatch.setattr(ish.subprocess, "Popen", _popen)
    ish._SESSIONS.clear()
    try:
        result = ish.register()
        assert result["success"] is True
        assert len(processes) == 2
        assert processes[0].signal == signal.SIGINT
        assert Path(session_path).read_text(encoding="utf-8") == "saved-session"
        assert ish._SESSIONS[result["session_id"]].proc is processes[1]
    finally:
        for sid in list(ish._SESSIONS):
            ish.stop(sid)


def test_live_canary_reports_worker_health_failure_without_keyerror(monkeypatch):
    script_path = Path(__file__).resolve().parents[1] / "scripts" / "check_interactsh.py"
    spec = importlib.util.spec_from_file_location("check_interactsh_test", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module.interactsh_service,
        "health",
        lambda: {"success": False, "error": "worker unavailable"},
    )

    assert module.main(["--live"]) == 1
