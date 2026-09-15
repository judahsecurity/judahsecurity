import importlib.util
import json
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
