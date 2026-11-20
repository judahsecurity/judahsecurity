"""Explorer sandbox client: availability gating, prechecks, evidence capture."""

import json
from types import SimpleNamespace

import pytest

from app.services.agent import explorer_sandbox as sb
from app.services.agent.assessment_depth import current_assessment_depth, set_assessment_depth


@pytest.fixture
def deep():
    token = set_assessment_depth("deep")
    try:
        yield
    finally:
        current_assessment_depth.reset(token)


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setattr(sb.settings, "PROWL_SANDBOX_URL", "http://prowl-sandbox:8090")
    monkeypatch.setattr(sb.settings, "PROWL_SANDBOX_TOKEN", "x" * 32)


def _manager(**kw):
    m = SimpleNamespace(_assessment_scope={"app.test"}, _fallback_target="https://app.test",
                        _scoped_policy_applied=False, _oob_callbacks_allowed=False,
                        _credential_testing_allowed=False, _explorer_sandbox={})
    for key, value in kw.items():
        setattr(m, key, value)
    return m


def test_unavailable_without_config_or_deep_mode(configured, monkeypatch):
    # deep mode off
    assert "only available in deep" in sb.sandbox_unavailable_reason(_manager())


def test_unavailable_when_not_configured(deep):
    assert "not configured" in sb.sandbox_unavailable_reason(_manager())


def test_unavailable_under_operator_scope_or_no_scope(deep, configured):
    assert "operator method and path" in sb.sandbox_unavailable_reason(
        _manager(_scoped_policy_applied=True))
    assert "No assessment scope" in sb.sandbox_unavailable_reason(
        _manager(_assessment_scope=set(), _fallback_target=""))


def test_available_in_deep_mode_with_scope(deep, configured):
    assert sb.sandbox_unavailable_reason(_manager()) == ""


def test_precheck_blocks_destructive_and_ssrf_and_credential_tools():
    assert "destructive" in sb.precheck("sqlmap -u x --os-shell",
                                        credential_testing=False, oob_callbacks=False)
    assert "metadata" in sb.precheck("curl http://169.254.169.254/",
                                     credential_testing=False, oob_callbacks=False)
    assert "credential testing" in sb.precheck("hydra -l a -P w ssh://x",
                                               credential_testing=False, oob_callbacks=False)
    # Allowed once the operator authorizes credential testing.
    assert sb.precheck("hydra -l a -P w ssh://x",
                       credential_testing=True, oob_callbacks=False) == ""
    # A hostname that merely contains a tool name is not matched as a command.
    assert sb.precheck("curl https://hydra.example.test/",
                       credential_testing=False, oob_callbacks=False) == ""


def test_scope_includes_oob_only_when_authorized(deep, configured):
    assert sb.session_scope(_manager())["oob_suffixes"] == []
    scope = sb.session_scope(_manager(_oob_callbacks_allowed=True))
    assert any("oast" in s or "interact" in s for s in scope["oob_suffixes"])


def test_run_rejects_denied_source_before_any_network(deep, configured, monkeypatch):
    async def fail_post(*a, **k):
        raise AssertionError("must not call the runner on a denied source")

    monkeypatch.setattr(sb, "_post", fail_post)
    import asyncio
    out = asyncio.run(sb.run_in_sandbox(_manager(), kind="shell",
                                        source="sqlmap --os-pwn -u x", timeout_sec=10))
    assert out["ok"] is False and out["blocked_by"] == "sandbox_precheck"


def test_run_records_exchanges_as_evidence_and_summarizes(deep, configured, monkeypatch):
    import asyncio

    manager = _manager()
    published = {}

    async def fake_post(path, payload, timeout):
        return {"exit_code": 0, "timed_out": False, "duration_sec": 1.2,
                "stdout": {"text": "200"}, "stderr": {"text": ""}}

    class FakeRedis:
        def __init__(self): self.store = {}
        def pipeline(self): return self
        def lrange(self, *a): self._op = ("lrange",); return self
        def delete(self, *a): self._op = ("delete",); return self
        def execute(self):
            rows = [json.dumps({"request": {"method": "GET", "url": "https://app.test/x"},
                                "response": {"status": 200, "body": {"bytes": 5}}})]
            return [rows, 1]
        def get(self, *a): return b"7"
        def set(self, *a, **k): pass

    monkeypatch.setattr(sb, "_post", fake_post)
    monkeypatch.setattr(sb, "_redis", lambda: FakeRedis())

    recorded = []
    monkeypatch.setattr(sb, "record_exchanges",
                        lambda m, ex: recorded.append(ex) or [{"evidence_id": "ev1", "url": "https://app.test/x"}])

    out = asyncio.run(sb.run_in_sandbox(manager, kind="shell",
                                        source="curl https://app.test/x", timeout_sec=10))
    assert out["ok"] is True
    assert out["http_exchanges"] == [{"evidence_id": "ev1", "url": "https://app.test/x"}]
    assert out["requests_used"] == 7
    assert recorded and recorded[0][0]["request"]["url"] == "https://app.test/x"
    # The session keeps a stable workspace and token.
    assert set(manager._explorer_sandbox) == {"token", "workspace"}


def test_record_exchanges_uses_the_evidence_store():
    from app.services.agent.evidence_store import evidence_store

    manager = SimpleNamespace()
    store = evidence_store(manager)
    index = sb.record_exchanges(manager, [{
        "request": {"method": "POST", "url": "https://app.test/login"},
        "response": {"status": 401, "body": {"bytes": 12}},
    }])
    assert len(index) == 1 and index[0]["evidence_id"] in store.records
    assert index[0]["status"] == 401
