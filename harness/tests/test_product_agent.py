import asyncio
from types import SimpleNamespace

from local_harness.product_agent import assess


def test_adapter_drives_product_invocation_and_stops_on_user_input(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(tmp_path / "findings.jsonl"))
    args = SimpleNamespace(
        target="https://app.test/",
        scope="app.test",
        user_id=1,
        organization_id=2,
        identities=None,
        max_turns=3,
        max_iterations=8,
        price_limit_usd=1.0,
    )
    calls = []

    async def invoke(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            task_complete=False,
            error=None,
            awaiting_question=True,
            awaiting_approval=False,
        )

    orch = SimpleNamespace(tool_manager=object(), invoke=invoke)
    assert asyncio.run(assess(args, orch)) == 3
    assert len(calls) == 1
    assert calls[0]["organization_id"] == 2
    assert "Scope: app.test" in calls[0]["question"]
    assert (tmp_path / "product_assessment.json").exists()


def test_adapter_can_require_custom_oast(monkeypatch):
    monkeypatch.setattr(
        "app.services.interactsh_service.health",
        lambda: {"success": False, "error": "interactsh-client missing"},
    )
    args = SimpleNamespace(
        target="https://app.test/",
        scope="app.test",
        user_id=1,
        organization_id=2,
        identities=None,
        max_turns=1,
        max_iterations=1,
        price_limit_usd=1.0,
        require_oast=True,
    )
    orch = SimpleNamespace(tool_manager=object())
    try:
        asyncio.run(assess(args, orch))
    except ValueError as exc:
        assert "Custom OAST is required but unavailable" in str(exc)
    else:
        raise AssertionError("required OAST preflight should fail closed")


def test_autonomy_flags_apply_limits_governor_and_delegation(tmp_path, monkeypatch):
    import json

    import httpx

    from app.services.agent.autonomy_limits import current_autonomy_limits

    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(tmp_path / "findings.jsonl"))
    args = SimpleNamespace(
        target="https://app.test/", scope="app.test", user_id=1, organization_id=2,
        identities=None, max_turns=1, max_iterations=4, price_limit_usd=1.0,
        autonomy=True, delegate_replay_approval=True,
    )
    seen = {}

    async def invoke(**kwargs):
        seen["policy"] = kwargs.get("assessment_policy")
        seen["limits"] = current_autonomy_limits.get()
        transport = httpx.MockTransport(lambda r: httpx.Response(200))
        async with httpx.AsyncClient(transport=transport) as client:
            await client.get("https://app.test/a")
            await client.get("https://provider.test/v1")  # not target traffic
        return SimpleNamespace(task_complete=True, error=None,
                               awaiting_question=False, awaiting_approval=False)

    orch = SimpleNamespace(tool_manager=SimpleNamespace(_engagement_brain={
        "replay_approvals": [{"decision": "approved"}, {"decision": "denied"}],
    }), invoke=invoke)
    asyncio.run(assess(args, orch))
    assert seen["policy"] == {"delegated_replay_approval": {"enabled": True}}
    assert seen["limits"].delegate_replay_approval is True
    assert current_autonomy_limits.get() is None  # reset after the run
    summary = json.loads((tmp_path / "product_assessment.json").read_text())
    assert summary["autonomy"]["enabled"] is True
    assert summary["autonomy"]["traffic"]["per_host"] == {"app.test": 1}
    assert summary["autonomy"]["replay_approvals"] == {"approved": 1, "denied": 1}
    assert summary["autonomy"]["delegated_replay_approval"] is True


def test_without_autonomy_flags_nothing_changes(tmp_path, monkeypatch):
    import json

    monkeypatch.setenv("AEGIS_FINDINGS_SINK", str(tmp_path / "findings.jsonl"))
    args = SimpleNamespace(
        target="https://app.test/", scope="app.test", user_id=1, organization_id=2,
        identities=None, max_turns=1, max_iterations=4, price_limit_usd=1.0,
    )
    seen = {}

    async def invoke(**kwargs):
        seen.update(kwargs)
        return SimpleNamespace(task_complete=True, error=None,
                               awaiting_question=False, awaiting_approval=False)

    asyncio.run(assess(args, SimpleNamespace(tool_manager=object(), invoke=invoke)))
    assert "assessment_policy" not in seen
    summary = json.loads((tmp_path / "product_assessment.json").read_text())
    assert summary["autonomy"] == {"enabled": False, "delegated_replay_approval": False}
