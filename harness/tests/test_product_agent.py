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
