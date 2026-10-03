"""DeepSeek must boot the Aegis agent and retain its scoped PROWL tools."""

import pytest

from app.core.config import settings
from app.services.agent import model_router, prompts
from app.services.agent.orchestrator import AgentOrchestrator


@pytest.mark.asyncio
async def test_deepseek_only_starts_agent_and_exposes_scoped_tools(monkeypatch):
    from app.api.routes.agent import get_agent_status

    for name in (
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "MOONSHOT_API_KEY", "GROQ_API_KEY",
    ):
        monkeypatch.setattr(settings, name, None)
    monkeypatch.setattr(settings, "AI_PROVIDER", "deepseek")
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "test-deepseek-key")
    monkeypatch.setattr(settings, "DEEPSEEK_MODEL", "deepseek-chat")
    monkeypatch.setattr(settings, "PROWL_ASSESSMENT_URL", "http://prowl-assessment:8833")
    monkeypatch.setattr(settings, "PROWL_ADMIN_TOKEN", "test-admin-token")
    monkeypatch.setattr(model_router, "ollama_fallback_available", lambda: False)

    # Constructing the model, tools, and graph does not call the cloud API.
    orchestrator = AgentOrchestrator()
    await orchestrator.initialize()

    assert orchestrator._initialized is True
    assert orchestrator._provider == "deepseek"
    assert orchestrator._model == "deepseek-chat"
    assert orchestrator.llm.primary.openai_api_base == "https://api.deepseek.com/v1"

    status = await get_agent_status()
    assert status["available"] is True
    assert status["provider"] == "deepseek"
    assert status["model"] == "deepseek-chat"
    assert status["providers_configured"]["deepseek"] is True

    manager = orchestrator.tool_manager
    assert callable(manager.get_tool("scoped_assessment_observe"))
    assert callable(manager.get_tool("scoped_assessment_probe"))
    assert "scoped_assessment_observe" in prompts.get_phase_tools("informational")
    assert "scoped_assessment_probe" in prompts.get_phase_tools("exploitation")


def test_global_runtime_selects_configured_deepseek_over_other_keys(monkeypatch):
    monkeypatch.setattr(settings, "AI_PROVIDER", "deepseek")
    monkeypatch.setattr(settings, "DEEPSEEK_API_KEY", "test-deepseek-key")
    monkeypatch.setattr(settings, "ANTHROPIC_API_KEY", "test-anthropic-key")
    assert model_router.global_runtime_model_spec() == (
        "deepseek", settings.DEEPSEEK_MODEL,
    )
