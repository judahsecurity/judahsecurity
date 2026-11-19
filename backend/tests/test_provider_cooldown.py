"""Provider cooldown: a provider that fails on billing/auth is skipped by later calls."""

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import HumanMessage

from app.services.agent.model_router import ResilientFallbackChatModel
from app.services.agent.provider_cooldown import ProviderCooldowns, provider_cooldowns


class _Broke(FakeListChatModel):
    calls: int = 0

    def _call(self, *args, **kwargs):
        object.__setattr__(self, "calls", self.calls + 1)
        raise RuntimeError("Your credit balance is too low")

    async def _acall(self, *args, **kwargs):
        return self._call()


def test_stepped_cooldown_and_clear():
    now = [0.0]
    cd = ProviderCooldowns(clock=lambda: now[0])
    assert cd.trip("org:1", "anthropic:x") == 60
    assert cd.trip("org:1", "anthropic:y") == 300  # same provider, same key
    assert cd.trip("org:1", "anthropic:x") == 1800
    assert cd.trip("org:1", "anthropic:x") == 1800
    assert cd.remaining("org:2", "anthropic:x") == 0  # other orgs unaffected
    cd.clear("org:1", "anthropic:x")
    assert cd.remaining("org:1", "anthropic:x") == 0
    cd.trip("org:1", "openai:a")
    now[0] = 61
    assert cd.remaining("org:1", "openai:a") == 0


def test_cooling_providers_move_to_the_back_not_out():
    cd = ProviderCooldowns(clock=lambda: 0.0)
    cd.trip("s", "anthropic:x")
    order = cd.order("s", ["A", "B"], ["anthropic:x", "groq:y"])
    assert order == [("B", "groq:y"), ("A", "anthropic:x")]


def _wrapper(broke):
    good = FakeListChatModel(responses=["ok"] * 10)
    return ResilientFallbackChatModel(
        primary=broke, fallbacks=[good], fallback_labels=["groq:llama"],
        primary_label="anthropic:sonnet", cooldown_scope="org:7",
    )


def test_second_call_skips_the_failed_provider():
    broke = _Broke(responses=["never"])
    llm = _wrapper(broke)
    assert llm.invoke([HumanMessage(content="hi")]).content == "ok"
    assert broke.calls == 1
    assert provider_cooldowns.remaining("org:7", "anthropic:sonnet") > 0
    assert llm.invoke([HumanMessage(content="hi")]).content == "ok"
    assert broke.calls == 1  # not retried while cooling


@pytest.mark.asyncio
async def test_async_path_shares_the_cooldown():
    broke = _Broke(responses=["never"])
    llm = _wrapper(broke)
    assert (await llm.ainvoke([HumanMessage(content="hi")])).content == "ok"
    assert (await llm.ainvoke([HumanMessage(content="hi")])).content == "ok"
    assert broke.calls == 1
