"""
Optional LLM provider adapters for the benchmark judge.

Kept dependency-light: providers are imported lazily so the harness installs
and runs (in heuristic mode) without ``anthropic`` or ``openai`` present.
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from .config import HarnessConfig

LLMCall = Callable[[str, str], str]


def build_llm_call(config: HarnessConfig) -> Optional[LLMCall]:
    """Return an ``(system, user) -> text`` callable, or None if unavailable."""
    backend = config.judge_backend

    if backend == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return None
        try:
            import anthropic
        except ImportError:
            return None

        client = anthropic.Anthropic(api_key=api_key)

        def _call(system: str, user: str) -> str:
            resp = client.messages.create(
                model=config.judge_model,
                max_tokens=config.judge_max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(
                block.text for block in resp.content if getattr(block, "type", "") == "text"
            )

        return _call

    if backend == "openai":
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        try:
            from openai import OpenAI
        except ImportError:
            return None

        client = OpenAI(api_key=api_key)

        def _call(system: str, user: str) -> str:
            resp = client.chat.completions.create(
                model=config.judge_model,
                max_tokens=config.judge_max_tokens,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            )
            return resp.choices[0].message.content or ""

        return _call

    return None
