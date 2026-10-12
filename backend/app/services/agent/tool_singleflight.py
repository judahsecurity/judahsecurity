"""Share one in-flight read/recon tool call across concurrent specialists.

This intentionally has no completed-result cache: a later call may need fresh
target state, and a verifier must always execute its own proof.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


# These calls can be expensive but an identical concurrent invocation has no
# useful independent side effect. Browser actions, HTTP mutations, candidate
# submission, and verification are deliberately excluded.
SHAREABLE_TOOLS = frozenset({
    "execute_httpx",
    "execute_wafw00f",
    "execute_whatweb",
    "execute_katana",
    "execute_feroxbuster",
    "execute_arjun",
    "execute_nuclei",
    "execute_nikto",
    "execute_wpscan",
    "discover_parameters",
})


class ToolSingleFlight:
    """Coalesce identical calls on one agent run and event loop."""

    def __init__(self) -> None:
        self._running: dict[str, asyncio.Task[dict[str, Any]]] = {}

    async def run(
        self,
        key: str,
        operation: Callable[[], Awaitable[dict[str, Any]]],
    ) -> tuple[dict[str, Any], bool]:
        """Return (result, reused); a cancelled owner cancels the shared call."""
        task = self._running.get(key)
        if task is not None:
            # A follower stopping must not cancel the owner's approved work.
            return await asyncio.shield(task), True

        task = asyncio.create_task(operation())
        self._running[key] = task
        try:
            return await task, False
        finally:
            if self._running.get(key) is task:
                del self._running[key]
