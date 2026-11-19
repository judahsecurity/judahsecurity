"""Provider cooldown: stop every caller re-trying an LLM provider that just failed.

Each Prowl model call goes through ``ResilientFallbackChatModel``, which walks
its provider chain on billing, quota or bad-key errors. Without shared state,
every specialist and every turn starts at the dead provider again, paying a
failed request (and its latency) each time.

This module keeps a process-wide cooldown per (organization, provider):

* a billing/quota/auth failure trips the provider immediately;
* repeated trips step the cooldown up: 1 min, 5 min, 30 min;
* a success clears it.

A cooling provider moves to the back of the chain rather than being removed,
so if every option is cooling the call still tries them (soonest-expiring
first) instead of failing outright, and a fixed key recovers on its own.
"""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional, Sequence, TypeVar

STEPS_SECONDS = (60.0, 300.0, 1800.0)
T = TypeVar("T")


def provider_of(label: str) -> str:
    return (label or "").split(":", 1)[0].strip().lower() or "unknown"


class ProviderCooldowns:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        # key -> (cooling_until, consecutive_trips)
        self._state: dict[str, tuple[float, int]] = {}

    @staticmethod
    def _key(scope: str, label: str) -> str:
        return f"{scope}|{provider_of(label)}"

    def trip(self, scope: str, label: str) -> float:
        """Record a failure; return the cooldown in seconds."""
        key = self._key(scope, label)
        with self._lock:
            _, trips = self._state.get(key, (0.0, 0))
            seconds = STEPS_SECONDS[min(trips, len(STEPS_SECONDS) - 1)]
            self._state[key] = (self._clock() + seconds, trips + 1)
        return seconds

    def clear(self, scope: str, label: str) -> None:
        with self._lock:
            self._state.pop(self._key(scope, label), None)

    def remaining(self, scope: str, label: str) -> float:
        with self._lock:
            until, _ = self._state.get(self._key(scope, label), (0.0, 0))
        return max(0.0, until - self._clock())

    def order(self, scope: str, items: Sequence[T], labels: Sequence[str]) -> list[tuple[T, str]]:
        """Ready providers in their configured order, then cooling ones, soonest first."""
        pairs = list(zip(items, labels))
        ready = [(item, label) for item, label in pairs if self.remaining(scope, label) <= 0]
        cooling = [(item, label) for item, label in pairs if self.remaining(scope, label) > 0]
        cooling.sort(key=lambda pair: self.remaining(scope, pair[1]))
        return ready + cooling

    def reset(self) -> None:
        with self._lock:
            self._state.clear()


provider_cooldowns = ProviderCooldowns()


def scope_for(organization_id: Optional[int]) -> str:
    return f"org:{organization_id}" if organization_id is not None else "global"


__all__ = ["ProviderCooldowns", "STEPS_SECONDS", "provider_cooldowns", "provider_of", "scope_for"]
