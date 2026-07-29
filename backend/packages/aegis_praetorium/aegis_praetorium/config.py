"""
aegis_praetorium.config — runtime configuration for Lictor / Censor / Augur.

Two configuration modes:

  1. Programmatic (preferred when the host has its own settings system, e.g.
     the platform agent's pydantic ``app.core.config.settings``):

         from aegis_praetorium import PraetoriumConfig, set_config
         set_config(PraetoriumConfig(lictor_enabled=settings.AGENT_LICTOR_ENABLED, ...))

  2. Environment variables (preferred for the Aegis Vanguard container):

         AEGIS_LICTOR_ENABLED=true
         AEGIS_CENSOR_ENABLED=true
         AEGIS_AUGUR_ENABLED=true
         AEGIS_AUGUR_VERBOSE=false
         AEGIS_ENFORCE_SCOPE=false
         AEGIS_RATE_CAPACITY=30
         AEGIS_RATE_PER_MINUTE=30
         AEGIS_TOOL_OUTPUT_MAX_CHARS=20000

If no ``set_config`` call is made and no env vars are set, defaults apply
(everything on except scope enforcement).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional


@dataclass(frozen=True)
class PraetoriumConfig:
    """All runtime tunables for the Aegis guard layer."""

    lictor_enabled: bool = True
    censor_enabled: bool = True
    augur_enabled: bool = True
    augur_verbose: bool = False              # if True, keep raw_output beside Augur reading
    enforce_scope: bool = False              # use the registered ScopeResolver?
    rate_capacity: int = 30                  # token bucket burst size
    rate_per_minute: int = 30                # token bucket sustained refill
    tool_output_max_chars: int = 20_000      # Augur output cap


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def load_from_env() -> PraetoriumConfig:
    """Build a config from AEGIS_* env vars, falling back to defaults."""
    return PraetoriumConfig(
        lictor_enabled=_env_bool("AEGIS_LICTOR_ENABLED", True),
        censor_enabled=_env_bool("AEGIS_CENSOR_ENABLED", True),
        augur_enabled=_env_bool("AEGIS_AUGUR_ENABLED", True),
        augur_verbose=_env_bool("AEGIS_AUGUR_VERBOSE", False),
        enforce_scope=_env_bool("AEGIS_ENFORCE_SCOPE", False),
        rate_capacity=_env_int("AEGIS_RATE_CAPACITY", 30),
        rate_per_minute=_env_int("AEGIS_RATE_PER_MINUTE", 30),
        tool_output_max_chars=_env_int("AEGIS_TOOL_OUTPUT_MAX_CHARS", 20_000),
    )


_config: Optional[PraetoriumConfig] = None
_config_lock = Lock()


def set_config(config: PraetoriumConfig) -> None:
    """Replace the active config. Thread-safe."""
    global _config
    with _config_lock:
        _config = config


def get_config() -> PraetoriumConfig:
    """Return the active config. Initializes from env on first call."""
    global _config
    if _config is None:
        with _config_lock:
            if _config is None:
                _config = load_from_env()
    return _config


__all__ = [
    "PraetoriumConfig",
    "get_config",
    "set_config",
    "load_from_env",
]
