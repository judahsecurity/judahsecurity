"""
aegis_praetorium — Aegis Vanguard's deterministic guard layer.

Houses the three shared "magistrate" components that sit between every agent
(the platform agent in `backend/` and the Aegis Vanguard agent in `aegis-vanguard/`)
and every security tool invocation:

    Censor  — input validator (rejects malformed / dangerous arguments early)
    Lictor  — pre/post tool-execution enforcer (SSRF, scope, destructive flags,
              safe defaults, rate limit, audit log)
    Augur   — output interpreter (smart per-tool filters that retain actionable
              info/low findings and emit deterministic next-step pivots)

The package is intentionally dependency-free (stdlib only). Configuration is
either programmatic (see ``set_config``) or read from environment variables
(see ``aegis_praetorium.config.load_from_env``). Scope enforcement is
pluggable via a ``ScopeResolver`` protocol so each agent can plug in its own
resolution strategy (DB lookup in the platform, --scope flag in Aegis Vanguard).
"""

from aegis_praetorium.augur import (
    Augur,
    AugurReading,
    NextStep,
    get_augur,
)
from aegis_praetorium.censor import (
    Censor,
    CensorVerdict,
    FieldSchema,
    ToolSchema,
    get_censor,
)
from aegis_praetorium.config import (
    PraetoriumConfig,
    get_config,
    load_from_env,
    set_config,
)
from aegis_praetorium.lictor import (
    HookContext,
    HookResult,
    Lictor,
    PostHookContext,
    PostHookResult,
    get_lictor,
)
from aegis_praetorium.scope import (
    AllowAllResolver,
    HostListResolver,
    ScopeResolver,
    get_scope_resolver,
    set_scope_resolver,
)

__all__ = [
    # Lictor
    "Lictor",
    "HookContext",
    "HookResult",
    "PostHookContext",
    "PostHookResult",
    "get_lictor",
    # Censor
    "Censor",
    "CensorVerdict",
    "ToolSchema",
    "FieldSchema",
    "get_censor",
    # Augur
    "Augur",
    "AugurReading",
    "NextStep",
    "get_augur",
    # Config
    "PraetoriumConfig",
    "get_config",
    "load_from_env",
    "set_config",
    # Scope
    "ScopeResolver",
    "AllowAllResolver",
    "HostListResolver",
    "get_scope_resolver",
    "set_scope_resolver",
]
