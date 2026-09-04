"""
Network mode — first-class offline / air-gapped operation.

CAI can run fully offline, which makes it viable for air-gapped labs. We already
had a local-model *fallback* (Ollama, triggered only on a cloud quota error);
this makes offline a deliberate, first-class mode:

  * **Model routing:** in offline mode every agent turn is routed to the local
    Ollama model (see ``AgentRunner._resolve_model``), not just on error.
  * **Network-tool guard:** tools that reach the internet (CVE lookups, WHOIS
    pivots, remote intel) call ``require_online(tool_name)`` and short-circuit
    with a clear, structured "offline" result instead of attempting egress.

Enabled with ``AEGIS_OFFLINE=1`` (or ``--offline`` on run_pentest.py, which sets
the env var). Kept as a tiny module so any tool can consult it without importing
the whole agent core.
"""
from __future__ import annotations

import json
import os
from typing import Optional


def is_offline() -> bool:
    """True when air-gapped/offline mode is enabled."""
    return os.environ.get("AEGIS_OFFLINE", "").lower() in ("1", "true", "yes")


def require_online(tool_name: str) -> Optional[str]:
    """Guard for network-dependent tools.

    Returns a structured JSON error string when offline (the tool should return
    it as-is), or ``None`` when online (the tool should proceed).
    """
    if is_offline():
        return json.dumps({
            "available": False,
            "offline": True,
            "tool": tool_name,
            "error": f"{tool_name} needs network access and AEGIS_OFFLINE is set; "
                     "skipped in air-gapped mode.",
        })
    return None


__all__ = ["is_offline", "require_online"]
