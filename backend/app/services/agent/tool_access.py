"""Read-only view of who can call which agent tool, and when.

Answers, for every tool the agent knows about:

  - which phases the main agent may call it in (``TOOL_PHASE_MAP``)
  - which fireteam specialists have it on their allowlist
  - what the org's confirmation policy decides (interactive and autonomous)
  - whether its CLI binary is installed on this worker
  - whether it is built in or a YAML recipe, and whether the denylist checks it

Every answer comes from the same functions the runtime uses, so the view
cannot drift from enforcement.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.services.agent.prompts import TOOL_PHASE_MAP
from app.services.tool_recipes import PHASES, get_recipes, help_tool_names


def _registered_tool_names() -> set[str]:
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    return set(ASMToolsManager._register_tools(manager))


def _installed(name: str) -> Optional[bool]:
    """True/False for CLI-backed tools, None when no external binary is needed."""
    from app.services.mcp.server import get_mcp_server

    server = get_mcp_server()
    if name not in server._HANDLER_BINARY and name != "execute_httpx":
        return None
    return server.tool_binary_available(name)


def build_tool_access(
    policy_cfg: Dict[str, Any],
    *,
    roe_requires_confirmation: bool,
) -> Dict[str, Any]:
    from app.services import agent_denylist
    from app.services.agent.confirmation_service import describe_policy_decision
    from app.services.agent.fireteam_service import (
        DEFAULT_SPECIALISTS,
        OOB_GRANT_TOOLS,
        specialist_tool_list,
    )

    specialists = [
        {
            "name": p.name,
            "epithet": p.epithet,
            "role": p.role.split(". ")[0][:160],
            "tools": specialist_tool_list(p, oob_allowed=True),
        }
        for p in DEFAULT_SPECIALISTS
    ]
    by_tool: Dict[str, List[str]] = {}
    for spec in specialists:
        for tool in spec["tools"]:
            by_tool.setdefault(tool, []).append(spec["name"])

    registered = _registered_tool_names()
    recipes = get_recipes()
    recipe_helps = help_tool_names()
    names = sorted(set(TOOL_PHASE_MAP) | set(by_tool) | registered)

    tools: List[Dict[str, Any]] = []
    for name in names:
        recipe = recipes.get(name) or recipe_helps.get(name)
        tools.append({
            "name": name,
            "source": "recipe" if recipe else "builtin",
            "registered": name in registered,
            "phases": [p for p in PHASES if p in TOOL_PHASE_MAP.get(name, [])],
            "specialists": by_tool.get(name, []),
            "confirmation": describe_policy_decision(
                policy_cfg, name, roe_requires_confirmation=roe_requires_confirmation,
            ),
            "installed": _installed(name),
            "denylist_checked": not agent_denylist.is_exempt(name),
            "requires_grant": "oob_callbacks" if name in OOB_GRANT_TOOLS else None,
        })

    return {
        "phases": list(PHASES),
        "specialists": [{k: v for k, v in s.items() if k != "tools"} for s in specialists],
        "tools": tools,
        "notes": [
            "Specialists are not phase-gated; their allowlist is the boundary.",
            "Per-wave directives and bounded pilot runs narrow these lists further.",
            "Bounded informational Nuclei templates and login crawls have argument-specific approval rules.",
        ],
    }
