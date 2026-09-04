"""
MCP server — expose Vanguard's arsenal to any MCP client, our way.

HexStrike's model is to expose 150+ tools over the Model Context Protocol so any
LLM client can drive them. The course's own critique of that family: they
"expose every tool at once with no methodology guiding the model." So this is
deliberately *not* a dump-everything bridge. It exposes a **curated, guardrailed
surface that leads with our sharp process**:

  * Process/knowledge tools are always on and listed first — `search_prior_art`
    (proven techniques), `suggest_remediation` (CWE-mapped fixes),
    `lookup_cves` (live NVD intel), `brain_query` (engagement memory). An
    external agent driving Vanguard gets our methodology, not just our scanners.
  * Scanners are risk-gated: only `safe`/`low` recon is exposed by default.
    Active-exploit tools (`medium`+: sqlmap, XSStrike, wpscan, DOM-XSS, PoC
    confirmation) are **off** unless `AEGIS_MCP_ALLOW_EXPLOIT=true` — the same
    authorize-before-you-attack posture as the CLI.
  * Every call an MCP client makes is routed through the same
    `GuardrailEngine` the ReAct loop uses, and any tool not in the exposed
    manifest is refused — an external client cannot reach a hidden tool.

The MCP runtime (`mcp` SDK) is an optional dependency: this module imports fine
without it; only ``serve()`` needs it. The manifest/dispatch logic is pure and
unit-tested.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from agent.tools import ToolRegistry
from agent.guardrails import GuardrailEngine

logger = logging.getLogger("agent.mcp_server")

# Our "sharp process" — always exposed, listed first, regardless of risk gate.
PROCESS_TOOLS = (
    "search_prior_art",
    "suggest_remediation",
    "lookup_cves",
    "brain_query",
)

# Never exposed over MCP: session handoffs and platform-coupled sinks.
_DENY = {
    "submit_findings_to_platform",
}

_RISK_ORDER = ["safe", "low", "medium", "high", "critical"]


def _risk_leq(risk: str, max_risk: str) -> bool:
    try:
        return _RISK_ORDER.index(risk) <= _RISK_ORDER.index(max_risk)
    except ValueError:
        return False


def build_manifest(
    registry: Optional[ToolRegistry] = None,
    max_risk: str = "low",
    include_exploit: bool = False,
) -> List[Dict[str, Any]]:
    """Return the curated MCP tool manifest (descriptors), process tools first.

    ``max_risk`` gates scanners; ``include_exploit`` lifts the gate to
    ``critical``. Descriptors are MCP-shaped: ``{name, description, inputSchema}``.
    """
    reg = registry or ToolRegistry()
    effective_max = "critical" if include_exploit else max_risk

    exposed: List[str] = []
    seen = set()

    # 1. Process/knowledge tools always on, in declared order.
    for name in PROCESS_TOOLS:
        if reg.get(name) and name not in _DENY and name not in seen:
            exposed.append(name)
            seen.add(name)

    # 2. Risk-gated scanners/utility tools, excluding handoffs and denies.
    for tool in sorted(reg.all_tools(), key=lambda t: (t.category, t.name)):
        name = tool.name
        if name in seen or name in _DENY or name.startswith("handoff_"):
            continue
        if not _risk_leq(tool.risk_level, effective_max):
            continue
        exposed.append(name)
        seen.add(name)

    manifest: List[Dict[str, Any]] = []
    for name in exposed:
        schema = reg.get(name).to_anthropic_schema()
        manifest.append({
            "name": schema["name"],
            "description": schema["description"],
            "inputSchema": schema["input_schema"],
        })
    return manifest


def exposed_names(
    registry: Optional[ToolRegistry] = None,
    max_risk: str = "low",
    include_exploit: bool = False,
) -> set:
    return {t["name"] for t in build_manifest(registry, max_risk, include_exploit)}


def dispatch(
    name: str,
    arguments: Dict[str, Any],
    registry: Optional[ToolRegistry] = None,
    guardrails: Optional[GuardrailEngine] = None,
    allowed: Optional[set] = None,
) -> Dict[str, Any]:
    """Execute one MCP tool call under our safety posture.

    Returns ``{"content": <str>, "isError": <bool>}``. Refuses any tool not in
    the exposed manifest, and runs the same guardrail checks as the ReAct loop.
    """
    reg = registry or ToolRegistry()
    allow = allowed if allowed is not None else exposed_names(reg)

    if name not in allow:
        return {
            "content": json.dumps({
                "error": "tool_not_exposed",
                "detail": f"{name!r} is not part of the exposed Vanguard MCP "
                          "surface (raise AEGIS_MCP_ALLOW_EXPLOIT or check the "
                          "tool name).",
            }),
            "isError": True,
        }

    tool = reg.get(name)
    if tool is None:
        return {"content": json.dumps({"error": f"unknown tool: {name}"}),
                "isError": True}

    gr = guardrails or GuardrailEngine()
    violation = gr.check_tool_call(name, arguments, tool.risk_level)
    if violation:
        logger.warning("MCP guardrail block: %s on %s", violation.rule, name)
        return {
            "content": json.dumps({
                "error": "blocked_by_guardrail",
                "rule": violation.rule,
                "description": violation.description,
            }),
            "isError": True,
        }

    try:
        result = reg.execute(name, arguments)
    except Exception as exc:  # pragma: no cover - registry already guards
        return {"content": json.dumps({"error": str(exc)}), "isError": True}
    return {"content": result, "isError": False}


def serve(max_risk: str = "low", include_exploit: Optional[bool] = None) -> None:
    """Start the MCP stdio server. Requires the optional ``mcp`` SDK.

    Import all Vanguard tools first so the registry is populated, then serve the
    curated manifest with guardrailed dispatch.
    """
    if include_exploit is None:
        include_exploit = os.environ.get("AEGIS_MCP_ALLOW_EXPLOIT", "").lower() \
            in ("1", "true", "yes")

    import agent.agents  # noqa: F401 — registers @security_tool functions

    try:
        import asyncio
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        import mcp.types as types
    except ImportError as exc:
        raise RuntimeError(
            "MCP SDK not installed. Install with `pip install mcp` to expose "
            "Vanguard over the Model Context Protocol."
        ) from exc

    registry = ToolRegistry()
    guardrails = GuardrailEngine()
    allow = exposed_names(registry, max_risk, include_exploit)
    manifest = build_manifest(registry, max_risk, include_exploit)
    logger.info(
        "Vanguard MCP: exposing %d tools (exploit=%s): %s",
        len(manifest), include_exploit, ", ".join(sorted(allow)),
    )

    server = Server("aegis-vanguard")

    @server.list_tools()
    async def _list_tools() -> list:  # type: ignore[no-untyped-def]
        return [
            types.Tool(
                name=t["name"],
                description=t["description"],
                inputSchema=t["inputSchema"],
            )
            for t in manifest
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict) -> list:  # type: ignore[no-untyped-def]
        out = dispatch(name, arguments or {}, registry, guardrails, allow)
        return [types.TextContent(type="text", text=out["content"])]

    async def _run() -> None:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    serve()


__all__ = [
    "PROCESS_TOOLS",
    "build_manifest",
    "exposed_names",
    "dispatch",
    "serve",
]
