"""
Tool Registry for Aegis Vanguard Agent Framework

Provides @security_tool decorator that:
1. Auto-generates Anthropic tool-calling JSON schemas from function signatures
2. Registers tools in a global registry
3. Wraps execution with guardrails and tracing
"""

import inspect
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, get_type_hints

logger = logging.getLogger("agent.tools")

PYTHON_TO_JSON = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    List[str]: "array",
    List[int]: "array",
    List[dict]: "array",
}


@dataclass
class ToolDef:
    """A registered tool that the LLM can call."""
    name: str
    description: str
    category: str
    risk_level: str  # safe, low, medium, high, critical
    function: Callable
    parameters: Dict[str, Any]  # JSON schema
    required_params: List[str] = field(default_factory=list)

    def to_anthropic_schema(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.parameters,
                "required": self.required_params,
            },
        }


class ToolRegistry:
    """Global registry of security tools available to agents."""

    _instance = None
    _tools: Dict[str, ToolDef] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._tools = {}
        return cls._instance

    def register(self, tool: ToolDef):
        self._tools[tool.name] = tool
        logger.debug(f"Registered tool: {tool.name} [{tool.category}/{tool.risk_level}]")

    def get(self, name: str) -> Optional[ToolDef]:
        return self._tools.get(name)

    def get_by_category(self, category: str) -> List[ToolDef]:
        return [t for t in self._tools.values() if t.category == category]

    def get_by_risk(self, max_risk: str) -> List[ToolDef]:
        levels = ["safe", "low", "medium", "high", "critical"]
        max_idx = levels.index(max_risk) if max_risk in levels else len(levels)
        return [t for t in self._tools.values()
                if levels.index(t.risk_level) <= max_idx]

    def all_tools(self) -> List[ToolDef]:
        return list(self._tools.values())

    def to_anthropic_schemas(self, tools: Optional[List[str]] = None) -> List[dict]:
        if tools:
            return [self._tools[n].to_anthropic_schema() for n in tools if n in self._tools]
        return [t.to_anthropic_schema() for t in self._tools.values()]

    def execute(self, name: str, arguments: dict) -> str:
        tool = self._tools.get(name)
        if not tool:
            return json.dumps({"error": f"Unknown tool: {name}"})
        try:
            result = tool.function(**arguments)
            if not isinstance(result, str):
                result = json.dumps(result, default=str)
            return result
        except Exception as e:
            logger.error(f"Tool {name} failed: {e}")
            return json.dumps({"error": str(e)})


def _parse_docstring(doc: str) -> tuple:
    """Extract description and per-param descriptions from a Google-style docstring."""
    if not doc:
        return "", {}
    lines = doc.strip().split("\n")
    desc_lines = []
    param_descs = {}
    in_args = False

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith("args:"):
            in_args = True
            continue
        if stripped.lower().startswith(("returns:", "raises:", "yields:")):
            in_args = False
            continue
        if in_args and ":" in stripped:
            param_name, param_desc = stripped.split(":", 1)
            param_descs[param_name.strip()] = param_desc.strip()
        elif not in_args:
            desc_lines.append(stripped)

    return " ".join(desc_lines).strip(), param_descs


def _python_type_to_json(py_type) -> str:
    if py_type in PYTHON_TO_JSON:
        return PYTHON_TO_JSON[py_type]
    origin = getattr(py_type, "__origin__", None)
    if origin is list:
        return "array"
    if origin is dict:
        return "object"
    return "string"


def security_tool(
    category: str = "recon",
    risk: str = "safe",
    name: Optional[str] = None,
):
    """Decorator to register a function as a security tool for LLM tool-calling.

    Args:
        category: Kill-chain category (recon, exploit, escalation, lateral, exfil, report)
        risk: Risk level (safe, low, medium, high, critical)
        name: Override tool name (default: function name)
    """
    def decorator(func: Callable) -> Callable:
        tool_name = name or func.__name__
        sig = inspect.signature(func)
        hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}
        doc_desc, param_descs = _parse_docstring(func.__doc__ or "")

        properties = {}
        required = []
        for pname, param in sig.parameters.items():
            if pname in ("self", "cls"):
                continue
            py_type = hints.get(pname, str)
            json_type = _python_type_to_json(py_type)
            prop: Dict[str, Any] = {"type": json_type}
            if pname in param_descs:
                prop["description"] = param_descs[pname]
            if param.default is inspect.Parameter.empty:
                required.append(pname)
            elif param.default is not None:
                prop["default"] = param.default
            properties[pname] = prop

        tool_def = ToolDef(
            name=tool_name,
            description=doc_desc or f"Security tool: {tool_name}",
            category=category,
            risk_level=risk,
            function=func,
            parameters=properties,
            required_params=required,
        )
        ToolRegistry().register(tool_def)
        func._tool_def = tool_def
        return func

    return decorator
