"""Declarative tool specs for the Prowl agent (AntiFox-style tool registry).

A ``ToolSpec`` declares a tool once: name, one-line documentation, the phases it
is offered in, whether it only reads (and may run concurrently), an optional
permission check, and the ``ASMToolsManager`` method that runs it. The registry
(``ASMToolsManager._register_tools``), the phase map (``prompts.TOOL_PHASE_MAP``)
and the tool docs in the system prompt (``prompts.get_phase_tools``) are derived
from it, so a new tool is one spec next to its implementation instead of three
hand-kept entries.

Legacy tools still live in the hand-written registry, phase map and docs.
``legacy_spec`` describes any of them in the same shape, so callers that need
tool metadata (read-only checks, docs, phases) can ask one place for all tools.

Spec modules list themselves in ``SPEC_MODULES`` and expose ``TOOL_SPECS``.
This module imports nothing from ``tools`` or ``prompts`` so both can use it.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

ALL_PHASES: Tuple[str, ...] = ("informational", "exploitation", "post_exploitation")
ACTIVE_PHASES: Tuple[str, ...] = ("exploitation", "post_exploitation")

# A permission check returns None to allow, or a short refusal reason.
PermissionCheck = Callable[[Any, Dict[str, Any]], Optional[str]]

# Modules that declare TOOL_SPECS, in registration order.
SPEC_MODULES: Tuple[str, ...] = (
    "app.services.agent.tools_ported_probes",
    "app.services.agent.tools_brain",
    "app.services.agent.tools_request_mutation",
    "app.services.agent.tools_graph",
)


@dataclass(frozen=True)
class ToolSpec:
    name: str
    doc: str
    run: str  # ASMToolsManager method name
    phases: Tuple[str, ...] = ALL_PHASES
    read_only: bool = False
    concurrent: bool = False
    section: str = ""
    permission: Optional[PermissionCheck] = None
    schema: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not self.name.replace("_", "").isalnum() or self.name != self.name.lower():
            raise ValueError(f"invalid tool name: {self.name!r}")
        unknown = set(self.phases) - set(ALL_PHASES)
        if not self.phases or unknown:
            raise ValueError(f"{self.name}: invalid phases {sorted(unknown) or '(none)'}")
        if self.concurrent and not self.read_only:
            raise ValueError(f"{self.name}: only read-only tools may run concurrently")
        if not self.doc.strip():
            raise ValueError(f"{self.name}: doc is required")

    def doc_line(self) -> str:
        """The tool's line in the system prompt, in the hand-written docs' format."""
        return f"- **{self.name}**: {' '.join(self.doc.split())}"


def read_tool(name: str, doc: str, run: Optional[str] = None, *,
              phases: Iterable[str] = ALL_PHASES, section: str = "",
              permission: Optional[PermissionCheck] = None,
              concurrent: bool = True, schema: Optional[Dict[str, Any]] = None) -> ToolSpec:
    """A tool that changes no target or platform state (lookups, passive reads)."""
    return ToolSpec(name=name, doc=doc, run=run or name, phases=tuple(phases), read_only=True,
                    concurrent=concurrent, section=section, permission=permission,
                    schema=dict(schema or {}))


def write_tool(name: str, doc: str, run: Optional[str] = None, *,
               phases: Iterable[str] = ACTIVE_PHASES, section: str = "",
               permission: Optional[PermissionCheck] = None,
               schema: Optional[Dict[str, Any]] = None) -> ToolSpec:
    """A tool that sends active test traffic or changes engagement/platform state."""
    return ToolSpec(name=name, doc=doc, run=run or name, phases=tuple(phases), read_only=False,
                    concurrent=False, section=section, permission=permission,
                    schema=dict(schema or {}))


_CACHE: Optional[Tuple[ToolSpec, ...]] = None


def all_specs() -> Tuple[ToolSpec, ...]:
    """Every declared spec, in SPEC_MODULES order. Names must be unique."""
    global _CACHE
    if _CACHE is None:
        specs: List[ToolSpec] = []
        seen: Dict[str, str] = {}
        for module_name in SPEC_MODULES:
            module = importlib.import_module(module_name)
            for spec in getattr(module, "TOOL_SPECS", ()):
                if spec.name in seen:
                    raise ValueError(f"tool {spec.name} declared in {seen[spec.name]} and {module_name}")
                seen[spec.name] = module_name
                specs.append(spec)
        _CACHE = tuple(specs)
    return _CACHE


def get_spec(name: str) -> Optional[ToolSpec]:
    return next((s for s in all_specs() if s.name == name), None)


def spec_phase_map() -> Dict[str, List[str]]:
    return {s.name: list(s.phases) for s in all_specs()}


def section_notes() -> Dict[str, str]:
    """Optional intro text per section heading (modules' TOOL_SECTION_NOTES)."""
    notes: Dict[str, str] = {}
    for module_name in SPEC_MODULES:
        notes.update(getattr(importlib.import_module(module_name), "TOOL_SECTION_NOTES", {}) or {})
    return notes


def spec_docs(phase: str) -> str:
    """Doc block for one phase, grouped under each spec's section heading."""
    sections: Dict[str, List[str]] = {}
    for spec in all_specs():
        if phase in spec.phases:
            sections.setdefault(spec.section or "Additional Tools", []).append(spec.doc_line())
    notes = section_notes()
    out = []
    for title, lines in sections.items():
        note = " ".join(notes.get(title, "").split())
        out.append(f"\n### {title}\n" + (note + "\n" if note else "") + "\n".join(lines) + "\n")
    return "".join(out)


def bind_specs(manager: Any) -> Dict[str, Callable[..., Any]]:
    """name -> bound callable for the manager; permission checks wrap the call."""
    bound: Dict[str, Callable[..., Any]] = {}
    for spec in all_specs():
        method = getattr(manager, spec.run, None)
        if method is None or not callable(method):
            raise AttributeError(f"tool {spec.name}: manager has no method {spec.run}")
        bound[spec.name] = _guarded(manager, spec, method) if spec.permission else method
    return bound


def _guarded(manager: Any, spec: ToolSpec, method: Callable[..., Any]) -> Callable[..., Any]:
    async def call(**kwargs: Any) -> Any:
        reason = spec.permission(manager, dict(kwargs))
        if reason:
            return {"success": False, "error": "permission_denied", "output": reason}
        return await method(**kwargs)

    call.__name__ = spec.name
    call.__doc__ = getattr(method, "__doc__", None)
    call.__wrapped__ = method  # keeps inspect.signature() hints accurate
    return call


# ---------------------------------------------------------------- legacy tools

def legacy_spec(manager: Any, name: str) -> Optional[ToolSpec]:
    """Describe a tool from the hand-written registry in spec form (read-only view).

    read_only is True only for tools the confirmation gate already treats as
    safe recon, or the read-only recovery set; everything else is assumed to
    act. This is metadata, not a new permission rule.
    """
    declared = get_spec(name)
    if declared is not None:
        return declared
    if name not in getattr(manager, "tools", {}):
        return None
    from app.services.agent.prompts import TOOL_PHASE_MAP, all_tool_docs

    doc_line = all_tool_docs().get(name) or ""
    doc = doc_line.split(":", 1)[1].strip() if ":" in doc_line else (
        (getattr(manager.tools[name], "__doc__", "") or "").strip().splitlines() or [name])[0]
    phases = tuple(p for p in TOOL_PHASE_MAP.get(name, ALL_PHASES) if p in ALL_PHASES) or ALL_PHASES
    read_only = is_read_only(name)
    return ToolSpec(name=name, doc=doc or name, run=name, phases=phases, read_only=read_only,
                    concurrent=read_only, section="legacy")


def is_read_only(name: str) -> bool:
    spec = get_spec(name)
    if spec is not None:
        return spec.read_only
    try:
        from app.services.agent.confirmation_service import SAFE_RECON_TOOLS
    except Exception:  # pragma: no cover - import guard
        SAFE_RECON_TOOLS = frozenset()
    return name in SAFE_RECON_TOOLS
