"""
Operation directives — Praetorian-style scoped hunt orders.

Each specialist receives a concrete directive (target, goal, pass/kill,
allowed tools, hypothesis ids) instead of only a shared mission dump.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from app.services.agent.aegis_pantheon import epithet_for, pantheon_line


@dataclass
class OperationDirective:
    """Scoped order for one specialist front."""

    specialist: str
    epithet: str
    target: str
    goal: str
    assumption: str = ""
    test: str = ""
    pass_criteria: str = ""
    kill_criteria: str = ""
    allowed_tools: List[str] = field(default_factory=list)
    hypothesis_ids: List[str] = field(default_factory=list)
    max_iterations: int = 6
    priority: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_prompt_block(self) -> str:
        hyps = ", ".join(self.hypothesis_ids) if self.hypothesis_ids else "none"
        tools = ", ".join(self.allowed_tools[:20])
        if len(self.allowed_tools) > 20:
            tools += ", …"
        return (
            f"OPERATION DIRECTIVE — {pantheon_line(self.specialist)}\n"
            f"- Target: {self.target}\n"
            f"- Goal: {self.goal}\n"
            f"- Assumption: {self.assumption or 'n/a'}\n"
            f"- Test: {self.test or 'n/a'}\n"
            f"- PASS: {self.pass_criteria or 'demonstrated impact with evidence'}\n"
            f"- KILL: {self.kill_criteria or 'no impact after disciplined probes'}\n"
            f"- Hypothesis IDs: {hyps}\n"
            f"- Max iterations: {self.max_iterations}\n"
            f"- Priority: {self.priority}\n"
            f"- Allowed tools: {tools}\n"
            "Rules: stay in lane; do not call fireteam_dispatch; "
            "status 200 alone is never a finding; prove with differentials when authz/tenant."
        )


def directives_from_hypotheses(
    *,
    brain: Any,
    profiles_by_name: Dict[str, Any],
    specialists: Iterable[str],
    default_target: str = "",
) -> Dict[str, OperationDirective]:
    """Build per-specialist directives from open/in_progress hypotheses."""
    open_hyps = [
        h for h in getattr(brain, "hypotheses", []) or []
        if getattr(h, "status", "") in ("open", "in_progress")
    ]
    out: Dict[str, OperationDirective] = {}
    for name in specialists:
        profile = profiles_by_name.get(name)
        if not profile:
            continue
        matched = [h for h in open_hyps if getattr(h, "specialist", None) == name]
        if matched:
            h0 = matched[0]
            goal = h0.title
            assumption = h0.assumption
            test = h0.test
            pass_c = h0.pass_criteria
            kill_c = h0.kill_criteria
            hyp_ids = [h.id for h in matched]
            priority = h0.priority
            target = default_target or ""
        else:
            goal = profile.role.split(".")[0][:200]
            assumption = ""
            test = ""
            pass_c = "Demonstrable impact with concrete evidence"
            kill_c = "No impact after lane-appropriate probes"
            hyp_ids = []
            priority = "medium"
            target = default_target or ""
        out[name] = OperationDirective(
            specialist=name,
            epithet=getattr(profile, "epithet", None) or epithet_for(name),
            target=target,
            goal=goal,
            assumption=assumption,
            test=test,
            pass_criteria=pass_c,
            kill_criteria=kill_c,
            allowed_tools=list(profile.allowed_tools),
            hypothesis_ids=hyp_ids,
            max_iterations=int(getattr(profile, "max_iterations", 6) or 6),
            priority=priority,
        )
    return out


def merge_directive_into_mission(mission: str, directive: Optional[OperationDirective]) -> str:
    if not directive:
        return mission
    block = directive.to_prompt_block()
    return f"{mission.strip()}\n\n{block}"
