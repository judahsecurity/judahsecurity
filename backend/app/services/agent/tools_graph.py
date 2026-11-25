"""Facts-and-intents graph tools (attack_graph.py) for the Prowl agent.

Mixin for ASMToolsManager; declared with tool specs (tool_specs.py).
"""

import json
from typing import Any, List, Optional

from app.services.agent.tool_specs import ALL_PHASES, read_tool, write_tool


def _as_list(value: Any) -> List[str]:
    if isinstance(value, str):
        return [v.strip() for v in value.replace(",", " ").split() if v.strip()]
    return [str(v).strip() for v in (value or []) if str(v).strip()]


class AttackGraphToolsMixin:
    """Facts, intents and lineage on the engagement brain."""

    def _graph_brain(self):
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if not brain.target:
            brain.target = str(getattr(self, "_fallback_target", "") or "")
        return brain

    def _graph_save(self, brain) -> None:
        self._engagement_brain = brain.to_dict()

    def _graph_scope(self, url: str) -> Optional[str]:
        from app.services.agent.assessment_scope import assert_url_in_scope

        try:
            assert_url_in_scope(self, url)
        except ValueError as exc:
            return str(exc)
        return None

    async def graph_overview(self, **_kwargs: Any) -> str:
        """Planner snapshot of facts, open/claimed intents with lineage and finding count."""
        from app.services.agent.attack_graph import ensure_origin_fact, overview

        brain = self._graph_brain()
        if brain.target:
            ensure_origin_fact(brain, brain.target)
            self._graph_save(brain)
        return json.dumps(overview(brain), default=str)[:12000]

    async def record_fact(self, kind: str, summary: str, target: str = "",
                          evidence_ids: Any = None, parents: Any = None, source: str = "",
                          **_kwargs: Any) -> str:
        """Record an observation as a fact (cite parent fact/intent/finding ids)."""
        from app.services.agent.attack_graph import LineageError, record_fact

        if target:
            denied = self._graph_scope(target) if "://" in target else None
            if denied:
                return json.dumps({"error": f"out of scope: {denied}"})
        brain = self._graph_brain()
        try:
            fact = record_fact(brain, kind=kind, summary=summary, target=target,
                               evidence_ids=_as_list(evidence_ids), parents=_as_list(parents),
                               source=source or "agent")
        except (LineageError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        self._graph_save(brain)
        return json.dumps({"fact": fact}, default=str)

    async def add_intent(self, test_type: str, target: str, parents: Any, objective: str = "",
                         parameter: str = "", location: str = "", method: str = "GET",
                         identity: str = "", **_kwargs: Any) -> str:
        """Plan one test; it must cite an existing fact or finding."""
        from app.services.agent.attack_graph import LineageError, add_intent

        denied = self._graph_scope(target)
        if denied:
            return json.dumps({"error": f"out of scope: {denied}"})
        brain = self._graph_brain()
        try:
            intent = add_intent(brain, objective=objective, test_type=test_type, target=target,
                                parents=_as_list(parents), parameter=parameter, location=location,
                                method=method, identity=identity, created_by="agent")
        except (LineageError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        self._graph_save(brain)
        return json.dumps({"intent": intent}, default=str)

    async def claim_intent(self, intent_id: str, worker: str = "agent", **_kwargs: Any) -> str:
        """Claim one open intent before working it."""
        from app.services.agent.attack_graph import claim_intent

        brain = self._graph_brain()
        try:
            intent = claim_intent(brain, intent_id, worker)
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        self._graph_save(brain)
        return json.dumps({"intent": intent}, default=str)

    async def complete_intent(self, intent_id: str, result_facts: Any, worker: str = "agent",
                              status: str = "done", note: str = "", **_kwargs: Any) -> str:
        """Close a claimed intent, citing the facts its work produced."""
        from app.services.agent.attack_graph import LineageError, complete_intent

        brain = self._graph_brain()
        try:
            intent = complete_intent(brain, intent_id, worker, result_facts=_as_list(result_facts),
                                     status=status, note=note)
        except (LineageError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        self._graph_save(brain)
        return json.dumps({"intent": intent}, default=str)


GRAPH_SECTION = "Attack Graph (facts and intents; planning state, never proof)"
TOOL_SECTION_NOTES = {
    GRAPH_SECTION: (
        "Record what you observed as facts and plan each test as an intent that cites the "
        "fact or finding it comes from. Claim an intent before working it and complete it "
        "with the result facts. Confirmation still needs submit_finding_candidate and the "
        "independent verifier."
    ),
}

TOOL_SPECS = (
    read_tool(
        "graph_overview",
        "Facts, open and claimed intents (with lineage), and finding count for this "
        "engagement. No args. Call it before planning new work.",
        phases=ALL_PHASES, section=GRAPH_SECTION, concurrent=False,
    ),
    write_tool(
        "record_fact",
        "Record an observation. Args: **kind** (observation | evidence | operator | callback "
        "| replay | verdict | parser), **summary**, target (in-scope URL), evidence_ids, "
        "parents (fact, intent or finding ids; defaults to the engagement origin), source. "
        "Example: record_fact(kind=\"evidence\", summary=\"/api/orders/1 returns another "
        "user's order\", evidence_ids=[\"ev-12\"], parents=[\"intent-abc\"])",
        phases=ALL_PHASES, section=GRAPH_SECTION,
    ),
    write_tool(
        "add_intent",
        "Plan one test. Args: **test_type** (coverage class, e.g. sqli, xss, authz, ssrf), "
        "**target** (absolute in-scope URL), **parents** (existing fact or finding ids; "
        "required), parameter, location (query | body_form | body_json | body_xml | header | "
        "cookie | path | fragment), method, identity, objective. Backs the intent with a "
        "coverage cell so scoped probes can lease it. The same test on the same input "
        "returns the existing intent.",
        phases=ALL_PHASES, section=GRAPH_SECTION,
    ),
    write_tool(
        "claim_intent",
        "Claim an open intent before working it. Args: **intent_id**, worker (your lane name).",
        phases=ALL_PHASES, section=GRAPH_SECTION,
    ),
    write_tool(
        "complete_intent",
        "Close a claimed intent. Args: **intent_id**, **result_facts** (fact ids recorded by "
        "the work; required for done), worker, status (done | blocked | cancelled), note.",
        phases=ALL_PHASES, section=GRAPH_SECTION,
    ),
)
