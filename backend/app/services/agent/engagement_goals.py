"""Engagement goals and operator constraints taken from the objective.

An operator who writes "show whether one customer can read another
customer's invoices; do not touch the payments API" has stated an end result
and a boundary. Without them the agent tends to stop at the first finding.

At the start of an assessment the objective is read once (by the model) into:

* goals - end results that would count as success, not steps ("read another
  tenant's invoice", not "enumerate endpoints"), each with an optional
  vulnerability class;
* constraints - allow/deny rules the operator stated, rewritten to name the
  concrete target instead of "this site", never invented.

Each goal must be accounted for before the run counts as complete, the way
coverage cells are: ``prove_goal`` links it to an independently verified
finding candidate, or ``close_goal`` records why it was not achieved after
real attempts. Constraints go to the planner and every specialist as a
high-priority block. They add to Prowl's scope and permission checks; they
never widen them.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Optional

MAX_GOALS = 5
MAX_CONSTRAINTS = 10
MAX_TEXT = 300
MIN_CLOSE_REASON = 40
GOAL_OPEN = "open"
GOAL_MET = "met"
GOAL_NOT_ACHIEVED = "not_achieved"

_GENERIC_WORDS = {
    "a", "an", "the", "and", "or", "of", "for", "to", "on", "in", "at", "against", "with",
    "please", "can", "you", "run", "perform", "do", "start", "begin", "full", "complete",
    "assess", "assessment", "test", "testing", "pentest", "pen", "penetration", "scan",
    "scanning", "audit", "check", "find", "security", "web", "app", "application", "site",
    "website", "target", "vulnerability", "vulnerabilities", "vulns", "issues", "this",
    "it", "my", "our", "all", "any", "url", "host", "domain", "api",
}

GOALS_PROMPT = """You read a penetration-test objective written by the operator.
Return JSON only: {"constraints": [...], "goals": [...]}.

constraints: rules the operator explicitly stated about what may or may not be
done. Each item: {"kind": "allow"|"deny", "text": "..."}.
- Only rules written or clearly emphasised in the objective. Never invent one.
- Make each rule self-contained: replace "this site", "the target", "this port"
  with the concrete host, path or port from the objective.
- When unsure whether a rule allows or forbids, use "deny".

goals: the end results the operator wants demonstrated. Each item:
{"text": "...", "vuln_class": "" or a class such as idor, sqli, xss, ssrf,
authz, auth_bypass, rce, info_disclosure, business_logic}.
- A goal is a deliverable result that evidence can prove, e.g. "read another
  customer's invoice", "access the admin console without credentials".
- Not goals: reconnaissance, scanning, analysis, attack steps, verification.
- One stated result means one goal. List several only for independent results.
- If the objective only names a target to assess, return no goals.
- Never invent goals the operator did not ask for.

Objective:
<<<
{objective}
>>>"""


def objective_states_more_than_a_target(objective: str) -> bool:
    """Cheap pre-check: is there anything beyond "assess <target>"?"""
    text = re.sub(r"https?://\S+", " ", objective or "")
    text = re.sub(r"\b[\w-]+(?:\.[\w-]+)+(?::\d+)?(?:/\S*)?", " ", text)
    words = [word for word in re.findall(r"[A-Za-z][A-Za-z'-]+", text.lower())
             if word not in _GENERIC_WORDS]
    return len(words) >= 3


def _clean(text: Any) -> str:
    return " ".join(str(text or "").split())[:MAX_TEXT]


def _goal_id(text: str) -> str:
    return "goal-" + hashlib.sha1(text.lower().encode()).hexdigest()[:10]


def parse_goals_response(raw: str) -> tuple[list[dict], list[dict]]:
    """Validate the model's JSON. Anything malformed is dropped, not guessed."""
    match = re.search(r"\{.*\}", raw or "", re.S)
    try:
        data = json.loads(match.group(0)) if match else {}
    except ValueError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    goals: list[dict] = []
    for row in data.get("goals") or []:
        text = _clean(row.get("text") if isinstance(row, dict) else row)
        if len(text) < 8 or any(goal["text"].lower() == text.lower() for goal in goals):
            continue
        vuln_class = _clean(row.get("vuln_class") if isinstance(row, dict) else "")[:40]
        goals.append({"id": _goal_id(text), "text": text,
                      "vuln_class": re.sub(r"[^a-z_]", "", vuln_class.lower()),
                      "status": GOAL_OPEN})
        if len(goals) >= MAX_GOALS:
            break
    constraints: list[dict] = []
    for row in data.get("constraints") or []:
        if not isinstance(row, dict):
            continue
        text = _clean(row.get("text"))
        kind = "allow" if row.get("kind") == "allow" else "deny"
        if len(text) < 4 or any(c["text"].lower() == text.lower() for c in constraints):
            continue
        constraints.append({"kind": kind, "text": text})
        if len(constraints) >= MAX_CONSTRAINTS:
            break
    return goals, constraints


async def derive_goals(objective: str, llm: Any) -> tuple[list[dict], list[dict]]:
    from langchain_core.messages import HumanMessage

    prompt = GOALS_PROMPT.replace("{objective}", (objective or "")[:4000])
    response = await llm.ainvoke([HumanMessage(content=prompt)])
    content = getattr(response, "content", response)
    if isinstance(content, list):
        content = "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part)
                          for part in content)
    return parse_goals_response(str(content or ""))


def record_goals(brain: Any, goals: list[dict], constraints: list[dict]) -> None:
    existing = {goal.get("id") for goal in brain.engagement_goals}
    brain.engagement_goals.extend(goal for goal in goals if goal["id"] not in existing)
    seen = {(c.get("kind"), c.get("text", "").lower()) for c in brain.operator_constraints}
    brain.operator_constraints.extend(
        c for c in constraints if (c["kind"], c["text"].lower()) not in seen
    )
    brain.goals_derived = True


def _goal(brain: Any, goal_id: str) -> Optional[dict]:
    return next((goal for goal in brain.engagement_goals if goal.get("id") == goal_id), None)


def prove_goal(brain: Any, goal_id: str, candidate_id: str, reason: str) -> dict:
    """Mark a goal met by an independently verified finding candidate."""
    goal = _goal(brain, goal_id)
    if goal is None:
        raise ValueError(f"Unknown goal {goal_id!r}; call list_engagement_goals")
    if goal.get("status") == GOAL_MET:
        return goal
    candidate = next((row for row in brain.candidates or []
                      if isinstance(row, dict) and row.get("id") == candidate_id), None)
    if candidate is None:
        raise ValueError(f"Unknown finding candidate {candidate_id!r}")
    if candidate.get("status") != "confirmed" or not candidate.get("verified_at"):
        raise ValueError("Only an independently verified (confirmed) candidate can prove a goal")
    reason = _clean(reason)
    if len(reason) < 20:
        raise ValueError("Explain how this candidate demonstrates the goal")
    goal.update(status=GOAL_MET, proof={
        "candidate_id": candidate_id,
        "title": _clean(candidate.get("title")),
        "finding_id": candidate.get("finding_id") or "",
        "evidence_ids": list(candidate.get("evidence_ids") or [])[:10],
        "reason": reason,
        "at": time.time(),
    })
    goal.pop("closed", None)
    return goal


def close_goal(brain: Any, goal_id: str, reason: str) -> dict:
    """Record that a goal was not achieved, and what was tried."""
    goal = _goal(brain, goal_id)
    if goal is None:
        raise ValueError(f"Unknown goal {goal_id!r}; call list_engagement_goals")
    if goal.get("status") == GOAL_MET:
        raise ValueError("This goal is already proven")
    reason = " ".join(str(reason or "").split())[:800]
    if len(reason) < MIN_CLOSE_REASON:
        raise ValueError("Say which routes were tried and why each failed before closing a goal")
    goal.update(status=GOAL_NOT_ACHIEVED, closed={"reason": reason, "at": time.time()})
    return goal


def open_goals(brain: Any) -> list[dict]:
    return [goal for goal in brain.engagement_goals if goal.get("status") == GOAL_OPEN]


def goals_prompt_block(brain: Any) -> str:
    """Goals and constraints for the planner, compact and stable."""
    lines: list[str] = []
    if brain.operator_constraints:
        lines.append("OPERATOR CONSTRAINTS (highest priority; check every action against "
                     "them; they never widen scope):")
        for row in brain.operator_constraints:
            lines.append(f"- {row['kind'].upper()}: {row['text']}")
    if brain.engagement_goals:
        lines.append("ENGAGEMENT GOALS (prove each with a verified candidate via prove_goal, "
                     "or close_goal with the routes tried; a finding alone is not the goal):")
        for goal in brain.engagement_goals:
            extra = f" [{goal['vuln_class']}]" if goal.get("vuln_class") else ""
            lines.append(f"- {goal['id']} ({goal['status']}){extra}: {goal['text']}")
    return "\n".join(lines)


def specialist_block(brain: Any) -> str:
    """The same block for specialists: constraints and open goals only."""
    lines: list[str] = []
    if brain.operator_constraints:
        lines.append("Operator constraints (override every heuristic below; never act "
                     "against them):")
        lines.extend(f"- {row['kind'].upper()}: {row['text']}" for row in brain.operator_constraints)
    goals = open_goals(brain)
    if goals:
        lines.append("Engagement goals (push a confirmed issue toward these results; report "
                     "evidence, the orchestrator links it):")
        lines.extend(f"- {goal['text']}" for goal in goals)
    return "\n".join(lines)
