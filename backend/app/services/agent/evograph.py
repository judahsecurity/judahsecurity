"""
EvoGraph — Cross-Session Learning via Neo4j

Stores agent execution chains as a persistent graph so new sessions can
build on intelligence from prior sessions instead of starting from scratch.

Node types:
  - AgentChain       — root node for one conversation session
  - ChainStep        — single tool execution within a chain
  - ChainFinding     — important discovery (vulnerability, credential, etc.)
  - ChainFailure     — failed attempt with lesson learned

Relationships:
  - (AgentChain)-[:HAS_STEP]->(ChainStep)
  - (ChainStep)-[:NEXT_STEP]->(ChainStep)
  - (ChainStep)-[:PRODUCED]->(ChainFinding)
  - (ChainStep)-[:FAILED_WITH]->(ChainFailure)
  - (AgentChain)-[:TARGETS]->(Asset)  — bridge to recon graph (set on the first
    finding about an organization asset)
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from app.core.config import settings

logger = logging.getLogger(__name__)

_driver = None


def _get_driver():
    """Lazy-init Neo4j driver, shared across calls."""
    global _driver
    if _driver is not None:
        return _driver
    try:
        from neo4j import GraphDatabase
        _driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
        _driver.verify_connectivity()
        logger.info("EvoGraph: connected to Neo4j")
        return _driver
    except Exception as e:
        logger.warning(f"EvoGraph: Neo4j unavailable — cross-session learning disabled ({e})")
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Write helpers (fire-and-forget, never block the agent loop)
# ---------------------------------------------------------------------------

def record_chain_start(
    session_id: str,
    organization_id: int,
    user_id: str,
    objective: str,
    mode: str = "assist",
) -> None:
    """Create or update the root AgentChain node for this session."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MERGE (c:AgentChain {session_id: $sid})
                ON CREATE SET
                    c.organization_id = $org,
                    c.user_id         = $uid,
                    c.objective        = $obj,
                    c.mode             = $mode,
                    c.status           = 'running',
                    c.started_at       = $ts,
                    c.step_count       = 0
                ON MATCH SET
                    c.objective = $obj,
                    c.status    = 'running'
                """,
                sid=session_id, org=organization_id, uid=user_id,
                obj=(objective or "")[:500], mode=mode, ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_chain_start error: {e}")


def record_step(
    session_id: str,
    iteration: int,
    phase: str,
    tool_name: Optional[str],
    tool_args: Optional[Dict[str, Any]],
    tool_output_summary: Optional[str],
    success: Optional[bool],
    thought: str,
) -> None:
    """Record a ChainStep and link it to the chain."""
    driver = _get_driver()
    if not driver:
        return
    try:
        args_str = str(tool_args)[:500] if tool_args else ""
        output_str = (tool_output_summary or "")[:1000]
        with driver.session() as s:
            s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})
                CREATE (step:ChainStep {
                    session_id: $sid,
                    iteration:  $iter,
                    phase:      $phase,
                    tool_name:  $tool,
                    tool_args:  $args,
                    output_summary: $output,
                    success:    $success,
                    thought:    $thought,
                    created_at: $ts
                })
                MERGE (c)-[:HAS_STEP]->(step)
                SET c.step_count = $iter
                WITH step
                OPTIONAL MATCH (prev:ChainStep {session_id: $sid, iteration: $prev_iter})
                WHERE prev IS NOT NULL
                MERGE (prev)-[:NEXT_STEP]->(step)
                """,
                sid=session_id, iter=iteration, phase=phase,
                tool=tool_name or "", args=args_str, output=output_str,
                success=success, thought=(thought or "")[:300], ts=_now_iso(),
                prev_iter=iteration - 1,
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_step error: {e}")


def record_finding(
    session_id: str,
    iteration: int,
    finding_type: str,
    severity: str,
    description: str,
    organization_id: Optional[int] = None,
    target: Optional[str] = None,
) -> None:
    """Record a finding and link it to an exact asset in the same organization."""
    driver = _get_driver()
    if not driver:
        return
    try:
        target_value = str(target or "").strip()[:500]
        parsed = urlparse(target_value)
        targets = [target_value] if target_value else []
        if parsed.scheme in {"http", "https"} and parsed.hostname:
            targets.append(parsed.hostname.lower())
        with driver.session() as s:
            s.run(
                """
                MATCH (step:ChainStep {session_id: $sid, iteration: $iter})
                CREATE (f:ChainFinding {
                    session_id:   $sid,
                    finding_type: $ftype,
                    severity:     $sev,
                    description:  $desc,
                    created_at:   $ts
                })
                MERGE (step)-[:PRODUCED]->(f)
                WITH f
                OPTIONAL MATCH (a:Asset {organization_id: $org})
                WHERE a.value IN $targets
                FOREACH (_ IN CASE WHEN a IS NULL THEN [] ELSE [1] END |
                    MERGE (f)-[:ABOUT_ASSET]->(a))
                WITH f, a
                OPTIONAL MATCH (c:AgentChain {session_id: $sid})
                FOREACH (_ IN CASE WHEN a IS NULL OR c IS NULL THEN [] ELSE [1] END |
                    MERGE (c)-[:TARGETS]->(a))
                """,
                sid=session_id, iter=iteration,
                ftype=finding_type, sev=severity,
                desc=(description or "")[:500], ts=_now_iso(),
                org=organization_id or -1, targets=targets,
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_finding error: {e}")


def record_failure(
    session_id: str,
    iteration: int,
    tool_name: str,
    error: str,
    lesson: str,
) -> None:
    """Record a ChainFailure so future sessions know what didn't work."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (step:ChainStep {session_id: $sid, iteration: $iter})
                CREATE (f:ChainFailure {
                    session_id: $sid,
                    tool_name:  $tool,
                    error:      $err,
                    lesson:     $lesson,
                    created_at: $ts
                })
                MERGE (step)-[:FAILED_WITH]->(f)
                """,
                sid=session_id, iter=iteration,
                tool=tool_name, err=(error or "")[:500],
                lesson=(lesson or "")[:500], ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_failure error: {e}")


_LESSONS = (
    (("403", "forbidden", "waf", "blocked by", "cloudflare", "akamai", "incapsula"),
     "blocked by a WAF or access control; vary encoding/transport or test another input instead of repeating"),
    (("401", "unauthorized", "login required", "authentication required"),
     "needs an authenticated identity; establish one before retrying"),
    (("429", "rate limit", "too many requests"),
     "rate limited; slow down or spread requests before retrying"),
    (("timeout", "timed out", "deadline"),
     "timed out; narrow the scope or raise the timeout once, then move on"),
    (("404", "not found", "no such"),
     "the target path/resource does not exist; re-map before retrying"),
    (("connection refused", "unreachable", "name or service not known", "dns", "reset by peer"),
     "target unreachable from the agent; verify host, port and scope"),
    (("unexpected keyword", "missing required", "invalid argument", "invalid_arguments", "validation error"),
     "the tool call was malformed; fix the arguments to match the tool signature"),
    (("out of scope", "not in scope", "scope"),
     "outside the registered scope; do not retry"),
)


def lesson_for_failure(tool_name: str, error: str, tool_args: Any = None) -> str:
    """Turn a tool failure into a reusable instruction for later sessions."""
    text = f"{error or ''}".lower()
    target = ""
    if isinstance(tool_args, dict):
        target = str(tool_args.get("url") or tool_args.get("target") or tool_args.get("host") or "")[:120]
    for markers, advice in _LESSONS:
        if any(m in text for m in markers):
            return f"{tool_name}{' on ' + target if target else ''}: {advice}."[:500]
    first = (error or "unknown error").strip().splitlines()[0][:160]
    return f"{tool_name}{' on ' + target if target else ''} failed ({first}); change approach before retrying."[:500]


def record_specialist_steps(session_id: str, reports: List[Any]) -> int:
    """Record fireteam specialist work under the step that dispatched it.

    (ChainStep)-[:DELEGATED]->(SpecialistStep {specialist, verdict, tools, ...})
    A separate label keeps (session_id, iteration) unique for ChainStep.
    """
    driver = _get_driver()
    if not driver or not reports:
        return 0
    rows = []
    for report in reports:
        calls = list(getattr(report, "tool_calls", None) or [])
        rows.append({
            "specialist": str(getattr(report, "specialist", "") or "")[:64],
            "mission": str(getattr(report, "mission", "") or "")[:300],
            "verdict": str(getattr(report, "verdict", "") or "")[:24],
            "summary": str(getattr(report, "summary", "") or "")[:600],
            "error": str(getattr(report, "error", "") or "")[:300],
            "stop_reason": str(getattr(report, "stop_reason", "") or "")[:24],
            "tool_count": len(calls),
            "tools": list(dict.fromkeys(str(getattr(c, "tool", "")) for c in calls))[:20],
            "failed_tools": sum(1 for c in calls if not getattr(c, "success", True)),
            "hypothesis_ids": [str(h) for h in (getattr(report, "hypothesis_ids", None) or [])][:10],
            "evidence_ids": [e for c in calls for e in (getattr(c, "evidence_ids", None) or [])][:20],
        })
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})-[:HAS_STEP]->(main:ChainStep)
                WITH main ORDER BY main.iteration DESC LIMIT 1
                UNWIND $rows AS row
                CREATE (sub:SpecialistStep {
                    session_id: $sid, iteration: main.iteration,
                    specialist: row.specialist, mission: row.mission, verdict: row.verdict,
                    summary: row.summary, error: row.error, stop_reason: row.stop_reason,
                    tool_count: row.tool_count, tools: row.tools, failed_tools: row.failed_tools,
                    hypothesis_ids: row.hypothesis_ids, evidence_ids: row.evidence_ids,
                    created_at: $ts
                })
                MERGE (main)-[:DELEGATED]->(sub)
                """,
                sid=session_id, rows=rows, ts=_now_iso(),
            )
        return len(rows)
    except Exception as e:
        logger.debug(f"EvoGraph record_specialist_steps error: {e}")
        return 0


def record_chain_end(
    session_id: str,
    status: str = "completed",
    outcome: str = "",
    final_phase: str = "informational",
    iteration_count: int = 0,
) -> None:
    """Finalize the AgentChain node."""
    driver = _get_driver()
    if not driver:
        return
    try:
        with driver.session() as s:
            s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})
                SET c.status          = $status,
                    c.outcome          = $outcome,
                    c.final_phase      = $phase,
                    c.iteration_count  = $iters,
                    c.ended_at         = $ts
                """,
                sid=session_id, status=status,
                outcome=(outcome or "")[:500], phase=final_phase,
                iters=iteration_count, ts=_now_iso(),
            )
    except Exception as e:
        logger.debug(f"EvoGraph record_chain_end error: {e}")


# ---------------------------------------------------------------------------
# Read helpers — cross-session context
# ---------------------------------------------------------------------------

def get_prior_chain_context(
    organization_id: int,
    current_session_id: str,
    max_chains: int = 5,
    max_findings: int = 15,
    max_failures: int = 10,
) -> str:
    """
    Load summaries from prior sessions for the same org.

    Returns a formatted string to inject into the agent's system prompt
    so it starts with accumulated intelligence rather than a blank slate.
    """
    driver = _get_driver()
    if not driver:
        return ""

    try:
        with driver.session() as s:
            # Recent chains
            chains = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})
                WHERE c.session_id <> $cur AND c.status IN ['completed', 'aborted']
                RETURN c.objective AS objective,
                       c.status AS status,
                       c.outcome AS outcome,
                       c.final_phase AS phase,
                       c.iteration_count AS iters,
                       c.started_at AS started
                ORDER BY c.started_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_chains,
            ).data()

            # Key findings (critical + high)
            findings = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})-[:HAS_STEP]->()-[:PRODUCED]->(f:ChainFinding)
                WHERE c.session_id <> $cur
                  AND f.severity IN ['critical', 'high']
                RETURN f.finding_type AS type,
                       f.severity AS severity,
                       f.description AS description
                ORDER BY f.created_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_findings,
            ).data()

            # Lessons learned from failures
            failures = s.run(
                """
                MATCH (c:AgentChain {organization_id: $org})-[:HAS_STEP]->()-[:FAILED_WITH]->(f:ChainFailure)
                WHERE c.session_id <> $cur AND f.lesson <> ''
                RETURN f.tool_name AS tool,
                       f.error AS error,
                       f.lesson AS lesson
                ORDER BY f.created_at DESC
                LIMIT $limit
                """,
                org=organization_id, cur=current_session_id, limit=max_failures,
            ).data()

        if not chains and not findings and not failures:
            return ""

        parts = ["## Prior Session Intelligence\n"]

        if chains:
            parts.append("### Recent Sessions")
            for c in chains:
                status_icon = "completed" if c["status"] == "completed" else "aborted"
                parts.append(
                    f"- [{status_icon}] {(c.get('objective') or '?')[:120]} "
                    f"(phase: {c.get('phase', '?')}, {c.get('iters', 0)} steps)"
                )
                if c.get("outcome"):
                    parts.append(f"  Outcome: {(c.get('outcome') or '')[:200]}")

        if findings:
            parts.append("\n### Key Findings from Prior Sessions")
            for f in findings:
                parts.append(f"- [{f.get('severity')}] {f.get('type')}: {(f.get('description') or '')[:200]}")

        if failures:
            parts.append("\n### Lessons Learned (avoid repeating)")
            for f in failures:
                parts.append(f"- {f.get('tool')}: {(f.get('lesson') or f.get('error') or '')[:200]}")

        return "\n".join(parts)

    except Exception as e:
        logger.debug(f"EvoGraph get_prior_chain_context error: {e}")
        return ""


def get_session_chain(session_id: str) -> Dict[str, Any]:
    """
    Fetch the full attack chain graph for a session.
    Returns nodes and edges suitable for frontend force-graph visualization.
    """
    driver = _get_driver()
    if not driver:
        return {"nodes": [], "edges": [], "meta": {}}

    try:
        with driver.session() as s:
            chain = s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})
                RETURN c.objective AS objective, c.status AS status,
                       c.mode AS mode, c.started_at AS started_at,
                       c.step_count AS step_count, c.final_phase AS final_phase
                """,
                sid=session_id,
            ).single()

            if not chain:
                return {"nodes": [], "edges": [], "meta": {}}

            steps = s.run(
                """
                MATCH (c:AgentChain {session_id: $sid})-[:HAS_STEP]->(step:ChainStep)
                OPTIONAL MATCH (step)-[:PRODUCED]->(f:ChainFinding)
                OPTIONAL MATCH (step)-[:FAILED_WITH]->(fail:ChainFailure)
                OPTIONAL MATCH (step)-[:DELEGATED]->(sub:SpecialistStep)
                RETURN step.iteration AS iteration, step.phase AS phase,
                       step.tool_name AS tool_name, step.tool_args AS tool_args,
                       step.output_summary AS output_summary,
                       step.success AS success, step.thought AS thought,
                       step.created_at AS created_at,
                       collect(DISTINCT {type: f.finding_type, severity: f.severity, description: f.description}) AS findings,
                       collect(DISTINCT {tool: fail.tool_name, error: fail.error, lesson: fail.lesson}) AS failures,
                       collect(DISTINCT {specialist: sub.specialist, verdict: sub.verdict,
                                         summary: sub.summary, tool_count: sub.tool_count,
                                         tools: sub.tools, error: sub.error}) AS specialists
                ORDER BY step.iteration
                """,
                sid=session_id,
            ).data()

            nodes: List[Dict[str, Any]] = []
            edges: List[Dict[str, Any]] = []

            chain_node_id = f"chain-{session_id[:8]}"
            nodes.append({
                "id": chain_node_id,
                "label": (chain["objective"] or "Session")[:60],
                "type": "chain",
                "properties": {
                    "status": chain["status"],
                    "mode": chain["mode"],
                    "started_at": chain["started_at"],
                },
            })

            prev_step_id = None
            for step in steps:
                step_id = f"step-{step['iteration']}"
                findings = [f for f in (step.get("findings") or []) if f.get("type")]
                failures = [f for f in (step.get("failures") or []) if f.get("tool")]
                step_type = "step"
                if failures:
                    step_type = "failure"
                elif findings:
                    sev = next((f["severity"] for f in findings if f.get("severity") in ("critical", "high")), None)
                    step_type = "finding_critical" if sev else "finding"

                tool_label = step.get("tool_name") or "think"
                phase_label = step.get("phase") or ""
                nodes.append({
                    "id": step_id,
                    "label": f"{tool_label}",
                    "type": step_type,
                    "properties": {
                        "iteration": step["iteration"],
                        "phase": phase_label,
                        "tool_name": step.get("tool_name"),
                        "tool_args": step.get("tool_args"),
                        "output_summary": step.get("output_summary"),
                        "success": step.get("success"),
                        "thought": step.get("thought"),
                        "created_at": step.get("created_at"),
                        "findings": findings,
                        "failures": failures,
                    },
                })

                edges.append({
                    "source": chain_node_id if prev_step_id is None else prev_step_id,
                    "target": step_id,
                    "type": "HAS_STEP" if prev_step_id is None else "NEXT_STEP",
                })

                for i, finding in enumerate(findings):
                    fid = f"finding-{step['iteration']}-{i}"
                    nodes.append({
                        "id": fid,
                        "label": f"{finding.get('type', 'finding')}: {(finding.get('description') or '')[:50]}",
                        "type": f"finding_{finding.get('severity', 'info')}",
                        "properties": finding,
                    })
                    edges.append({"source": step_id, "target": fid, "type": "PRODUCED"})

                specialists = [x for x in (step.get("specialists") or []) if x.get("specialist")]
                nodes[-1]["properties"]["specialists"] = specialists
                for i, sub in enumerate(specialists):
                    sid_ = f"specialist-{step['iteration']}-{i}"
                    nodes.append({
                        "id": sid_,
                        "label": f"{sub['specialist']}: {sub.get('verdict') or 'done'} ({sub.get('tool_count') or 0} tools)",
                        "type": "failure" if sub.get("error") else "specialist",
                        "properties": sub,
                    })
                    edges.append({"source": step_id, "target": sid_, "type": "DELEGATED"})

                prev_step_id = step_id

            return {
                "nodes": nodes,
                "edges": edges,
                "meta": {
                    "session_id": session_id,
                    "objective": chain.get("objective"),
                    "status": chain.get("status"),
                    "step_count": chain.get("step_count"),
                    "final_phase": chain.get("final_phase"),
                },
            }

    except Exception as e:
        logger.debug(f"EvoGraph get_session_chain error: {e}")
        return {"nodes": [], "edges": [], "meta": {}}
