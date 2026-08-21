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
  - (AgentChain)-[:TARGETS]->(Asset/IP/Domain)  — bridge to recon graph
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

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
) -> None:
    """Record a ChainFinding linked to the step that produced it."""
    driver = _get_driver()
    if not driver:
        return
    try:
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
                """,
                sid=session_id, iter=iteration,
                ftype=finding_type, sev=severity,
                desc=(description or "")[:500], ts=_now_iso(),
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
                RETURN step.iteration AS iteration, step.phase AS phase,
                       step.tool_name AS tool_name, step.tool_args AS tool_args,
                       step.output_summary AS output_summary,
                       step.success AS success, step.thought AS thought,
                       step.created_at AS created_at,
                       collect(DISTINCT {type: f.finding_type, severity: f.severity, description: f.description}) AS findings,
                       collect(DISTINCT {tool: fail.tool_name, error: fail.error, lesson: fail.lesson}) AS failures
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
