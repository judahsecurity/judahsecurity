"""
Parallel Specialist Sub-Agents — Fan-Out / Fan-In Runner

Implements the Scatter-Gather ReAct (SG-ReAct) pattern for the vuln phase:
a root phase fans out to N specialist sub-agents that work concurrently,
each running its own multi-step ReAct loop with a focused mission, then
fan back in to merge/dedupe their findings into one consolidated result.

Design notes:
  • Uses a ThreadPoolExecutor so each hunter's sync `AgentRunner.run()`
    loop runs in its own thread. Anthropic's sync client is thread-safe
    (httpx-backed). Full async migration is Phase 2-adjacent.
  • Each hunter gets a deep-copied context to avoid mid-run races; findings
    are merged at fan-in under a lock.
  • Cross-validation: if two hunters independently surface the same finding,
    it's flagged `cross_validated=True` — a strong signal against FPs.
  • Tracing: wraps the whole phase in a `parallel_vuln_phase` span with one
    child span per hunter, recording turns/tool_calls/elapsed/errors.
"""

from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agent.core import Agent, AgentRunner, RunResult

logger = logging.getLogger("agent.parallel")


# =========================================================================
# Result types
# =========================================================================

@dataclass
class HunterResult:
    """Outcome of a single specialist hunter's ReAct loop."""
    name: str
    category: str
    findings: List[dict]
    tool_calls: int
    turns_used: int
    elapsed_sec: float
    coverage_events: List[dict] = field(default_factory=list)
    final_text: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "finding_count": len(self.findings),
            "tool_calls": self.tool_calls,
            "turns_used": self.turns_used,
            "elapsed_sec": round(self.elapsed_sec, 1),
            "coverage_event_count": len(self.coverage_events),
            "error": self.error,
        }


@dataclass
class ParallelVulnResult:
    """Fan-in output of the full parallel vuln phase."""
    hunters: List[HunterResult]
    merged_findings: List[dict]
    total_tool_calls: int
    total_turns: int
    total_elapsed_sec: float  # wall-clock
    serial_elapsed_sec: float  # sum of hunter times (for speedup ratio)

    @property
    def finding_count(self) -> int:
        return len(self.merged_findings)

    @property
    def cross_validated_count(self) -> int:
        return sum(1 for f in self.merged_findings if f.get("cross_validated"))

    @property
    def speedup(self) -> float:
        if self.total_elapsed_sec <= 0:
            return 0.0
        return self.serial_elapsed_sec / self.total_elapsed_sec

    def summary(self) -> dict:
        return {
            "hunters_run": len(self.hunters),
            "hunters_errored": sum(1 for h in self.hunters if h.error),
            "findings_total": self.finding_count,
            "findings_cross_validated": self.cross_validated_count,
            "total_tool_calls": self.total_tool_calls,
            "total_turns": self.total_turns,
            "wall_sec": round(self.total_elapsed_sec, 1),
            "serial_sec": round(self.serial_elapsed_sec, 1),
            "speedup": round(self.speedup, 2),
            "coverage_event_count": sum(len(h.coverage_events) for h in self.hunters),
            "per_hunter": [h.to_dict() for h in self.hunters],
        }


# =========================================================================
# Runner
# =========================================================================

class ParallelVulnPhase:
    """Fans out to N specialist sub-agents via a thread pool, then merges.

    Typical usage (called from run_pentest.py between recon_agent and exploit_agent):

        from agent.owasp_hunters import create_all_hunters
        from agent.parallel_subagents import ParallelVulnPhase

        phase = ParallelVulnPhase(runner, hunters=create_all_hunters())
        result = phase.run(
            task="Hunt your OWASP category against the target.",
            shared_ctx=ctx,
            recon_brief=recon_result.final_text,
        )
        ctx["parallel_vuln_findings"] = result.merged_findings
    """

    def __init__(
        self,
        runner: AgentRunner,
        hunters: List[Agent],
        max_workers: Optional[int] = None,
        coverage=None,
        lease_limit: int = 24,
    ):
        if not hunters:
            raise ValueError("ParallelVulnPhase requires at least one hunter agent")
        self.runner = runner
        self.hunters = hunters
        # Default: one worker per hunter so none queue behind each other.
        self.max_workers = max_workers or len(hunters)
        self._merge_lock = threading.Lock()
        # Optional coverage ledger. When present, each hunter is leased a
        # disjoint, bounded worklist of its own pending cells so breadth is
        # guaranteed before any one input is deepened, and a failed handoff is
        # retried once without losing its lease.
        self.coverage = coverage
        self.lease_limit = lease_limit

    # --------------------------------------------------------------- run()

    def run(
        self,
        task: str,
        shared_ctx: Dict[str, Any],
        recon_brief: str = "",
    ) -> ParallelVulnResult:
        """Fan out to all hunters concurrently, fan back in with merged findings.

        Args:
            task: The high-level vuln-phase task, reused verbatim by each hunter
                  (hunter-specific instructions live in their agent definitions).
            shared_ctx: The Vanguard context dict carried through the pipeline.
                        Hunters each get a deep copy, then findings are merged back.
            recon_brief: Text summary of what the recon agent found (usually
                         `recon_result.final_text`). Prepended to each hunter's task
                         so they start with attack-surface awareness.
        """
        wall_start = time.time()
        hunter_results: List[HunterResult] = []

        with self.runner.tracer.span(
            "parallel_vuln_phase",
            "parallel_phase",
            hunters=[h.name for h in self.hunters],
            max_workers=self.max_workers,
        ):
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=self.max_workers,
                thread_name_prefix="owasp-hunter",
            ) as pool:
                futures = {
                    pool.submit(
                        self._run_one_hunter,
                        hunter,
                        task,
                        shared_ctx,
                        recon_brief,
                    ): hunter
                    for hunter in self.hunters
                }
                for fut in concurrent.futures.as_completed(futures):
                    hunter = futures[fut]
                    try:
                        hunter_results.append(fut.result())
                    except Exception as e:  # noqa: BLE001
                        logger.exception("Hunter %s crashed", hunter.name)
                        hunter_results.append(
                            HunterResult(
                                name=hunter.name,
                                category=_category_of(hunter),
                                findings=[],
                                tool_calls=0,
                                turns_used=0,
                                elapsed_sec=0.0,
                                error=str(e),
                            )
                        )

        merged = self._merge_findings(hunter_results)
        wall_elapsed = time.time() - wall_start
        serial_elapsed = sum(h.elapsed_sec for h in hunter_results)

        result = ParallelVulnResult(
            hunters=hunter_results,
            merged_findings=merged,
            total_tool_calls=sum(h.tool_calls for h in hunter_results),
            total_turns=sum(h.turns_used for h in hunter_results),
            total_elapsed_sec=wall_elapsed,
            serial_elapsed_sec=serial_elapsed,
        )

        logger.info(
            "Parallel vuln phase complete: %d hunters, %d merged findings "
            "(%d cross-validated), %.1fs wall (%.1fs serial, %.2fx speedup)",
            len(hunter_results),
            result.finding_count,
            result.cross_validated_count,
            wall_elapsed,
            serial_elapsed,
            result.speedup,
        )
        return result

    # --------------------------------------------------------- per-hunter

    def _run_one_hunter(
        self,
        hunter: Agent,
        task: str,
        shared_ctx: Dict[str, Any],
        recon_brief: str,
    ) -> HunterResult:
        start = time.time()

        # Deep-copy ctx so hunters can't interfere with each other's system
        # prompt during their own ReAct loops. Findings merge at fan-in.
        hunter_ctx = copy.deepcopy(shared_ctx)

        # Lease a disjoint, bounded worklist of this hunter's own pending cells
        # so specialists spread across the surface instead of colliding on one
        # input. The lease is retained across a single retry; only a final
        # failure releases it so the inputs return to the pending pool.
        lease_token, worklist = self._lease_worklist(hunter)

        hunter_task = self._build_hunter_task(hunter, task, recon_brief, worklist)

        logger.info("[%s] starting (max_turns=%d)", hunter.name, hunter.max_turns)

        run_result = None
        last_error: Optional[Exception] = None
        for attempt in (1, 2):  # retry a failed handoff once, keeping the lease
            try:
                run_result = self.runner.run(
                    agent=hunter,
                    task=hunter_task,
                    context=copy.deepcopy(hunter_ctx),
                )
                break
            except Exception as e:  # noqa: BLE001
                last_error = e
                logger.exception(
                    "[%s] runner.run() raised (attempt %d/2)", hunter.name, attempt
                )
        if run_result is None:
            if lease_token:
                self.coverage.release(lease_token)  # don't lose the coverage
            return HunterResult(
                name=hunter.name,
                category=_category_of(hunter),
                findings=[],
                tool_calls=0,
                turns_used=0,
                elapsed_sec=time.time() - start,
                error=str(last_error),
            )

        findings = self._extract_findings(run_result)
        coverage_events = self._extract_coverage_events(run_result)
        elapsed = time.time() - start

        logger.info(
            "[%s] done: %d turns, %d tool calls, %d findings, %.1fs",
            hunter.name,
            run_result.turns_used,
            run_result.tool_calls_made,
            len(findings),
            elapsed,
        )

        return HunterResult(
            name=hunter.name,
            category=_category_of(hunter),
            findings=findings,
            tool_calls=run_result.tool_calls_made,
            turns_used=run_result.turns_used,
            elapsed_sec=elapsed,
            coverage_events=coverage_events,
            final_text=run_result.final_text or "",
        )

    # -------------------------------------------------------- task prompt

    def _lease_worklist(self, hunter: Agent):
        """Reserve this hunter's disjoint, bounded set of pending cells.

        Returns ``(lease_token, cells)``. When no coverage ledger is attached
        (legacy callers, unit tests) leasing is skipped and the hunter runs
        exactly as before.
        """
        if self.coverage is None:
            return "", []
        try:
            from agent.coverage import coverage_classes_for
            classes = coverage_classes_for(_category_of(hunter))
            lease = self.coverage.lease(
                classes=sorted(classes) if classes else None,
                limit=self.lease_limit,
                owner=f"{hunter.name}-{int(time.time()*1000) % 100000}",
            )
            return lease.get("lease", ""), lease.get("cells", [])
        except Exception:  # leasing must never block a hunt
            logger.exception("[%s] lease failed; running without a worklist", hunter.name)
            return "", []

    @staticmethod
    def _build_hunter_task(
        hunter: Agent,
        parent_task: str,
        recon_brief: str,
        worklist: Optional[List[dict]] = None,
    ) -> str:
        """Assemble the per-hunter opening user message.

        The hunter's own system prompt (in owasp_hunters.py) already describes
        its mission. Here we feed it the recon brief, the parent task, and —
        when coverage leasing is active — the concrete, bounded set of untested
        inputs reserved for it, so it covers breadth before deepening any one.
        """
        sections = [parent_task.strip()] if parent_task.strip() else []

        if recon_brief:
            sections.append(
                "## Recon Brief (summary from recon_agent)\n"
                f"{recon_brief.strip()}"
            )

        if worklist:
            compact = [
                {
                    "endpoint": c.get("endpoint"),
                    "method": c.get("method"),
                    "parameter": c.get("parameter"),
                    "identity": c.get("identity"),
                    "vulnerability_class": c.get("vulnerability_class"),
                }
                for c in worklist
            ]
            sections.append(
                "## Your leased worklist (cover these FIRST, one pass each)\n"
                "These untested input cells are reserved for you — no other "
                "hunter will take them. Give every one a first pass before "
                "deepening any single input, and do not re-probe an input once "
                "it is proven. Repeat and over-budget requests are suppressed.\n"
                "```json\n" + json.dumps(compact, indent=2, default=str) + "\n```"
            )

        sections.append(
            f"## Your focus\nYou are the **{hunter.name}**. "
            "Stay strictly within your OWASP category. The other hunters "
            "are working in parallel on the other categories — trust them."
        )

        return "\n\n".join(sections)

    # ----------------------------------------------------- finding extract

    @staticmethod
    def _tool_payloads(result: RunResult) -> List[dict]:
        """Decode structured tool outputs, including Augur-wrapped payloads."""
        payloads: List[dict] = []
        for msg in result.messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                raw = block.get("content", "")
                if not isinstance(raw, str) or not raw.strip():
                    continue
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                payload = (
                    parsed.get("output")
                    if isinstance(parsed, dict) and "augur" in parsed
                    else parsed
                )
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                if isinstance(payload, dict):
                    payloads.append(payload)
        return payloads

    @classmethod
    def _extract_coverage_events(cls, result: RunResult) -> List[dict]:
        """Return only tool payloads that provide machine-readable test evidence."""
        evidence_keys = {
            "probe", "coverage", "tested_params", "params_tested",
            "coverage_complete", "skipped_parameters",
        }
        return [
            copy.deepcopy(payload)
            for payload in cls._tool_payloads(result)
            if evidence_keys.intersection(payload) or payload.get("error")
        ]

    @classmethod
    def _extract_findings(cls, result: RunResult) -> List[dict]:
        """Scrape likely finding shapes out of the hunter's tool_result messages.

        Scanners in agents.py return JSON blobs whose `vulnerabilities`,
        `findings`, `results`, or `issues` arrays hold the actionable items.
        We also promote confirm_vulnerability_poc and probe_* hits so confirmed
        SQLi/XSS do not vanish at fan-in.
        """
        findings: List[dict] = []
        for payload in cls._tool_payloads(result):

            # confirm_vulnerability_poc — previously dropped at fan-in
            if payload.get("confirmed") and (
                payload.get("finding") or payload.get("poc_endpoint")
            ):
                findings.append({
                    "title": payload.get("finding") or "Confirmed vulnerability",
                    "name": payload.get("finding") or "Confirmed vulnerability",
                    "url": payload.get("poc_endpoint") or payload.get("endpoint") or "",
                    "matched_at": payload.get("poc_endpoint") or "",
                    "severity": payload.get("escalated_severity")
                                 or payload.get("original_severity")
                                 or "high",
                    "vuln_type": payload.get("vuln_type") or "confirmed",
                    "host": payload.get("host") or "",
                    "confirmed": True,
                    "source": "confirm_vulnerability_poc",
                })

            for key in ("vulnerabilities", "findings", "results", "issues", "candidates"):
                arr = payload.get(key)
                if not isinstance(arr, list):
                    continue
                for item in arr:
                    if not isinstance(item, dict):
                        continue
                    # Skip empty sqlmap/xss "not vulnerable" stubs
                    if item.get("vulnerable") is False and not item.get("title"):
                        continue
                    # Normalize minimal tool stubs into reportable findings
                    if item.get("vulnerable") is True and not item.get("title"):
                        item = {
                            **item,
                            "title": item.get("title")
                                     or f"Potential injection at {item.get('url', 'unknown')}",
                            "name": item.get("name")
                                    or f"Potential injection at {item.get('url', 'unknown')}",
                            "severity": item.get("severity") or "high",
                            "vuln_type": item.get("vuln_type")
                                         or item.get("type")
                                         or "injection",
                        }
                    findings.append(item)

            # probe_* tools may set vulnerable/confirmed at top level with reflections
            if payload.get("vulnerable") and not any(
                isinstance(payload.get(k), list) for k in ("findings", "results", "candidates")
            ):
                findings.append({
                    "title": payload.get("title") or "Probe-confirmed vulnerability",
                    "name": payload.get("title") or "Probe-confirmed vulnerability",
                    "url": payload.get("url") or "",
                    "severity": payload.get("severity") or "high",
                    "vuln_type": payload.get("vuln_type") or "unknown",
                    "confirmed": True,
                    "source": "probe",
                    "evidence": payload.get("evidence") or "",
                })
        return findings

    # ----------------------------------------------------- merge + dedupe

    def _merge_findings(self, hunters: List[HunterResult]) -> List[dict]:
        """Dedupe across hunters with a stable fingerprint.

        When two hunters independently surface the same finding we mark it
        `cross_validated=True` — a signal the exploit phase should treat
        as higher-confidence than single-hunter findings.
        """
        merged: Dict[str, dict] = {}
        with self._merge_lock:
            for hr in hunters:
                for f in hr.findings:
                    key = self._finding_key(f)
                    if key in merged:
                        existing = merged[key]
                        hunters_set = set(existing.get("hunters", []))
                        hunters_set.add(hr.name)
                        existing["hunters"] = sorted(hunters_set)
                        existing["cross_validated"] = len(hunters_set) > 1
                    else:
                        f_copy = dict(f)
                        f_copy["hunters"] = [hr.name]
                        f_copy["owasp_category"] = hr.category
                        f_copy["cross_validated"] = False
                        merged[key] = f_copy
        return list(merged.values())

    @staticmethod
    def _finding_key(f: dict) -> str:
        title = str(f.get("name") or f.get("title") or "")
        endpoint = str(
            f.get("matched_at")
            or f.get("matched-at")
            or f.get("url")
            or f.get("endpoint")
            or ""
        ).rstrip("/")
        kind_source = " ".join(
            str(value)
            for value in (
                f.get("vuln_type"), f.get("type"), f.get("template"),
                f.get("template-id"), f.get("template_id"), title,
                " ".join(f.get("tags") or []),
            )
            if value
        ).lower()
        kind = ""
        for canonical, pattern in (
            ("sqli", r"\bsqli\b|sql[\s-]*injection"),
            ("xss", r"\bxss\b|cross[\s-]*site[\s-]*script"),
            ("ssrf", r"\bssrf\b|server[\s-]*side[\s-]*request"),
            ("ssti", r"\bssti\b|template[\s-]*injection"),
            ("xxe", r"\bxxe\b|xml[\s-]*external[\s-]*entity"),
            ("idor", r"\bidor\b|insecure[\s-]*direct[\s-]*object"),
        ):
            if re.search(pattern, kind_source):
                kind = canonical
                break

        parameter = str(f.get("parameter") or f.get("param") or "").lower()
        if not parameter:
            for pattern in (
                r"(?:parameter|param)\s+['\"`]?([a-zA-Z_][\w.-]*)",
                r"['\"`]([a-zA-Z_][\w.-]*)['\"`]\s*\(",
                r"\(([a-zA-Z_][\w.-]*)\s+parameter\)",
            ):
                match = re.search(pattern, title, re.IGNORECASE)
                if match:
                    parameter = match.group(1).lower()
                    break

        # Different tools often emit the same defect under different titles
        # and severities.  Collapse those records before validation/chain
        # building so one SQLi cannot masquerade as a multi-finding chain.
        if kind and endpoint:
            semantic = f"{kind}|{endpoint.lower()}|{parameter}"
            return hashlib.sha256(semantic.encode()).hexdigest()[:16]

        parts = [
            str(f.get("template") or f.get("template-id") or f.get("template_id") or ""),
            title,
            endpoint,
            str(f.get("severity") or ""),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


# =========================================================================
# Helpers
# =========================================================================

def _category_of(agent: Agent) -> str:
    """Derive an OWASP category slug from a hunter agent's name.

    Matches the naming convention in owasp_hunters.py (e.g. `injection_hunter`
    -> `injection`). Falls back to the bare name if the agent doesn't follow
    the `<category>_hunter` convention.
    """
    name = agent.name or "unknown"
    return name.replace("_hunter", "")
