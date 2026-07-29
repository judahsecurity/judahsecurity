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
    ):
        if not hunters:
            raise ValueError("ParallelVulnPhase requires at least one hunter agent")
        self.runner = runner
        self.hunters = hunters
        # Default: one worker per hunter so none queue behind each other.
        self.max_workers = max_workers or len(hunters)
        self._merge_lock = threading.Lock()

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

        hunter_task = self._build_hunter_task(hunter, task, recon_brief)

        logger.info("[%s] starting (max_turns=%d)", hunter.name, hunter.max_turns)

        try:
            run_result = self.runner.run(
                agent=hunter,
                task=hunter_task,
                context=hunter_ctx,
            )
        except Exception as e:  # noqa: BLE001
            logger.exception("[%s] runner.run() raised", hunter.name)
            return HunterResult(
                name=hunter.name,
                category=_category_of(hunter),
                findings=[],
                tool_calls=0,
                turns_used=0,
                elapsed_sec=time.time() - start,
                error=str(e),
            )

        findings = self._extract_findings(run_result)
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
            final_text=run_result.final_text or "",
        )

    # -------------------------------------------------------- task prompt

    @staticmethod
    def _build_hunter_task(hunter: Agent, parent_task: str, recon_brief: str) -> str:
        """Assemble the per-hunter opening user message.

        The hunter's own system prompt (in owasp_hunters.py) already describes
        its mission. Here we just feed it the recon brief + the parent task so
        it has attack-surface context before its first tool call.
        """
        sections = [parent_task.strip()] if parent_task.strip() else []

        if recon_brief:
            sections.append(
                "## Recon Brief (summary from recon_agent)\n"
                f"{recon_brief.strip()}"
            )

        sections.append(
            f"## Your focus\nYou are the **{hunter.name}**. "
            "Stay strictly within your OWASP category. The other hunters "
            "are working in parallel on the other categories — trust them."
        )

        return "\n\n".join(sections)

    # ----------------------------------------------------- finding extract

    @staticmethod
    def _extract_findings(result: RunResult) -> List[dict]:
        """Scrape likely finding shapes out of the hunter's tool_result messages.

        Scanners in agents.py return JSON blobs whose `vulnerabilities`,
        `findings`, `results`, or `issues` arrays hold the actionable items.
        We pull those up so the fan-in can dedupe across hunters.
        """
        findings: List[dict] = []
        for msg in result.messages:
            if msg.get("role") != "user":
                continue
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_result":
                    continue
                raw = block.get("content", "")
                if not isinstance(raw, str) or not raw.strip():
                    continue
                # Augur wraps outputs as {"output": "...", "augur": {...}}
                # Handle both the wrapped and unwrapped cases.
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                payload = parsed.get("output") if isinstance(parsed, dict) and "augur" in parsed else parsed
                # After unwrapping Augur, payload might still be a string
                # (the filtered text); try another JSON decode.
                if isinstance(payload, str):
                    try:
                        payload = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                if not isinstance(payload, dict):
                    continue
                for key in ("vulnerabilities", "findings", "results", "issues"):
                    arr = payload.get(key)
                    if isinstance(arr, list):
                        findings.extend(x for x in arr if isinstance(x, dict))
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
        parts = [
            str(f.get("template") or f.get("template-id") or f.get("template_id") or ""),
            str(f.get("name") or f.get("title") or ""),
            str(f.get("matched_at") or f.get("matched-at") or f.get("url") or ""),
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
