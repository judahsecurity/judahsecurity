"""Run observation follow-ups inside the live tool manager.

The tool manager rebuilds the engagement brain from a dict on each call and
saves it back afterwards. Model calls therefore run in a background task on
prebuilt packets only; their results are applied to whichever live brain the
next ``refresh`` receives. Events that were mid-planning when a process died
return to the queue after a short timeout (see ``begin_planning``).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from app.services.agent.coverage_cells import (
    CoverageCellLease,
    release_coverage_cell_lease,
)
from app.services.agent.observation_followups import (
    FollowupPolicy,
    _cell,
    _chain,
    _claimable_ids,
    _ledger,
    apply_planning,
    begin_planning,
    claim_followup,
    commit_observation,
    complete_followup,
    record_first_request,
    release_held_proposals,
    run_planning,
    scope_host,
)

logger = logging.getLogger(__name__)

RuntimeKey = tuple[Any, ...]
_MAX_JOBS = 64


def followups_enabled() -> bool:
    from app.core.config import settings

    return bool(getattr(settings, "PROWL_FOLLOWUP_PLANNER_ENABLED", True))


def current_run_id() -> str:
    from app.services.agent.action_ledger import active_run_id

    try:
        from app.services.agent.tools import current_session_id

        session = current_session_id.get() or ""
    except ImportError:  # pragma: no cover - tools imports this module lazily
        session = ""
    return str(active_run_id.get() or session or "interactive")[:96]


def policy_for(manager: Any, brain: Any, *, run_id: str | None = None) -> FollowupPolicy:
    """Engagement policy for follow-up planning and claims.

    Approved identities are ``anonymous``, identities registered with the
    assessment identity registry, and the engagement's own sessions recorded on
    the brain. A scheduled turn narrows that to its ``allowed_identities``.
    """
    from app.core.config import settings
    from app.services.agent.assessment_scope import observation_scope_hosts
    from app.services.agent.assessment_sessions import identity_registry
    from app.services.agent.autonomy_limits import current_autonomy_limits

    hosts = {scope_host(h) for h in observation_scope_hosts(manager) if scope_host(h)}
    if not hosts and getattr(brain, "target", ""):
        hosts.add(scope_host(brain.target))
    approved = {"anonymous", *identity_registry(manager).identities,
                *(getattr(brain, "identities", None) or [])}
    limits = current_autonomy_limits.get()
    if limits:
        approved &= set(limits.allowed_identities)
    return FollowupPolicy(
        run_id=run_id or current_run_id(),
        scope_hosts=frozenset(hosts),
        approved_identities=frozenset(approved),
        max_planned_events_per_run=int(
            getattr(settings, "PROWL_FOLLOWUP_MAX_EVENTS_PER_RUN", 60) or 0
        ),
    )


def record_inventory_captures(brain: Any, inventory: Iterable[dict[str, Any]], *,
                              run_id: str) -> int:
    """Commit one capture event per observed request shape with evidence.

    Only inventory rows backed by a capture artifact count; repeated mapping of
    the same request updates the existing event instead of creating work.
    """
    grouped: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in inventory or []:
        if (not isinstance(row, dict) or row.get("testable") is not True
                or not row.get("artifact_id") or not row.get("host")):
            continue
        key = (str(row.get("method") or "GET").upper(), str(row["host"]).lower(),
               str(row.get("path") or "/"), str(row.get("identity") or "anonymous"))
        group = grouped.setdefault(key, {"parameters": [], "evidence": []})
        group["parameters"].append({"location": row.get("location") or "query",
                                    "name": row.get("name") or ""})
        group["evidence"].append(str(row["artifact_id"]))
    created = 0
    for (method, host, path, identity), group in grouped.items():
        try:
            _event, new = commit_observation(
                brain, run_id=run_id, kind="capture",
                evidence_ids=sorted(set(group["evidence"])), identity=identity,
                facts={"method": method, "host": host, "path": path,
                       "parameters": group["parameters"]},
            )
        except ValueError:
            logger.debug("Skipped capture observation for %s %s", method, path, exc_info=True)
            continue
        created += int(new)
    return created


@dataclass
class _Job:
    task: asyncio.Task
    event_ids: list[str]
    queued_at: float


class FollowupRuntime:
    """Session-isolated background planning plus claim/finish helpers."""

    def __init__(self) -> None:
        self._jobs: dict[RuntimeKey, _Job] = {}
        # Keys whose planning finished and whose results wait to be applied.
        # The tool manager applies them after the next tool call completes,
        # so new follow-ups appear without waiting for a sync/map/dispatch.
        self._finished: set[RuntimeKey] = set()

    def has_finished(self, key: RuntimeKey) -> bool:
        return key in self._finished

    def cancel(self, key: RuntimeKey) -> None:
        self._finished.discard(key)
        job = self._jobs.pop(key, None)
        if job and not job.task.done():
            job.task.cancel()

    async def settle(self, key: RuntimeKey, timeout: float = 30) -> None:
        """Wait for the running planning job, if any (tests and shutdown)."""
        job = self._jobs.get(key)
        if job is not None:
            await asyncio.wait({job.task}, timeout=timeout)

    def refresh(self, key: RuntimeKey, brain: Any, policy: FollowupPolicy,
                llm_factory: Callable[[], Any]) -> dict[str, Any]:
        """Apply finished planning, release approved holds, queue new events.

        Never awaits the model. The caller must persist ``brain`` afterwards.
        """
        if not followups_enabled():
            return {"status": "disabled"}
        out: dict[str, Any] = {"status": "idle"}
        self._finished.discard(key)
        job = self._jobs.get(key)
        if job is not None and job.task.done():
            del self._jobs[key]
            try:
                results = job.task.result()
            except (asyncio.CancelledError, Exception) as exc:  # noqa: BLE001
                logger.warning("Follow-up planning job failed: %s", type(exc).__name__)
                results = [{"event_id": event_id, "error": type(exc).__name__}
                           for event_id in job.event_ids]
            out["applied"] = apply_planning(brain, results, policy)
            out["queue_to_apply_ms"] = round((time.monotonic() - job.queued_at) * 1000)
            out["status"] = "applied"
        released = release_held_proposals(brain, policy)
        if released:
            out["released_held"] = released
        running = self._jobs.get(key)
        if running is not None:
            out["status"] = "planning"
            out["planning_events"] = len(running.event_ids)
        else:
            jobs = begin_planning(brain, policy)
            if jobs:
                if len(self._jobs) >= _MAX_JOBS:
                    oldest = min(self._jobs, key=lambda k: self._jobs[k].queued_at)
                    self.cancel(oldest)
                task = asyncio.create_task(run_planning(
                    jobs, llm_factory, target=str(getattr(brain, "target", "") or ""),
                ))
                self._jobs[key] = _Job(task, [j["event_id"] for j in jobs], time.monotonic())
                task.add_done_callback(lambda _t, k=key: self._finished.add(k))
                out["status"] = "planning"
                out["planning_events"] = len(jobs)
        events = _ledger(brain, "observation_events")
        out["committed_events"] = sum(1 for e in events if e.get("status") == "committed")
        out["claimable"] = len(_claimable_ids(brain, policy))
        return out


def specialists_with_followups(brain: Any, policy: FollowupPolicy) -> list[str]:
    names = []
    for cell_id in sorted(_claimable_ids(brain, policy)):
        cell = _cell(brain, cell_id) or {}
        if cell.get("specialist"):
            names.append(str(cell["specialist"]))
    return list(dict.fromkeys(names))


def claim_for_specialists(brain: Any, specialists: Iterable[str], policy: FollowupPolicy,
                          *, lease_seconds: int = 3600) -> dict[str, CoverageCellLease]:
    leases = {}
    for name in dict.fromkeys(specialists):
        lease = claim_followup(brain, name, policy, lease_seconds=lease_seconds)
        if lease is not None:
            leases[name] = lease
    return leases


def required_identities(brain: Any, lease: CoverageCellLease) -> list[str]:
    cell = _cell(brain, lease.coverage_cell_id) or {}
    return list((cell.get("followup") or {}).get("required_identities") or [])


def finish_followup(brain: Any, lease: CoverageCellLease, reports: list[Any], *, run_id: str,
                    candidate_id: str = "") -> dict[str, Any] | None:
    """Close one follow-up lease from a specialist's reports.

    With evidence, the result is committed as a ``worker_result`` event that
    can produce the next follow-up. Without evidence, the lease is released
    as inconclusive and no event is created.
    """
    final = reports[-1] if reports else None
    calls = [call for report in reports for call in (getattr(report, "tool_calls", None) or [])]
    evidence = [eid for call in calls for eid in (getattr(call, "evidence_ids", None) or [])]
    started = [float(getattr(call, "started_at", 0) or 0) for call in calls]
    started = [value for value in started if value > 0]
    cell = _cell(brain, lease.coverage_cell_id)
    if cell is None or cell.get("lease_id") != lease.id:
        return None
    if started:
        record_first_request(brain, lease, now=min(started))
    verdict = (getattr(final, "verdict", "") or "inconclusive") if final else "inconclusive"
    reason = (
        (getattr(final, "error", "") or getattr(final, "evidence", "")
         or getattr(final, "summary", "")) if final
        else "Specialist did not return a coverage receipt"
    )
    if evidence:
        return complete_followup(brain, lease, run_id=run_id, verdict=verdict,
                                 evidence_ids=evidence, candidate_id=candidate_id,
                                 reason=str(reason or ""))
    release_coverage_cell_lease(brain, lease, verdict=verdict, candidate_id=candidate_id,
                                reason=str(reason or ""))
    chain = _chain(brain, lease.id)
    if chain is not None:
        chain.update(verdict=f"{verdict}:no_evidence"[:40], verdict_at=time.time())
    return None
