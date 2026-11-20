"""Facts a running specialist shares, and code-only checks of new endpoints.

``record_fact`` lets a specialist hand on something a tool result showed
(an endpoint outside its lane, a leaked parameter, a technology version, an
error that reveals internals) while it is still working, instead of only in
its final report. Every fact must cite evidence from this session. Endpoint
facts become capture events for the follow-up planner, and with rolling
dispatch they wake the dispatcher so the follow-up can start in a free slot.

New in-scope endpoints from facts and leads also get one bounded anonymous
GET in code (status, content type, length): routine reconnaissance that does
not need a model turn. The result is attached to the engagement surface and
recorded as evidence, so the planner sees "GET /api/admin -> 401" instead of
a bare path. Unsafe-looking paths (logout, delete, ...) are never fetched.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional
from urllib.parse import urlsplit

from app.services.agent.session_runtime import SessionValue

logger = logging.getLogger(__name__)

FACT_KINDS = ("endpoint", "parameter", "technology", "error_leak", "auth_hint", "note")
MAX_FACTS = 200
MAX_FACT_TEXT = 300
MAX_ENRICHMENTS = 15
ENRICH_CONCURRENCY = 3
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def _clean(text: Any, limit: int = MAX_FACT_TEXT) -> str:
    return " ".join(str(text or "").split())[:limit]


def parse_endpoint(value: str) -> tuple[str, str]:
    """'POST https://h/p' or 'https://h/p' -> (method, url)."""
    parts = _clean(value, 2100).split(" ", 1)
    if len(parts) == 2 and parts[0].upper() in _METHODS:
        return parts[0].upper(), parts[1].strip()
    return "GET", parts[0]


class FactSharingTools:
    """Mixin for ASMToolsManager."""

    _enrich_seen = SessionValue(set)
    _enrich_tasks = SessionValue(set)
    _enrich_slots = SessionValue(lambda: asyncio.Semaphore(ENRICH_CONCURRENCY))

    def _fact_evidence_ok(self, evidence_id: str) -> bool:
        from app.services.agent.evidence_store import evidence_store

        record = evidence_store(self).records.get(str(evidence_id or ""))
        return bool(record and record.get("success"))

    async def record_fact(self, kind: str, value: str, evidence_id: str, note: str = "") -> str:
        """Share a fact a tool result showed, while you keep working (kind: endpoint|parameter|technology|error_leak|auth_hint|note; value: e.g. 'GET https://host/path'; evidence_id: the tool result that shows it)."""
        from app.services.agent.assessment_scope import assert_url_in_scope
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        kind = str(kind or "").strip().lower()
        if kind not in FACT_KINDS:
            return json.dumps({"success": False, "error": f"kind must be one of {list(FACT_KINDS)}"})
        if not self._fact_evidence_ok(evidence_id):
            return json.dumps({"success": False,
                               "error": "evidence_id must be a successful tool result from this session"})
        fact: dict[str, Any] = {"kind": "fact", "fact_kind": kind, "value": _clean(value),
                                "note": _clean(note), "evidence_ids": [str(evidence_id)],
                                "at": time.time()}
        method = url = ""
        if kind == "endpoint":
            method, url = parse_endpoint(value)
            try:
                assert_url_in_scope(self, url)
            except ValueError as exc:
                return json.dumps({"success": False, "error": str(exc)})
            fact.update(method=method, url=url[:2048])
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        duplicate = any(
            isinstance(row, dict) and row.get("kind") == "fact"
            and row.get("fact_kind") == kind and row.get("value") == fact["value"]
            for row in live.recon_observations
        )
        if not duplicate:
            facts = [row for row in live.recon_observations
                     if isinstance(row, dict) and row.get("kind") == "fact"]
            if len(facts) >= MAX_FACTS:
                return json.dumps({"success": False, "error": "fact limit reached for this session"})
            live.recon_observations.append(fact)
        queued = False
        if kind == "endpoint" and not duplicate:
            from app.services.agent.observation_followups import capture_facts

            queued = self._record_followup_event(
                live, kind="capture", identity="anonymous",
                evidence_ids=[str(evidence_id)], facts=capture_facts(method, url),
            ) is not None
        self._engagement_brain = live.to_dict()
        if kind == "endpoint" and not duplicate:
            self._schedule_endpoint_enrichment(method, url)
        wake: Optional[asyncio.Event] = getattr(self, "_fact_wake", None)
        if wake is not None and queued:
            wake.set()
        return json.dumps({"success": True, "duplicate": duplicate,
                           "followup_queued": queued})

    # -- recon in code ------------------------------------------------------

    def _schedule_endpoint_enrichment(self, method: str, url: str) -> None:
        """Queue one bounded anonymous GET of a new in-scope endpoint."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        key = (urlsplit(url).netloc, urlsplit(url).path or "/")
        seen: set = self._enrich_seen
        if key in seen or len(seen) >= MAX_ENRICHMENTS:
            return
        seen.add(key)
        tasks: set = self._enrich_tasks
        task = loop.create_task(self._enrich_endpoint(method, url))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    async def _enrich_endpoint(self, method: str, url: str) -> Optional[dict]:
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

        parts = urlsplit(url)
        path = parts.path or "/"
        if not allowed_discovery_path(path):
            return None
        async with self._enrich_slots:
            try:
                # Query values are dropped: the check is "does this path exist
                # and is it guarded", not a test of any input.
                raw = await self.scoped_http_get(f"{parts.scheme}://{parts.netloc}{path}")
                result = json.loads(raw)
            except Exception as exc:  # budget, scope, or network: skip quietly
                logger.debug("endpoint enrichment skipped for %s: %s", path, type(exc).__name__)
                return None
        probe = {
            "status": result.get("status"),
            "content_type": str(result.get("content_type") or "")[:80],
            "bytes": result.get("bytes_captured"),
            "evidence_id": result.get("evidence_id"),
            "at": time.time(),
        }
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        key = (parts.netloc, method, path)
        surface = next((row for row in live.surfaces if isinstance(row, dict)
                        and (row.get("host"), row.get("method"), row.get("path")) == key), None)
        if surface is None and len(live.surfaces) < 200:
            surface = {"host": parts.netloc, "method": method, "path": path,
                       "takes_input": bool(parts.query) or method != "GET",
                       "source": "fact_enrichment"}
            live.surfaces.append(surface)
        if surface is not None:
            surface["probe"] = probe
            if probe["status"] in (401, 403):
                surface["auth_gated"] = True
        self._engagement_brain = live.to_dict()
        return probe

    async def wait_for_enrichment(self, timeout: float = 10.0) -> None:
        tasks = list(self._enrich_tasks or ())
        if tasks:
            await asyncio.wait(tasks, timeout=timeout)
