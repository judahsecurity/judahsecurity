"""Shaped requests for leased cells without a captured baseline.

Mixin for ASMToolsManager (helpers only, no new tools). The leased scoped
probes (``scoped_injection_probe_assigned``, ``scoped_response_probe_assigned``)
call these when a cell is

* intent-backed (``attack_graph`` intent, ``source=INTENT_CELL_SOURCE``, no
  capture): the request comes from the intent's method, URL, parameter and
  location, so operator-directed tests work on inputs Prowl never observed;
* an observed header or cookie input on a GET (no capture is needed to set
  one header or cookie on the observed endpoint).

Requests are planned in ``scoped_assessment.intent_request``. When a probe
works an intent-backed cell the intent is claimed and completed with a
result fact citing the receipt (planning state, never proof).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

SHAPED_OBSERVED_LOCATIONS = frozenset({"header", "cookie"})


class IntentProbeToolsMixin:
    """Request shapes for intent-backed and header/cookie coverage cells."""

    @staticmethod
    def _shaped_cell(cell: Optional[Dict[str, Any]]) -> bool:
        from app.services.agent.attack_graph import INTENT_CELL_SOURCE
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        if not cell:
            return False
        location = str(cell.get("parameter") or "").partition(":")[0]
        if (cell.get("source") == INTENT_CELL_SOURCE and cell.get("intent_id")
                and not cell.get("capture_id")):
            return True
        return bool(cell.get("source") == "parameter_inventory"
                    and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
                    and str(cell.get("method") or "").upper() == "GET"
                    and location in SHAPED_OBSERVED_LOCATIONS)

    @staticmethod
    def _cell_identity(cell: Dict[str, Any]) -> str:
        identity = str(cell.get("identity") or "")
        return "anonymous" if identity in {"", "unspecified"} else identity

    def _shaped_base(self, cell: Dict[str, Any], scoped_origin: str) -> Tuple[str, str, str, str, str]:
        """(method, url, location, parameter, request_context) for a shaped cell.

        The intent's URL is used only when it is on the scoped origin and its
        path is the cell's path; otherwise the cell's own path is used.
        """
        from app.services.agent.attack_graph import get_intent
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin

        location, _sep, parameter = str(cell.get("parameter") or "").partition(":")
        method = str(cell.get("method") or "GET").upper()
        path = str(cell.get("path") or "/")
        url = scoped_origin + path
        context = f"observed_{location}"
        if cell.get("intent_id") and not cell.get("capture_id"):
            context = f"intent_{location}"
            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            intent = get_intent(brain, str(cell["intent_id"])) or {}
            target = str(intent.get("target") or "")
            try:
                parts = urlsplit(target)
                if (target and _origin(target) == scoped_origin
                        and (parts.path or "/") == path and not parts.fragment):
                    url = target
            except ValueError:
                pass
        return method, url, location, parameter, context

    def _shaped_approval(self, method: str, path: str) -> Optional[str]:
        """Same POST approval as captured bodies: the path must be in body_replay_paths."""
        if method == "GET":
            return None
        if method == "POST" and path in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            return None
        return "POST path is not in body_replay_paths" if method == "POST" else "method_unsupported"

    def _shaped_shape_error(self, cell: Dict[str, Any], test_type: str) -> str:
        from app.services.agent.scoped_assessment.intent_request import shape_error

        location, _sep, parameter = str(cell.get("parameter") or "").partition(":")
        return shape_error(test_type, str(cell.get("method") or "GET").upper(), location, parameter)

    def _charge(self, method: str, count: int) -> None:
        if method == "GET":
            self._scoped_claim_gets(count)
        else:
            self._scoped_claim_posts(count)

    async def _run_shaped_injection(
        self, cell: Dict[str, Any], test_type: str, nonce: str, factors: tuple,
        identity: str, *, scoped_origin: str, recipe: str = "",
    ) -> Tuple[dict, str]:
        """One SSTI/command/traversal/NoSQL proof on a shaped cell."""
        from app.services.agent.scoped_assessment import injection_probe, intent_request

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        denied = self._shaped_approval(method, str(cell.get("path") or "/"))
        if denied:
            raise ValueError("operator_approval_required")
        state = self._scoped_state(identity, url)
        requests = intent_request.injection_requests(
            method=method, url=url, location=location, parameter=parameter,
            test_type=test_type, nonce=nonce, factors=factors, state=state,
            recipes=[recipe] if recipe and test_type != "nosql" else (),
        )
        for planned in requests.values():
            self._scoped_origin(planned.url)
        self._charge(method, len(requests))
        if test_type == "nosql":
            proof = await asyncio.to_thread(
                injection_probe.probe_nosql, requests, allowed_origin=scoped_origin,
                state=None, nonce=nonce, fetch=intent_request.fetch_body,
            )
        else:
            proof = await asyncio.to_thread(
                injection_probe.probe_injection, requests, test_type=test_type,
                allowed_origin=scoped_origin, state=None, nonce=nonce, factors=factors,
                fetch=intent_request.fetch_body,
            )
        return proof, context

    async def _run_shaped_response(
        self, cell: Dict[str, Any], test_type: str, nonce: str, identity: str, *,
        scoped_origin: str,
    ) -> Tuple[dict, str]:
        """One CRLF/open-redirect canary on a shaped cell."""
        from app.services.agent.scoped_assessment import intent_request

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        denied = self._shaped_approval(method, str(cell.get("path") or "/"))
        if denied:
            raise ValueError("operator_approval_required")
        control_value, probe_value = intent_request.response_values(
            test_type, location, nonce, scoped_origin)
        requests = intent_request.plan_requests(
            method=method, url=url, location=location, parameter=parameter,
            values={"control": control_value, "probe": probe_value},
            state=self._scoped_state(identity, url), test_type=test_type,
        )
        for planned in requests.values():
            self._scoped_origin(planned.url)
        self._charge(method, 2)
        proof = await asyncio.to_thread(
            intent_request.probe_response_requests, requests["control"], requests["probe"],
            test_type=test_type, allowed_origin=scoped_origin, nonce=nonce,
        )
        return proof, context

    async def _run_response_probe(
        self, cell: Dict[str, Any], url: str, parameter: str, test_type: str, nonce: str,
        identity: str, *, scoped_origin: str,
    ) -> Tuple[dict, str]:
        """Hunter and verifier entry point: shaped cells, else the observed GET query."""
        if self._shaped_cell(cell):
            return await self._run_shaped_response(
                cell, test_type, nonce, identity, scoped_origin=scoped_origin)
        from app.services.agent.scoped_assessment.intent_request import response_values
        from app.services.agent.scoped_assessment.response_probe import probe_response

        control_value, probe_value = response_values(test_type, "query", nonce, scoped_origin)
        control_url, control_source = self._observed_get_query_template(
            url, parameter, control_value, identity, capture_id=cell.get("capture_id") or "",
        )
        probe_url, probe_source = self._observed_get_query_template(
            url, parameter, probe_value, identity, capture_id=cell.get("capture_id") or "",
        )
        if control_source == "single_parameter" or probe_source != control_source:
            raise ValueError("observed_query_baseline_missing")
        self._scoped_origin(control_url)
        self._scoped_origin(probe_url)
        self._scoped_claim_gets(2)
        proof = await asyncio.to_thread(
            probe_response, control_url, probe_url, test_type=test_type,
            allowed_origin=scoped_origin, state=self._scoped_state(identity, url),
            nonce=nonce,
        )
        return proof, control_source

    # ------------------------------------------------------------ intents

    def _mark_unsupported_shape(self, brain: Any, cell: Dict[str, Any], lease_id: str,
                                reason: str) -> Dict[str, Any]:
        """Leave the cell open (inconclusive, not re-leased) and block its intent."""
        from app.services.agent.coverage_cells import release_coverage_cell_lease

        worker = str(cell.get("lease_owner") or "")
        release_coverage_cell_lease(
            brain, {"id": lease_id, "coverage_cell_id": cell["id"]}, verdict="inconclusive",
            reason=f"Unsupported request shape ({reason}); not tested, not clean",
        )
        cell["unsupported_shape"] = reason
        cell["last_probe"] = "unsupported_request_shape"
        intent = self._settle_cell_intent(brain, cell, worker=worker, outcome="blocked",
                                          reason=reason)
        return {"success": False, "error": "unsupported_request_shape", "reason": reason,
                "coverage_cell_id": cell["id"], "coverage_cell_status": cell.get("status"),
                "intent": intent}

    def _settle_cell_intent(self, brain: Any, cell: Dict[str, Any], *, worker: str,
                            outcome: str, test_type: str = "", evidence_id: str = "",
                            proof_confirmed: bool = False, reason: str = "") -> Optional[Dict[str, Any]]:
        """Claim and complete the cell's intent with a result fact.

        ``outcome`` is ``probed`` (done, citing the receipt) or ``blocked``.
        An intent claimed by another worker only gains the fact; its claimant
        completes it. A probe without a signal completes the intent, not the
        coverage cell: the cell's verdict is recorded separately.
        """
        from app.services.agent import attack_graph as graph

        intent_id = str(cell.get("intent_id") or "")
        intent = graph.get_intent(brain, intent_id) if intent_id else None
        if not intent or intent.get("status") in {"done", "blocked", "cancelled"}:
            return None
        worker = worker or "scoped_probe"
        input_name = str(cell.get("parameter") or "")
        if outcome == "blocked":
            kind, summary = "verdict", f"{intent['test_type']} on {input_name} not run: {reason}"
        elif proof_confirmed:
            kind, summary = "evidence", (
                f"{test_type} probe on {input_name} showed the fixed signal; "
                "needs the independent verifier")
        else:
            kind, summary = "replay", (
                f"{test_type} probe on {input_name} showed no signal (not a clean verdict)")
        try:
            fact = graph.record_fact(
                brain, kind=kind, summary=summary, target=str(intent.get("target") or ""),
                evidence_ids=[evidence_id] if evidence_id else [], source="scoped_probe",
                parents=[intent_id],
                data={"coverage_cell_id": cell.get("id"), "proof_confirmed": bool(proof_confirmed),
                      "reason": reason},
                key=f"{intent_id}:{evidence_id or reason}",
            )
            if intent.get("status") == "claimed" and intent.get("claimed_by") != worker:
                return {"id": intent_id, "status": intent["status"], "result_fact": fact["id"],
                        "note": f"claimed by {intent['claimed_by']}; fact recorded only"}
            graph.claim_intent(brain, intent_id, worker)
            done = graph.complete_intent(
                brain, intent_id, worker, result_facts=[fact["id"]],
                status="done" if outcome == "probed" else "blocked", note=reason or summary,
            )
        except (graph.LineageError, ValueError):
            return None
        return {"id": intent_id, "status": done["status"], "result_fact": fact["id"]}
