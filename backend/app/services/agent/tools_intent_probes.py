"""Shaped requests for leased cells without a captured baseline.

Mixin for ASMToolsManager (helpers only, no new tools). The leased scoped
probes (``scoped_injection_probe_assigned``, ``scoped_response_probe_assigned``)
call these when a cell is

* intent-backed (``attack_graph`` intent, ``source=INTENT_CELL_SOURCE``, no
  capture): the request comes from the intent's method, URL, parameter and
  location, so operator-directed tests work on inputs Prowl never observed;
* an observed header or cookie input on a GET (no capture is needed to set
  one header or cookie on the observed endpoint).

Intent-backed ``xss`` and ``sqli`` cells go through
``scoped_input_probe_assigned`` to ``_shaped_input_probe_assigned`` here: XSS
as a browser nonce navigation (GET query or fragment), SQLi as the string
Boolean/error/AND/time recipes on any server-side location.

Requests are planned in ``scoped_assessment.intent_request``. When a probe
works an intent-backed cell the intent is claimed and completed with a
result fact citing the receipt (planning state, never proof).

Method approval (``_shaped_approval``): GET is free; POST needs the path in
``body_replay_paths``; PUT/PATCH/DELETE need the exact (method, path) in the
operator's ``write_method_paths``, and DELETE also needs the path to be an
approved cleanup path. Without it the probe returns
``operator_approval_required`` and the cell stays leased/open.
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
        """None when the operator approved this exact method and path, else why not.

        POST: ``body_replay_paths`` (as for captured bodies). PUT/PATCH/DELETE:
        ``write_method_paths``; DELETE also only on an approved cleanup path.
        """
        if method == "GET":
            return None
        if method == "POST":
            if path in (getattr(self, "_scoped_body_replay_paths", None) or set()):
                return None
            return "POST path is not in body_replay_paths"
        if method in {"PUT", "PATCH", "DELETE"}:
            if (method, path) not in (getattr(self, "_scoped_write_method_paths", None) or set()):
                return f"{method} path is not in write_method_paths"
            if method == "DELETE" and path not in (
                    (getattr(self, "_scoped_stored_xss_cleanup_paths", None) or set())
                    | (getattr(self, "_scoped_race_cleanup_paths", None) or set())
                    | (getattr(self, "_scoped_csrf_cleanup_paths", None) or set())):
                return "DELETE path is not an approved cleanup path"
            return None
        return "method_unsupported"

    def _shaped_write_approved(self, method: str, cell: Dict[str, Any]) -> bool:
        return self._shaped_approval(method, str(cell.get("path") or "/")) is None

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
            write_approved=self._shaped_write_approved(method, cell),
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
            write_approved=self._shaped_write_approved(method, cell),
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

    # ------------------------------------------------------------ xss / sqli

    async def _run_shaped_sqli(self, cell: Dict[str, Any], identity: str, *,
                               scoped_origin: str, recipe: str = "",
                               family: str = "") -> dict:
        """String SQLi recipes on one intent-backed input (hunter or verifier).

        Hunter (no ``recipe``): OR Boolean, then the error or AND follow-up
        and the time families exactly as the observed GET lane runs them.
        Verifier: only the hunter's recipe (and SQL family), with fresh nonces.
        """
        from app.services.agent.scoped_assessment import intent_request, sqli_string, sqli_time

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        path = str(cell.get("path") or "/")
        if self._shaped_approval(method, path):
            raise intent_request.ApprovalRequired()
        state = self._scoped_state(identity, url)
        target = scoped_origin + path
        base = intent_request.sqli_baseline_value(url, location, parameter)
        validators = {"sqli_boolean_string": sqli_string.string_sql_proof_valid,
                      "sqli_error_string": sqli_string.string_error_proof_valid,
                      "sqli_time_string": sqli_time.time_sql_proof_valid}

        async def run(name: str, fam: str = "") -> dict:
            nonce, false_nonce = intent_request.sqli_nonces()
            values = intent_request.sqli_values(name, base, nonce, false_nonce, fam)
            requests = intent_request.plan_requests(
                method=method, url=url, location=location, parameter=parameter,
                values=values, state=state, test_type="sqli",
                write_approved=self._shaped_write_approved(method, cell),
            )
            for planned in requests.values():
                self._scoped_origin(planned.url)
            self._charge(method, len(requests))
            checks = await asyncio.to_thread(
                intent_request.probe_sqli_requests, requests, recipe=name,
                allowed_origin=scoped_origin,
            )
            if name == "or":
                result = sqli_string.build_string_boolean_result(
                    target, nonce, parameter=parameter, checks=checks)
            elif name == "and":
                result = sqli_string.build_string_and_result(
                    target, nonce, parameter=parameter, checks=checks)
            elif name == "error":
                result = sqli_string.build_string_error_result(
                    target, parameter=parameter, checks=checks)
            else:
                result = sqli_time.build_string_time_result(
                    target, nonce, parameter=parameter, family=fam, checks=checks)
            result.update(method=method, location=location, request_context=context,
                          intent_request=True, baseline_source="intent_request")
            result["proof_confirmed"] = validators[result["operation"]](result)
            result["finding"] = False
            return result

        if recipe:
            name = {"string_or_boolean_v1": "or", "string_or_json_rows_v1": "or",
                    "string_and_boolean_v1": "and", "string_error_v1": "error",
                    "string_time_v1": "time"}.get(recipe)
            if not name or (name == "time" and family not in sqli_time.FAMILIES):
                raise intent_request.UnsupportedShape("recipe_unknown")
            result = await run(name, family)
            result["total_requests_sent"] = result["requests_sent"]
            return result
        or_result = await run("or")
        result, prior = or_result, []

        def done(row: dict) -> None:
            prior.append({"proof_recipe": row.get("proof_recipe"),
                          "sql_family": row.get("sql_family", ""),
                          "proof_confirmed": row.get("proof_confirmed") is True,
                          "requests_sent": row.get("requests_sent")})

        if result["proof_confirmed"] is not True:
            if sqli_string.error_followup_eligible(or_result):
                done(result)
                result = await run("error")
            elif sqli_string.and_fallback_eligible(or_result):
                done(result)
                result = await run("and")
        if result["proof_confirmed"] is not True and sqli_time.time_followup_eligible(or_result):
            for fam in sqli_time.FAMILIES:
                done(result)
                result = await run("time", fam)
                if result["proof_confirmed"] is True:
                    break
        result["prior_recipes"] = prior
        result["total_requests_sent"] = (int(result.get("requests_sent") or 0)
                                         + sum(int(row["requests_sent"] or 0) for row in prior))
        return result

    def _shaped_xss_template_matches(self, cell: Dict[str, Any], template: str,
                                     scoped_origin: str) -> bool:
        """Whether ``template`` is exactly what browser_template builds for this cell."""
        from app.services.agent.scoped_assessment import intent_request

        try:
            _method, url, location, parameter, _context = self._shaped_base(cell, scoped_origin)
            value = intent_request.browser_template_value(template, location, parameter)
            return bool(value and "__PROWL_NONCE__" in value and template == (
                intent_request.browser_template(url, location, parameter, value)))
        except ValueError:
            return False

    async def _shaped_input_probe_assigned(
        self, brain: Any, cell: Dict[str, Any], coverage_lease_id: str,
        technique: str, variant: str,
    ) -> Dict[str, Any]:
        """``scoped_input_probe_assigned`` for intent-backed xss and sqli cells."""
        import json
        import time

        from app.services.agent.coverage_cells import parameter_test_funnel, record_sqli_trace
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment import intent_request
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.xss_feedback import (
            MAX_ATTEMPTS, payload_for, xss_trace,
        )
        from app.services.agent.tools_common import _lease_failure_reason

        if (cell.get("status") != "leased" or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        test_type = cell["test_type"]

        def unsupported(reason: str) -> Dict[str, Any]:
            result = self._mark_unsupported_shape(brain, cell, coverage_lease_id, reason)
            self._engagement_brain = brain.to_dict()
            return result

        reason = self._shaped_shape_error(cell, test_type)
        if reason:
            return unsupported(reason)
        method = str(cell.get("method") or "GET").upper()
        denied = self._shaped_approval(method, str(cell.get("path") or "/"))
        if denied:
            return {"success": False, "error": "operator_approval_required", "reason": denied}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        _method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        identity = self._cell_identity(cell)
        try:
            self._scoped_origin(url)
            self._scoped_state(identity, url)
        except (KeyError, ValueError):
            return {"success": False, "error": "identity_unavailable"}
        if test_type == "xss":
            technique = {
                "xss_browser": "html_body", "xss_browser_svg": "html_body_svg",
                "xss_browser_attribute": "html_attribute",
                "xss_browser_attribute_single": "html_attribute_single",
                "xss_browser_js_single": "js_single", "xss_browser_js_double": "js_double",
            }.get(technique, technique)
            attempts = list(cell.get("xss_probe_attempts") or [])
            if len(attempts) >= MAX_ATTEMPTS:
                return {"success": False, "error": "xss_probe_budget_exhausted"}
            if any(row.get("technique") == technique and row.get("variant", "base") == variant
                   for row in attempts):
                return {"success": False, "error": "technique_already_attempted"}
            try:
                payload = payload_for(technique, variant)
            except ValueError as exc:
                return {"success": False, "error": str(exc)}
            try:
                template = intent_request.browser_template(url, location, parameter, payload)
                self._scoped_origin(template)
            except intent_request.UnsupportedShape as exc:
                return unsupported(str(exc))
            proof = json.loads(await self.scoped_browser_assessment(
                "check_xss", template, identity=identity))
            operation = "scoped_browser_check_xss"
            confirmed = proof.get("executed") is True
        else:
            if technique != "html_body" or variant != "base":
                return {"success": False, "error": "unsupported_technique"}
            try:
                proof = await self._run_shaped_sqli(cell, identity, scoped_origin=scoped_origin)
            except intent_request.UnsupportedShape as exc:
                return unsupported(str(exc))
            except intent_request.ApprovalRequired as exc:
                return {"success": False, "error": "operator_approval_required",
                        "reason": str(exc)}
            except (ValueError, OSError) as exc:
                return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
            proof["evidence_id"] = evidence_store(self).record(
                "scoped_string_sqli", proof, target=proof["target"], identity=identity,
                coverage_cell_id=cell["id"], test_type="sqli",
                success=proof["proof_confirmed"],
            )
            operation = "scoped_string_sqli"
            confirmed = proof.get("proof_confirmed") is True
        artifact_id = str(proof.get("evidence_id") or "")
        if not artifact_id:
            return {"success": False,
                    "error": str(proof.get("error") or "missing_probe_evidence")[:100]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == cell["id"]
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed"}
        current["probe_artifact_ids"] = list(dict.fromkeys([
            *(current.get("probe_artifact_ids") or []), artifact_id]))[:20]
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), artifact_id]))[:30]
        current["last_probe"] = operation
        extra: Dict[str, Any] = {}
        settle = True
        if test_type == "sqli":
            record_sqli_trace(current, proof)
            probe_result = {key: proof[key] for key in (
                "proof_confirmed", "proof_recipe", "requests_sent", "total_requests_sent",
                "baseline_source", "sql_family") if key in proof}
        else:
            current["xss_probe_attempts"] = [
                *(current.get("xss_probe_attempts") or []),
                {"technique": technique, "variant": variant, "evidence_id": artifact_id,
                 "executed": confirmed},
            ][:MAX_ATTEMPTS]
            trace = xss_trace(current, proof, technique=technique, variant=variant,
                              attempts=current["xss_probe_attempts"])
            current["xss_trace"] = trace
            # Further techniques may follow; the intent settles on execution or
            # when the bounded technique budget is spent.
            settle = confirmed or len(current["xss_probe_attempts"]) >= MAX_ATTEMPTS
            probe_result = {"executed": confirmed,
                            "reflection_contexts": trace["rendered_contexts"],
                            "reflection_observations": trace["render_observations"]}
            extra = {"xss_trace": trace, "technique": technique, "variant": variant}
        if confirmed:
            current["status"] = "in_focus"
            current["reason"] = "Execution-owned proof signal; independent verification required"
        intent = None
        if settle:
            intent = self._settle_cell_intent(
                live, current, worker=str(current.get("lease_owner") or ""), outcome="probed",
                test_type=test_type, evidence_id=artifact_id, proof_confirmed=confirmed)
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": cell["id"],
                "coverage_lease_id": coverage_lease_id, "operation": operation,
                "evidence_id": artifact_id, "proof_confirmed": confirmed,
                "request_context": context, "intent": intent,
                "probe_result": {**probe_result, "request_context": context},
                "funnel": parameter_test_funnel(live), **extra}
