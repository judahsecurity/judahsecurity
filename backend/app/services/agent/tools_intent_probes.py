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
Boolean/error/AND/UNION/time recipes on any server-side location, plus the
numeric Boolean recipe when the input's baseline value is a positive integer.

Baselines (``_shaped_baseline``): the operator's ``baseline_value`` on the
intent, else the value the linked observation carried (the intent's
``source_capture_id``, or an observed header cell's own capture), else the
value already in the intent target (query field or path segment). Numeric and
UNION SQLi and JSON-header NoSQL need such a value; without one the shape is
unsupported (open, never clean).

NoSQL (``_run_shaped_nosql``): query/form/JSON bracket or operator objects,
cookie-parser ``j:`` JSON cookies, JSON-valued headers (JSON object/array
baseline only), XML operator elements, and string ``$where``/``$regex``
recipes on one path segment, all under the same interleaved differential.

Requests are planned in ``scoped_assessment.intent_request``. When a probe
works an intent-backed cell the intent is claimed and completed with a
result fact citing the receipt (planning state, never proof).

Method approval (``_shaped_approval``): GET is free; POST needs the path in
``body_replay_paths``. PUT/PATCH/DELETE never touch an existing record: the
cell path must match a ``test_record_endpoints`` ``record_path`` template with
the method in its ``write_methods``, and the probe is sent only to a dummy
record Prowl creates, verifies as its own (nonce read back) and cleans up
(``scoped_assessment.test_records.OwnRecordWriter``). A concrete id in the
intent is never used. Without a matching endpoint the probe returns
``operator_approval_required`` and the cell stays leased/open.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from app.services.agent.tool_specs import ALL_PHASES, read_tool

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

    def _test_record_endpoint(self, method: str, path: str) -> Optional[Dict[str, Any]]:
        from app.services.agent.scoped_assessment.test_records import match_endpoint

        return match_endpoint(getattr(self, "_scoped_test_record_endpoints", None) or [],
                              method, path)

    def _shaped_approval(self, method: str, path: str) -> Optional[str]:
        """None when the operator approved this method for this path, else why not.

        POST: ``body_replay_paths`` (as for captured bodies). PUT/PATCH/DELETE:
        a ``test_record_endpoints`` entry whose ``record_path`` template
        matches the path and whose ``write_methods`` hold the method; the
        request then goes only to Prowl's own dummy record.
        """
        if method == "GET":
            return None
        if method == "POST":
            if path in (getattr(self, "_scoped_body_replay_paths", None) or set()):
                return None
            return "POST path is not in body_replay_paths"
        if method in {"PUT", "PATCH", "DELETE"}:
            if self._test_record_endpoint(method, path) is None:
                return (f"{method} {path} matches no test_record_endpoints record_path with "
                        f"{method} in write_methods; write probes only touch a record Prowl "
                        "creates and verifies as its own")
            return None
        return "method_unsupported"

    def _shaped_write_approved(self, method: str, cell: Dict[str, Any]) -> bool:
        return self._shaped_approval(method, str(cell.get("path") or "/")) is None

    def _shaped_shape_error(self, cell: Dict[str, Any], test_type: str) -> str:
        from app.services.agent.scoped_assessment.intent_request import WRITE_METHODS, shape_error

        location, _sep, parameter = str(cell.get("parameter") or "").partition(":")
        method = str(cell.get("method") or "GET").upper()
        if method in WRITE_METHODS and location == "path":
            # A path probe would change the record URL itself, i.e. write to a
            # record that is not Prowl's own.
            return "path_location_unsupported_for_record_writes"
        return shape_error(test_type, method, location, parameter)

    def _own_record_writer(self, cell: Dict[str, Any], method: str, identity: str,
                           state: Optional[dict], scoped_origin: str):
        """``OwnRecordWriter`` for a PUT/PATCH/DELETE cell, None for GET/POST."""
        from app.services.agent.scoped_assessment import intent_request
        from app.services.agent.scoped_assessment.test_records import OwnRecordWriter

        if method not in intent_request.WRITE_METHODS:
            return None
        endpoint = self._test_record_endpoint(method, str(cell.get("path") or "/"))
        if endpoint is None:
            raise intent_request.ApprovalRequired()
        return OwnRecordWriter(self, endpoint, method=method, identity=identity, state=state,
                               scoped_origin=scoped_origin,
                               coverage_cell_id=str(cell.get("id") or ""))

    def _test_record_aborted(self, cell: Dict[str, Any], exc: Exception) -> Dict[str, Any]:
        """The probe did not run: its dummy record was not provably Prowl's own.

        The cell stays leased/open (never tested_clean); the record's state is
        in list_test_records.
        """
        from app.services.agent.scoped_assessment.test_records import public_record

        rows = [public_record(row) for row in getattr(self, "_scoped_test_records", None) or []
                if row.get("coverage_cell_id") == cell.get("id")][-3:]
        return {"success": False, "error": "test_record_aborted", "reason": str(exc)[:200],
                "coverage_cell_id": cell.get("id"), "coverage_cell_status": cell.get("status"),
                "test_records": rows}

    def _persist_test_records(self) -> None:
        """Mirror the session's test-record registry next to its run snapshot."""
        from app.services.agent.run_snapshot import save_session_sidecar
        from app.services.agent.scoped_assessment.test_records import public_record
        from app.services.agent.tools import current_organization_id, current_session_id

        org_id, session_id = current_organization_id.get(), current_session_id.get()
        if org_id and session_id:
            save_session_sidecar(org_id, session_id, test_records=[
                public_record(row) for row in getattr(self, "_scoped_test_records", None) or []])

    async def list_test_records(self, **_kwargs: Any) -> str:
        """Dummy records Prowl created for write probes, and their cleanup state."""
        import json

        from app.services.agent.scoped_assessment.test_records import summarize

        rows = list(getattr(self, "_scoped_test_records", None) or [])
        endpoints = getattr(self, "_scoped_test_record_endpoints", None) or []
        return json.dumps({**summarize(rows), "endpoints": [
            {"create_path": e["create_path"], "record_path": e["record_path"],
             "write_methods": e["write_methods"], "cleanup": e["cleanup"]} for e in endpoints]},
            default=str)

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

        if test_type == "nosql":
            return await self._run_shaped_nosql(cell, nonce, identity,
                                                scoped_origin=scoped_origin, recipe=recipe)

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        denied = self._shaped_approval(method, str(cell.get("path") or "/"))
        if denied:
            raise ValueError("operator_approval_required")
        state = self._scoped_state(identity, url)
        writer = self._own_record_writer(cell, method, identity, state, scoped_origin)
        if writer is not None:
            url = writer.plan_url(url)
        requests = intent_request.injection_requests(
            method=method, url=url, location=location, parameter=parameter,
            test_type=test_type, nonce=nonce, factors=factors, state=state,
            recipes=[recipe] if recipe and test_type != "nosql" else (),
            write_approved=self._shaped_write_approved(method, cell),
        )
        for planned in requests.values():
            self._scoped_origin(planned.url)
        self._charge(method, len(requests))
        fetch = writer.wrap(intent_request.fetch_body) if writer else intent_request.fetch_body
        try:
            if test_type == "nosql":
                proof = await asyncio.to_thread(
                    injection_probe.probe_nosql, requests, allowed_origin=scoped_origin,
                    state=None, nonce=nonce, fetch=fetch,
                )
            else:
                proof = await asyncio.to_thread(
                    injection_probe.probe_injection, requests, test_type=test_type,
                    allowed_origin=scoped_origin, state=None, nonce=nonce, factors=factors,
                    fetch=fetch,
                )
        finally:
            if writer is not None:
                await asyncio.to_thread(writer.finish)
        if writer is not None:
            proof.update(writer.receipt())
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
        state = self._scoped_state(identity, url)
        writer = self._own_record_writer(cell, method, identity, state, scoped_origin)
        if writer is not None:
            url = writer.plan_url(url)
        requests = intent_request.plan_requests(
            method=method, url=url, location=location, parameter=parameter,
            values={"control": control_value, "probe": probe_value},
            state=state, test_type=test_type,
            write_approved=self._shaped_write_approved(method, cell),
        )
        for planned in requests.values():
            self._scoped_origin(planned.url)
        self._charge(method, 2)
        observe = (writer.wrap(intent_request.observe_headers) if writer
                   else intent_request.observe_headers)
        try:
            proof = await asyncio.to_thread(
                intent_request.probe_response_requests, requests["control"], requests["probe"],
                test_type=test_type, allowed_origin=scoped_origin, nonce=nonce, observe=observe,
            )
        finally:
            if writer is not None:
                await asyncio.to_thread(writer.finish)
        if writer is not None:
            proof.update(writer.receipt())
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

    # ------------------------------------------------------------ baselines

    def _shaped_capture(self, capture_id: str, identity: str) -> Optional[Dict[str, Any]]:
        """The private capture a shaped cell is bound to, or None.

        The binding comes from planning state (the intent's
        ``source_capture_id`` or the observed cell's ``capture_id``), never from
        a candidate. The independent verifier may read the hunter's capture
        for that binding only, as for observed GET SQLi replays.
        """
        import json

        from app.services.agent.evidence_store import verification_run

        try:
            row = self._scoped_capture_row(capture_id)
        except Exception:
            return None
        if not row or row.get("identity") != identity or not isinstance(row.get("private"), bytes):
            return None
        run = verification_run.get()
        if row.get("verifier_run_id") not in (None, run.id if run else None):
            return None
        try:
            captured = json.loads(row["private"])
        except ValueError:
            return None
        return captured if isinstance(captured, dict) else None

    def _shaped_baseline(self, cell: Dict[str, Any], identity: str,
                         scoped_origin: str) -> Dict[str, str]:
        """The input's baseline value and the request URL it came with.

        Order: the intent's operator ``baseline_value``; the linked
        observation (intent ``source_capture_id`` or the observed cell's
        capture) when it is the same method, origin and path; the value the
        intent target already carries (query field or path segment). ``value``
        is '' when none exists. Values never enter receipts; ``source`` does.
        """
        from app.services.agent.attack_graph import get_intent
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment import intent_request

        method, url, location, parameter, _context = self._shaped_base(cell, scoped_origin)
        intent: Dict[str, Any] = {}
        if cell.get("intent_id"):
            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            intent = get_intent(brain, str(cell["intent_id"])) or {}
        supplied = intent.get("baseline_value")
        if intent_request.valid_baseline_value(supplied):
            return {"value": supplied, "source": "operator_baseline_value"
                    if intent.get("created_by") == "operator" else "intent_baseline_value",
                    "url": url, "capture_id": ""}
        capture_id = str(intent.get("source_capture_id") or cell.get("capture_id") or "")
        captured = self._shaped_capture(capture_id, identity) if capture_id else None
        if captured is not None:
            from urllib.parse import urlsplit, urlunsplit

            try:
                parts = urlsplit(str(captured.get("url") or ""))
                same = (_origin(str(captured.get("url") or "")) == scoped_origin
                        and (parts.path or "/") == str(cell.get("path") or "/")
                        and str(captured.get("method") or "").upper() == method)
            except ValueError:
                same = False
            value = intent_request.captured_value(captured, location, parameter) if same else None
            if value and intent_request.valid_baseline_value(value):
                return {"value": value, "source": "captured_request",
                        "url": urlunsplit(parts._replace(fragment="")), "capture_id": capture_id}
        value = intent_request.url_value(url, location, parameter)
        return {"value": value, "source": "intent_target" if value else "", "url": url,
                "capture_id": ""}

    async def _run_shaped_nosql(self, cell: Dict[str, Any], nonce: str, identity: str, *,
                                scoped_origin: str, recipe: str = "") -> Tuple[dict, str]:
        """The NoSQL operator differential on a shaped cell (hunter and verifier).

        Every location shares ``probe_nosql``'s standard: stable control,
        stable always-true variant that differs from it, and a same-meaning
        variant equal to the control. Path segments try the string recipes in
        order (the verifier replays only the hunter's). All requests are
        planned before any is sent, so an unsupported shape sends nothing.
        """
        from app.services.agent.scoped_assessment import injection_probe, intent_request

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        if self._shaped_approval(method, str(cell.get("path") or "/")):
            raise ValueError("operator_approval_required")
        recipes = intent_request.nosql_recipes_for(location)
        if recipe and location in intent_request.NOSQL_OBJECT_LOCATIONS:
            if recipe not in recipes:
                raise intent_request.UnsupportedShape("recipe_unknown")
            recipes = (recipe,)
        baseline = {"value": "", "source": "", "capture_id": ""}
        if location == "header":
            baseline = self._shaped_baseline(cell, identity, scoped_origin)
            if not baseline["value"]:
                raise intent_request.UnsupportedShape("header_baseline_value_unavailable")
        state = self._scoped_state(identity, url)
        writer = self._own_record_writer(cell, method, identity, state, scoped_origin)
        if writer is not None:
            url = writer.plan_url(url)
        plans = {name: intent_request.injection_requests(
            method=method, url=url, location=location, parameter=parameter, test_type="nosql",
            nonce=nonce, factors=(0, 0), state=state, baseline=baseline["value"],
            nosql_recipe=name, write_approved=self._shaped_write_approved(method, cell))
            for name in recipes}
        for requests in plans.values():
            for planned in requests.values():
                self._scoped_origin(planned.url)
        fetch = writer.wrap(intent_request.fetch_body) if writer else intent_request.fetch_body
        tried = []
        proof: Dict[str, Any] = {}
        try:
            for name, requests in plans.items():
                self._charge(method, len(requests))
                proof = await asyncio.to_thread(
                    injection_probe.probe_nosql, requests, allowed_origin=scoped_origin,
                    state=None, nonce=nonce, fetch=fetch, recipe=name,
                )
                tried.append(name)
                if proof.get("proof_confirmed") is True:
                    break
        finally:
            if writer is not None:
                await asyncio.to_thread(writer.finish)
        proof.update(method=method, location=location, recipes_tried=tried,
                     total_requests_sent=sum(len(plans[name]) for name in tried))
        if baseline["source"]:
            proof["baseline_value_source"] = baseline["source"]
        if writer is not None:
            proof.update(writer.receipt())
        return proof, context

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

        Hunter (no ``recipe``): numeric Boolean first when the baseline value is
        a positive integer; then OR Boolean, the error or AND follow-up, UNION
        (ordinary string baseline whose fresh response reflects result data)
        and the time families exactly as the observed GET lane runs them.
        Verifier: only the hunter's recipe (and SQL family), with fresh nonces.
        PUT/PATCH/DELETE go only to Prowl's own fresh record (one per call).
        """
        import asyncio

        from app.services.agent.scoped_assessment import intent_request

        method, url, _location, _parameter, _context = self._shaped_base(cell, scoped_origin)
        if self._shaped_approval(method, str(cell.get("path") or "/")):
            raise intent_request.ApprovalRequired()
        writer = self._own_record_writer(cell, method, identity,
                                         self._scoped_state(identity, url), scoped_origin)
        try:
            result = await self._shaped_sqli_recipes(
                cell, identity, scoped_origin=scoped_origin, recipe=recipe, family=family,
                writer=writer)
        finally:
            if writer is not None:
                await asyncio.to_thread(writer.finish)
        if writer is not None:
            result.update(writer.receipt())
        return result

    async def _shaped_sqli_recipes(self, cell: Dict[str, Any], identity: str, *,
                                   scoped_origin: str, recipe: str, family: str,
                                   writer: Any) -> dict:
        import secrets

        from app.services.agent.scoped_assessment import (
            intent_request, sqli_boolean, sqli_string, sqli_time, sqli_union,
        )

        method, url, location, parameter, context = self._shaped_base(cell, scoped_origin)
        path = str(cell.get("path") or "/")
        baseline = self._shaped_baseline(cell, identity, scoped_origin)
        url = baseline["url"]
        value = baseline["value"]
        state = self._scoped_state(identity, url)
        if writer is not None:
            url = writer.plan_url(url)
        observe = (writer.wrap(intent_request.observe_planned) if writer is not None
                   else intent_request.observe_planned)
        target = scoped_origin + path
        # String recipes extend an ordinary value; anything else uses the
        # intent target's value or a fresh harmless canary, as before.
        base = (value if intent_request.sqli_safe_value(value)
                else intent_request.sqli_baseline_value(url, location, parameter))
        validators = {"sqli_boolean_string": sqli_string.string_sql_proof_valid,
                      "sqli_error_string": sqli_string.string_error_proof_valid,
                      "sqli_time_string": sqli_time.time_sql_proof_valid,
                      "sqli_boolean_numeric": sqli_boolean.numeric_sql_proof_valid,
                      "sqli_union_string": sqli_union.union_sql_proof_valid}

        def plan(values: Dict[str, str]) -> Dict[str, Any]:
            requests = intent_request.plan_requests(
                method=method, url=url, location=location, parameter=parameter,
                values=values, state=state, test_type="sqli",
                write_approved=self._shaped_write_approved(method, cell),
            )
            for planned in requests.values():
                self._scoped_origin(planned.url)
            self._charge(method, len(requests))
            return requests

        def stamp(result: dict, value_source: str) -> dict:
            result.update(method=method, location=location, request_context=context,
                          intent_request=True, baseline_source="intent_request",
                          baseline_value_source=value_source)
            if value_source == "captured_request" and baseline.get("capture_id"):
                result["source_capture_id"] = baseline["capture_id"]
            result["proof_confirmed"] = validators[result["operation"]](result)
            result["finding"] = False
            return result

        async def preflight(marker: str = "") -> dict:
            """One fresh baseline request with the exact baseline value."""
            requests = plan({"baseline": value})
            row = await asyncio.to_thread(observe, requests["baseline"],
                                          allowed_origin=scoped_origin,
                                          reflection_marker=marker)
            return {key: row.get(key) for key in (
                "status", "content_type", "bytes_captured", "truncated", "body_sha256",
                "redirected", "json_array_lengths", "reflection_detected")}

        async def run(name: str, fam: str = "") -> dict:
            nonce, false_nonce = intent_request.sqli_nonces()
            values = intent_request.sqli_values(name, base, nonce, false_nonce, fam)
            checks = await asyncio.to_thread(
                intent_request.probe_sqli_requests, plan(values), recipe=name,
                allowed_origin=scoped_origin, observe=observe,
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
            source = baseline["source"] if base == value and value else "intent_request"
            return stamp(result, source)

        async def run_numeric() -> Tuple[Optional[dict], str]:
            """Numeric Boolean (``sqli_boolean``) on a positive-integer baseline."""
            if not intent_request.positive_integer(value):
                return None, "baseline_not_positive_integer"
            pre = await preflight()
            if (pre["status"] != 200 or pre["truncated"] is not False
                    or pre["redirected"] is not False):
                return None, "baseline_response_not_ok"
            nonce = str(secrets.randbelow(90000) + 10000)
            checks = await asyncio.to_thread(
                intent_request.probe_sqli_requests, plan(intent_request.numeric_values(value, nonce)),
                recipe="numeric", allowed_origin=scoped_origin, observe=observe,
            )
            result = sqli_boolean.build_numeric_boolean_result(
                target, nonce, parameter=parameter, checks=checks)
            result["baseline_preflight"] = {k: pre[k] for k in (
                "status", "body_sha256", "redirected", "truncated")}
            result["preflight_requests"] = 1
            return stamp(result, baseline["source"]), ""

        async def union_ready(or_result: Optional[dict]) -> str:
            """'' when UNION may run: ordinary value whose response renders results."""
            if not intent_request.sqli_safe_value(value) or not baseline["source"]:
                return "baseline_not_ordinary_string"
            if or_result is not None and not sqli_union.union_followup_eligible(or_result):
                return "baseline_unstable"
            pre = await preflight(marker=value if len(value) >= 4 else "")
            return "" if intent_request.result_data_reflected(pre) else "baseline_result_not_reflected"

        async def run_union(fam: str) -> Tuple[Optional[dict], int]:
            """Column count by NULL padding, reflected cell, then the fixed confirm."""
            nonce = str(secrets.randbelow(90000) + 10000)
            marker = sqli_union.marker_for(nonce)
            found, probes = None, 0
            for columns in range(1, sqli_union.MAX_COLUMNS + 1):
                for position in range(1, columns + 1):
                    if probes >= sqli_union.MAX_DISCOVERY:
                        break
                    probes += 1
                    requests = plan({"union": intent_request.union_value(
                        value, fam, columns, position, marker)})
                    row = await asyncio.to_thread(observe, requests["union"],
                                                  allowed_origin=scoped_origin,
                                                  reflection_marker=marker)
                    if (row.get("status") == 200 and row.get("reflection_detected") is True
                            and row.get("truncated") is False and not row.get("redirected")):
                        found = (columns, position)
                        break
                if found or probes >= sqli_union.MAX_DISCOVERY:
                    break
            if not found:
                return None, probes
            columns, position = found
            union = intent_request.union_value(value, fam, columns, position, marker)
            checks = await asyncio.to_thread(
                intent_request.probe_sqli_requests,
                plan({"baseline_first": value, "union_first": union,
                      "union_second": union, "baseline_last": value}),
                recipe="union", allowed_origin=scoped_origin, observe=observe,
                reflection_marker=marker,
            )
            result = sqli_union.build_string_union_result(
                target, nonce, parameter=parameter, family=fam, column_count=columns,
                reflected_position=position, checks=checks)
            result["discovery_requests"] = probes
            return stamp(result, baseline["source"]), probes

        if recipe:
            name = {"string_or_boolean_v1": "or", "string_or_json_rows_v1": "or",
                    "string_and_boolean_v1": "and", "string_error_v1": "error",
                    "string_time_v1": "time", "numeric_and_boolean_v1": "numeric",
                    "string_union_v1": "union"}.get(recipe)
            if (not name or (name == "time" and family not in sqli_time.FAMILIES)
                    or (name == "union" and family not in sqli_union.FAMILIES)):
                raise intent_request.UnsupportedShape("recipe_unknown")
            if name == "numeric":
                result, why = await run_numeric()
                if result is None:
                    raise intent_request.UnsupportedShape(why)
                result["total_requests_sent"] = result["requests_sent"] + 1
                return result
            if name == "union":
                why = await union_ready(None)
                if why:
                    raise intent_request.UnsupportedShape(why)
                result, probes = await run_union(family)
                if result is None:
                    return {"operation": "sqli_union_string", "proof_recipe": recipe,
                            "target": target, "parameter": parameter, "method": method,
                            "location": location, "request_context": context,
                            "intent_request": True, "sql_family": family,
                            "requests_sent": probes, "total_requests_sent": probes + 1,
                            "proof_confirmed": False, "finding": False,
                            "union_skipped": "no_reflected_column_layout"}
                result["total_requests_sent"] = result["requests_sent"] + probes + 1
                return result
            result = await run(name, family)
            result["total_requests_sent"] = result["requests_sent"]
            return result

        prior: list = []
        extra_requests = 0
        skipped: Dict[str, str] = {}

        def done(row: dict) -> None:
            prior.append({"proof_recipe": row.get("proof_recipe"),
                          "sql_family": row.get("sql_family", ""),
                          "proof_confirmed": row.get("proof_confirmed") is True,
                          "requests_sent": row.get("requests_sent")})

        result: Optional[dict] = None
        if intent_request.positive_integer(value):
            result, why = await run_numeric()
            extra_requests += 1
            if why:
                skipped["numeric_skipped"] = why
        elif value:
            skipped["numeric_skipped"] = "baseline_not_positive_integer"
        if result is not None and result["proof_confirmed"] is True:
            result["prior_recipes"] = prior
            result["total_requests_sent"] = result["requests_sent"] + extra_requests
            return result
        if result is not None:
            done(result)
        or_result = await run("or")
        result = or_result
        if result["proof_confirmed"] is not True:
            if sqli_string.error_followup_eligible(or_result):
                done(result)
                result = await run("error")
            elif sqli_string.and_fallback_eligible(or_result):
                done(result)
                result = await run("and")
        if result["proof_confirmed"] is not True:
            why = await union_ready(or_result)
            if why:
                skipped["union_skipped"] = why
            else:
                extra_requests += 1
                union_result = None
                for fam in sqli_union.FAMILIES:
                    attempt, probes = await run_union(fam)
                    extra_requests += probes
                    if attempt is not None:
                        if union_result is not None:
                            extra_requests += int(union_result["requests_sent"] or 0)
                        union_result = attempt
                        if attempt["proof_confirmed"] is True:
                            break
                if union_result is None:
                    skipped["union_skipped"] = "no_reflected_column_layout"
                else:
                    done(result)
                    result = union_result
        if result["proof_confirmed"] is not True and sqli_time.time_followup_eligible(or_result):
            for fam in sqli_time.FAMILIES:
                done(result)
                result = await run("time", fam)
                if result["proof_confirmed"] is True:
                    break
        result["prior_recipes"] = prior
        result.update(skipped)
        result["total_requests_sent"] = (int(result.get("requests_sent") or 0) + extra_requests
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
        from app.services.agent.scoped_assessment.test_records import TestRecordAborted
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
            except TestRecordAborted as exc:
                return self._test_record_aborted(cell, exc)
            except (ValueError, OSError) as exc:
                return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
            # Numeric Boolean receipts are scoped_numeric_sqli, as on the observed lane.
            operation = ("scoped_numeric_sqli" if proof.get("operation") == "sqli_boolean_numeric"
                         else "scoped_string_sqli")
            proof["evidence_id"] = evidence_store(self).record(
                operation, proof, target=proof["target"], identity=identity,
                coverage_cell_id=cell["id"], test_type="sqli",
                success=proof["proof_confirmed"],
            )
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
                "baseline_source", "baseline_value_source", "sql_family", "column_count",
                "reflected_position", "prior_recipes", "numeric_skipped", "union_skipped",
                "record_paths", "test_records") if key in proof}
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


TOOL_SPECS = (
    read_tool(
        "list_test_records",
        "Dummy records Prowl created for PUT/PATCH/DELETE probes (write probes only ever "
        "touch records Prowl created and verified as its own). No args. Returns each "
        "record's path, endpoint, state (active | cleaned | cleanup_pending | "
        "create_failed), created_at and role, plus the approved test_record_endpoints. "
        "Report every cleanup_pending record to the operator.",
        phases=ALL_PHASES, section="Scoped Assessment", concurrent=False,
    ),
)
