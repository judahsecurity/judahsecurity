"""PROWL's bounded assessment operations inside the Aegis agent tool manager.

The model receives metadata and evidence IDs. Browser exchanges with request
values remain private to the current assessment session.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from contextvars import ContextVar
from urllib.parse import parse_qsl, quote, unquote_plus, urlencode, urljoin, urlsplit, urlunsplit

from app.services.agent.assessment_scope import assert_url_in_scope
from app.services.agent.assessment_sessions import browser_storage_state, identity_registry
from app.services.agent.evidence_store import evidence_store, verification_run
from app.services.agent.private_capture_store import delete_capture, load_capture, persist_capture
from app.services.agent.scoped_assessment import (
    authz_proof, body_probe, browser, http_observe, planning, query_probe,
    sqli_boolean, sqli_string, technology,
)
from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path


SCOPED_ASSESSMENT_TOOLS = (
    "scoped_browser_assessment",
    "scoped_http_get",
    "scoped_http_compare",
    "scoped_query_probe",
    "scoped_numeric_sqli",
    "scoped_string_sqli",
    "scoped_body_probe",
    "scoped_owner_only",
    "list_scoped_browser_exchanges",
    "scoped_assessment_summary",
    "complete_scoped_assessment",
    "get_finding_candidate",
)

# Exploratory probes cannot consume the capacity needed to give observed
# SQLi/XSS inputs a first pass. The total cap still bounds target traffic.
HUNTER_GET_BUDGET = 1024
HUNTER_GENERAL_GET_BUDGET = 256
VERIFIER_GET_BUDGET = 80
first_pass_get_context: ContextVar[bool] = ContextVar(
    "prowl_first_pass_get", default=False,
)
HUNTER_POST_BUDGET = 10
VERIFIER_POST_BUDGET = 10


class ScopedAssessmentTools:
    async def complete_scoped_assessment(self, reason: str = "") -> str:
        """Close complete work, or record why an assessment ended partial.

        A partial closure preserves open coverage and candidate counts. It must
        never be represented as a fully completed assessment.
        """
        summary = json.loads(await self.scoped_assessment_summary())
        if summary["complete"]:
            self._scoped_assessment_partial_reason = ""
            return json.dumps({**summary, "status": "completed"})
        reason = str(reason or "").strip()
        if not reason:
            raise ValueError("Assessment has no threat model or has unfinished coverage or candidates")
        self._scoped_assessment_partial_reason = reason[:500]
        return json.dumps({**summary, "status": "partial", "reason": self._scoped_assessment_partial_reason})

    async def get_finding_candidate(self, candidate_id: str) -> str:
        """Read one Aegis agent finding candidate and its review state."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        row = next((row for row in brain.candidates or []
                    if (row.get("id") if isinstance(row, dict) else row.id) == candidate_id), None)
        if row is None:
            raise ValueError("Unknown finding candidate in this assessment")
        return json.dumps(row if isinstance(row, dict) else row.to_dict())

    async def scoped_assessment_summary(self) -> str:
        """Require a threat model and accounted coverage before declaring completion."""
        from app.services.agent.engagement_brain import coverage_progress, engagement_brain_from_dict

        self._scoped_assessment_started = True
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        coverage = coverage_progress(brain)
        pending = [row.get("id") if isinstance(row, dict) else row.id
                   for row in brain.candidates or []
                   if (row.get("status") if isinstance(row, dict) else row.status) == "pending"]
        unpublished = [row.get("id") if isinstance(row, dict) else row.id
                       for row in brain.candidates or []
                       if (row.get("status") if isinstance(row, dict) else row.status) == "confirmed"
                       and not (row.get("finding_id") if isinstance(row, dict) else row.finding_id)]
        complete = bool(brain.threat_model and coverage["denominator"]
                        and coverage["untested_count"] == 0
                        and coverage["open_cell_count"] == 0
                        and coverage["pending_proof_escalation_count"] == 0
                        and not pending and not unpublished)
        self._engagement_brain = brain.to_dict()
        return json.dumps({"complete": complete, "threat_model_present": bool(brain.threat_model),
                           "coverage": coverage, "pending_candidates": pending,
                           "unpublished_candidates": unpublished})

    def set_scoped_assessment_policy(self, policy: dict | None) -> None:
        """Install operator supplied rules for this agent session, never model supplied rules."""
        policy = policy or {}
        paths = policy.get("body_replay_paths") or []
        cleanup_paths = policy.get("stored_xss_cleanup_paths") or []
        expectations = policy.get("owner_only_resources") or []
        auth_login_path = policy.get("auth_login_path") or ""
        if (auth_login_path and (not isinstance(auth_login_path, str)
                or not auth_login_path.startswith("/") or auth_login_path.startswith("//")
                or auth_login_path == "/" or len(auth_login_path) > 256
                or ".." in auth_login_path
                or any(not (char.isascii() and (char.isalnum() or char in "/_.-")) for char in auth_login_path))):
            raise ValueError("Invalid authenticated login path")
        if (not isinstance(paths, list) or len(paths) > 8
                or not isinstance(cleanup_paths, list) or len(cleanup_paths) > 8
                or not isinstance(expectations, list) or len(expectations) > 8):
            raise ValueError("Invalid bounded assessment policy")
        for path in [*paths, *cleanup_paths]:
            if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                    or path == "/" or len(path) > 256 or any(char in path for char in "?#\\\r\n\t ")):
                raise ValueError("Invalid approved write or cleanup path")
        approved = {}
        for row in expectations:
            if not isinstance(row, dict):
                raise ValueError("Invalid owner-only policy")
            target = row.get("target")
            owner, other = row.get("owner_identity"), row.get("other_identity")
            if (not isinstance(target, str) or len(target) > 2048
                    or not isinstance(owner, str) or not isinstance(other, str)
                    or not owner or not other or owner == other):
                raise ValueError("Owner-only resource needs two distinct identities")
            parts = urlsplit(target)
            if (parts.query or parts.fragment or not allowed_discovery_path(parts.path or "/")
                    or target != browser.origin(target) + (parts.path or "/")):
                raise ValueError("Owner-only resource needs an exact safe path")
            approved[target] = (owner, other)
        self._scoped_body_replay_paths = set(paths)
        self._scoped_stored_xss_cleanup_paths = set(cleanup_paths)
        self._scoped_owner_expectations = approved
        self._scoped_auth_login_path = auth_login_path
        if paths or cleanup_paths or approved:
            self._scoped_assessment_started = True

    def _scoped_origin(self, url: str) -> str:
        assert_url_in_scope(self, url)
        selected = browser.origin(url)
        from app.services.agent.tools import current_seed_target

        targets = [current_seed_target.get(), getattr(self, "_fallback_target", "")]
        registry = identity_registry(self)
        targets.extend(session["target"] for session in registry.identities.values())
        known = set()
        for target in targets:
            try:
                if target:
                    known.add(browser.origin(target))
            except ValueError:
                continue
        if selected not in known:
            raise ValueError("The exact origin must be part of this assessment's target or a registered identity")
        browser.assert_in_scope(url, [selected])
        return selected

    def _scoped_state(self, identity: str, url: str) -> dict | None:
        if identity == "anonymous":
            return None
        if identity == "legacy":
            from app.services.agent.evidence_store import origin

            session = getattr(self, "_auth_session", None) or {}
            try:
                same_origin = origin(str(session.get("target") or "")) == origin(url)
            except ValueError:
                same_origin = False
            if session.get("authenticated") is not True or not same_origin:
                raise ValueError("Legacy test identity requires an authenticated session on this origin")
            return browser_storage_state(session, url)
        session = identity_registry(self).resolve(identity, url)
        return browser_storage_state(session, url)

    def _observed_get_query_template(
        self, url: str, parameter: str, payload: str, identity: str,
        capture_id: str = "",
    ) -> tuple[str, str]:
        """Replace one observed GET value while retaining its other query fields.

        The raw baseline stays session local. Only the resulting scoped browser
        request and a value-free source label enter the probe receipt.
        """
        target = urlsplit(url)
        cmap = getattr(self, "_capability_map", None) or {}
        private_captures = []
        capture_ids = [capture_id] if capture_id else list(reversed(self._scoped_capture_ids()))[:40]
        for artifact_id in capture_ids:
            try:
                captured = json.loads(self._scoped_exchange(artifact_id, identity))
            except (TypeError, ValueError):
                continue
            if (isinstance(captured, dict) and captured.get("method") == "GET"
                    and captured.get("resource_type") in {"document", "xhr", "fetch"}):
                private_captures.append(("browser_traffic", captured.get("url")))
        private_links = (getattr(self, "_scoped_link_baselines", None) or {}).get(identity) or []
        candidates = [*private_captures, *(("browser_link", value) for value in private_links)]
        if identity == "anonymous":
            candidates.extend(("page_url", value) for value in (cmap.get("pages_visited") or []))
        candidates.extend(
            ("captured_api", sample.get("url"))
            for sample in (cmap.get("api_samples") or [])
            if isinstance(sample, dict)
            and str(sample.get("method") or "GET").upper() == "GET"
            and str(sample.get("identity") or "anonymous") == identity
        )
        for source, candidate in candidates:
            if not isinstance(candidate, str) or len(candidate) > 2048:
                continue
            try:
                parts = urlsplit(candidate)
            except ValueError:
                continue
            if (parts.scheme, parts.netloc, parts.path or "/") != (
                target.scheme, target.netloc, target.path or "/"
            ) or parts.fragment or len(parts.query) > 2048:
                continue
            fields = parts.query.split("&")
            if len(fields) > 40:
                continue
            matches = [index for index, field in enumerate(fields)
                       if field and unquote_plus(field.split("=", 1)[0]) == parameter]
            if len(matches) != 1:
                continue
            index = matches[0]
            raw_name = fields[index].split("=", 1)[0]
            fields[index] = raw_name + "=" + quote(payload, safe="")
            template = urlunsplit(parts._replace(query="&".join(fields)))
            if len(template) <= 2048:
                return template, source
        return f"{url}?{quote(parameter, safe='')}={quote(payload, safe='')}", "single_parameter"

    def _scoped_claim_gets(self, count: int) -> None:
        if count < 1 or count > 9:
            raise ValueError("Invalid assessment request reservation")
        verifier = verification_run.get() is not None
        counter = "_scoped_verify_get_count" if verifier else "_scoped_get_count"
        limit = VERIFIER_GET_BUDGET if verifier else HUNTER_GET_BUDGET
        used = int(getattr(self, counter, 0) or 0)
        if used + count > limit:
            raise ValueError("Scoped HTTP GET budget exhausted for this assessment session")
        if not verifier and not first_pass_get_context.get():
            general_used = int(getattr(self, "_scoped_general_get_count", 0) or 0)
            if general_used + count > HUNTER_GENERAL_GET_BUDGET:
                raise ValueError(
                    "Exploratory HTTP GET budget exhausted; observed-input first passes remain reserved"
                )
            setattr(self, "_scoped_general_get_count", general_used + count)
        setattr(self, counter, used + count)

    def _scoped_capture_ids(self) -> list[str]:
        """Find current and recovered capture IDs without exposing private bytes."""
        live = list((getattr(self, "_scoped_browser_exchanges", None) or {}).keys())
        historical = [artifact_id for artifact_id, record in evidence_store(self).records.items()
                      if record.get("kind") == "scoped_browser_exchange"]
        return list(dict.fromkeys([*(artifact_id for artifact_id in live
                                   if artifact_id not in historical), *historical]))[-120:]

    def _scoped_claim_posts(self, count: int) -> None:
        """Charge actual POST probe requests to the hunter or verifier budget."""
        verifier = verification_run.get() is not None
        counter = "_scoped_verifier_post_count" if verifier else "_scoped_post_count"
        limit = VERIFIER_POST_BUDGET if verifier else HUNTER_POST_BUDGET
        used = int(getattr(self, counter, 0) or 0)
        if used + count > limit:
            raise ValueError("Scoped POST request budget exhausted for this assessment session")
        setattr(self, counter, used + count)

    def _scoped_capture_row(self, artifact_id: str) -> dict | None:
        row = (getattr(self, "_scoped_browser_exchanges", None) or {}).get(artifact_id)
        if row is not None:
            return row
        store = evidence_store(self)
        record = store.records.get(artifact_id)
        if not record or record.get("kind") != "scoped_browser_exchange":
            return None
        recovered = load_capture(store.namespace, artifact_id)
        from app.services.agent.observability import redact_string

        if (not recovered or record["identity"] not in {
                recovered["identity"], redact_string(recovered["identity"])}
                or recovered["verifier_run_id"] != (record.get("verifier_run_id") or None)
                or not isinstance(record.get("payload"), dict)):
            return None
        return {**recovered, "public": record["payload"]}

    def _scoped_exchange(self, artifact_id: str, identity: str) -> bytes:
        row = self._scoped_capture_row(artifact_id)
        if not row or row["identity"] != identity:
            raise ValueError("Unknown browser exchange for this identity")
        current = verification_run.get()
        if row.get("verifier_run_id") != (current.id if current else None):
            raise ValueError("Browser exchange must be fresh for this verifier run")
        return row["private"]

    async def list_scoped_browser_exchanges(self) -> str:
        """List execution-owned browser XHR/fetch samples without request values."""
        rows = []
        for artifact_id in self._scoped_capture_ids():
            row = self._scoped_capture_row(artifact_id)
            if row:
                rows.append({**row["public"], "artifact_id": artifact_id, "identity": row["identity"]})
        return json.dumps({"exchanges": rows[-40:]})

    async def scoped_browser_assessment(
        self, operation: str, url: str, identity: str = "anonymous",
        max_pages: int = 1, max_actions: int = 3,
        form_action: str = "", form_field: str = "",
        form_payload_template: str = "",
        xhr_path: str = "", xhr_parameter: str = "",
        xhr_payload_template: str = "",
        xhr_query_keys: list[str] | None = None,
        xhr_actions: list[dict] | None = None,
        readback_url: str = "", cleanup_url_template: str = "",
        client_test_type: str = "",
    ) -> str:
        """Run scoped map, crawl, JS inspection, or nonce XSS execution in Chromium."""
        if operation not in ("map", "crawl", "inspect_js", "check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss", "check_client"):
            raise ValueError("Unsupported scoped browser operation")
        allowed = self._scoped_origin(url)
        if operation in {"check_form_xss", "check_stored_xss"}:
            if self._scoped_origin(form_action) != allowed:
                raise ValueError("Form action is outside the assessment origin")
            action_path = urlsplit(form_action).path or "/"
            if action_path not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
                raise ValueError("POST form path was not approved by the assessment operator")
            if operation == "check_stored_xss":
                if (self._scoped_origin(readback_url) != allowed
                        or urlsplit(readback_url).query or urlsplit(readback_url).fragment):
                    raise ValueError("Stored XSS needs an exact same-origin readback page")
                if (self._scoped_origin(cleanup_url_template) != allowed
                        or (urlsplit(cleanup_url_template).path or "/") not in
                        (getattr(self, "_scoped_stored_xss_cleanup_paths", None) or set())):
                    raise ValueError("Stored XSS cleanup path was not approved by the assessment operator")
            used = int(getattr(self, "_scoped_post_count", 0) or 0)
            if used >= 10:
                raise ValueError("Scoped POST budget exhausted for this assessment session")
            self._scoped_post_count = used + 1
        state = self._scoped_state(identity, url)
        sources: list[dict] = []
        exchanges: list[dict] = []
        link_baselines: list[str] = []
        result, screenshot = await browser.check_browser(
            operation=operation, url=url, allowed_origins=[allowed],
            storage_state=state, max_pages=max_pages,
            javascript_sources=sources if operation == "inspect_js" else None,
            traffic_exchanges=exchanges if operation in {"map", "crawl", "inspect_js"} else None,
            link_baselines=link_baselines if operation in {"map", "crawl", "inspect_js"} else None,
            max_actions=max_actions,
            form_action=form_action, form_field=form_field,
            form_payload_template=form_payload_template,
            xhr_path=xhr_path, xhr_parameter=xhr_parameter,
            xhr_payload_template=xhr_payload_template,
            xhr_query_keys=xhr_query_keys,
            xhr_actions=xhr_actions,
            readback_url=readback_url, cleanup_url_template=cleanup_url_template,
            client_test_type=client_test_type,
        )
        result["identity"] = identity
        if link_baselines:
            private = dict(getattr(self, "_scoped_link_baselines", None) or {})
            private[identity] = list(dict.fromkeys([
                *(private.get(identity) or []), *link_baselines,
            ]))[-120:]
            self._scoped_link_baselines = private
        self._scoped_assessment_started = True
        target = allowed + (xhr_path if operation == "check_xhr_xss" else
                            (urlsplit(form_action if operation in {"check_form_xss", "check_stored_xss"} else url).path or "/"))
        result["screenshot_sha256"] = hashlib.sha256(screenshot).hexdigest() if screenshot else None
        if operation in ("map", "crawl", "inspect_js"):
            result["directory_candidates"] = http_observe.observed_parent_directories(
                result.get("requests") or [], allowed,
            )
            result["technology_detection"] = await asyncio.to_thread(
                technology.detect_technologies,
                result.get("requests") or [], allowed, result.get("final_path", "/"),
            )
            result["recommended_specialists"] = planning.routes_from_observation(result)
            result["suggested_coverage"] = planning.coverage_from_observation(result)
        if operation == "inspect_js":
            from app.services.agent.scoped_assessment.javascript import analyze_javascript

            scripts = []
            for source in sources[:20]:
                data = source["data"]
                source_url = allowed + (urlsplit(source["url"]).path or "/")
                analysis = analyze_javascript(data, source_url=source_url, expected_origin=allowed)
                source_id = evidence_store(self).record(
                    "scoped_js_analysis",
                    {"url": source_url, "sha256": hashlib.sha256(data).hexdigest(),
                     "analysis": analysis, "action_ref": source.get("action_ref")},
                    target=source_url, identity=identity,
                )
                scripts.append({"url": source_url, "kind": source["kind"],
                                "page_path": source.get("page_path", ""),
                                "page_paths": source.get("page_paths", []),
                                "action_ref": source.get("action_ref"), "artifact_id": source_id,
                                "sha256": hashlib.sha256(data).hexdigest(), "analysis": analysis})
            result["scripts"] = scripts
        if operation in ("map", "crawl", "inspect_js"):
            from app.services.agent.scoped_assessment.surface_inventory import build_surface_inventory
            traffic = []
            private_store = dict(getattr(self, "_scoped_browser_exchanges", None) or {})
            retained_ids = [artifact_id for artifact_id in self._scoped_capture_ids()
                            if self._scoped_capture_row(artifact_id) is not None]
            from app.services.agent.engagement_brain import engagement_brain_from_dict
            active_brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            pinned = {str(cell.get("capture_id")) for cell in active_brain.coverage_cells
                      if isinstance(cell, dict) and cell.get("capture_id")
                      and cell.get("status") not in {"finding", "tested_clean", "skipped"}}
            dropped = 0
            for row in exchanges[:120]:
                if len(retained_ids) >= 120:
                    oldest = next((key for key in retained_ids if key not in pinned), None)
                    if oldest is None:
                        dropped += 1
                        continue
                    retained_ids.remove(oldest)
                    private_store.pop(oldest, None)
                    delete_capture(evidence_store(self).namespace, oldest)
                public = row["public"]
                private = row["private"]
                if operation == "inspect_js":
                    action_ref = public.get("action_ref")
                    prior_actions = []
                    for action in (result.get("actions") or [])[:12]:
                        if not isinstance(action, dict):
                            continue
                        if (action.get("kind") in {"tab", "disclosure", "summary"}
                                and action.get("status") == "completed"
                                and action.get("before_path") == public.get("page_path")
                                and action.get("after_path") == public.get("page_path")):
                            prior_actions.append({key: action.get(key) for key in (
                                "kind", "label", "aria_controls", "before_path",
                            )})
                        if action.get("ref") == action_ref:
                            if action.get("kind") in {"tab", "disclosure", "summary"} and prior_actions:
                                payload = json.loads(private)
                                payload["replay_actions"] = prior_actions[-6:]
                                private = json.dumps(payload, sort_keys=True).encode()
                                public["replay_action_count"] = len(payload["replay_actions"])
                            break
                artifact_id = evidence_store(self).record(
                    "scoped_browser_exchange", public, target=allowed + public["path"],
                    identity=identity,
                )
                current = verification_run.get()
                private_store[artifact_id] = {
                    "identity": identity, "private": private, "public": public,
                    "verifier_run_id": current.id if current else None,
                }
                persist_capture(evidence_store(self).namespace, artifact_id, private_store[artifact_id])
                retained_ids.append(artifact_id)
                # Only captures referenced by an existing open coverage cell are
                # pinned. A new, unused capture can yield to a later route.
                public["artifact_id"] = artifact_id
                traffic.append(public)
            self._scoped_browser_exchanges = private_store
            result["traffic"] = traffic
            result["traffic_store_dropped"] = dropped
            result["surface_inventory"] = build_surface_inventory(
                result, body_replay_paths=getattr(self, "_scoped_body_replay_paths", None),
            )
        observed = [
            {"method": row.get("method", "GET"), "url": allowed + row["path"]}
            for row in (result.get("requests") or [])[:300]
            if isinstance(row, dict) and isinstance(row.get("path"), str)
            and row["path"].startswith("/") and not row["path"].startswith("//")
        ]
        if observed:
            await self.map_application_traffic(observed, identity=identity, source="scoped_browser")
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        inventory = result.get("surface_inventory") or {}
        params = {(row.get("path"), row.get("method"))
                  for row in (inventory.get("parameters") or []) if isinstance(row, dict)}
        known = {(row.get("host"), row.get("method"), row.get("path"))
                 for row in (brain.surfaces or []) if isinstance(row, dict)}
        host = urlsplit(allowed).netloc
        for check in (result.get("suggested_coverage") or [])[:20]:
            parts = urlsplit(check["target"])
            if parts.netloc != host:
                continue
            path = parts.path or "/"
            key = (host, "GET", path)
            existing = next((row for row in brain.surfaces
                             if isinstance(row, dict) and (row.get("host"), row.get("method"), row.get("path")) == key), None)
            if existing is not None:
                existing["assessment_check"] = True
                existing["check_kind"] = check["kind"]
            elif len(brain.surfaces) < 200:
                brain.surfaces.append({"host": host, "method": "GET", "path": path,
                                       "takes_input": False, "assessment_check": True,
                                       "check_kind": check["kind"], "source": "scoped_browser"})
                known.add(key)
        for request in (result.get("requests") or [])[:300]:
            if not isinstance(request, dict) or request.get("resource_type") not in ("xhr", "fetch"):
                continue
            path, method = request.get("path"), request.get("method", "GET")
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
                continue
            key = (host, method, path)
            if key not in known and len(brain.surfaces) < 200:
                brain.surfaces.append({"host": host, "method": method, "path": path,
                                       "takes_input": bool(request.get("query_keys") or method != "GET"),
                                       "source": "scoped_browser"})
                known.add(key)
        for endpoint in (inventory.get("endpoints") or [])[:100]:
            if "live_browser" not in (endpoint.get("sources") or []):
                continue
            path = endpoint.get("path")
            if not isinstance(path, str):
                continue
            for method in (endpoint.get("methods") or ["GET"])[:8]:
                key = (host, method, path)
                if key not in known:
                    brain.surfaces.append({"host": host, "method": method, "path": path,
                                           "takes_input": (path, method) in params,
                                           "source": "scoped_browser"})
                    known.add(key)
                if len(brain.surfaces) >= 200:
                    break
        self._engagement_brain = brain.to_dict()
        if operation in ("map", "crawl", "inspect_js"):
            # The browser already runs in this backend. Feed its observations
            # into the same map and specialist worklist used by the agent.
            from app.services.agent.prowl_service_bridge import capability_map_from_observation
            from app.services.agent.capability_map import merge_capability_maps
            from app.services.agent.coverage_cells import (
                seed_js_coverage_cells, seed_parameter_coverage_cells,
            )
            from app.services.agent.parameter_inventory import collect_parameter_inventory
            from app.services.agent.runtime_mapper import ingest_capability_map_operations

            observed_map = capability_map_from_observation({
                "signal": "browser_" + operation, "result": result,
            })
            if observed_map:
                merged = merge_capability_maps(getattr(self, "_capability_map", None), observed_map)
                self._capability_map = merged
                brain = engagement_brain_from_dict(self._engagement_brain)
                ingest_capability_map_operations(brain, merged)
                seed_parameter_coverage_cells(brain, collect_parameter_inventory(merged))
                seed_js_coverage_cells(brain, merged)
                self._engagement_brain = brain.to_dict()
        receipt_id = evidence_store(self).record(
            "scoped_browser_" + operation, result, target=target, identity=identity,
            success=(bool(result.get("executed")) if operation in
                     {"check_xss", "check_form_xss", "check_xhr_xss", "check_stored_xss"}
                     else bool(result.get("behavior_observed")) if operation == "check_client"
                     else True),
        )
        result["evidence_id"] = receipt_id
        output = json.dumps(result)
        if len(output) > 20_000:
            return json.dumps({
                "evidence_id": receipt_id, "truncated": True,
                "operation": operation, "target_template": result.get("target_template"),
                "final_origin": result.get("final_origin"),
                "request_count": len(result.get("requests") or []),
                "action_count": len(result.get("actions") or []),
                "technology_detection": result.get("technology_detection"),
                "recommended_specialists": result.get("recommended_specialists"),
                "suggested_coverage": (result.get("suggested_coverage") or [])[:10],
                "next_tool": "read_evidence",
            })
        return output

    async def scoped_http_get(self, url: str, identity: str = "anonymous") -> str:
        """Read one exact-origin URL without redirects or raw response content."""
        allowed = self._scoped_origin(url)
        self._scoped_assessment_started = True
        state = self._scoped_state(identity, url)
        self._scoped_claim_gets(1)
        result = await asyncio.to_thread(http_observe.observe_get, url, [allowed], state)
        artifact_id = evidence_store(self).record(
            "scoped_http_get", result, target=allowed + (urlsplit(url).path or "/"),
            identity=identity,
        )
        return json.dumps({**result, "evidence_id": artifact_id})

    async def scoped_http_compare(self, url: str, first_identity: str, second_identity: str) -> str:
        """Compare two explicit test identities; a difference is only a lead."""
        if first_identity == second_identity:
            raise ValueError("Two distinct identities are required")
        allowed = self._scoped_origin(url)
        self._scoped_assessment_started = True
        states = [self._scoped_state(name, url) for name in (first_identity, second_identity)]
        self._scoped_claim_gets(2)
        rows = [
            await asyncio.to_thread(http_observe.observe_get, url, [allowed], state)
            for state in states
        ]
        result = {
            "target": allowed + (urlsplit(url).path or "/"),
            "first_identity": first_identity, "second_identity": second_identity,
            "first": rows[0], "second": rows[1], "finding": False,
        }
        result["evidence_id"] = evidence_store(self).record(
            "scoped_http_compare", result, target=result["target"], identity=first_identity,
        )
        return json.dumps(result)

    async def scoped_query_probe(self, artifact_id: str, parameter: str, identity: str = "anonymous") -> str:
        """Replay one browser observed GET field with a fixed quote probe; lead only."""
        private = self._scoped_exchange(artifact_id, identity)
        self._scoped_assessment_started = True
        allowed = self._scoped_origin(browser.origin(json.loads(private)["url"]))
        baseline, mutated = query_probe.plan_observed_query(
            private, parameter=parameter, allowed_origins=[allowed],
        )
        state = self._scoped_state(identity, baseline)
        self._scoped_claim_gets(2)
        result = await asyncio.to_thread(
            query_probe.probe_observed_query, baseline, mutated, parameter=parameter,
            allowed_origins=[allowed], storage_state=state,
        )
        result["source_artifact_id"] = artifact_id
        result["evidence_id"] = evidence_store(self).record(
            "scoped_query_probe", result, target=result["target"], identity=identity,
            success=not result["inconclusive"],
        )
        return json.dumps(result)

    async def scoped_body_probe(self, artifact_id: str, parameter: str, identity: str = "anonymous") -> str:
        """Probe one approved POST form or JSON field with bounded SQL controls."""
        private = self._scoped_exchange(artifact_id, identity)
        self._scoped_assessment_started = True
        observed = json.loads(private)
        allowed = self._scoped_origin(observed["url"])
        url, mime, baseline, changed = body_probe.plan_observed_body(
            private, parameter=parameter, allowed_origins=[allowed],
        )
        if (urlsplit(url).path or "/") not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            raise ValueError("POST path was not approved by the assessment operator")
        state = self._scoped_state(identity, url)
        self._scoped_claim_posts(2)
        result = await asyncio.to_thread(
            body_probe.probe_observed_body, url, mime, baseline, changed,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=state,
            replay_headers=body_probe.safe_replay_headers(private),
        )
        if result.get("sql_error_signal") and result.get("inconclusive") is False:
            try:
                _, _, baseline, quote_body, escaped_body = body_probe.plan_sql_error_body(
                    private, parameter=parameter, allowed_origins=[allowed],
                )
                self._scoped_claim_posts(3)
                result = await asyncio.to_thread(
                    body_probe.probe_sql_error_body, url, mime, baseline,
                    quote_body, escaped_body, parameter=parameter,
                    allowed_origins=[allowed], storage_state=state,
                    replay_headers=body_probe.safe_replay_headers(private), initial=result,
                )
            except (ValueError, OSError, TimeoutError) as exc:
                result["error_followup_blocked"] = type(exc).__name__
        result["source_artifact_id"] = artifact_id
        result["evidence_id"] = evidence_store(self).record(
            "scoped_body_sqli_error" if result.get("operation") in {"sqli_error_form", "sqli_error_json"} else "scoped_body_probe",
            result, target=result["target"], identity=identity,
            success=result.get("proof_confirmed") is True if result.get("operation") in {"sqli_error_form", "sqli_error_json"}
                    else not result["inconclusive"],
        )
        return json.dumps(result)

    async def _scoped_body_sql_error_verifier(
        self, artifact_id: str, parameter: str, identity: str,
    ) -> dict:
        """Freshly replay an immutable hunter capture inside a verifier run."""
        run = verification_run.get()
        record = evidence_store(self).records.get(artifact_id)
        row = self._scoped_capture_row(artifact_id)
        if (run is None or not record or record.get("kind") != "scoped_browser_exchange"
                or record.get("run_id") or not row or row.get("identity") != identity
                or row.get("verifier_run_id")):
            raise ValueError("Verifier requires a hunter-owned browser capture for this identity")
        private = row["private"]
        observed = json.loads(private)
        allowed = self._scoped_origin(observed["url"])
        url, mime, baseline, quote_body, escaped_body = body_probe.plan_sql_error_body(
            private, parameter=parameter, allowed_origins=[allowed],
        )
        if (urlsplit(url).path or "/") not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            raise ValueError("POST path was not approved by the assessment operator")
        state = self._scoped_state(identity, url)
        self._scoped_claim_posts(5)
        result = await asyncio.to_thread(
            body_probe.probe_sql_error_body, url, mime, baseline, quote_body, escaped_body,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=state,
            replay_headers=body_probe.safe_replay_headers(private),
        )
        result["source_artifact_id"] = artifact_id
        result["evidence_id"] = evidence_store(self).record(
            "scoped_body_sqli_error", result, target=result["target"], identity=identity,
            success=result["proof_confirmed"],
        )
        return result

    async def scoped_body_xss_reflection(
        self, artifact_id: str, parameter: str, identity: str = "anonymous",
    ) -> str:
        """Probe one approved captured POST with an XSS canary; never claim execution."""
        private = self._scoped_exchange(artifact_id, identity)
        observed = json.loads(private)
        allowed = self._scoped_origin(observed["url"])
        marker = "prowl-xss-" + secrets.token_hex(8)
        payload = f'<img src=x onerror=alert("{marker}")>'
        url, mime, baseline, changed = body_probe.plan_observed_body(
            private, parameter=parameter, allowed_origins=[allowed], payload=payload,
        )
        if (urlsplit(url).path or "/") not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            raise ValueError("POST path was not approved by the assessment operator")
        state = self._scoped_state(identity, url)
        self._scoped_claim_posts(2)
        result = await asyncio.to_thread(
            body_probe.probe_observed_body_reflection, url, mime, baseline, changed,
            parameter=parameter, payload=payload, allowed_origins=[allowed],
            storage_state=state,
            replay_headers=body_probe.safe_replay_headers(private),
        )
        result["source_artifact_id"] = artifact_id
        result["probe_marker"] = marker
        result["evidence_id"] = evidence_store(self).record(
            "scoped_body_xss_reflection", result, target=result["target"], identity=identity,
            success=not result["inconclusive"],
        )
        return json.dumps(result)

    async def scoped_owner_only(self, artifact_id: str, owner_identity: str) -> str:
        """Repeat an operator declared owner-only GET as owner, other, anonymous."""
        private = self._scoped_exchange(artifact_id, owner_identity)
        self._scoped_assessment_started = True
        target = authz_proof.observed_owner_resource(private)
        allowed = self._scoped_origin(target)
        policy = (getattr(self, "_scoped_owner_expectations", None) or {}).get(target)
        if not policy or policy[0] != owner_identity:
            raise ValueError("Owner-only policy was not declared for this exact resource")
        other_identity = policy[1]
        owner_state = self._scoped_state(owner_identity, target)
        other_state = self._scoped_state(other_identity, target)
        self._scoped_claim_gets(6)
        result = await asyncio.to_thread(
            authz_proof.probe_owner_only, target,
            owner_identity=owner_identity, other_identity=other_identity,
            owner_state=owner_state,
            other_state=other_state,
            allowed_origins=[allowed], before_request=lambda: None,
        )
        result["captured_artifact_id"] = artifact_id
        result["finding"] = False
        result["evidence_id"] = evidence_store(self).record(
            "scoped_owner_only", result, target=target, identity=owner_identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)

    def _observed_numeric_baseline(
        self, url: str, parameter: str, identity: str, allowed: str,
    ) -> tuple[str, str, str, str]:
        from app.services.agent.parameter_inventory import collect_parameter_inventory

        parts = urlsplit(url)
        cmap = getattr(self, "_capability_map", None) or {}
        observed = any(
            row.get("method") == "GET" and row.get("host") == parts.netloc
            and row.get("path") == (parts.path or "/")
            and row.get("name") == parameter and row.get("location") == "query"
            and row.get("identity") == identity and row.get("testable")
            for row in collect_parameter_inventory(cmap)
        )
        if not observed:
            raise ValueError("Numeric SQLi proof requires a mapped GET query parameter")
        candidates = [
            *(page for page in cmap.get("pages_visited", [])
              if identity == "anonymous" and isinstance(page, str)),
            *(sample.get("url") for sample in cmap.get("api_samples", [])
              if isinstance(sample, dict)
              and str(sample.get("method") or "GET").upper() == "GET"
              and str(sample.get("identity") or "anonymous") == identity),
            *((getattr(self, "_scoped_link_baselines", None) or {}).get(identity) or []),
        ]
        for candidate in candidates:
            if not isinstance(candidate, str):
                continue
            try:
                candidate_parts = urlsplit(candidate)
            except ValueError:
                continue
            if (candidate_parts.scheme, candidate_parts.netloc,
                    candidate_parts.path or "/") != (
                    parts.scheme, parts.netloc, parts.path or "/"):
                continue
            if parts.query and candidate != url:
                continue
            try:
                return sqli_boolean.plan_numeric_boolean_url(
                    candidate, parameter=parameter, allowed_origins=[allowed],
                )
            except ValueError:
                continue
        raise ValueError("Numeric SQLi proof needs an observed positive numeric GET value")

    async def scoped_numeric_sqli(
        self, artifact_id: str = "", parameter: str = "", identity: str = "anonymous",
        url: str = "",
    ) -> str:
        """Prove an observed numeric GET input from a capture or mapped link."""
        if bool(artifact_id) == bool(url):
            raise ValueError("Provide exactly one captured artifact or mapped URL")
        baseline_source = "browser_traffic"
        if artifact_id:
            private = self._scoped_exchange(artifact_id, identity)
            allowed = self._scoped_origin(browser.origin(json.loads(private)["url"]))
            baseline, true_url, false_url, nonce = sqli_boolean.plan_numeric_boolean(
                private, parameter=parameter, allowed_origins=[allowed],
            )
        else:
            allowed = self._scoped_origin(url)
            baseline, true_url, false_url, nonce = self._observed_numeric_baseline(
                url, parameter, identity, allowed,
            )
            baseline_source = "observed_url"
        self._scoped_assessment_started = True
        state = self._scoped_state(identity, baseline)
        self._scoped_claim_gets(6)
        result = await asyncio.to_thread(
            sqli_boolean.probe_numeric_boolean,
            baseline, true_url, false_url, nonce,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=state,
            before_request=lambda: None,
        )
        if artifact_id:
            result["source_artifact_id"] = artifact_id
        result["baseline_source"] = baseline_source
        result["finding"] = False  # One actor's proof is a candidate, never publication.
        result["evidence_id"] = evidence_store(self).record(
            "scoped_numeric_sqli", result, target=result["target"], identity=identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)

    async def scoped_string_sqli(self, url: str, parameter: str, identity: str = "anonymous") -> str:
        """Try bounded OR and, if needed, AND controls on an observed GET input."""
        allowed = self._scoped_origin(url)
        parts = urlsplit(url)
        from app.services.agent.parameter_inventory import collect_parameter_inventory

        cmap = getattr(self, "_capability_map", None) or {}
        observed = next((row for row in collect_parameter_inventory(
            cmap,
        ) if row.get("method") == "GET" and row.get("host") == parts.netloc
            and row.get("path") == (parts.path or "/")
            and row.get("name") == parameter and row.get("location") == "query"
            and row.get("identity") == identity and row.get("testable")
            and row.get("source") in {
                "page_url", "observed_form", "captured_api", "browser_traffic",
                "browser_link", "browser_request", "api_endpoint",
                "application_operation",
            }), None)
        if observed is None:
            raise ValueError("String SQLi proof requires a mapped GET query parameter")
        needs_preflight = False
        baseline_source = observed["source"]
        if not parts.query:
            # The public inventory is value-free. Keep ordinary link values in
            # session-local browser state, then recover only this exact input.
            captured_urls = []
            # Search the complete session and prefer this input's exact capture.
            capture_ids = list(reversed(self._scoped_capture_ids()))
            preferred_id = str(observed.get("artifact_id") or "")
            if preferred_id in capture_ids:
                capture_ids.remove(preferred_id)
                capture_ids.insert(0, preferred_id)
            for artifact_id in capture_ids:
                try:
                    captured = json.loads(self._scoped_exchange(artifact_id, identity))
                except (TypeError, ValueError):
                    continue
                if (isinstance(captured, dict) and captured.get("method") == "GET"
                        and captured.get("resource_type") in {"document", "xhr", "fetch"}):
                    captured_urls.append(captured.get("url"))
            candidates = [
                *captured_urls,
                *(page for page in cmap.get("pages_visited", []) if isinstance(page, str)),
                *(sample.get("url") for sample in cmap.get("api_samples", [])
                  if isinstance(sample, dict) and str(sample.get("method", "GET")).upper() == "GET"),
                *((getattr(self, "_scoped_link_baselines", None) or {}).get(identity) or []),
            ]
            for candidate in candidates:
                if not isinstance(candidate, str) or urlsplit(candidate).scheme != parts.scheme \
                        or urlsplit(candidate).netloc != parts.netloc \
                        or (urlsplit(candidate).path or "/") != (parts.path or "/"):
                    continue
                try:
                    baseline, variants, nonce = sqli_string.plan_string_boolean(
                        candidate, parameter=parameter, allowed_origins=[allowed],
                    )
                    baseline_source = "observed_url"
                    break
                except ValueError:
                    continue
            else:
                # A one-field GET form can supply a harmless baseline. Observe
                # the response once before using that value for a proof recipe.
                if identity != "anonymous":
                    raise ValueError("String SQLi proof needs an ordinary observed GET URL with this parameter")
                baseline = ""
                for form in cmap.get("forms", []):
                    if not isinstance(form, dict) or str(form.get("method", "GET")).upper() != "GET":
                        continue
                    raw_action = form.get("action") or form.get("page")
                    if not isinstance(raw_action, str) or not raw_action:
                        continue
                    action = urljoin(allowed + "/", raw_action)
                    action_parts = urlsplit(action)
                    if (action_parts.scheme, action_parts.netloc, action_parts.path or "/") != (
                        parts.scheme, parts.netloc, parts.path or "/"
                    ):
                        continue
                    fields = form.get("fields") or form.get("inputs") or []
                    names = [field.get("name") if isinstance(field, dict) else field for field in fields]
                    if names != [parameter]:
                        continue
                    pairs = parse_qsl(action_parts.query, keep_blank_values=True)
                    if pairs:
                        continue
                    canary = "AegisProbe" + str(secrets.randbelow(900000) + 100000)
                    baseline = urlunsplit(action_parts._replace(
                        query=urlencode([*pairs, (parameter, canary)]),
                    ))
                    break
                if not baseline and observed["source"] in {
                    "browser_link", "browser_request", "browser_traffic",
                    "page_url", "captured_api", "application_operation",
                    "observed_form", "api_endpoint",
                }:
                    # Browser maps intentionally expose parameter names without
                    # link values. A fresh, harmless value can still establish
                    # an execution-owned baseline for an observed safe GET input.
                    # The preflight below must succeed before SQL controls run.
                    from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

                    if allowed_discovery_path(parts.path or "/"):
                        canary = "AegisProbe" + str(secrets.randbelow(900000) + 100000)
                        baseline = urlunsplit(parts._replace(query=urlencode([(parameter, canary)])))
                        baseline_source = "observed_parameter_preflight"
                if not baseline:
                    raise ValueError("String SQLi proof needs an ordinary observed GET URL with this parameter")
                baseline, variants, nonce = sqli_string.plan_string_boolean(
                    baseline, parameter=parameter, allowed_origins=[allowed],
                )
                needs_preflight = True
                if baseline_source != "observed_parameter_preflight":
                    baseline_source = "observed_get_form"
        else:
            baseline, variants, nonce = sqli_string.plan_string_boolean(
                url, parameter=parameter, allowed_origins=[allowed],
            )
        self._scoped_assessment_started = True
        state = self._scoped_state(identity, baseline)
        self._scoped_claim_gets(9 if needs_preflight else 8)
        if needs_preflight:
            preflight = await asyncio.to_thread(http_observe.observe_get, baseline, [allowed], state)
            if (preflight.get("status") != 200 or preflight.get("redirected")
                    or preflight.get("truncated")):
                raise ValueError("Observed GET form did not produce a stable baseline response")
        result = await asyncio.to_thread(
            sqli_string.probe_string_boolean,
            baseline, variants, nonce,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=state,
            before_request=lambda: None,
        )
        result["source"] = observed["source"]
        result["baseline_source"] = baseline_source
        result["finding"] = False  # One actor's proof is a candidate, never publication.
        if result.get("proof_confirmed") is not True and sqli_string.error_followup_eligible(result):
            # A database-specific diagnostic needs a second controlled run;
            # one error response on its own is only a lead.
            or_evidence_id = evidence_store(self).record(
                "scoped_string_sqli", result, target=result["target"], identity=identity,
                success=False,
            )
            try:
                self._scoped_claim_gets(len(sqli_string.ERROR_CHECK_ORDER))
                error_result = await asyncio.to_thread(
                    sqli_string.probe_string_error,
                    baseline, variants, parameter=parameter, allowed_origins=[allowed],
                    storage_state=state, before_request=lambda: None,
                )
            except Exception as exc:
                result["error_followup_error"] = type(exc).__name__
                result["evidence_id"] = or_evidence_id
                return json.dumps(result)
            error_result["prior_or_evidence_id"] = or_evidence_id
            error_result["total_requests_sent"] = (
                int(result.get("requests_sent") or 0)
                + int(error_result.get("requests_sent") or 0)
                + int(needs_preflight)
            )
            result = error_result
        elif result.get("proof_confirmed") is not True and sqli_string.and_fallback_eligible(result):
            # The second pattern shares the observed normal request but has
            # fresh true/false values. Reserve its own bounded request budget.
            or_evidence_id = evidence_store(self).record(
                "scoped_string_sqli", result, target=result["target"], identity=identity,
                success=False,
            )
            try:
                self._scoped_claim_gets(len(sqli_string.AND_CHECK_ORDER))
                _, and_variants, and_nonce = sqli_string.plan_string_and_boolean(
                    baseline, parameter=parameter, allowed_origins=[allowed],
                )
                and_result = await asyncio.to_thread(
                    sqli_string.probe_string_and_boolean,
                    baseline, and_variants, and_nonce,
                    parameter=parameter, allowed_origins=[allowed],
                    storage_state=state,
                    before_request=lambda: None,
                )
            except Exception as exc:
                # Preserve the completed OR receipt if the optional second
                # pattern cannot run. Never turn this into a clean verdict.
                result["and_followup_error"] = type(exc).__name__
                result["evidence_id"] = or_evidence_id
                return json.dumps(result)
            and_result["prior_or_evidence_id"] = or_evidence_id
            and_result["total_requests_sent"] = (
                int(result.get("requests_sent") or 0)
                + int(and_result.get("requests_sent") or 0)
                + int(needs_preflight)
            )
            result = and_result
        else:
            result["total_requests_sent"] = int(result.get("requests_sent") or 0) + int(needs_preflight)
        result["source"] = observed["source"]
        result["baseline_source"] = baseline_source
        result["finding"] = False
        result["evidence_id"] = evidence_store(self).record(
            "scoped_string_sqli", result, target=result["target"], identity=identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)
