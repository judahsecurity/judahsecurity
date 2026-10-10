"""PROWL's bounded assessment operations inside the Aegis agent tool manager.

The model receives metadata and evidence IDs. Browser exchanges with request
values remain private to the current assessment session.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from app.services.agent.assessment_scope import assert_url_in_scope
from app.services.agent.assessment_sessions import browser_storage_state, identity_registry
from app.services.agent.evidence_store import evidence_store, verification_run
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

HUNTER_GET_BUDGET = 160
VERIFIER_GET_BUDGET = 40


class ScopedAssessmentTools:
    async def complete_scoped_assessment(self) -> str:
        """Close the assessment only after its threat model and coverage gate pass."""
        summary = json.loads(await self.scoped_assessment_summary())
        if not summary["complete"]:
            raise ValueError("Assessment has no threat model or has unfinished coverage or candidates")
        return json.dumps(summary)

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
        expectations = policy.get("owner_only_resources") or []
        if not isinstance(paths, list) or len(paths) > 8 or not isinstance(expectations, list) or len(expectations) > 8:
            raise ValueError("Invalid bounded assessment policy")
        for path in paths:
            if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
                    or path == "/" or len(path) > 256 or any(char in path for char in "?#\\\r\n\t ")):
                raise ValueError("Invalid body replay path")
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
        self._scoped_owner_expectations = approved
        if paths or approved:
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
        session = identity_registry(self).resolve(identity, url)
        return browser_storage_state(session, url)

    def _scoped_claim_gets(self, count: int) -> None:
        if count < 1 or count > 9:
            raise ValueError("Invalid assessment request reservation")
        verifier = verification_run.get() is not None
        counter = "_scoped_verify_get_count" if verifier else "_scoped_get_count"
        limit = VERIFIER_GET_BUDGET if verifier else HUNTER_GET_BUDGET
        used = int(getattr(self, counter, 0) or 0)
        if used + count > limit:
            raise ValueError("Scoped HTTP GET budget exhausted for this assessment session")
        setattr(self, counter, used + count)

    def _scoped_exchange(self, artifact_id: str, identity: str) -> bytes:
        row = (getattr(self, "_scoped_browser_exchanges", None) or {}).get(artifact_id)
        if not row or row["identity"] != identity:
            raise ValueError("Unknown browser exchange for this identity")
        current = verification_run.get()
        if row.get("verifier_run_id") != (current.id if current else None):
            raise ValueError("Browser exchange must be fresh for this verifier run")
        return row["private"]

    async def list_scoped_browser_exchanges(self) -> str:
        """List execution-owned browser XHR/fetch samples without request values."""
        rows = []
        for artifact_id, row in (getattr(self, "_scoped_browser_exchanges", None) or {}).items():
            rows.append({"artifact_id": artifact_id, "identity": row["identity"], **row["public"]})
        return json.dumps({"exchanges": rows[-40:]})

    async def scoped_browser_assessment(
        self, operation: str, url: str, identity: str = "anonymous",
        max_pages: int = 1, max_actions: int = 3,
    ) -> str:
        """Run scoped map, crawl, JS inspection, or nonce XSS execution in Chromium."""
        if operation not in ("map", "crawl", "inspect_js", "check_xss"):
            raise ValueError("Unsupported scoped browser operation")
        allowed = self._scoped_origin(url)
        state = self._scoped_state(identity, url)
        sources: list[dict] = []
        exchanges: list[dict] = []
        link_baselines: list[str] = []
        result, screenshot = await browser.check_browser(
            operation=operation, url=url, allowed_origins=[allowed],
            storage_state=state, max_pages=max_pages,
            javascript_sources=sources if operation == "inspect_js" else None,
            traffic_exchanges=exchanges if operation == "inspect_js" else None,
            link_baselines=link_baselines if operation != "check_xss" else None,
            max_actions=max_actions,
        )
        if link_baselines:
            private = dict(getattr(self, "_scoped_link_baselines", None) or {})
            private[identity] = list(dict.fromkeys([
                *(private.get(identity) or []), *link_baselines,
            ]))[-120:]
            self._scoped_link_baselines = private
        self._scoped_assessment_started = True
        target = allowed + (urlsplit(url).path or "/")
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
            from app.services.agent.scoped_assessment.surface_inventory import build_surface_inventory

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
                                "action_ref": source.get("action_ref"), "artifact_id": source_id,
                                "sha256": hashlib.sha256(data).hexdigest(), "analysis": analysis})
            traffic = []
            private_store = dict(getattr(self, "_scoped_browser_exchanges", None) or {})
            for row in exchanges[:40]:
                public = row["public"]
                artifact_id = evidence_store(self).record(
                    "scoped_browser_exchange", public, target=allowed + public["path"],
                    identity=identity,
                )
                current = verification_run.get()
                private_store[artifact_id] = {
                    "identity": identity, "private": row["private"], "public": public,
                    "verifier_run_id": current.id if current else None,
                }
                public["artifact_id"] = artifact_id
                traffic.append(public)
            while len(private_store) > 40:
                private_store.pop(next(iter(private_store)))
            self._scoped_browser_exchanges = private_store
            result["scripts"] = scripts
            result["traffic"] = traffic
            result["surface_inventory"] = build_surface_inventory(result)
        observed = [
            {"method": row.get("method", "GET"), "url": allowed + row["path"]}
            for row in (result.get("requests") or [])[:100]
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
        for request in (result.get("requests") or [])[:100]:
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
            success=bool(result.get("executed")) if operation == "check_xss" else True,
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
        self._scoped_claim_gets(2)
        result = await asyncio.to_thread(
            query_probe.probe_observed_query, baseline, mutated, parameter=parameter,
            allowed_origins=[allowed], storage_state=self._scoped_state(identity, baseline),
        )
        result["source_artifact_id"] = artifact_id
        result["evidence_id"] = evidence_store(self).record(
            "scoped_query_probe", result, target=result["target"], identity=identity,
            success=not result["inconclusive"],
        )
        return json.dumps(result)

    async def scoped_body_probe(self, artifact_id: str, parameter: str, identity: str = "anonymous") -> str:
        """Probe one browser observed POST field on an operator approved path; lead only."""
        private = self._scoped_exchange(artifact_id, identity)
        self._scoped_assessment_started = True
        observed = json.loads(private)
        allowed = self._scoped_origin(observed["url"])
        url, mime, baseline, changed = body_probe.plan_observed_body(
            private, parameter=parameter, allowed_origins=[allowed],
        )
        if (urlsplit(url).path or "/") not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            raise ValueError("POST path was not approved by the assessment operator")
        used = int(getattr(self, "_scoped_post_count", 0) or 0)
        if used >= 10:
            raise ValueError("Scoped POST budget exhausted for this assessment session")
        self._scoped_post_count = used + 1
        result = await asyncio.to_thread(
            body_probe.probe_observed_body, url, mime, baseline, changed,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=self._scoped_state(identity, url),
        )
        result["source_artifact_id"] = artifact_id
        result["evidence_id"] = evidence_store(self).record(
            "scoped_body_probe", result, target=result["target"], identity=identity,
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
        self._scoped_claim_gets(6)
        result = await asyncio.to_thread(
            authz_proof.probe_owner_only, target,
            owner_identity=owner_identity, other_identity=other_identity,
            owner_state=self._scoped_state(owner_identity, target),
            other_state=self._scoped_state(other_identity, target),
            allowed_origins=[allowed], before_request=lambda: None,
        )
        result["captured_artifact_id"] = artifact_id
        result["finding"] = False
        result["evidence_id"] = evidence_store(self).record(
            "scoped_owner_only", result, target=target, identity=owner_identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)

    async def scoped_numeric_sqli(self, artifact_id: str, parameter: str, identity: str = "anonymous") -> str:
        """Run a six-request numeric Boolean proof on a browser-observed GET."""
        private = self._scoped_exchange(artifact_id, identity)
        self._scoped_assessment_started = True
        allowed = self._scoped_origin(browser.origin(json.loads(private)["url"]))
        baseline, true_url, false_url, nonce = sqli_boolean.plan_numeric_boolean(
            private, parameter=parameter, allowed_origins=[allowed],
        )
        self._scoped_claim_gets(6)
        result = await asyncio.to_thread(
            sqli_boolean.probe_numeric_boolean,
            baseline, true_url, false_url, nonce,
            parameter=parameter, allowed_origins=[allowed],
            storage_state=self._scoped_state(identity, baseline),
            before_request=lambda: None,
        )
        result["source_artifact_id"] = artifact_id
        result["finding"] = False  # One actor's proof is a candidate, never publication.
        result["evidence_id"] = evidence_store(self).record(
            "scoped_numeric_sqli", result, target=result["target"], identity=identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)

    async def scoped_string_sqli(self, url: str, parameter: str, identity: str = "anonymous") -> str:
        """Run an eight-request Boolean proof on an observed string GET input."""
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
            }), None)
        if observed is None:
            raise ValueError("String SQLi proof requires a mapped GET query parameter")
        needs_preflight = False
        baseline_source = observed["source"]
        if not parts.query:
            # The public inventory is value-free. Keep ordinary link values in
            # session-local browser state, then recover only this exact input.
            candidates = [
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
                if not baseline and observed["source"] in {"browser_link", "browser_request", "browser_traffic"}:
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
        self._scoped_claim_gets(9 if needs_preflight else 8)
        state = self._scoped_state(identity, baseline)
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
        result["finding"] = False
        result["evidence_id"] = evidence_store(self).record(
            "scoped_string_sqli", result, target=result["target"], identity=identity,
            success=result["proof_confirmed"],
        )
        return json.dumps(result)
