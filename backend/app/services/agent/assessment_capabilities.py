"""Agent-tool adapters for the application model, authorization and proof engines."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from app.services.agent.authorization_engine import (
    apply_proof_result,
    coverage_report,
    generate_matrix,
)
from app.services.agent.engagement_brain import engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store, origin
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.js_intelligence import JSIntelligence
from app.services.agent.proof_engine import ProofEngine
from app.services.agent.runtime_mapper import ingest_operations, merge_operations

CAPABILITY_TOOLS = (
    "scoped_browser_assessment",
    "scoped_http_get",
    "scoped_http_compare",
    "scoped_query_probe",
    "scoped_numeric_sqli",
    "scoped_string_sqli",
    "scoped_body_probe",
    "scoped_owner_only",
    "list_scoped_browser_exchanges",
    "scoped_ingest_caido_exchange",
    "scoped_assessment_summary",
    "complete_scoped_assessment",
    "get_finding_candidate",
    "map_application_traffic",
    "import_api_spec",
    "import_source_routes",
    "generate_authorization_matrix",
    "run_authorization_proof",
    "get_assessment_coverage",
    "collect_js_intelligence",
    "validate_js_secret_candidate",
    "browse_as_identity",
    "list_proof_captures",
    "list_authorization_leads",
    "prepare_captured_authorization_proof",
)


class AssessmentCapabilities:
    def _queue_operation_inputs(self, brain):
        """Keep central-ledger parameters visible to class-specific test scheduling."""
        from app.services.agent.coverage_cells import seed_parameter_coverage_cells
        from app.services.agent.parameter_inventory import (
            collect_parameter_inventory, inventory_with_operations,
        )

        cmap = getattr(self, "_capability_map", None) or {}
        if not isinstance(cmap, dict):
            cmap = {}
        if not cmap.get("scope") and not cmap.get("target"):
            target = str(getattr(brain, "target", "") or
                         getattr(self, "_fallback_target", "") or "")
            cmap = {**cmap, "target": target, "scope": target}
        cmap = inventory_with_operations(cmap, brain.application_operations)
        self._capability_map = cmap
        seed_parameter_coverage_cells(brain, collect_parameter_inventory(cmap))

    def _capture_requests(self):
        from app.services.agent.request_capture import RequestCaptureStore

        if self._request_capture_store is None:
            self._request_capture_store = RequestCaptureStore()
        return self._request_capture_store

    def _queue_captured_authorization_leads(self):
        from app.services.agent.coverage_cells import seed_authorization_capture_cells

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        active = {row["id"] for row in self._capture_requests().list()}
        for cell in brain.coverage_cells:
            if (
                cell.get("source") == "authorization_capture"
                and cell.get("capture_id")
                and cell["capture_id"] not in active
                and cell.get("status") in {"untested", "in_focus", "inconclusive"}
                and not cell.get("lease_id")
            ):
                cell["capture_id"] = ""
                cell["status"] = "inconclusive"
                cell["reason"] = "Proof capture expired; repeat the owner request"
        seed_authorization_capture_cells(
            brain, self._capture_requests().authorization_leads()
        )
        self._engagement_brain = brain.to_dict()

    def _authorization_handoff(self, brain, operation_id=None):
        from app.services.agent.authorization_leads import handoff_report

        store = self._capture_requests()
        report = handoff_report(
            store.authorization_leads(operation_id),
            brain,
            getattr(self, "_captured_proof_plans", {}) or {},
        )
        report["summary"]["captures"] = len(store.list(operation_id))
        report["summary"]["evicted_captures_session"] = store.evicted
        report["summary"]["capture_rejections_session"] = dict(store.rejected)
        report["summary"]["eligible_captures"] = len({
            lead["capture_id"] for lead in report["leads"] if lead["replayable"]
        })
        return report

    async def list_proof_captures(self, operation_id: str | None = None) -> str:
        """List execution-owned REST/GraphQL replay templates without private values."""
        return json.dumps(dict(captures=self._capture_requests().list(operation_id)))

    async def list_authorization_leads(
        self, operation_id: str | None = None, limit: int = 50
    ) -> str:
        """List prioritized captured object-reference leads and their proof handoff state."""
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        report = self._authorization_handoff(brain, operation_id)
        report["leads"] = report["leads"][: max(1, min(int(limit), 100))]
        return json.dumps(report)

    async def prepare_captured_authorization_proof(
        self,
        hypothesis_id: str,
        capture_id: str,
        owner_identity: str,
        object_id: str,
        configuration: dict,
    ) -> str:
        """Prepare (do not execute) a controlled captured_read/mutation/property/delete recipe.

        configuration requires strategy, setup POST JSON, verify GET and cleanup
        DELETE URLs. The captured object ID can be a complete path segment or
        query value, form field, JSON pointer or GraphQL variable pointer. Pass
        object_parameter such as query:record, form:record, body:/input/record,
        or variable:/input/record; an empty object_id selects the sole observed
        field value. Object URLs use {{object_id}}. REST POST reads require an
        explicit post_read_only assertion. For nested mutations, set
        attack_value_path separately from the owner readback value_path.
        GraphQL reads may need attack_object_path and attack_canary_path to
        identify the fresh object inside data. captured_property needs a typed
        attack_value. Delete proofs need inventory_path (/items).
        The owner must have captured the selected operation; policy must deny
        the other identity. Only disposable fixtures with explicit cleanup work.
        """
        from copy import deepcopy
        from app.services.agent.captured_proof import build_plan, matrix_parameter_for_object

        capture = self._capture_requests().get(capture_id)
        brain = engagement_brain_from_dict(self._engagement_brain)
        cell = next(
            (
                r
                for r in brain.authorization_matrix
                if r["hypothesis_id"] == hypothesis_id
            ),
            None,
        )
        if (
            not cell
            or cell["operation_id"] != capture["operation_id"]
            or cell["expected"] != "deny"
        ):
            raise ValueError(
                "Capture must match a matrix cell with explicit deny policy"
            )
        plan = build_plan(
            capture,
            owner_identity=owner_identity,
            object_id=object_id,
            configuration=configuration,
        )
        selected = cell["parameter"]
        reference_parameter = matrix_parameter_for_object(plan["object_parameter"])
        object_selected = bool(reference_parameter and selected == reference_parameter)
        body_selected = (
            plan["strategy"] in ("captured_mutation", "captured_property")
            and plan["body_format"] == "json"
            and selected == "body:" + plan["attack_value_path"].lstrip("/").split("/", 1)[0]
        )
        if selected and not (object_selected or body_selected):
            raise ValueError("Recipe does not test the selected parameter")
        if reference_parameter and not object_selected:
            raise ValueError("Object-reference proofs require the matching parameter cell")
        existing = self._captured_proof_plans.get(hypothesis_id)
        if existing is not None and existing != plan:
            raise ValueError(
                "Use a new assessment to change a registered capture proof"
            )
        self._captured_proof_plans[hypothesis_id] = deepcopy(plan)
        self._proof_plans[hypothesis_id] = deepcopy(plan)
        return json.dumps(
            dict(
                hypothesis_id=hypothesis_id,
                capture_id=capture_id,
                strategy=plan["strategy"],
                ready=True,
                next_tool="run_authorization_proof",
            )
        )

    def _assessment_engines(self):
        if getattr(self, "_proof_engine", None) is None:
            self._proof_engine = ProofEngine(evidence_store(self))
        if getattr(self, "_js_intelligence", None) is None:
            self._js_intelligence = JSIntelligence()
        return self._proof_engine, self._js_intelligence

    def _ingest_observed_operations(self, operations):
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        brain.application_operations = merge_operations(
            brain.application_operations, operations
        )
        ingest_operations(brain, [])
        self._queue_operation_inputs(brain)
        self._engagement_brain = brain.to_dict()

    def _spec_documents_for_session(self, asset_id: int, origin: str):
        """Stored spec documents for one org asset (explicit id or matching host)."""
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from app.services.agent.tools import get_tenant_context
        from app.services.api_spec_import import stored_documents

        _user_id, org_id = get_tenant_context()
        if not org_id:
            raise ValueError("An organization agent session is required to load stored specs")
        host = urlsplit(origin).hostname or ""
        db = SessionLocal()
        try:
            query = db.query(Asset).filter(Asset.organization_id == org_id)
            if asset_id:
                assets = query.filter(Asset.id == int(asset_id)).all()
            else:
                assets = [a for a in query.filter(Asset.value.ilike(f"%{host}%")).limit(20).all()
                          if (urlsplit(a.value).hostname if "://" in str(a.value)
                              else str(a.value).strip().lower()) == host]
            return [doc for asset in assets for doc in stored_documents(asset)]
        finally:
            db.close()

    async def import_api_spec(
        self, document: str = "", asset_id: int = 0, origin: str = "",
    ) -> str:
        """Seed the operation ledger and coverage cells from an OpenAPI/Swagger or Postman document; sends no requests."""
        from app.services.api_spec_import import (
            import_api_document, normalize_origin, parse_api_document,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        session_origin = normalize_origin(str(
            (cmap.get("scope") if isinstance(cmap, dict) else "")
            or (cmap.get("target") if isinstance(cmap, dict) else "")
            or getattr(brain, "target", "") or getattr(self, "_fallback_target", "") or ""
        ))
        requested = normalize_origin(origin) if origin else ""
        if session_origin and requested and requested != session_origin:
            raise ValueError("Spec origin must match this session's target origin")
        allowed = session_origin or requested
        if not allowed:
            raise ValueError("Set a target origin before importing a spec")
        if document:
            parsed_docs = [parse_api_document(document)]
        else:
            parsed_docs = self._spec_documents_for_session(asset_id, allowed)
        if not parsed_docs:
            return json.dumps(dict(
                imported=[], operations_added=0,
                note="No stored spec for this target; upload one to the asset or pass document",
            ))
        before = {op["id"] for op in brain.application_operations}
        summaries = []
        for parsed in parsed_docs[:4]:
            imported = import_api_document(parsed, allowed)
            ingest_operations(brain, imported.requests, identity="anonymous", source="api_spec")
            summaries.append(imported.summary())
        if not getattr(brain, "target", ""):
            brain.target = allowed
        self._queue_operation_inputs(brain)
        self._engagement_brain = brain.to_dict()
        added = [op for op in brain.application_operations if op["id"] not in before]
        return json.dumps(dict(
            imported=summaries,
            operations_added=len(added),
            operations=[{k: op.get(k) for k in ("id", "method", "path", "parameters")}
                        for op in added[:40]],
            note=("Spec operations are documentation leads: discovery_only until observed "
                  "or probed. Coverage cells now include their inputs."),
        ))

    async def import_source_routes(self, check_id: str = "") -> str:
        """Seed the operation ledger from routes a PR check extracted from source; sends no requests."""
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from app.models.pr_check import PrCheck
        from app.services.agent.tools import get_tenant_context
        from app.services.api_spec_import import normalize_origin
        from app.services.pr_check_service import synthetic_requests_for_routes

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        origin = normalize_origin(str(
            (cmap.get("scope") if isinstance(cmap, dict) else "")
            or (cmap.get("target") if isinstance(cmap, dict) else "")
            or getattr(brain, "target", "") or getattr(self, "_fallback_target", "") or ""
        ))
        if not origin:
            raise ValueError("Set a target origin before importing source routes")
        _user_id, org_id = get_tenant_context()
        if not org_id:
            raise ValueError("An organization agent session is required")
        host = urlsplit(origin).hostname or ""
        db = SessionLocal()
        try:
            query = db.query(PrCheck).filter(PrCheck.organization_id == org_id)
            if check_id:
                check = query.filter(PrCheck.id == str(check_id)).first()
            else:
                asset_ids = [a.id for a in db.query(Asset).filter(
                    Asset.organization_id == org_id, Asset.value.ilike(f"%{host}%")).limit(20).all()
                    if (urlsplit(a.value).hostname if "://" in str(a.value)
                        else str(a.value).strip().lower()) == host]
                check = (query.filter(PrCheck.asset_id.in_(asset_ids))
                         .order_by(PrCheck.created_at.desc()).first()) if asset_ids else None
            if check is None:
                return json.dumps(dict(operations_added=0,
                                       note="No PR check with routes for this target"))
            if check.asset_id:
                asset = db.query(Asset).filter(Asset.id == check.asset_id).first()
                asset_host = (urlsplit(asset.value).hostname if asset and "://" in str(asset.value)
                              else str(getattr(asset, "value", "")).strip().lower())
                if asset_host != host:
                    raise ValueError("That PR check belongs to a different asset than this session's target")
            routes = list(check.routes or [])
            findings = list(check.findings or [])
            check_ref = check.id
        finally:
            db.close()
        before = {op["id"] for op in brain.application_operations}
        ingest_operations(brain, synthetic_requests_for_routes(routes, origin),
                          identity="anonymous", source="source_code")
        if not getattr(brain, "target", ""):
            brain.target = origin
        self._queue_operation_inputs(brain)
        self._engagement_brain = brain.to_dict()
        added = [op for op in brain.application_operations if op["id"] not in before]
        leads = [{k: f.get(k) for k in ("rule_id", "title", "cwe", "file", "line",
                                         "route", "live_test_class")}
                 for f in findings if f.get("route") and f.get("live_test_class")][:30]
        return json.dumps(dict(
            check_id=check_ref, operations_added=len(added),
            operations=[{k: op.get(k) for k in ("id", "method", "path", "parameters")}
                        for op in added[:40]],
            source_leads=leads,
            note=("Source routes are leads, not observations: probe them live and verify "
                  "independently. A source-only finding stays advisory (medium max) "
                  "until a live repro."),
        ))

    async def map_application_traffic(
        self, requests: list, identity: str = "anonymous", source: str = "runtime"
    ) -> str:
        """Normalize captured traffic into operations and assessment hypotheses; no requests are sent."""
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        incoming = ingest_operations(brain, requests, identity=identity, source=source)
        self._queue_operation_inputs(brain)
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            dict(operations=incoming, engagement_brain=self._engagement_brain)
        )

    async def generate_authorization_matrix(
        self,
        expectations: list,
        operation_ids: list | None = None,
        identity_names: list | None = None,
    ) -> str:
        """Expand observed operations × registered identities × inputs; expectations use operation_id, identity, parameter, expected."""
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        registry = identity_registry(self)
        operations = [
            op
            for op in brain.application_operations
            if operation_ids is None or op["id"] in operation_ids
        ]
        names_count = (
            len(identity_names)
            if identity_names is not None
            else len(registry.identities) + 1
        )
        if (
            sum(1 + len(op.get("parameters", [])) for op in operations) * names_count
            > 5000
        ):
            raise ValueError(
                "Select a smaller operation/identity matrix slice (maximum 5000 cells)"
            )
        if identity_names is not None and set(identity_names) - set(
            registry.identities
        ) - {"anonymous"}:
            raise ValueError(
                "Register the requested identities first, even if their credentials are not yet available"
            )
        # Resolve per operation origin so the same identity name can have separate host sessions.
        for op in operations:
            identities = [
                dict(name="anonymous", tenant="", role="anonymous", authenticated=False)
            ]
            for name in registry.identities:
                try:
                    session = registry.resolve(name, op["url"])
                except ValueError:
                    continue
                identities.append(
                    dict(
                        name=name,
                        tenant=session.get("tenant", ""),
                        role=session.get("role", ""),
                        authenticated=session.get("authenticated", False),
                    )
                )
            if identity_names is not None:
                identities = [i for i in identities if i["name"] in identity_names]
            generate_matrix(brain, [op], identities, expectations)
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            dict(
                coverage=coverage_report(brain), engagement_brain=self._engagement_brain
            )
        )

    async def run_authorization_proof(
        self, hypothesis_id: str, plan: dict | None = None
    ) -> str:
        """Run a controlled authorization_read or authorization_mutation setup/attack/verify plan; return evidence receipt, never publish a finding."""
        from copy import deepcopy

        proof, _ = self._assessment_engines()
        if plan is None:
            plan = deepcopy(self._proof_plans.get(hypothesis_id))
        if not isinstance(plan, dict):
            raise ValueError(
                "Provide a controlled proof plan for this hypothesis first"
            )
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next(
            (
                r
                for r in brain.authorization_matrix
                if r["hypothesis_id"] == hypothesis_id
            ),
            None,
        )
        if cell is None:
            raise ValueError("Generate this authorization matrix cell first")
        op = next(
            o for o in brain.application_operations if o["id"] == cell["operation_id"]
        )
        if plan["target"] != op["url"]:
            raise ValueError(
                "Plan target must exactly match the selected operation URL"
            )
        if op["protocol"] not in ("rest", "graphql") or (
            op["protocol"] == "graphql" and plan.get("protocol") != "graphql"
        ):
            raise ValueError(
                "Captured proof protocol differs from the selected operation"
            )
        captured = plan["strategy"].startswith("captured_")
        if op["protocol"] == "graphql" and not captured:
            raise ValueError("GraphQL authorization requires an execution-owned capture")
        registered_capture = self._captured_proof_plans.get(hypothesis_id)
        if registered_capture is not None and registered_capture != plan:
            raise ValueError(
                "Execution-owned registered plans cannot be edited or downgraded"
            )
        if captured and self._captured_proof_plans.get(hypothesis_id) != plan:
            raise ValueError(
                "Prepare this execution-owned capture proof first; registered plans cannot be edited"
            )
        if cell["parameter"] and not captured:
            location, _, field = cell["parameter"].partition(":")
            if (
                location != "body"
                or plan["strategy"] != "authorization_mutation"
                or plan["value_path"]
                != "/" + field.replace("~", "~0").replace("/", "~1")
            ):
                raise ValueError(
                    "This parameter requires a dedicated proof recipe; coverage remains untested"
                )
            if (plan["attack"].get("body") or {}).get(field) != "{{nonce}}":
                raise ValueError(
                    "Attack must mutate the selected parameter using the fresh nonce"
                )
        attack = plan["attack"]
        if attack.get("method", "GET").upper() != op["method"]:
            raise ValueError("Attack method differs from the selected operation")
        # Captured plans may bind the controlled object in a path segment or
        # observed query value; both retain the operation's normalized path.
        attack_path = urlsplit(attack["url"]).path
        if "{{object_id}}" not in attack_path and attack_path != op["path"]:
            raise ValueError("Attack path differs from the selected operation")
        if "{{object_id}}" in attack_path:
            import re

            pattern = re.escape(attack_path).replace(
                re.escape("{{object_id}}"), "[^/]+"
            )
            if not re.fullmatch(pattern, op["path"]):
                raise ValueError(
                    "Attack template does not match the selected operation"
                )
        if captured:
            from app.services.agent.captured_proof import matrix_parameter_for_object

            reference_parameter = matrix_parameter_for_object(plan.get("object_parameter", ""))
            if reference_parameter and reference_parameter not in op.get("parameters", []):
                raise ValueError("Object reference was not observed on the operation")
            bound = attack["url"].count("{{object_id}}") + json.dumps(
                attack.get("body")
            ).count("{{object_id}}")
            if bound != 1:
                raise ValueError("Attack must bind exactly one controlled object ID")
        registry = identity_registry(self)
        for name in (plan["owner_identity"], cell["identity"]):
            if name != "anonymous":
                session = registry.resolve(name, plan["target"])
                check = session.get("identity_check")
                if check:
                    await self.check_test_identity(name, **check)
                else:
                    session["authenticated"] = False
        self._proof_plans[hypothesis_id] = deepcopy(plan)
        result = await proof.run(
            plan, cell, execute=self._http_exchange, registry=registry
        )
        # Re-read shared brain after I/O so concurrent independent cells cannot erase each other.
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        apply_proof_result(brain, result.to_dict())
        brain.proof_receipts.append(result.to_dict())
        brain.proof_receipts = brain.proof_receipts[-500:]
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            dict(
                receipt=result.to_dict(),
                coverage=coverage_report(brain),
                engagement_brain=self._engagement_brain,
            )
        )

    async def get_assessment_coverage(self) -> str:
        """Expose tested, untested, blocked and inconclusive cells by hypothesis, identity, tenant, parameter and operation."""
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        return json.dumps({
            **coverage_report(brain),
            "authorization_handoff": self._authorization_handoff(brain)["summary"],
        })

    async def collect_js_intelligence(
        self, url: str, identity: str = "anonymous", max_files: int = 20
    ) -> str:
        """Collect same-origin HTML scripts, bundles, imports and embedded source maps; extract redacted leads."""
        _, intelligence = self._assessment_engines()

        async def fetch(target):
            return await self._http_exchange(
                "GET",
                target,
                identity=identity,
                follow_redirects=False,
                max_response_bytes=1024 * 1024,
            )

        result = await intelligence.collect(url, fetch=fetch, max_files=max_files)
        from urllib.parse import urljoin

        requests = []
        for source in result["sources"]:
            for endpoint in source["endpoints"]:
                resolved = urljoin(url, endpoint)
                try:
                    if origin(resolved) == origin(url):
                        requests.append(dict(url=resolved, method="GET"))
                except ValueError:
                    continue
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        ingest_operations(brain, requests, identity=identity, source="javascript_hint")
        brain.js_intelligence = result
        self._engagement_brain = brain.to_dict()
        return json.dumps(dict(**result, engagement_brain=self._engagement_brain))

    async def validate_js_secret_candidate(self, candidate_id: str) -> str:
        """Invoke an operator-configured provider validation hook; result remains a candidate."""
        _, intelligence = self._assessment_engines()
        policy = getattr(self, "_secret_validation_policy", {})
        return json.dumps(
            await intelligence.validate(
                candidate_id,
                enabled=bool(policy.get("enabled")),
                allowed_providers=policy.get("providers", []),
            )
        )

    async def browse_as_identity(self, identity: str, url: str, actions: list) -> str:
        """Run browser actions in a fresh origin-bound identity context and ingest observed operations."""
        from app.services.browser_automation_service import execute_browser_actions
        from app.services.agent.assessment_sessions import browser_storage_state

        registry = identity_registry(self)
        session = registry.resolve(identity, url)
        # All browser state comes from this registry entry. No legacy state injection.
        spec = dict(
            actions=[dict(action="navigate", url=url), *actions],
            identity=identity,
            allowed_origin=url,
            storage_state=browser_storage_state(session, url),
            cookies=session.get("cookies") or [],
            extra_headers=session.get("headers") or {},
        )
        captures = []
        store = self._capture_requests()

        def capture_request(request):
            if (
                len(captures) >= 200
                or identity == "anonymous"
                or origin(request["url"]) != origin(url)
            ):
                return
            captured = store.record(request, identity=identity, source="browser")
            if captured:
                captures.append(captured)

        result = await execute_browser_actions(
            json.dumps(spec), capture_callback=capture_request
        )
        self._ingest_observed_operations(result.get("application_operations", []))
        self._queue_captured_authorization_leads()
        artifact = evidence_store(self).record(
            "browser_capture",
            dict(operations=result.get("application_operations", [])),
            target=url,
            identity=identity,
            success=bool(result.get("success")),
        )
        # Cookies are retained only within the chosen session. Authentication is rechecked over HTTP.
        exported = result.get("auth_session") or {}
        if identity != "anonymous" and exported.get("storage_state"):
            session["storage_state"] = exported["storage_state"]
            session["cookies"] = exported.get("cookies", [])
            session["authenticated"] = False
        return json.dumps(
            dict(
                success=result.get("success"),
                evidence_id=artifact,
                operations=result.get("application_operations", []),
                captures=captures,
                authorization_handoff=self._authorization_handoff(
                    engagement_brain_from_dict(self._engagement_brain)
                )["summary"],
                errors=result.get("error"),
                engagement_brain=self._engagement_brain,
            )
        )
