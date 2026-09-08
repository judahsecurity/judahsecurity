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
    "map_application_traffic",
    "generate_authorization_matrix",
    "run_authorization_proof",
    "get_assessment_coverage",
    "collect_js_intelligence",
    "validate_js_secret_candidate",
    "browse_as_identity",
)


class AssessmentCapabilities:
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
        self._engagement_brain = brain.to_dict()

    async def map_application_traffic(
        self, requests: list, identity: str = "anonymous", source: str = "runtime"
    ) -> str:
        """Normalize captured traffic into operations and assessment hypotheses; no requests are sent."""
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        incoming = ingest_operations(brain, requests, identity=identity, source=source)
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
        if op["protocol"] != "rest":
            raise ValueError(
                "Current proof recipes support REST JSON operations; protocol-specific verification is required"
            )
        if cell["parameter"]:
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
        # Binding is allowed only in the path segment occupied by the controlled object.
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
        return json.dumps(coverage_report(brain))

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
        result = await execute_browser_actions(json.dumps(spec))
        self._ingest_observed_operations(result.get("application_operations", []))
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
                errors=result.get("error"),
                engagement_brain=self._engagement_brain,
            )
        )
