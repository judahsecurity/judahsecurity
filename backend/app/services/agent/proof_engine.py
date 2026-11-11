"""Execution-owned setup → attack → verify proofs for controlled test objects.

Strategies are code, not model-supplied verdicts. Every phase gets an evidence
artifact. Proof receipts inform (and never bypass) independent verification.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Awaitable, Callable
from urllib.parse import quote

from app.services.agent.evidence_store import origin, verification_run


@dataclass(frozen=True)
class ProofReceipt:
    run_id: str
    hypothesis_id: str
    operation_id: str
    identity: str
    parameter: str
    strategy: str
    target: str
    attack_url: str
    verdict: str
    reason: str
    evidence_ids: tuple[str, ...]
    verifier_run_id: str
    candidate_id: str
    candidate_revision: int
    created_at: float
    capture_id: str = ""
    cleanup_status: str = ""
    cleanup_evidence_ids: tuple[str, ...] = ()
    coverage_cell_id: str = ""

    def to_dict(self):
        return asdict(self)


def pointer(document, path: str):
    if not path.startswith("/"):
        raise ValueError("Proof selectors must be nonempty JSON pointers")
    for part in path[1:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        document = document[int(part)] if isinstance(document, list) else document[part]
    return document


def render(value, bindings: dict, *, url=False):
    if isinstance(value, dict):
        return {k: render(v, bindings) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, bindings) for v in value]
    if isinstance(value, str):
        for key, replacement in bindings.items():
            value = value.replace(
                "{{" + key + "}}",
                quote(str(replacement), safe="") if url else str(replacement),
            )
        if "{{" in value:
            raise ValueError("Unresolved proof binding")
    return value


def _mutation_verdict(documents, nonce, object_path, value_path):
    before, after = documents["setup"], documents["verify"]
    before_value, after_value = pointer(before, value_path), pointer(after, value_path)
    if after_value == nonce:
        verdict, reason = (
            "confirmed",
            "Owner readback contains the fresh unauthorized mutation canary",
        )
    elif after_value == before_value:
        verdict, reason = (
            "refuted",
            "Owner readback shows the controlled value unchanged",
        )
    else:
        verdict, reason = (
            "inconclusive",
            "Owner readback changed without the expected canary",
        )
    return verdict, reason


def _read_verdict(documents, nonce, object_path, value_path):
    before, after = documents["setup"], documents["verify"]
    if pointer(after, value_path) != nonce:
        raise ValueError("Owner can no longer read the setup canary")
    control = documents["control"]
    if pointer(control, object_path) == pointer(
        before, object_path
    ) or nonce in json.dumps(control):
        raise ValueError("Attacker control is not a distinct legitimate object")
    attack = documents["attack"]
    try:
        exposed = pointer(attack, value_path) == nonce and pointer(
            attack, object_path
        ) == pointer(before, object_path)
    except (KeyError, IndexError, ValueError, TypeError):
        exposed = False
    # Absence alone does not prove a complete denial policy, even with 403.
    verdict = "confirmed" if exposed else "inconclusive"
    reason = (
        "Attacker read the fresh owner canary absent from its control"
        if exposed
        else "Fresh owner canary was not observed in the attack response"
    )
    return verdict, reason


@dataclass(frozen=True)
class ProofStrategy:
    """Trusted deterministic evaluator over execution-owned phase documents."""

    name: str
    attack_methods: tuple[str, ...]
    requires_control: bool
    evaluate: Callable


PROOF_STRATEGIES = {
    "authorization_read": ProofStrategy(
        "authorization_read", ("GET",), True, _read_verdict
    ),
    "authorization_mutation": ProofStrategy(
        "authorization_mutation", ("POST", "PUT", "PATCH"), False, _mutation_verdict
    ),
}


@dataclass(frozen=True)
class DerivedProofProposal:
    """A reviewed path from a one-off open-tier exploit to a fixed probe type.

    The open exploit-development tier can find something the fixed probe set does
    not cover. To fold that back into the deterministic probe set, it *proposes*
    a new named strategy that binds to an **existing trusted evaluator** — never
    new, model-supplied verdict code — and that proposal only becomes usable
    after explicit operator review. This keeps the invariant that every verdict
    is code, while letting open-ended exploration grow the fixed set over time.
    """

    name: str
    base_strategy: str
    source_lead_id: str
    target: str
    notes: str = ""
    reviewer: str = ""
    approved: bool = False
    created_at: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)


class DerivedProofRegistry:
    """Hold derived-strategy proposals; expose only the reviewed, approved ones.

    Scoped per run/engagement rather than mutating the process-wide
    ``PROOF_STRATEGIES`` map, so one tenant's derived probe never leaks into
    another's assessment.
    """

    # Built-ins a derived strategy is allowed to reuse. A derived probe is a new
    # *name* over a known evaluator, so no untrusted evaluator is ever run.
    ALLOWED_BASES = frozenset(PROOF_STRATEGIES)

    def __init__(self):
        self._proposals: dict[str, DerivedProofProposal] = {}

    def propose(self, *, name: str, base_strategy: str, source_lead_id: str,
                source_kind: str, target: str, notes: str = "") -> DerivedProofProposal:
        name = str(name or "").strip()
        if not (name.startswith("derived_") and name.replace("_", "").isalnum()):
            raise ValueError("Derived strategy name must be derived_<alnum>")
        if name in PROOF_STRATEGIES:
            raise ValueError("Derived strategy cannot shadow a built-in")
        if base_strategy not in self.ALLOWED_BASES:
            raise ValueError("Derived strategy must bind to a known trusted evaluator")
        # Only a genuine open-tier lead can seed a derived probe.
        if source_kind not in ("exploit_workspace_lead", "post_exploit_lead"):
            raise ValueError("A derived probe must originate from an open-tier lead")
        if not source_lead_id:
            raise ValueError("A derived probe must cite its source lead artifact")
        proposal = DerivedProofProposal(
            name=name, base_strategy=base_strategy, source_lead_id=source_lead_id,
            target=target, notes=str(notes or "")[:2000],
        )
        self._proposals[name] = proposal
        return proposal

    def approve(self, name: str, reviewer: str) -> DerivedProofProposal:
        """Operator review. Without a named reviewer nothing is ever approved."""
        proposal = self._proposals.get(name)
        if proposal is None:
            raise KeyError(name)
        if not str(reviewer or "").strip():
            raise ValueError("Approval requires a named reviewer")
        approved = DerivedProofProposal(
            **{**proposal.to_dict(), "approved": True, "reviewer": reviewer.strip()}
        )
        self._proposals[name] = approved
        return approved

    def pending(self) -> list[DerivedProofProposal]:
        return [p for p in self._proposals.values() if not p.approved]

    def resolve(self, name: str) -> ProofStrategy | None:
        """Return a usable strategy: built-ins, or an *approved* derived one."""
        if name in PROOF_STRATEGIES:
            return PROOF_STRATEGIES[name]
        proposal = self._proposals.get(name)
        if proposal is None or not proposal.approved:
            return None
        base = PROOF_STRATEGIES[proposal.base_strategy]
        # Reuse the trusted evaluator under the new derived name.
        return ProofStrategy(
            proposal.name, base.attack_methods, base.requires_control, base.evaluate,
        )


class ProofEngine:
    def __init__(self, store):
        self.store = store
        self.receipts: dict[str, ProofReceipt] = {}

    def validate_receipt(self, run_id, candidate, evidence_ids, *, fresh=True):
        receipt = self.receipts.get(run_id)
        context = verification_run.get()
        if not receipt or receipt.verdict != "confirmed" or (fresh and context is None):
            return (
                False,
                "A confirmed execution-owned workflow receipt from this verifier is required",
            )
        if (receipt.candidate_id, receipt.candidate_revision) != (
            candidate.id,
            candidate.revision,
        ) or (fresh and receipt.verifier_run_id != context.id):
            return (
                False,
                "Workflow receipt belongs to a different verifier or candidate revision",
            )
        if receipt.target != candidate.target or not receipt.attack_url:
            return False, "Workflow target does not match the candidate"
        if receipt.hypothesis_id != candidate.hypothesis_id:
            return False, "Workflow receipt belongs to a different hypothesis"
        if tuple(evidence_ids) != receipt.evidence_ids:
            return False, "Cite the exact ordered workflow evidence artifacts"
        return True, ""

    async def run(
        self,
        plan: dict,
        cell: dict,
        *,
        execute: Callable[..., Awaitable[dict]],
        registry,
    ) -> ProofReceipt:
        strategy = plan.get("strategy")
        if strategy and strategy.startswith("captured_"):
            from app.services.agent.captured_proof import run_captured

            return await run_captured(
                self, plan, cell, execute=execute, registry=registry
            )
        recipe = PROOF_STRATEGIES.get(strategy)
        if recipe is None:
            raise ValueError("Unsupported proof strategy")
        if cell["expected"] != "deny":
            raise ValueError(
                "Unauthorized-access proofs require an explicit deny expectation"
            )
        if not plan.get("controlled_resource"):
            raise ValueError("Proof requires an operator-controlled resource")
        owner, attacker = plan["owner_identity"], cell["identity"]
        if owner in ("anonymous", attacker):
            raise ValueError("Setup and verify require a distinct owner identity")
        target = plan["setup"]["url"]
        expected_origin = origin(target)
        if origin(plan["target"]) != expected_origin:
            raise ValueError("Proof target differs from setup origin")
        for name in (owner, attacker):
            session = registry.resolve(name, target)
            if name != "anonymous" and not session.get("authenticated"):
                return self._receipt(
                    cell, strategy, "blocked", "Identity has not been verified", [], ""
                )
        if attacker != "anonymous":
            owner_principal = (
                registry.resolve(owner, target)
                .get("identity_check", {})
                .get("expected")
            )
            attacker_principal = (
                registry.resolve(attacker, target)
                .get("identity_check", {})
                .get("expected")
            )
            if (
                owner_principal is None
                or attacker_principal is None
                or owner_principal == attacker_principal
            ):
                return self._receipt(
                    cell,
                    strategy,
                    "blocked",
                    "Distinct verified account principals are required",
                    [],
                    "",
                )
        if recipe.requires_control and "control" not in plan:
            raise ValueError("Read proofs require an attacker-owned control request")
        value_path, object_path = plan["value_path"], plan.get("object_path", "/id")
        for path in (value_path, object_path):
            if not isinstance(path, str) or not path.startswith("/"):
                raise ValueError("Invalid JSON pointer")
        if plan["attack"].get("method", "GET").upper() not in recipe.attack_methods:
            raise ValueError("Attack method is not supported by this proof strategy")
        if strategy == "authorization_mutation" and "{{nonce}}" not in json.dumps(
            plan["attack"].get("body")
        ):
            raise ValueError("Attack must write the fresh nonce")
        canary_phase = "setup" if recipe.requires_control else "attack"
        for phase in ("setup", "control", "attack", "verify"):
            if phase != canary_phase and "{{nonce}}" in json.dumps(plan.get(phase, {})):
                raise ValueError(
                    "Canary must not be supplied to control/readback requests or reflected by a read attack"
                )
        nonce = secrets.token_hex(16)
        bindings = {"nonce": nonce}
        ids, documents = [], {}
        attack_url = ""
        run_id = secrets.token_hex(16)
        phases = (
            ["setup", "control", "attack", "verify"]
            if recipe.requires_control
            else ["setup", "attack", "verify"]
        )
        try:
            for phase in phases:
                spec = plan[phase]
                identity = owner if phase in ("setup", "verify") else attacker
                url = render(spec["url"], bindings, url=True)
                if origin(url) != expected_origin:
                    raise ValueError("Proof steps must remain on the registered origin")
                if phase == "attack":
                    attack_url = url
                if (
                    phase in ("control", "verify")
                    and spec.get("method", "GET").upper() != "GET"
                ):
                    raise ValueError(
                        "Control and verification must be read-only GET requests"
                    )
                response = await execute(
                    method=spec.get("method", "GET"),
                    url=url,
                    headers=render(spec.get("headers", {}), bindings),
                    body=render(spec.get("body"), bindings),
                    identity=identity,
                    hypothesis_id=cell["hypothesis_id"],
                    # The cell identity is the attacking identity. Setup/control
                    # and owner verification intentionally run as other actors.
                    coverage_cell_id=(
                        cell.get("coverage_cell_id", "") if phase == "attack" else ""
                    ),
                    follow_redirects=False,
                )
                artifact_id = response.get("evidence_id")
                if not artifact_id:
                    raise ValueError("Transport did not return an execution artifact")
                ids.append(artifact_id)
                raw = response.get("_body_text", "")
                status = response.get("response", {}).get("status", 0)
                # A status can invalidate a control, but cannot establish impact.
                if phase != "attack" and not 200 <= status < 300:
                    raise ValueError(
                        f"{phase} did not return a successful control response"
                    )
                try:
                    documents[phase] = json.loads(raw)
                except (TypeError, ValueError):
                    raise ValueError(
                        f"{phase} requires a structured JSON response"
                    ) from None
                if phase == "setup":
                    object_id = pointer(documents[phase], object_path)
                    if (
                        isinstance(object_id, (dict, list, bool))
                        or object_id is None
                        or str(object_id) == ""
                    ):
                        raise ValueError("Setup did not identify a controlled object")
                    bindings["object_id"] = object_id
                    if (
                        strategy == "authorization_read"
                        and pointer(documents[phase], value_path) != nonce
                    ):
                        raise ValueError(
                            "Setup must persist and return the fresh canary"
                        )
                    if (
                        strategy == "authorization_mutation"
                        and pointer(documents[phase], value_path) == nonce
                    ):
                        raise ValueError(
                            "Mutation canary already exists before the attack"
                        )
            before, after = documents["setup"], documents["verify"]
            if pointer(before, object_path) != pointer(after, object_path):
                raise ValueError("Owner readback refers to a different object")
            verdict, reason = recipe.evaluate(documents, nonce, object_path, value_path)
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            verdict, reason = "inconclusive", str(exc)
        except Exception:
            verdict, reason = "inconclusive", "Transport failed; proof did not complete"
        return self._receipt(
            cell, strategy, verdict, reason, ids, run_id, plan["target"], attack_url
        )

    def _receipt(
        self,
        cell,
        strategy,
        verdict,
        reason,
        ids,
        run_id,
        target="",
        attack_url="",
        **metadata,
    ):
        context = verification_run.get()
        receipt = ProofReceipt(
            run_id or secrets.token_hex(16),
            cell["hypothesis_id"],
            cell["operation_id"],
            cell["identity"],
            cell["parameter"],
            strategy,
            target,
            attack_url,
            verdict,
            reason,
            tuple(ids),
            context.id if context else "",
            context.candidate_id if context else "",
            context.revision if context else 0,
            time.time(),
            coverage_cell_id=cell.get("coverage_cell_id", ""),
            **metadata,
        )
        self.receipts[receipt.run_id] = receipt
        while len(self.receipts) > 500:
            self.receipts.pop(next(iter(self.receipts)))
        return receipt
