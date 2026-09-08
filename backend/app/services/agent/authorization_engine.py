"""Explicit policy expectations → per-identity/tenant/parameter hypotheses.

Roles do not imply permissions. The operator supplies expectations for controlled
resources; unknown expectations remain blocked instead of inventing an ACL.
"""

from __future__ import annotations

from collections import Counter
from app.services.agent.runtime_mapper import stable_id


def generate_matrix(
    brain, operations: list[dict], identities: list[dict], expectations: list[dict]
) -> list[dict]:
    from app.services.agent.engagement_brain import Hypothesis
    from app.services.agent.penetration_task_graph import sync_graph_from_brain

    policies = {}
    for rule in expectations:
        expected = rule.get("expected")
        if expected not in ("allow", "deny", "unknown"):
            raise ValueError("expected must be allow, deny, or unknown")
        key = (rule["operation_id"], rule["identity"], rule.get("parameter", ""))
        if key in policies:
            raise ValueError("Duplicate authorization expectation")
        policies[key] = expected
    cells = {row["id"]: row for row in brain.authorization_matrix}
    hyps = {h.id for h in brain.hypotheses}
    # One row for operation-level authorization plus each observed input.
    if (
        sum(1 + len(op.get("parameters", [])) for op in operations) * len(identities)
        > 5000
    ):
        raise ValueError(
            "Matrix exceeds 5000 cells; select a smaller operation/identity slice"
        )
    for op in operations:
        for identity in identities:
            for parameter in ["", *op.get("parameters", [])]:
                name, tenant = identity["name"], identity.get("tenant", "")
                hid = "authz-" + stable_id(op["id"], name, tenant, parameter)
                expected = policies.get((op["id"], name, parameter), "unknown")
                if hid in cells:
                    row = cells[hid]
                    expected = policies.get(
                        (op["id"], name, parameter), row["expected"]
                    )
                    if row["expected"] != expected:
                        if row.get("evidence_ids") or row.get("proof_run_id"):
                            raise ValueError(
                                "Expectation changed; use a new assessment instead of reusing prior verdicts"
                            )
                        row["expected"] = expected
                        reason = (
                            "Access expectation is not specified"
                            if expected == "unknown"
                            else (
                                "Identity has not been verified"
                                if name != "anonymous"
                                and not identity.get("authenticated")
                                else ""
                            )
                        )
                        row.update(
                            status="blocked" if reason else "untested", reason=reason
                        )
                    if (
                        row["status"] == "blocked"
                        and row["reason"] == "Identity has not been verified"
                        and identity.get("authenticated")
                    ):
                        row.update(status="untested", reason="")
                    continue
                if len(cells) >= 5000:
                    raise ValueError("Assessment matrix limit of 5000 cells reached")
                reason = ""
                if expected == "unknown":
                    reason = "Access expectation is not specified"
                elif name != "anonymous" and not identity.get("authenticated"):
                    reason = "Identity has not been verified"
                row = dict(
                    id=hid,
                    hypothesis_id=hid,
                    operation_id=op["id"],
                    identity=name,
                    tenant=tenant,
                    role=identity.get("role", ""),
                    parameter=parameter,
                    expected=expected,
                    status="blocked" if reason else "untested",
                    reason=reason,
                    verdict="",
                    evidence_ids=[],
                    proof_run_id="",
                )
                cells[hid] = row
                if hid not in hyps:
                    brain.hypotheses.append(
                        Hypothesis(
                            id=hid,
                            title=f"Authorization {name} {op['method']} {op['path']} {parameter}",
                            assumption=f"Expected access: {expected}; tenant: {tenant or 'unspecified'}",
                            test="Execute controlled setup → attack → owner verify workflow for this matrix cell",
                            pass_criteria="Unauthorized content disclosure or persisted canary mutation; independent verifier receipt",
                            kill_criteria="Controlled proof refutes this exact cell; status alone is insufficient",
                            specialist="auth_logic",
                            target=op["url"],
                            source="authorization",
                            identity=name,
                            tenant=tenant,
                            parameter=parameter,
                            operation_id=op["id"],
                        )
                    )
                    hyps.add(hid)
    brain.authorization_matrix = list(cells.values())
    brain.task_graph = sync_graph_from_brain(brain).to_dict()
    return brain.authorization_matrix


def apply_proof_result(brain, result: dict) -> dict:
    row = next(
        (
            r
            for r in brain.authorization_matrix
            if r["hypothesis_id"] == result["hypothesis_id"]
        ),
        None,
    )
    if row is None or any(
        row[key] != result[key] for key in ("identity", "operation_id", "parameter")
    ):
        raise ValueError("Proof result does not match an authorization matrix cell")
    row.update(
        status="tested"
        if result["verdict"] in ("confirmed", "refuted")
        else result["verdict"],
        verdict=result["verdict"],
        reason=result["reason"],
        evidence_ids=list(result["evidence_ids"]),
        proof_run_id=result["run_id"],
    )
    # A deterministic proof is evidence for the independent verifier, not publication authority.
    for hyp in brain.hypotheses:
        if hyp.id == row["hypothesis_id"]:
            hyp.status = "in_progress"
            hyp.evidence = "Proof " + result["run_id"] + ": " + result["verdict"]
    return row


def coverage_report(brain) -> dict:
    rows = [dict(row) for row in brain.authorization_matrix]
    dimensions = {}
    for key in ("hypothesis_id", "identity", "tenant", "parameter", "operation_id"):
        groups = {}
        for row in rows:
            groups.setdefault(row[key], Counter())[row["status"]] += 1
        dimensions[key] = {value: dict(counts) for value, counts in groups.items()}
    return dict(
        total=len(rows),
        counts=dict(Counter(row["status"] for row in rows)),
        dimensions=dimensions,
        rows=rows,
    )
