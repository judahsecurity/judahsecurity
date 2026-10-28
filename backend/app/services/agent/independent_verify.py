"""
Independent verification — finders propose; a fresh agent refutes or confirms.

Discovery and verification want opposite things. Hunters submit candidates.
A verifier with a new conversation (no hunter transcript) re-derives the proof
and issues a receipt. create_finding for medium+ consumes that receipt, not the
finder's own validate_finding score.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit


VERDICTS = ("pending", "confirmed", "refuted", "inconclusive")


@dataclass
class FindingCandidate:
    id: str
    title: str
    description: str = ""
    severity: str = "medium"
    target: str = ""
    evidence: str = ""
    hypothesis_id: str = ""
    threat_id: str = ""
    claimed_request: str = ""
    specialist: str = ""
    operation_id: str = ""
    identity: str = ""
    tenant: str = ""
    parameter: str = ""
    test_type: str = ""
    vulnerability_class: str = ""
    coverage_cell_id: str = ""
    capture_id: str = ""
    evidence_ids: List[str] = field(default_factory=list)
    proof_run_id: str = ""
    proof_escalation_id: str = ""
    verifier_run_id: str = ""
    finding_id: str = ""
    nonce: str = ""
    revision: int = 1
    status: str = "pending"  # pending | confirmed | refuted | inconclusive
    verifier_evidence: str = ""
    verifier_summary: str = ""
    counterevidence: Dict[str, str] = field(default_factory=dict)
    proof_gap: Dict[str, str] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verified_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def candidate_from_dict(raw: Optional[Dict[str, Any]]) -> Optional[FindingCandidate]:
    if not isinstance(raw, dict) or not raw.get("id"):
        return None
    allowed = {f.name for f in fields(FindingCandidate)}
    return FindingCandidate(**{k: v for k, v in raw.items() if k in allowed})


def _same_observed_origin(scheme: str, host: str, target: str) -> bool:
    from app.services.agent.evidence_store import origin

    try:
        return origin(f"{scheme}://{host}") == origin(target)
    except (ValueError, TypeError):
        return False


def observed_sql_cell_for_proof(
    brain: Any, store: Any, *, target: str, evidence_ids: Iterable[str],
) -> Optional[Dict[str, Any]]:
    """Link a scoped SQLi receipt to one exact observed GET or POST input.

    Narrative claims and parameter-name guesses cannot create this link.
    Ambiguous inventory rows are deliberately left for analyst review.
    """
    from urllib.parse import urlsplit
    from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES
    from app.services.agent.scoped_assessment.sqli_boolean import numeric_sql_proof_valid
    from app.services.agent.scoped_assessment.body_probe import post_sql_error_proof_valid
    from app.services.agent.scoped_assessment.sqli_string import (
        string_error_proof_valid, string_sql_proof_valid,
    )

    parsed = urlsplit(target)
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        return None
    matches: Dict[str, Dict[str, Any]] = {}
    for evidence_id in evidence_ids:
        receipt = store.records.get(str(evidence_id))
        if (not receipt or receipt.get("kind") not in {"scoped_string_sqli", "scoped_numeric_sqli", "scoped_body_sqli_error"}
                or receipt.get("target") != target):
            continue
        proof = receipt.get("payload")
        if (not isinstance(proof, dict) or proof.get("proof_confirmed") is not True
                or proof.get("target") != target):
            continue
        valid = (post_sql_error_proof_valid(proof) if receipt.get("kind") == "scoped_body_sqli_error"
                 else numeric_sql_proof_valid(proof) if receipt.get("kind") == "scoped_numeric_sqli"
                 else string_error_proof_valid(proof) if proof.get("proof_recipe") == "string_error_v1"
                 else string_sql_proof_valid(proof))
        if not valid:
            continue
        parameter = str(proof.get("parameter") or "")
        for cell in getattr(brain, "coverage_cells", None) or []:
            if (cell.get("source") == "parameter_inventory"
                    and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
                    and cell.get("test_type") == "sqli"
                    and cell.get("method") == proof.get("method")
                    and _same_observed_origin(parsed.scheme, str(cell.get("host") or ""), target)
                    and cell.get("path") == (parsed.path or "/")
                    and cell.get("parameter") == (
                        f"body_form:{parameter}" if proof.get("method") == "POST"
                        else f"query:{parameter}"
                    )
                    and (proof.get("method") != "POST"
                         or (cell.get("capture_id") == proof.get("source_artifact_id")
                             and cell.get("observation_source") == "browser_traffic"))
                    and (cell.get("identity") or "anonymous") == receipt.get("identity")):
                matches[str(cell["id"])] = cell
    return next(iter(matches.values())) if len(matches) == 1 else None


def resolve_observed_sql_candidate_proof(
    brain: Any, store: Any, *, target: str, evidence_ids: Iterable[str],
    claim: str = "",
) -> Optional[tuple[str, Dict[str, Any], str]]:
    """Recover one execution-owned SQLi receipt for an exact observed input.

    Candidate authors sometimes cite a request URL (including its query) or
    omit the evidence ID after a scoped probe. The scoped receipt already owns
    the canonical path, parameter, and proof result. Only an unambiguous match
    to the claim and inventory may repair that handoff.
    """
    parsed = urlsplit(str(target or ""))
    if (parsed.scheme not in {"http", "https"} or not parsed.netloc
            or parsed.username or parsed.password or parsed.fragment):
        return None
    canonical = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    cited = [str(item) for item in evidence_ids or []]
    ids = cited or list(store.records)
    query_names = {name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    matches: list[tuple[str, Dict[str, Any], float]] = []
    for artifact_id in ids:
        receipt = store.records.get(artifact_id)
        if (not receipt or receipt.get("kind") not in {"scoped_string_sqli", "scoped_numeric_sqli", "scoped_body_sqli_error"}
                or receipt.get("target") != canonical or receipt.get("run_id")):
            continue
        proof = receipt.get("payload") or {}
        parameter = str(proof.get("parameter") or "")
        if not parameter or (not cited and parameter not in query_names and not re.search(
            rf"(?<![A-Za-z0-9_]){re.escape(parameter)}(?![A-Za-z0-9_])", claim,
            re.IGNORECASE,
        )):
            continue
        cell = observed_sql_cell_for_proof(
            brain, store, target=canonical, evidence_ids=[artifact_id],
        )
        if cell:
            matches.append((artifact_id, cell, float(receipt.get("created_at") or 0)))
    if len({row[1]["id"] for row in matches}) != 1:
        return None
    artifact_id, cell, _ = max(matches, key=lambda row: row[2])
    return canonical, cell, artifact_id


def observed_xss_cell_for_proof(
    brain: Any, store: Any, *, target: str, evidence_ids: Iterable[str],
) -> Optional[Dict[str, Any]]:
    """Link browser execution to one mapped GET parameter, never to a guess."""
    from urllib.parse import parse_qs, parse_qsl, urlsplit
    from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

    parsed_target = urlsplit(target)
    if (parsed_target.scheme not in {"http", "https"} or not parsed_target.netloc
            or parsed_target.query or parsed_target.fragment):
        return None
    matches: Dict[str, Dict[str, Any]] = {}
    for evidence_id in evidence_ids:
        receipt = store.records.get(str(evidence_id))
        if (not receipt or receipt.get("kind") not in {"scoped_browser_check_xss", "scoped_browser_check_xhr_xss"}
                or receipt.get("target") != target):
            continue
        proof = receipt.get("payload")
        xhr_xss = receipt.get("kind") == "scoped_browser_check_xhr_xss"
        if (not isinstance(proof, dict)
                or proof.get("operation") != ("check_xhr_xss" if xhr_xss else "check_xss")
                or proof.get("executed") is not True):
            continue
        template = str(proof.get("target_template") or "")
        parsed = urlsplit(template)
        if not _same_observed_origin(parsed.scheme, parsed.netloc, target):
            continue
        if parsed.fragment:
            if (xhr_xss or parsed.query or (parsed.path or "/") != (parsed_target.path or "/")
                    or "__PROWL_NONCE__" not in parsed.fragment):
                continue
            for cell in getattr(brain, "coverage_cells", None) or []:
                if (cell.get("source") == "js_inventory"
                        and cell.get("test_type") == "dom_xss"
                        and cell.get("page_path") == (parsed_target.path or "/")
                        and _same_observed_origin(parsed_target.scheme, str(cell.get("host") or ""), target)
                        and any(isinstance(lead, dict) and lead.get("kind") == "fragment"
                                for lead in cell.get("source_leads") or [])
                        and (cell.get("identity") or "anonymous") == receipt.get("identity")):
                    matches[str(cell["id"])] = cell
            continue
        if xhr_xss:
            if (proof.get("xhr_path") != (parsed_target.path or "/")
                    or "__PROWL_NONCE__" not in str(proof.get("xhr_payload_template") or "")
                    or not isinstance(proof.get("xhr_query_keys"), list)
                    or proof.get("xhr_parameter") not in proof["xhr_query_keys"]
                    or proof.get("xhr_mutated") is not True
                    or proof.get("xhr_response_seen") is not True):
                continue
            parameters = {str(proof.get("xhr_parameter") or "")}
        else:
            if (parsed.path or "/") != (parsed_target.path or "/"):
                continue
            parameters = {
                name for name, values in parse_qs(parsed.query).items()
                if any("__PROWL_NONCE__" in value for value in values)
            }
        for cell in getattr(brain, "coverage_cells", None) or []:
            if (cell.get("source") == "parameter_inventory"
                    and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
                    and cell.get("test_type") == "xss" and cell.get("method") == "GET"
                    and _same_observed_origin(parsed_target.scheme, str(cell.get("host") or ""), target)
                    and cell.get("path") == (parsed_target.path or "/")
                    and cell.get("parameter") in {f"query:{name}" for name in parameters}
                    and (cell.get("identity") or "anonymous") == receipt.get("identity")):
                matches[str(cell["id"])] = cell
    return next(iter(matches.values())) if len(matches) == 1 else None


def candidate_id(title: str, target: str = "", coverage_cell_id: str = "") -> str:
    blob = f"{(title or '').strip().lower()}|{(target or '').strip()}"
    if coverage_cell_id:
        blob += "|" + coverage_cell_id.strip()
    return hashlib.sha1(blob.encode()).hexdigest()[:12]


def new_nonce() -> str:
    return uuid.uuid4().hex[:16]


def verify_receipt_key(title: str, target: str = "") -> str:
    blob = f"{(title or '').strip().lower()}|{(target or '').strip()}"
    return "iv:" + hashlib.sha256(blob.encode()).hexdigest()[:24]


def record_verify_receipt(
    store: Dict[str, Dict[str, Any]],
    *,
    title: str,
    target: str,
    verdict: str,
    candidate_id: str = "",
    evidence: str = "",
    nonce: str = "",
    nonce_observed: bool = False,
    evidence_ids: Optional[List[str]] = None,
    run_id: str = "",
    revision: int = 0,
) -> str:
    key = verify_receipt_key(title, target)
    store[key] = {
        "title": title,
        "target": target,
        "verdict": verdict,
        "candidate_id": candidate_id,
        "nonce": nonce,
        "nonce_observed": bool(nonce_observed),
        "evidence_ids": list(evidence_ids or []),
        "run_id": run_id,
        "revision": revision,
        "evidence": (evidence or "")[:2000],
        "ts": time.time(),
    }
    return key


def finding_publish_allowed(
    tools_manager: Any,
    *,
    title: str,
    target: str,
    severity: str,
    skip: bool = False,
) -> tuple[bool, str]:
    """Gate create_finding. Independent verify wins once fireteam/candidates are in play."""
    from app.services.agent.finding_gate import severity_requires_gate
    if not severity_requires_gate(severity):
        return True, "info_ok"
    # Tool arguments and benchmark flags must not bypass production publication.
    return check_verify_receipt(
        getattr(tools_manager, "_verify_receipts", None), title=title or "",
        target=target or "", tools_manager=tools_manager,
    )


def verified_publication_claim(
    candidate: FindingCandidate, *, title: str, target: str, severity: str,
) -> tuple[bool, str, str]:
    """Keep the verified claim fixed while allowing a separate report writeup.

    The model's publication description often differs from its candidate
    wording. Publish the verified description instead of invalidating a sound
    verifier receipt or accepting an unverified change to the claim.
    """
    if (candidate.title != title or candidate.target != target
            or candidate.severity.lower() != severity.lower()):
        return False, (
            "Verified title, target, or severity changed. Use the exact confirmed "
            f"candidate: title={candidate.title!r}, target={candidate.target!r}, "
            f"severity={candidate.severity!r}"
        ), ""
    return True, "", candidate.description


def check_verify_receipt(
    store: Optional[Dict[str, Dict[str, Any]]],
    *,
    title: str,
    target: str,
    tools_manager: Any = None,
) -> tuple[bool, str]:
    store = store if store is not None else {}
    key = verify_receipt_key(title, target)
    receipt = store.get(key)
    brain = _brain(tools_manager) if tools_manager is not None else None
    if not receipt and brain is not None:
        durable = (getattr(brain, "verification_receipts", None) or {}).get(key)
        if isinstance(durable, dict):
            receipt = dict(durable)
            store[key] = receipt
            tools_manager._verify_receipts = store
    if not receipt:
        candidate = next((c for c in (
            candidate_from_dict(raw) for raw in (getattr(brain, "candidates", None) or [])
        ) if c and c.title.strip() == title.strip() and c.target.strip() == target.strip()), None) if brain else None
        if candidate and candidate.status in ("inconclusive", "refuted"):
            return False, (
                "INDEPENDENT VERIFY GATE: candidate " + candidate.id
                + " is " + candidate.status + " at revision " + str(candidate.revision)
                + ". Do not retry create_finding or independent_verify on this revision. "
                "Collect a new supported execution proof, resubmit the exact candidate "
                "with its new evidence ID, then verify the new revision. Reason: "
                + (candidate.verifier_summary or "unsupported or insufficient proof")[:300]
            )
        if candidate and candidate.status == "pending":
            return False, (
                "INDEPENDENT VERIFY GATE: candidate " + candidate.id
                + " is pending; call independent_verify(candidate_id=\"" + candidate.id
                + "\") once before create_finding."
            )
        related = [c for c in (
            candidate_from_dict(raw) for raw in (getattr(brain, "candidates", None) or [])
        ) if c and c.target.strip() == target.strip()][:3] if brain else []
        exact_claim = (
            " Existing candidate titles for this target: "
            + "; ".join(repr(c.title) + " [" + c.status + "]" for c in related)
            + ". Use the exact verified title, target, description, and severity."
        ) if related else ""
        return False, (
            "INDEPENDENT VERIFY GATE: medium+ findings require independent_verify → "
            f"confirmed for this title/target first (key={key}). "
            "Hunters must submit_finding_candidate; Joshua (or fireteam second wave) "
            "runs independent_verify; then create_finding." + exact_claim
        )
    if receipt.get("verdict") != "confirmed":
        return False, (
            f"INDEPENDENT VERIFY GATE: candidate verdict={receipt.get('verdict')} "
            "(need confirmed). Do not create_finding."
        )
    if tools_manager is None:
        return False, "Execution evidence store required"
    candidate = _candidate(brain, receipt.get("candidate_id", ""))
    if not candidate or candidate.status != "confirmed" or candidate.revision != receipt.get("revision"):
        return False, "Candidate changed or was refuted; reverify before publication"
    ok, why = publication_invariants(brain, candidate, receipt)
    if not ok:
        return False, why
    from app.services.agent.evidence_store import evidence_store
    evidence_target = candidate.target
    if receipt.get('workflow_run_id'):
        engine = getattr(tools_manager, '_proof_engine', None)
        if engine is None:
            return False, 'Workflow execution authority is unavailable; reverify'
        ok, why = engine.validate_receipt(receipt['workflow_run_id'], candidate, receipt.get('evidence_ids') or [], fresh=False)
        if not ok:
            return False, why
        evidence_target = engine.receipts[receipt['workflow_run_id']].attack_url
    ok, why = evidence_store(tools_manager).validate(
        receipt.get("evidence_ids") or [], candidate_id=candidate.id,
        revision=candidate.revision, run_id=receipt.get("run_id", ""), target=evidence_target,
    )
    return (True, f"verify_ok:{key}") if ok else (False, why)


def publication_invariants(
    brain: Any,
    candidate: FindingCandidate,
    receipt: Dict[str, Any],
) -> tuple[bool, str]:
    """Require one internally consistent request→proof→verify publication chain."""
    if candidate.finding_id:
        return False, f"Candidate already published as finding {candidate.finding_id}"
    if not candidate.verified_at or not candidate.verifier_run_id:
        return False, "Candidate is missing durable verifier execution metadata"
    if receipt.get("candidate_id") != candidate.id:
        return False, "Verification receipt belongs to another candidate"
    if (
        str(receipt.get("title") or "").strip() != candidate.title.strip()
        or str(receipt.get("target") or "").strip() != candidate.target.strip()
    ):
        return False, "Verification receipt claim does not match the candidate"
    if receipt.get("run_id") != candidate.verifier_run_id:
        return False, "Verification receipt and candidate verifier runs differ"
    if not receipt.get("nonce_observed") or receipt.get("nonce") != candidate.nonce:
        return False, "Verifier nonce was not observed for this candidate revision"
    receipt_evidence = {
        str(value) for value in (receipt.get("evidence_ids") or []) if value
    }
    if not receipt_evidence or not receipt_evidence.issubset(set(candidate.evidence_ids)):
        return False, "Verification evidence is not linked to the confirmed candidate"

    if candidate.coverage_cell_id:
        cell = next(
            (
                row
                for row in (getattr(brain, "coverage_cells", None) or [])
                if row.get("id") == candidate.coverage_cell_id
            ),
            None,
        )
        if not cell:
            return False, "Confirmed candidate references a missing coverage cell"
        if cell.get("candidate_id") != candidate.id:
            return False, "Coverage cell is linked to another candidate"
        if cell.get("status") not in ("in_focus", "finding"):
            return False, "Coverage cell is not in a publishable state"
        if cell.get("verifier_run_id") != candidate.verifier_run_id:
            return False, "Coverage cell verifier trace does not match the candidate"
        if (
            candidate.proof_escalation_id
            and cell.get("proof_escalation_id") != candidate.proof_escalation_id
        ):
            return False, "Coverage cell proof escalation does not match the candidate"
        for field_name in (
            "operation_id",
            "identity",
            "tenant",
            "parameter",
            "test_type",
        ):
            expected = str(getattr(candidate, field_name, "") or "")
            observed = str(cell.get(field_name) or "")
            if expected and observed and expected != observed:
                return False, f"Coverage cell {field_name} does not match the candidate"

    if candidate.proof_escalation_id:
        escalation = next(
            (
                row
                for row in (getattr(brain, "proof_escalations", None) or [])
                if row.get("id") == candidate.proof_escalation_id
            ),
            None,
        )
        if not escalation:
            return False, "Confirmed candidate references a missing proof escalation"
        if escalation.get("status") not in ("confirmed", "published"):
            return False, "Proof escalation has not been independently confirmed"
        if escalation.get("candidate_id") != candidate.id:
            return False, "Proof escalation is linked to another candidate"
        if escalation.get("verifier_run_id") != candidate.verifier_run_id:
            return False, "Proof escalation verifier trace does not match the candidate"
    return True, "publication_trace_ok"


def parse_verdict_from_text(text: str) -> str:
    blob = (text or "").lower()
    if re.search(r"\b(verdict\s*[:=]\s*)?(refuted|false positive|not exploitable|killed)\b", blob):
        return "refuted"
    if re.search(r"\b(verdict\s*[:=]\s*)?(confirmed|reproduced|exploitable)\b", blob):
        return "confirmed"
    if re.search(r"\b(inconclusive|could not reproduce|needs more)\b", blob):
        return "inconclusive"
    return "inconclusive"


def verifier_mission(candidate: FindingCandidate, *, threat_slice: str = "") -> str:
    from app.services.agent.proof_policy import PROOFS_BY_CLASS, inferred_vulnerability_class
    from app.services.agent.auth_header_bypass import (
        VERIFIER_ADDENDUM as AUTH_HEADER_VERIFIER_ADDENDUM,
        is_auth_header_finding,
    )
    from app.services.agent.email_change_ato import (
        VERIFIER_ADDENDUM as EMAIL_CHANGE_VERIFIER_ADDENDUM,
        is_email_change_finding,
    )
    from app.services.agent.ml_pipeline_rbac import (
        VERIFIER_ADDENDUM as ML_RBAC_VERIFIER_ADDENDUM,
        is_ml_rbac_finding,
    )
    from app.services.agent.socketio_idor import (
        VERIFIER_ADDENDUM as SOCKETIO_VERIFIER_ADDENDUM,
        is_socketio_finding,
    )
    from app.services.agent.unauth_account_lookup import (
        VERIFIER_ADDENDUM as ACCOUNT_VERIFIER_ADDENDUM,
        is_account_lookup_finding,
    )
    from app.services.agent.unauth_settings_write import (
        VERIFIER_ADDENDUM as SETTINGS_VERIFIER_ADDENDUM,
        is_settings_write_finding,
    )

    packet = " ".join(
        [
            candidate.title or "",
            candidate.description or "",
            candidate.evidence or "",
            candidate.claimed_request or "",
        ]
    )
    addenda = []
    if is_account_lookup_finding(packet):
        addenda.append(ACCOUNT_VERIFIER_ADDENDUM)
    if is_settings_write_finding(packet):
        addenda.append(SETTINGS_VERIFIER_ADDENDUM)
    if is_email_change_finding(packet):
        addenda.append(EMAIL_CHANGE_VERIFIER_ADDENDUM)
    if is_auth_header_finding(packet):
        addenda.append(AUTH_HEADER_VERIFIER_ADDENDUM)
    if is_socketio_finding(packet):
        addenda.append(SOCKETIO_VERIFIER_ADDENDUM)
    if is_ml_rbac_finding(packet):
        addenda.append(ML_RBAC_VERIFIER_ADDENDUM)
    from app.services.agent.interactsh_proof import (
        VERIFIER_ADDENDUM as INTERACTSH_VERIFIER_ADDENDUM,
        is_oob_finding,
    )

    if is_oob_finding(packet):
        addenda.append(INTERACTSH_VERIFIER_ADDENDUM)
    class_addendum = ("\n\n" + "\n\n".join(addenda)) if addenda else ""
    claim_class = candidate.vulnerability_class or inferred_vulnerability_class(candidate)
    proof_options = ", ".join(sorted(PROOFS_BY_CLASS.get(claim_class, ()))) or "none yet"

    return (
        "You are an ADVERSARIAL verifier in a FRESH session. You did not see the "
        "finder's transcript. Actively look for reasons this claim is WRONG.\n"
        "Re-derive the proof yourself (compare_requests or execute_curl). "
        "Do not trust the finder's markers, filenames, or 'log lines'.\n"
        f"Include request header X-Aegis-Verify: {candidate.nonce} on live probes "
        "so your evidence is distinguishable from the finder's.\n\n"
        f"CANDIDATE id={candidate.id}\n"
        f"Title: {candidate.title}\n"
        f"Vulnerability class: {claim_class or 'unclassified'}; supported proof kinds: {proof_options}\n"
        f"Severity: {candidate.severity}\n"
        f"Target: {candidate.target}\n"
        f"Hypothesis: {candidate.hypothesis_id or '—'}  threat={candidate.threat_id or '—'}\n"
        f"Coverage cell: {candidate.coverage_cell_id or '—'}  operation={candidate.operation_id or '—'} "
        f"identity={candidate.identity or '—'} tenant={candidate.tenant or '—'} "
        f"parameter={candidate.parameter or '—'} test={candidate.test_type or '—'}\n"
        f"Proof escalation: {candidate.proof_escalation_id or '—'}  "
        f"proof run={candidate.proof_run_id or '—'}\n"
        f"Claimed request: {candidate.claimed_request or '—'}\n"
        f"Finder evidence (untrusted):\n{(candidate.evidence or '')[:2500]}\n"
        f"Finder evidence IDs: {', '.join((candidate.evidence_ids or [])[:8]) or '—'}\n"
        f"Description (untrusted):\n{(candidate.description or '')[:1500]}\n\n"
        f"{threat_slice}\n"
        f"{class_addendum}\n"
        "For scoped browser/HTTP candidates, rerun the matching Aegis scoped tool. "
        "Inspect JavaScript again to get a fresh browser exchange before captured "
        "scoped_numeric_sqli, scoped_query_probe, scoped_body_probe, or scoped_owner_only. "
        "For a mapped numeric GET link, scoped_numeric_sqli(url=canonical_path, "
        "parameter=name) replays an ordinary observed positive value with fresh "
        "bounded Boolean controls. Use its new evidence_id with the hunter's earlier "
        "scoped_numeric_sqli evidence_id. "
        "For a mapped string-valued GET query input, scoped_string_sqli(url, parameter) "
        "builds a fresh bounded SQLi proof without an XHR capture. It tries "
        "OR controls first, including small JSON result arrays; when unproven, "
        "it repeats a recognized database error "
        "or compares AND true/false responses against a stable baseline. "
        "Its URL may be the canonical path when the browser map contains an ordinary "
        "observed page or private link value for that parameter, or a one-field GET "
        "form can be preflighted. Prefer this structured proof to raw curl "
        "replays; do not repeat the same controls after it completes. "
        "Use its evidence_id with the candidate's earlier scoped_string_sqli evidence_id. "
        "For a confirmed numeric or string Boolean SQLi, repeated SQL error, owner-only access, "
        "public directory index, or browser XSS, use proof "
        "{kind: numeric_boolean_sqli|string_boolean_sqli|string_error_sqli|owner_only|"
        "public_directory_index|scoped_browser_xss, hunter_artifact_id, artifact_id}. "
        "The first ID must be the candidate's hunter receipt and the second your fresh receipt. "
        f"For XSS use execute_browser check_xss with alert('aegis-verify-{candidate.nonce}'); "
        "proof {kind: browser_xss, artifact_id} requires the fresh canary dialog, not reflection. "
        "For blind sinks prefer run_oob_callback_workflow so fresh registration, planting, bounded polling, and evidence correlation happen together; "
        "manual execute_interactsh register, replay_http_request, then poll remains available. "
        "proof {kind: oob_callback, register_id, plant_id, poll_id} ties the callback to the sink. "
        "For HTTP evidence use replay_http_request or compare_requests; each response includes evidence_id. "
        "Other scanner output is a lead and cannot issue a confirmation receipt. "
        "Read complete observations with read_evidence(evidence_id, offset). "
        "When done, call record_verify_verdict(candidate_id, verdict, evidence, evidence_ids, proof) "
        "with IDs from YOUR HTTP exchanges and a structured proof: "
        "response_match {kind, artifact_id, contains} for exposure; "
        "authorization {kind, baseline_id, mutant_id, field} for cross-identity JSON object access; "
        "field may be a named nested path such as data.node.ownerId for GraphQL, "
        "but both identities must replay the same query and variables. "
        "state_change {kind, write_id, read_id, cleanup_id, field, value, owner_identity?} "
        "for persisted canary changes; upload_xss {kind, upload_id, read_id, browser_id, cleanup_id} "
        "for a canary file retrieved and executed in the browser. Use the exact value aegis-verify-<candidate nonce>. "
        "Anonymous writes must be explicitly claimed as unauthenticated; named actors require "
        "a distinct verified owner readback. Cleanup is mandatory. "
        "No body/schema/version alone proves authorization or mass assignment. "
        "with verdict confirmed|refuted|inconclusive, then done=true. "
        "confirmed = you reproduced impact with your own request/response. "
        "A product version within a CVE's published range is an applicability lead, "
        "not proof of the vulnerability. Mark inconclusive until a class-specific "
        "validator demonstrates the claimed behavior. "
        "Close every candidate as confirmed, refuted, or inconclusive with an explicit proof gap. "
        "Refuted requires a fresh exchange on the claimed attacker path and proof "
        "{kind: counterevidence, artifact_id, control, attacker_path, "
        "response_status, observation}; "
        "name the control that held and what the response showed. A fresh trusted "
        "workflow receipt with verdict refuted may instead use proof {kind: workflow, run_id}. "
        "A failed replay, timeout, or absence of a callback alone is inconclusive. "
        "For inconclusive include summary explaining the missing proof and "
        "proof {next_step: specific follow-up test}. Never call an untested path clean."
    )


async def run_independent_verifiers(
    candidates: Iterable[FindingCandidate],
    *,
    llm: Any,
    tools_manager: Any,
    targets: Optional[List[str]] = None,
    threat_slice: str = "",
    max_parallel: int = 3,
) -> List[Dict[str, Any]]:
    """Spawn a fresh verifier agent per pending candidate. No hunter transcript."""
    import asyncio
    from app.services.agent.fireteam_service import _run_specialist, get_specialist

    profile = get_specialist("independent_verifier")
    if not profile:
        return [{"error": "independent_verifier specialist missing"}]

    pending = [c for c in candidates if c.status == "pending"]
    if not pending:
        return []

    sem = asyncio.Semaphore(max(1, max_parallel))
    target_list = list(targets or [])

    async def _one(cand: FindingCandidate) -> Dict[str, Any]:
        async with sem:
            mission = verifier_mission(cand, threat_slice=threat_slice)
            if cand.hypothesis_id in (getattr(tools_manager, '_proof_plans', {}) or {}):
                mission += (f"\nA controlled workflow is registered for hypothesis {cand.hypothesis_id}. "
                            "Call run_authorization_proof with this hypothesis_id and no plan to reproduce it. "
                            "Use the returned receipt's evidence_ids and proof={kind: workflow, run_id: receipt.run_id} "
                            "in record_verify_verdict for a confirmed or refuted workflow verdict. "
                            "An inconclusive workflow receipt must stay inconclusive with a specific next_step. "
                            "A prior hunter receipt is not valid in this verifier run.")
            from app.services.agent.evidence_store import VerificationRun, verification_run
            run = VerificationRun(uuid.uuid4().hex, cand.id, cand.revision, cand.nonce)
            token = verification_run.set(run)
            try:
                replayed = await _verify_scoped_sql_candidate(tools_manager, cand, run)
                if replayed is not None:
                    return replayed
                replayed = await _verify_scoped_browser_xss_candidate(tools_manager, cand, run)
                if replayed is not None:
                    return replayed
                report = await _run_specialist(
                    profile, mission, [cand.target], llm, tools_manager,
                )
                live = _candidate(_brain(tools_manager), cand.id)
                if live and live.status == "pending":
                    # Narrative text cannot promote a candidate to confirmed.
                    apply_verdict(tools_manager, candidate_id=cand.id, verdict="inconclusive",
                                  evidence="Verifier did not record a supported verdict")
                    live = _candidate(_brain(tools_manager), cand.id)
            finally:
                verification_run.reset(token)
            return {
                "candidate_id": cand.id,
                "title": cand.title,
                "status": (live.status if live else "inconclusive"),
                "verifier_summary": (report.summary or "")[:1500],
                "key_findings": list(report.key_findings or [])[:8],
                "tool_calls": len(report.tool_calls or []),
                "error": report.error,
            }

    return list(await asyncio.gather(*(_one(c) for c in pending)))


async def _verify_scoped_sql_candidate(
    tools_manager: Any, cand: FindingCandidate, run: Any,
) -> Optional[Dict[str, Any]]:
    """Repeat an exact mapped SQLi proof before spending a verifier model wave.

    The candidate and its earlier receipt only select the observed input. The
    fresh scoped probe must independently satisfy the existing two-actor proof
    policy before this path can issue a confirmed verdict.
    """
    import logging
    from urllib.parse import urlsplit

    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.proof_policy import (
        inferred_vulnerability_class, validate_proof,
    )
    from app.services.agent.scoped_assessment.sqli_boolean import numeric_sql_proof_valid
    from app.services.agent.scoped_assessment.sqli_string import (
        string_error_proof_valid, string_sql_proof_valid,
    )
    from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

    if (cand.vulnerability_class or inferred_vulnerability_class(cand)) != "sql_injection":
        return None
    brain = _brain(tools_manager)
    cell = next((row for row in brain.coverage_cells
                 if row.get("id") == cand.coverage_cell_id), None)
    if not cell:
        cell = observed_sql_cell_for_proof(
            brain, evidence_store(tools_manager), target=cand.target,
            evidence_ids=cand.evidence_ids,
        )
        if cell:
            cand.coverage_cell_id = str(cell["id"])
            for raw in brain.candidates:
                if isinstance(raw, dict) and raw.get("id") == cand.id:
                    raw["coverage_cell_id"] = cand.coverage_cell_id
            cell["candidate_id"] = cand.id
            tools_manager._engagement_brain = brain.to_dict()
    if cell and cell.get("method") == "POST":
        return await _verify_scoped_post_sql_candidate(tools_manager, cand, run, cell)
    if not cell or cell.get("source") != "parameter_inventory" or (
        cell.get("observation_source") not in OBSERVED_INPUT_SOURCES
        or cell.get("test_type") != "sqli" or cell.get("method") != "GET"
    ):
        return None
    location, separator, parameter = str(cell.get("parameter") or "").partition(":")
    target = urlsplit(cand.target)
    identity = str(cell.get("identity") or "anonymous")
    if (location != "query" or not separator or not parameter
            or target.scheme not in {"http", "https"}
            or not _same_observed_origin(target.scheme, str(cell.get("host") or ""), cand.target)
            or (target.path or "/") != cell.get("path")
            or target.query or target.fragment
            or (cand.identity and cand.identity != identity)
            or (cand.parameter and cand.parameter != cell.get("parameter"))):
        return None
    store = evidence_store(tools_manager)
    hunter_ids = [artifact_id for artifact_id in cand.evidence_ids
                  if (artifact_id in store.records
                      and store.records[artifact_id]["kind"] in {"scoped_string_sqli", "scoped_numeric_sqli"}
                      and store.records[artifact_id]["target"] == cand.target
                      and store.records[artifact_id]["identity"] == identity
                      and store.records[artifact_id]["payload"].get("parameter") == parameter
                      and store.records[artifact_id]["payload"].get("proof_confirmed") is True)]
    if not hunter_ids:
        return None
    hunter_kind = store.records[hunter_ids[0]]["kind"]
    hunter_ids = [item for item in hunter_ids if store.records[item]["kind"] == hunter_kind]
    probe_name = "scoped_numeric_sqli" if hunter_kind == "scoped_numeric_sqli" else "scoped_string_sqli"
    failure = "Fresh SQLi replay did not reproduce the hunter proof"
    try:
        wrapped = await tools_manager.execute(probe_name, {
            "url": cand.target, "parameter": parameter, "identity": identity,
        })
        output = wrapped.get("output") if isinstance(wrapped, dict) else None
        result = json.loads(output) if isinstance(output, str) else output
        if not isinstance(result, dict):
            failure = "SQLi replay returned no structured result"
        elif result.get("proof_confirmed") is not True:
            failure = str(result.get("error") or "Fresh SQLi controls did not confirm injection")[:300]
        else:
            artifact_id = str(result.get("evidence_id") or "")
            verifier = store.records.get(artifact_id)
            if not verifier or verifier.get("run_id") != run.id or verifier.get("kind") != hunter_kind:
                failure = "SQLi replay had no fresh verifier evidence"
            else:
                recipe = result.get("proof_recipe")
                kind = ("numeric_boolean_sqli" if hunter_kind == "scoped_numeric_sqli" else
                        "string_error_sqli" if recipe == "string_error_v1" else "string_boolean_sqli")
                valid_recipe = (numeric_sql_proof_valid(result) if kind == "numeric_boolean_sqli" else
                                string_error_proof_valid(result) if kind == "string_error_sqli" else
                                string_sql_proof_valid(result))
                if not valid_recipe:
                    failure = "SQLi replay receipt failed recipe validation"
                else:
                    for hunter_id in hunter_ids:
                        proof = {"kind": kind, "hunter_artifact_id": hunter_id,
                                 "artifact_id": artifact_id}
                        valid, why = validate_proof(store, cand, proof, [artifact_id])
                        fresh, fresh_why = store.validate(
                            [artifact_id], candidate_id=cand.id, revision=cand.revision,
                            run_id=run.id, target=cand.target,
                        )
                        if valid and fresh:
                            verified = apply_verdict(
                                tools_manager, candidate_id=cand.id, verdict="confirmed",
                                evidence="Fresh scoped SQLi controls reproduced the candidate on the exact observed input.",
                                evidence_ids=[artifact_id], proof=proof,
                            )
                            if verified and verified.status == "confirmed":
                                return {
                                    "candidate_id": cand.id, "title": cand.title,
                                    "status": "confirmed", "verifier_summary": "Fresh scoped SQLi proof matched the hunter receipt",
                                    "key_findings": [], "tool_calls": 1, "error": None,
                                }
                        failure = why or fresh_why or "SQLi proof policy rejected the replay"
    except Exception:
        logging.getLogger(__name__).exception(
            "Deterministic SQLi verifier could not replay candidate %s", cand.id,
        )
        failure = "Scoped SQLi replay failed before verification completed"
    apply_verdict(
        tools_manager, candidate_id=cand.id, verdict="inconclusive",
        evidence=failure, summary=failure,
    )
    return {
        "candidate_id": cand.id, "title": cand.title, "status": "inconclusive",
        "verifier_summary": failure, "key_findings": [], "tool_calls": 1,
        "error": None,
    }


async def _verify_scoped_post_sql_candidate(
    tools_manager: Any, cand: FindingCandidate, run: Any, cell: dict,
) -> Optional[Dict[str, Any]]:
    """Repeat the same captured form with fresh POST controls and identity."""
    import logging

    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.proof_policy import validate_proof
    from app.services.agent.scoped_assessment.body_probe import post_sql_error_proof_valid
    from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

    target = urlsplit(cand.target)
    location, separator, parameter = str(cell.get("parameter") or "").partition(":")
    identity = str(cell.get("identity") or "anonymous")
    capture_id = str(cell.get("capture_id") or "")
    if (cell.get("source") != "parameter_inventory"
            or cell.get("observation_source") not in OBSERVED_INPUT_SOURCES
            or cell.get("observation_source") != "browser_traffic"
            or cell.get("test_type") != "sqli" or location != "body_form"
            or not separator or not parameter or not capture_id
            or target.scheme not in {"http", "https"}
            or not _same_observed_origin(target.scheme, str(cell.get("host") or ""), cand.target)
            or (target.path or "/") != cell.get("path")
            or target.query or target.fragment
            or (cand.identity and cand.identity != identity)
            or (cand.parameter and cand.parameter != cell.get("parameter"))):
        return None
    store = evidence_store(tools_manager)
    hunter_ids = [artifact_id for artifact_id in cand.evidence_ids
                  if (artifact_id in store.records
                      and store.records[artifact_id]["kind"] == "scoped_body_sqli_error"
                      and store.records[artifact_id]["target"] == cand.target
                      and store.records[artifact_id]["identity"] == identity
                      and store.records[artifact_id]["payload"].get("parameter") == parameter
                      and store.records[artifact_id]["payload"].get("source_artifact_id") == capture_id
                      and store.records[artifact_id]["payload"].get("proof_confirmed") is True
                      and post_sql_error_proof_valid(store.records[artifact_id]["payload"]))]
    if not hunter_ids:
        return None
    failure = "Fresh POST SQLi controls did not reproduce the hunter proof"
    try:
        result = await tools_manager._scoped_body_sql_error_verifier(capture_id, parameter, identity)
        artifact_id = str(result.get("evidence_id") or "")
        verifier = store.records.get(artifact_id)
        if (not post_sql_error_proof_valid(result) or result.get("proof_confirmed") is not True
                or not verifier or verifier.get("kind") != "scoped_body_sqli_error"
                or verifier.get("run_id") != run.id):
            failure = "Fresh POST SQL error controls did not confirm injection"
        else:
            for hunter_id in hunter_ids:
                proof = {"kind": "post_error_sqli", "hunter_artifact_id": hunter_id,
                         "artifact_id": artifact_id}
                valid, why = validate_proof(store, cand, proof, [artifact_id])
                fresh, fresh_why = store.validate(
                    [artifact_id], candidate_id=cand.id, revision=cand.revision,
                    run_id=run.id, target=cand.target,
                )
                if valid and fresh:
                    verified = apply_verdict(
                        tools_manager, candidate_id=cand.id, verdict="confirmed",
                        evidence="Fresh scoped POST SQL error controls reproduced the candidate on the exact captured form input.",
                        evidence_ids=[artifact_id], proof=proof,
                    )
                    if verified and verified.status == "confirmed":
                        return {"candidate_id": cand.id, "title": cand.title,
                                "status": "confirmed", "verifier_summary": "Fresh POST SQL error proof matched the hunter receipt",
                                "key_findings": [], "tool_calls": 1, "error": None}
                failure = why or fresh_why or "POST SQL error proof policy rejected the replay"
    except Exception:
        logging.getLogger(__name__).exception(
            "Deterministic POST SQLi verifier could not replay candidate %s", cand.id,
        )
        failure = "Scoped POST SQLi replay failed before verification completed"
    apply_verdict(tools_manager, candidate_id=cand.id, verdict="inconclusive",
                  evidence=failure, summary=failure)
    return {"candidate_id": cand.id, "title": cand.title, "status": "inconclusive",
            "verifier_summary": failure, "key_findings": [], "tool_calls": 1, "error": None}


async def _verify_scoped_browser_xss_candidate(
    tools_manager: Any, cand: FindingCandidate, run: Any,
) -> Optional[Dict[str, Any]]:
    """Replay a browser-executed XSS receipt against its exact observed input."""
    import logging
    from urllib.parse import parse_qs, urlsplit
    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.proof_policy import inferred_vulnerability_class, validate_proof
    from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

    if (cand.vulnerability_class or inferred_vulnerability_class(cand)) != "xss":
        return None
    brain = _brain(tools_manager)
    cell = next((row for row in brain.coverage_cells
                 if row.get("id") == cand.coverage_cell_id), None)
    if not cell:
        cell = observed_xss_cell_for_proof(
            brain, evidence_store(tools_manager), target=cand.target,
            evidence_ids=cand.evidence_ids,
        )
        if cell:
            cand.coverage_cell_id = str(cell["id"])
            for raw in brain.candidates:
                if isinstance(raw, dict) and raw.get("id") == cand.id:
                    raw["coverage_cell_id"] = cand.coverage_cell_id
            cell["candidate_id"] = cand.id
            tools_manager._engagement_brain = brain.to_dict()
    dom_xss = bool(cell and cell.get("source") == "js_inventory"
                   and cell.get("test_type") == "dom_xss"
                   and cell.get("method") == "GET"
                   and any(isinstance(lead, dict) and lead.get("kind") in {"fragment", "query"}
                           for lead in cell.get("source_leads") or []))
    stored_xss = bool(cell and cell.get("source") == "parameter_inventory"
                      and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
                      and cell.get("test_type") == "stored_xss"
                      and cell.get("method") == "POST")
    if not cell or not (dom_xss or stored_xss or (cell.get("source") == "parameter_inventory"
                    and cell.get("observation_source") in OBSERVED_INPUT_SOURCES
                    and cell.get("test_type") == "xss" and cell.get("method") in {"GET", "POST"})):
        return None
    location, separator, parameter = str(cell.get("parameter") or "").partition(":")
    dom_query = dom_xss and location == "query" and bool(separator and parameter)
    form_xss = cell.get("method") == "POST" and location == "body_form"
    target = urlsplit(cand.target)
    identity = str(cell.get("identity") or "anonymous")
    if (not (dom_xss or (location == "query" and not form_xss) or form_xss)
            or (not dom_xss and (not separator or not parameter))
            or target.scheme not in {"http", "https"}
            or not _same_observed_origin(target.scheme, str(cell.get("host") or ""), cand.target)
            or (target.path or "/") != (cell.get("page_path") if dom_xss else cell.get("path"))
            or target.query or target.fragment
            or (cand.identity and cand.identity != identity)
            or (cand.parameter and cand.parameter != cell.get("parameter"))):
        return None
    store = evidence_store(tools_manager)
    hunter = []
    for evidence_id in cand.evidence_ids:
        receipt = store.records.get(evidence_id)
        expected_receipts = ({"scoped_browser_check_stored_xss"} if stored_xss else
                             {"scoped_browser_check_form_xss"} if form_xss else
                             {"scoped_browser_check_xss", "scoped_browser_check_xhr_xss"})
        if (not receipt or receipt.get("kind") not in expected_receipts
                or receipt.get("target") != cand.target
                or receipt.get("identity") != identity):
            continue
        proof = receipt.get("payload")
        if not isinstance(proof, dict) or proof.get("executed") is not True:
            continue
        template = str(proof.get("target_template") or "")
        parsed = urlsplit(template)
        xhr_xss = receipt.get("kind") == "scoped_browser_check_xhr_xss"
        if stored_xss:
            if (proof.get("operation") != "check_stored_xss"
                    or proof.get("form_action") != cand.target
                    or proof.get("form_field") != parameter
                    or proof.get("post_submitted") is not True
                    or proof.get("post_response_seen") is not True
                    or proof.get("readback_response_seen") is not True
                    or proof.get("readback_final_exact") is not True
                    or not isinstance(proof.get("readback_status"), int)
                    or not 200 <= proof["readback_status"] < 300
                    or proof.get("readback_executed") is not True
                    or proof.get("cleanup_success") is not True
                    or "__PROWL_NONCE__" not in str(proof.get("form_payload_template") or "")
                    or not _same_observed_origin(parsed.scheme, parsed.netloc, cand.target)
                    or parsed.query or parsed.fragment
                    or not _same_observed_origin(
                        urlsplit(str(proof.get("readback_url") or "")).scheme,
                        urlsplit(str(proof.get("readback_url") or "")).netloc, cand.target)
                    or not _same_observed_origin(
                        urlsplit(str(proof.get("cleanup_url_template") or "")).scheme,
                        urlsplit(str(proof.get("cleanup_url_template") or "")).netloc, cand.target)):
                continue
        elif form_xss:
            if (proof.get("operation") != "check_form_xss"
                    or proof.get("form_action") != cand.target
                    or proof.get("form_field") != parameter
                    or proof.get("post_submitted") is not True
                    or proof.get("post_response_seen") is not True
                    or "__PROWL_NONCE__" not in str(proof.get("form_payload_template") or "")
                    or parsed.query or parsed.fragment
                    or not _same_observed_origin(parsed.scheme, parsed.netloc, cand.target)):
                continue
        elif dom_xss:
            if (proof.get("operation") != "check_xss" or xhr_xss
                    or not _same_observed_origin(parsed.scheme, parsed.netloc, cand.target)
                    or (parsed.path or "/") != (target.path or "/")):
                continue
            if dom_query:
                try:
                    fields = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=40)
                except ValueError:
                    continue
                if (parsed.fragment or len([value for name, value in fields
                                             if name == parameter]) != 1
                        or not any("__PROWL_NONCE__" in value
                                   for name, value in fields if name == parameter)):
                    continue
            elif parsed.query or "__PROWL_NONCE__" not in parsed.fragment:
                continue
        elif xhr_xss:
            if (proof.get("operation") != "check_xhr_xss"
                    or not _same_observed_origin(parsed.scheme, parsed.netloc, cand.target)
                    or parsed.fragment or proof.get("xhr_path") != (target.path or "/")
                    or proof.get("xhr_parameter") != parameter
                    or not isinstance(proof.get("xhr_query_keys"), list)
                    or parameter not in proof["xhr_query_keys"]
                    or "__PROWL_NONCE__" not in str(proof.get("xhr_payload_template") or "")
                    or proof.get("xhr_mutated") is not True
                    or proof.get("xhr_response_seen") is not True):
                continue
        elif (not _same_observed_origin(parsed.scheme, parsed.netloc, cand.target)
              or (parsed.path or "/") != (target.path or "/")
              or parsed.fragment or "__PROWL_NONCE__" not in template
              or not any("__PROWL_NONCE__" in value
                         for value in parse_qs(parsed.query).get(parameter, []))):
            continue
        hunter.append((evidence_id, template))
    if not hunter:
        return None
    failure = "Fresh browser replay did not execute the XSS canary"
    try:
        for hunter_id, template in hunter[:3]:
            replay_args = {"operation": "check_xss", "url": template, "identity": identity}
            hunter_proof = store.records[hunter_id]["payload"]
            if stored_xss:
                replay_args.update({"operation": "check_stored_xss", "form_action": cand.target,
                                    "form_field": parameter,
                                    "form_payload_template": hunter_proof["form_payload_template"],
                                    "readback_url": hunter_proof["readback_url"],
                                    "cleanup_url_template": hunter_proof["cleanup_url_template"]})
            elif form_xss:
                replay_args.update({"operation": "check_form_xss", "form_action": cand.target,
                                    "form_field": parameter,
                                    "form_payload_template": hunter_proof["form_payload_template"]})
            elif hunter_proof.get("operation") == "check_xhr_xss":
                replay_args.update({"operation": "check_xhr_xss", "xhr_path": target.path or "/",
                                    "xhr_parameter": parameter,
                                    "xhr_query_keys": hunter_proof["xhr_query_keys"],
                                    "xhr_payload_template": hunter_proof["xhr_payload_template"]})
                if hunter_proof.get("xhr_actions"):
                    replay_args["xhr_actions"] = hunter_proof["xhr_actions"]
            wrapped = await tools_manager.execute("scoped_browser_assessment", replay_args)
            output = wrapped.get("output") if isinstance(wrapped, dict) else None
            result = json.loads(output) if isinstance(output, str) else output
            if not isinstance(result, dict):
                failure = "XSS replay returned no structured result"
                continue
            if result.get("executed") is not True:
                failure = str(result.get("error") or "Fresh browser canary did not execute")[:300]
                continue
            artifact_id = str(result.get("evidence_id") or "")
            verifier = store.records.get(artifact_id)
            if (not verifier or verifier.get("run_id") != run.id
                    or verifier.get("identity") != identity):
                failure = "XSS replay had no fresh verifier evidence"
                continue
            proof = {"kind": ("scoped_browser_stored_xss" if stored_xss else
                              "scoped_browser_form_xss" if form_xss else
                              "scoped_browser_xhr_xss" if hunter_proof.get("operation") == "check_xhr_xss"
                              else "scoped_browser_xss"),
                     "hunter_artifact_id": hunter_id,
                     "artifact_id": artifact_id}
            valid, why = validate_proof(store, cand, proof, [artifact_id])
            fresh, fresh_why = store.validate(
                [artifact_id], candidate_id=cand.id, revision=cand.revision,
                run_id=run.id, target=cand.target,
            )
            if valid and fresh:
                verified = apply_verdict(
                    tools_manager, candidate_id=cand.id, verdict="confirmed",
                    evidence="Fresh browser execution reproduced the XSS candidate on the observed input.",
                    evidence_ids=[artifact_id], proof=proof,
                )
                if verified and verified.status == "confirmed":
                    return {"candidate_id": cand.id, "title": cand.title,
                            "status": "confirmed", "verifier_summary": "Fresh browser XSS proof matched the hunter receipt",
                            "key_findings": [], "tool_calls": 1, "error": None}
            failure = why or fresh_why or "XSS proof policy rejected the replay"
    except Exception:
        logging.getLogger(__name__).exception("Deterministic XSS verifier could not replay candidate %s", cand.id)
        failure = "Scoped XSS replay failed before verification completed"
    apply_verdict(tools_manager, candidate_id=cand.id, verdict="inconclusive",
                  evidence=failure, summary=failure)
    return {"candidate_id": cand.id, "title": cand.title, "status": "inconclusive",
            "verifier_summary": failure, "key_findings": [], "tool_calls": 1, "error": None}


def _brain(tools_manager: Any):
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    return engagement_brain_from_dict(getattr(tools_manager, "_engagement_brain", None))


def _candidate(brain: Any, cid: str) -> Optional[FindingCandidate]:
    for raw in getattr(brain, "candidates", None) or []:
        c = raw if isinstance(raw, FindingCandidate) else candidate_from_dict(raw)
        if c and c.id == cid:
            return c
    return None


def _validate_counterevidence(
    tools_manager: Any,
    candidate: FindingCandidate,
    run: Any,
    proof: Dict[str, Any],
    evidence_ids: List[str],
) -> tuple[Dict[str, str], str]:
    """A clean verdict needs an execution-owned check of the claimed path."""
    from app.services.agent.evidence_store import evidence_store, origin

    if proof.get("kind") == "workflow":
        run_id = proof.get("run_id")
        if not isinstance(run_id, str):
            return {}, "A fresh refuted workflow receipt for this candidate is required"
        receipt = (getattr(getattr(tools_manager, "_proof_engine", None), "receipts", {})
                   or {}).get(run_id)
        if (receipt and receipt.verdict == "refuted"
                and receipt.candidate_id == candidate.id
                and receipt.candidate_revision == candidate.revision
                and receipt.verifier_run_id == run.id
                and receipt.target == candidate.target
                and receipt.hypothesis_id == candidate.hypothesis_id
                and tuple(evidence_ids) == receipt.evidence_ids):
            return {
                "kind": "workflow",
                "control": receipt.strategy,
                "attacker_path": receipt.attack_url,
                "observation": receipt.reason,
                "artifact_id": receipt.run_id,
            }, ""
        return {}, "A fresh refuted workflow receipt for this candidate is required"

    if proof.get("kind") != "counterevidence":
        return {}, "Refutation requires structured counterevidence on the claimed attacker path"
    details = {
        key: str(proof.get(key) or "").strip()
        for key in ("control", "attacker_path", "observation", "artifact_id")
    }
    if not all(details.values()):
        return {}, "Refutation must name the control, attacker path, observation, and artifact ID"
    artifact_id = details["artifact_id"]
    if artifact_id not in evidence_ids:
        return {}, "Counterevidence artifact must be cited in evidence_ids"
    store = evidence_store(tools_manager)
    if artifact_id in store._historical_ids:
        return {}, "Counterevidence must come from this fresh verifier run"
    row = store.records.get(artifact_id)
    if (not row or row.get("kind") != "http_exchange"
            or row.get("candidate_id") != candidate.id
            or row.get("revision") != candidate.revision
            or row.get("run_id") != run.id
            or row.get("truncated")
            or time.time() - row.get("created_at", 0) > 3600):
        return {}, "Refutation requires a fresh, complete HTTP exchange from this verifier"
    for cited_id in evidence_ids:
        cited = store.records.get(cited_id)
        if (cited_id in store._historical_ids or not cited
                or cited.get("candidate_id") != candidate.id
                or cited.get("revision") != candidate.revision
                or cited.get("run_id") != run.id
                or cited.get("truncated")):
            return {}, "All counterevidence IDs must come from this fresh verifier run"
    payload = row.get("payload") or {}
    response = payload.get("response") if isinstance(payload, dict) else None
    response = response if isinstance(response, dict) else {}
    request = payload.get("request") if isinstance(payload, dict) else None
    request = request if isinstance(request, dict) else {}
    if not isinstance(response.get("status"), int):
        return {}, "Counterevidence HTTP exchange has no recorded response status"
    if proof.get("response_status") != response["status"]:
        return {}, "Counterevidence must state the recorded HTTP response status"
    try:
        claimed = urlsplit(candidate.target)
        checked = urlsplit(row["target"])
        described = urlsplit(details["attacker_path"])
        if (origin(row["target"]) != origin(candidate.target)
                or origin(details["attacker_path"]) != origin(candidate.target)
                or details["attacker_path"] != row["target"]
                or request.get("url") != row["target"]
                or origin(response.get("url") or "") != origin(candidate.target)
                or urlsplit(response.get("url") or "").path != claimed.path
                or checked.path != claimed.path
                or described.path != checked.path):
            return {}, "Counterevidence did not check the candidate endpoint"
    except (TypeError, ValueError):
        return {}, "Counterevidence needs an absolute in-scope attacker path"
    return {"kind": "counterevidence", **details,
            "response_status": str(response["status"])}, ""


def apply_verdict(
    tools_manager: Any,
    *,
    candidate_id: str,
    verdict: str,
    evidence: str = "",
    summary: str = "",
    nonce_observed: bool = False,
    evidence_ids: Optional[List[str]] = None,
    proof: Optional[Dict[str, Any]] = None,
) -> Optional[FindingCandidate]:
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    # Some verifier models serialize the proof object as a JSON string. Accept
    # that shape, but never let malformed output crash the whole assessment or
    # become a confirmed receipt.
    if isinstance(proof, str):
        try:
            proof = json.loads(proof)
        except ValueError:
            proof = None
    if not isinstance(proof, dict):
        proof = {}

    verdict = (verdict or "").strip().lower()
    if verdict not in ("confirmed", "refuted", "inconclusive"):
        return None
    brain = engagement_brain_from_dict(getattr(tools_manager, "_engagement_brain", None))
    from app.services.agent.evidence_store import evidence_store, verification_run
    run = verification_run.get()
    if run is None or run.candidate_id != candidate_id:
        return None
    cand = None
    updated: List[Dict[str, Any]] = []
    for raw in brain.candidates or []:
        c = raw if isinstance(raw, FindingCandidate) else candidate_from_dict(raw)
        if not c:
            continue
        if c.id == candidate_id:
            if c.revision != run.revision:
                return None
            if verdict == "confirmed":
                from app.services.agent.proof_policy import proof_kind_allowed
                ok, why = proof_kind_allowed(c, proof.get("kind"))
                matrix_candidate = any(row.get('hypothesis_id') == c.hypothesis_id for row in brain.authorization_matrix)
                is_workflow = matrix_candidate or (proof or {}).get('kind') == 'workflow'
                evidence_target = c.target
                if ok and is_workflow:
                    engine = getattr(tools_manager, '_proof_engine', None)
                    if engine and (proof or {}).get('kind') == 'workflow':
                        ok, why = engine.validate_receipt(proof.get('run_id'), c, evidence_ids or [])
                        if ok:
                            evidence_target = engine.receipts[proof['run_id']].attack_url
                    else:
                        ok, why = False, 'Authorization matrix candidates require a fresh workflow receipt'
                if ok:
                    ok, why = evidence_store(tools_manager).validate(
                        evidence_ids or [], candidate_id=c.id, revision=c.revision,
                        run_id=run.id, target=evidence_target,
                    )
                if ok and not is_workflow:
                    from app.services.agent.proof_policy import validate_proof
                    ok, why = validate_proof(evidence_store(tools_manager), c, proof or {}, evidence_ids or [])
                if not ok or not evidence.strip():
                    verdict = "inconclusive"
                    summary = why or "A supported impact explanation is required"
            elif verdict == "refuted":
                counterevidence, why = _validate_counterevidence(
                    tools_manager, c, run, proof, evidence_ids or [],
                )
                if why:
                    verdict = "inconclusive"
                    summary = why + (f"; verifier note: {summary}" if summary else "")
                else:
                    c.counterevidence = counterevidence
            c.status = verdict
            if verdict != "refuted":
                c.counterevidence = {}
            c.proof_gap = (
                {
                    "reason": (summary or evidence or "Verifier did not establish impact")[:2000],
                    "next_step": str(proof.get("next_step") or
                                     "Run a fresh, targeted impact or control check on the claimed path")[:500],
                }
                if verdict == "inconclusive" else {}
            )
            c.verifier_run_id = run.id
            c.evidence_ids = list(dict.fromkeys([*c.evidence_ids, *(evidence_ids or [])]))
            if (proof or {}).get("kind") == "workflow":
                c.proof_run_id = str((proof or {}).get("run_id") or "")
            c.verifier_evidence = (evidence or "")[:2000]
            c.verifier_summary = (summary or evidence or
                                  c.counterevidence.get("observation", ""))[:2000]
            c.verified_at = datetime.now(timezone.utc).isoformat()
            cand = c
        updated.append(c.to_dict())
    if not cand:
        return None
    brain.candidates = updated
    if cand.hypothesis_id and verdict == "confirmed":
        from app.services.agent.engagement_brain import update_hypothesis
        update_hypothesis(brain, cand.hypothesis_id, status="proven", evidence=evidence)
    for cell in brain.authorization_matrix:
        if cell.get('hypothesis_id') != cand.hypothesis_id:
            continue
        cell['verifier_verdict'] = verdict
        if verdict != 'confirmed':
            cell.update(status='inconclusive', reason='Independent verification: ' + verdict)
            for hyp in brain.hypotheses:
                if hyp.id == cand.hypothesis_id:
                    hyp.status = 'open'
            node = brain.task_graph.get('nodes', {}).get(cand.hypothesis_id)
            if node:
                node['status'] = 'retry'
    if cand.coverage_cell_id:
        for cell in brain.coverage_cells:
            if cell.get("id") != cand.coverage_cell_id:
                continue
            cell["candidate_id"] = cand.id
            cell["verifier_run_id"] = run.id
            cell["evidence_ids"] = list(
                dict.fromkeys([*(cell.get("evidence_ids") or []), *(evidence_ids or [])])
            )
            if cand.proof_run_id:
                cell["proof_run_id"] = cand.proof_run_id
            if verdict == "refuted":
                cell.update(status="tested_clean", reason=cand.verifier_summary or
                            cand.counterevidence.get("observation", "Independent control held"))
            elif verdict == "confirmed":
                cell.update(status="in_focus", reason="Confirmed candidate awaits publication")
            else:
                cell.update(status="inconclusive", reason=cand.proof_gap.get("reason") or
                            "Independent verification was inconclusive")
    if cand.proof_escalation_id:
        from app.services.agent.signal_escalation import apply_verifier_result

        apply_verifier_result(
            brain,
            cand.proof_escalation_id,
            verdict=verdict,
            verifier_run_id=run.id,
        )
    if not hasattr(tools_manager, "_verify_receipts") or tools_manager._verify_receipts is None:
        tools_manager._verify_receipts = {}
    receipt_key = verify_receipt_key(cand.title, cand.target)
    tools_manager._verify_receipts.pop(receipt_key, None)
    brain.verification_receipts.pop(receipt_key, None)
    if verdict == "confirmed":
        record_verify_receipt(
            tools_manager._verify_receipts,
            title=cand.title,
            target=cand.target,
            verdict="confirmed",
            candidate_id=cand.id,
            evidence=evidence,
            nonce=cand.nonce,
            nonce_observed=True,
            evidence_ids=evidence_ids,
            run_id=run.id,
            revision=cand.revision,
        )
        if (proof or {}).get("kind") == "workflow":
            tools_manager._verify_receipts[receipt_key]["workflow_run_id"] = proof["run_id"]
        brain.verification_receipts[receipt_key] = dict(
            tools_manager._verify_receipts[receipt_key]
        )
    tools_manager._engagement_brain = brain.to_dict()
    observer = getattr(tools_manager, "_early_verdict_observer", None)
    if callable(observer):
        try:
            observer(brain, cand)
        except Exception:
            import logging

            logging.getLogger(__name__).exception("Early verdict snapshot failed")
    return cand


def submit_candidate(
    brain: Any,
    *,
    title: str,
    description: str = "",
    severity: str = "medium",
    target: str = "",
    evidence: str = "",
    hypothesis_id: str = "",
    threat_id: str = "",
    claimed_request: str = "",
    specialist: str = "",
    operation_id: str = "",
    identity: str = "",
    tenant: str = "",
    parameter: str = "",
    test_type: str = "",
    coverage_cell_id: str = "",
    capture_id: str = "",
    evidence_ids: Optional[List[str]] = None,
    proof_run_id: str = "",
    proof_escalation_id: str = "",
    vulnerability_class: str = "",
) -> FindingCandidate:
    vulnerability_class = str(vulnerability_class or "").strip().lower()
    if coverage_cell_id and not proof_escalation_id:
        proof_escalation_id = next(
            (
                str(cell.get("proof_escalation_id") or "")
                for cell in (getattr(brain, "coverage_cells", None) or [])
                if cell.get("id") == coverage_cell_id
            ),
            "",
        )
    cid = candidate_id(title, target, coverage_cell_id)
    existing = []
    for raw in getattr(brain, "candidates", None) or []:
        c = raw if isinstance(raw, FindingCandidate) else candidate_from_dict(raw)
        if c:
            existing.append(c)
            if c.id == cid:
                new_evidence = set(evidence_ids or []) - set(c.evidence_ids)
                claim_changed = any(value and value != getattr(c, name) for name, value in (
                    ("evidence", evidence), ("description", description), ("severity", severity),
                    ("claimed_request", claimed_request),
                    ("vulnerability_class", vulnerability_class),
                ))
                class_changed = bool(vulnerability_class and vulnerability_class != c.vulnerability_class)
                changed = bool(new_evidence or class_changed) if c.status in ("inconclusive", "refuted") else claim_changed
                if changed:
                    c.evidence = evidence[:4000] if evidence else c.evidence
                    c.description = description or c.description
                    c.severity = severity or c.severity
                    c.claimed_request = claimed_request[:2000] or c.claimed_request
                    c.vulnerability_class = vulnerability_class or c.vulnerability_class
                    c.revision += 1
                    c.status = "pending"
                    c.nonce = new_nonce()
                    c.verifier_evidence = c.verifier_summary = c.verified_at = ""
                    c.counterevidence = c.proof_gap = {}
                    c.verifier_run_id = ""
                    brain.verification_receipts.pop(
                        verify_receipt_key(c.title, c.target), None
                    )
                for name, value in (
                    ("hypothesis_id", hypothesis_id), ("threat_id", threat_id),
                    ("specialist", specialist), ("operation_id", operation_id),
                    ("identity", identity), ("tenant", tenant), ("parameter", parameter),
                    ("test_type", test_type), ("coverage_cell_id", coverage_cell_id),
                    ("capture_id", capture_id), ("proof_run_id", proof_run_id),
                    ("proof_escalation_id", proof_escalation_id),
                ):
                    if value:
                        setattr(c, name, value)
                c.evidence_ids = list(
                    dict.fromkeys([*c.evidence_ids, *(evidence_ids or [])])
                )
                if c.coverage_cell_id:
                    for cell in getattr(brain, "coverage_cells", None) or []:
                        if cell.get("id") == c.coverage_cell_id:
                            cell["candidate_id"] = c.id
                if c.proof_escalation_id:
                    from app.services.agent.signal_escalation import bind_candidate

                    bind_candidate(
                        brain,
                        c.proof_escalation_id,
                        candidate_id=c.id,
                        proof_run_id=c.proof_run_id,
                    )
                brain.candidates = [c.to_dict() if (r.get("id") if isinstance(r, dict) else r.id) == cid
                                    else (r if isinstance(r, dict) else r.to_dict()) for r in brain.candidates]
                return c
    cand = FindingCandidate(
        id=cid,
        title=title,
        description=description,
        severity=(severity or "medium").lower(),
        target=target,
        evidence=evidence[:4000],
        hypothesis_id=hypothesis_id,
        threat_id=threat_id,
        claimed_request=claimed_request[:2000],
        specialist=specialist,
        operation_id=operation_id,
        identity=identity,
        tenant=tenant,
        parameter=parameter,
        test_type=test_type,
        vulnerability_class=vulnerability_class,
        coverage_cell_id=coverage_cell_id,
        capture_id=capture_id,
        evidence_ids=list(dict.fromkeys(evidence_ids or [])),
        proof_run_id=proof_run_id,
        proof_escalation_id=proof_escalation_id,
        nonce=new_nonce(),
        status="pending",
    )
    existing.append(cand)
    brain.candidates = [c.to_dict() for c in existing]
    if cand.coverage_cell_id:
        for cell in getattr(brain, "coverage_cells", None) or []:
            if cell.get("id") == cand.coverage_cell_id:
                cell["candidate_id"] = cand.id
    if cand.proof_escalation_id:
        from app.services.agent.signal_escalation import bind_candidate

        bind_candidate(
            brain,
            cand.proof_escalation_id,
            candidate_id=cand.id,
            proof_run_id=cand.proof_run_id,
        )
    return cand


def ingest_report_findings(
    brain: Any,
    reports: Iterable[Any],
) -> List[FindingCandidate]:
    """If hunters forgot submit_finding_candidate, lift key_findings into the queue."""
    created: List[FindingCandidate] = []
    known = {c.get("id") if isinstance(c, dict) else getattr(c, "id", "") for c in (brain.candidates or [])}
    for report in reports or []:
        specialist = getattr(report, "specialist", "") or ""
        if specialist in ("independent_verifier", "finding_judge"):
            continue
        findings = list(getattr(report, "key_findings", None) or [])
        target = ""
        mission = getattr(report, "mission", "") or ""
        m = re.search(r"https?://[^\s]+", mission)
        if m:
            target = m.group(0).rstrip(".,;")
        for kf in findings[:6]:
            title = str(kf).strip()[:200]
            if not title or len(title) < 8:
                continue
            # Specialist diagnostics are not vulnerability claims. In
            # particular, a failed lease/probe must never become a candidate.
            if ("invalid_coverage_lease" in title.lower()
                    or re.search(r"\b(?:returned|result:)\s+success\s*=\s*false\b", title, re.I)
                    or re.search(r"\b(?:tool|probe)\s+(?:failed|error|denied)\b", title, re.I)):
                continue
            cand = submit_candidate(
                brain,
                title=title,
                description=getattr(report, "summary", "") or "",
                severity="high",
                target=target,
                evidence=title,
                specialist=specialist,
                hypothesis_id=(
                    (getattr(report, "hypothesis_ids", None) or [""])[0]
                ),
                coverage_cell_id=getattr(report, "coverage_cell_id", "") or "",
                evidence_ids=[
                    evidence_id
                    for invocation in (getattr(report, "tool_calls", None) or [])
                    for evidence_id in (getattr(invocation, "evidence_ids", None) or [])
                ],
            )
            if cand.id not in known:
                created.append(cand)
                known.add(cand.id)
    return created
