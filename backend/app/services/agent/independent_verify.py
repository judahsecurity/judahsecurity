"""
Independent verification — finders propose; a fresh agent refutes or confirms.

Discovery and verification want opposite things. Hunters submit candidates.
A verifier with a new conversation (no hunter transcript) re-derives the proof
and issues a receipt. create_finding for medium+ consumes that receipt, not the
finder's own validate_finding score.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional


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
    nonce: str = ""
    revision: int = 1
    status: str = "pending"  # pending | confirmed | refuted | inconclusive
    verifier_evidence: str = ""
    verifier_summary: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verified_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def candidate_from_dict(raw: Optional[Dict[str, Any]]) -> Optional[FindingCandidate]:
    if not isinstance(raw, dict) or not raw.get("id"):
        return None
    allowed = {f.name for f in fields(FindingCandidate)}
    return FindingCandidate(**{k: v for k, v in raw.items() if k in allowed})


def candidate_id(title: str, target: str = "") -> str:
    blob = f"{(title or '').strip().lower()}|{(target or '').strip()}"
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


def check_verify_receipt(
    store: Optional[Dict[str, Dict[str, Any]]],
    *,
    title: str,
    target: str,
    tools_manager: Any = None,
) -> tuple[bool, str]:
    store = store or {}
    key = verify_receipt_key(title, target)
    receipt = store.get(key)
    if not receipt:
        return False, (
            "INDEPENDENT VERIFY GATE: medium+ findings require independent_verify → "
            f"confirmed for this title/target first (key={key}). "
            "Hunters must submit_finding_candidate; Joshua (or fireteam second wave) "
            "runs independent_verify; then create_finding."
        )
    if receipt.get("verdict") != "confirmed":
        return False, (
            f"INDEPENDENT VERIFY GATE: candidate verdict={receipt.get('verdict')} "
            "(need confirmed). Do not create_finding."
        )
    if tools_manager is None:
        return False, "Execution evidence store required"
    candidate = _candidate(_brain(tools_manager), receipt.get("candidate_id", ""))
    if not candidate or candidate.status != "confirmed" or candidate.revision != receipt.get("revision"):
        return False, "Candidate changed or was refuted; reverify before publication"
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

    return (
        "You are an ADVERSARIAL verifier in a FRESH session. You did not see the "
        "finder's transcript. Actively look for reasons this claim is WRONG.\n"
        "Re-derive the proof yourself (compare_requests or execute_curl). "
        "Do not trust the finder's markers, filenames, or 'log lines'.\n"
        f"Include request header X-Aegis-Verify: {candidate.nonce} on live probes "
        "so your evidence is distinguishable from the finder's.\n\n"
        f"CANDIDATE id={candidate.id}\n"
        f"Title: {candidate.title}\n"
        f"Severity: {candidate.severity}\n"
        f"Target: {candidate.target}\n"
        f"Hypothesis: {candidate.hypothesis_id or '—'}  threat={candidate.threat_id or '—'}\n"
        f"Claimed request: {candidate.claimed_request or '—'}\n"
        f"Finder evidence (untrusted):\n{(candidate.evidence or '')[:2500]}\n"
        f"Description (untrusted):\n{(candidate.description or '')[:1500]}\n\n"
        f"{threat_slice}\n"
        f"{class_addendum}\n"
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
        "state_change {kind, write_id, read_id, cleanup_id, field, value, owner_identity?} "
        "for persisted canary changes. Use the exact value aegis-verify-<candidate nonce>. "
        "Anonymous writes must be explicitly claimed as unauthenticated; named actors require "
        "a distinct verified owner readback. Cleanup is mandatory. "
        "field is a top-level JSON field. No body/schema/version alone proves authorization or mass assignment. "
        "with verdict confirmed|refuted|inconclusive, then done=true. "
        "confirmed = you reproduced impact with your own request/response. "
        "Version-in-range CVE applicability: confirmed if your GET still shows the "
        "claimed product+version inside the published range — do not exploit it. "
        "refuted = control holds or the finder hallucinated. "
        "inconclusive = you could not re-derive and must not rubber-stamp."
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
                            "in record_verify_verdict. A prior hunter receipt is not valid in this verifier run.")
            from app.services.agent.evidence_store import VerificationRun, verification_run
            run = VerificationRun(uuid.uuid4().hex, cand.id, cand.revision, cand.nonce)
            token = verification_run.set(run)
            try:
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


def _brain(tools_manager: Any):
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    return engagement_brain_from_dict(getattr(tools_manager, "_engagement_brain", None))


def _candidate(brain: Any, cid: str) -> Optional[FindingCandidate]:
    for raw in getattr(brain, "candidates", None) or []:
        c = raw if isinstance(raw, FindingCandidate) else candidate_from_dict(raw)
        if c and c.id == cid:
            return c
    return None


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
                matrix_candidate = any(row.get('hypothesis_id') == c.hypothesis_id for row in brain.authorization_matrix)
                is_workflow = matrix_candidate or (proof or {}).get('kind') == 'workflow'
                evidence_target = c.target
                if is_workflow:
                    engine = getattr(tools_manager, '_proof_engine', None)
                    if engine and (proof or {}).get('kind') == 'workflow':
                        ok, why = engine.validate_receipt(proof.get('run_id'), c, evidence_ids or [])
                        if ok:
                            evidence_target = engine.receipts[proof['run_id']].attack_url
                    else:
                        ok, why = False, 'Authorization matrix candidates require a fresh workflow receipt'
                else:
                    ok, why = True, ''
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
            c.status = verdict
            c.verifier_evidence = (evidence or "")[:2000]
            c.verifier_summary = (summary or evidence or "")[:2000]
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
    tools_manager._engagement_brain = brain.to_dict()

    if not hasattr(tools_manager, "_verify_receipts") or tools_manager._verify_receipts is None:
        tools_manager._verify_receipts = {}
    tools_manager._verify_receipts.pop(verify_receipt_key(cand.title, cand.target), None)
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
            tools_manager._verify_receipts[verify_receipt_key(cand.title, cand.target)]["workflow_run_id"] = proof["run_id"]
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
) -> FindingCandidate:
    cid = candidate_id(title, target)
    existing = []
    for raw in getattr(brain, "candidates", None) or []:
        c = raw if isinstance(raw, FindingCandidate) else candidate_from_dict(raw)
        if c:
            existing.append(c)
            if c.id == cid:
                changed = any(value and value != getattr(c, name) for name, value in (
                    ("evidence", evidence), ("description", description), ("severity", severity),
                    ("claimed_request", claimed_request),
                ))
                if changed:
                    c.evidence = evidence[:4000] if evidence else c.evidence
                    c.description = description or c.description
                    c.severity = severity or c.severity
                    c.claimed_request = claimed_request[:2000] or c.claimed_request
                    c.revision += 1
                    c.status = "pending"
                    c.nonce = new_nonce()
                    c.verifier_evidence = c.verifier_summary = c.verified_at = ""
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
        nonce=new_nonce(),
        status="pending",
    )
    existing.append(cand)
    brain.candidates = [c.to_dict() for c in existing]
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
            cand = submit_candidate(
                brain,
                title=title,
                description=getattr(report, "summary", "") or "",
                severity="high",
                target=target,
                evidence=title,
                specialist=specialist,
            )
            if cand.id not in known:
                created.append(cand)
                known.add(cand.id)
    return created
