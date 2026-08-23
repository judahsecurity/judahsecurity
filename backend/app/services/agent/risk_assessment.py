"""Marcus risk assessment — demonstrated-only RA on published findings.

Solomon (validate_finding) decides whether a card is a finding.
Deborah (independent_verify) re-derives the proof.
Marcus (assess_finding_risk) scores the *published* packet: confirm vs
inflate vs downgrade, CVSS on demonstrated evidence, control failures,
ordered remediation with close criteria. No live retest.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.orm.attributes import flag_modified

VERDICTS = frozenset({"confirm", "downgrade", "upgrade", "keep_open"})
SEVERITIES = ("critical", "high", "medium", "low", "info")
SLAS = frozenset({"now", "this_week", "follow_up"})
RA_STATUSES = frozenset({"pending", "queued", "in_progress", "complete", "failed"})

# Critical is reserved for demonstrated write / RCE / cloud credential theft,
# plus unauth OpenAPI account lookup (schema security: {} + is_staff/role, or
# sibling 401 vs lookup 200/404/500). Privilege enum on an ICS login oracle is
# the Judah Critical bar for that class — not Open High.
_CRITICAL_PROOF = re.compile(
    r"\b(rce|remote code|cloud.?token|imds|managed.?identity|access.?key|"
    r"secret.?dump|credential.?theft|wrote|write.?access|put\s+/|post\s+/.+201|"
    r"cluster.?admin|privilege.?escalat)\b",
    re.I,
)

RA_WRITEUP_GUIDANCE = """Risk assessment (Marcus) is required for every medium+ finding.
Score the *demonstrated packet only*. Do not live-retest. Do not invent writes, IMDS, or RCE.
Call assess_finding_risk after create_finding (or pass risk_assessment JSON into create_finding).
Required RA fields:
- verdict: confirm | downgrade | upgrade | keep_open
- confirmed_severity + why_this_severity AND why_not_higher AND why_not_lower
- cvss_score + cvss_vector scored on demonstrated evidence (cvss_basis=demonstrated)
- demonstrated[] and not_demonstrated[] (concrete assets/results — not 'impact is high')
- control_failures[] (identity / filter / network / authz — what actually broke)
- business_risk (customer/workload context, not CVSS restated)
- remediation_sequence[] with when + action + done_when close criteria
- retest_criteria[] (ticket closes only if all pass)
- ticket_title + ra_note (pasteable)
Critical requires demonstrated write, RCE, or cloud credential theft — except unauth
OpenAPI account lookup: schema security: {} + is_staff/role, or sibling 401 vs lookup
200/404/500, is Critical. Do not invent a 200 UserAccount body. 404 'User does not
exist!' is the existence oracle, not a kill. ACAO * is extra. Non-blind SSRF with
IMDS blocked is High. Unauth Settings/SaveSettings (sibling 401 vs 200 void) is High;
Critical needs GetSettings round-trip of the canary AND a demonstrated
security-control change. Open signup is the internet exposure, not a separate finding.
Complete is blocked while medium+ findings have RA pending."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                return parsed if isinstance(parsed, list) else [text]
            except Exception:
                pass
        return [line.strip(" -*\t") for line in text.splitlines() if line.strip(" -*\t")]
    return [value]


def _as_dict_rows(value: Any, key_a: str, key_b: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            a = str(item.get(key_a) or item.get("name") or item.get("item") or "").strip()
            b = str(
                item.get(key_b)
                or item.get("detail")
                or item.get("note")
                or item.get("description")
                or ""
            ).strip()
            if a or b:
                rows.append({key_a: a, key_b: b})
        elif isinstance(item, str) and item.strip():
            if ":" in item:
                left, right = item.split(":", 1)
                rows.append({key_a: left.strip(), key_b: right.strip()})
            else:
                rows.append({key_a: item.strip(), key_b: ""})
    return rows


def _as_remediation(value: Any) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for item in _as_list(value):
        if isinstance(item, dict):
            rows.append({
                "when": str(item.get("when") or item.get("sla") or "").strip(),
                "action": str(item.get("action") or item.get("step") or "").strip(),
                "done_when": str(item.get("done_when") or item.get("doneWhen") or "").strip(),
            })
        elif isinstance(item, str) and item.strip():
            rows.append({"when": "", "action": item.strip(), "done_when": ""})
    return [r for r in rows if r.get("action")]


def parse_assessment(raw: Any, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Accept a JSON string, dict, or flattened kwargs and return a dict."""
    data: Dict[str, Any] = {}
    if isinstance(raw, dict):
        data.update(raw)
    elif isinstance(raw, str) and raw.strip():
        text = raw.strip()
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                data.update(parsed)
            else:
                data["ra_note"] = text
        except json.JSONDecodeError:
            data["ra_note"] = text
    if extra:
        for key, val in extra.items():
            if val is not None and val != "":
                data[key] = val
    return data


def normalize_assessment(raw: Dict[str, Any]) -> Dict[str, Any]:
    sev = str(raw.get("confirmed_severity") or raw.get("severity") or "").strip().lower()
    if sev == "informational":
        sev = "info"
    verdict = str(raw.get("verdict") or "keep_open").strip().lower().replace(" ", "_")
    if verdict in ("confirmed", "confirm_high", "confirm_severity"):
        verdict = "confirm"
    sla = str(raw.get("sla") or raw.get("remediation_sla") or "").strip().lower().replace(" ", "_")
    if sla in ("immediate", "today", "urgent"):
        sla = "now"
    if sla in ("week", "this week"):
        sla = "this_week"
    if sla in ("later", "followup", "follow-up"):
        sla = "follow_up"

    cwes = []
    for item in _as_list(raw.get("cwes") or raw.get("cwe_ids") or raw.get("cwe")):
        token = str(item).strip().upper()
        if token:
            if not token.startswith("CWE-") and token.isdigit():
                token = f"CWE-{token}"
            cwes.append(token)

    score = raw.get("cvss_score")
    try:
        score_f = float(score) if score is not None and score != "" else None
    except (TypeError, ValueError):
        score_f = None

    return {
        "verdict": verdict,
        "confirmed_severity": sev,
        "proposed_severity": str(raw.get("proposed_severity") or "").strip().lower() or None,
        "cvss_score": score_f,
        "cvss_vector": str(raw.get("cvss_vector") or raw.get("cvss") or "").strip() or None,
        "cvss_basis": str(raw.get("cvss_basis") or "demonstrated").strip().lower(),
        "why_this_severity": str(raw.get("why_this_severity") or raw.get("why_this") or "").strip(),
        "why_not_higher": str(raw.get("why_not_higher") or "").strip(),
        "why_not_lower": str(raw.get("why_not_lower") or "").strip(),
        "demonstrated": _as_dict_rows(raw.get("demonstrated"), "asset", "result"),
        "not_demonstrated": _as_dict_rows(
            raw.get("not_demonstrated") or raw.get("notDemonstrated"),
            "target",
            "outcome",
        ),
        "control_failures": _as_dict_rows(raw.get("control_failures"), "control", "failure"),
        "business_risk": str(raw.get("business_risk") or "").strip(),
        "remediation_sequence": _as_remediation(
            raw.get("remediation_sequence") or raw.get("remediation")
        ),
        "retest_criteria": [
            str(x).strip() for x in _as_list(raw.get("retest_criteria")) if str(x).strip()
        ],
        "ticket_title": str(raw.get("ticket_title") or "").strip(),
        "ra_note": str(raw.get("ra_note") or raw.get("note") or "").strip(),
        "sla": sla,
        "cwes": cwes,
    }


def validate_risk_assessment(
    raw: Any,
    *,
    proposed_severity: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Return (normalized_payload, gaps). Empty gaps means SUBMIT-quality RA."""
    data = normalize_assessment(parse_assessment(raw, extra))
    gaps: List[str] = []
    sev = data["confirmed_severity"]
    if sev not in SEVERITIES:
        gaps.append("confirmed_severity must be critical|high|medium|low|info")
    if data["verdict"] not in VERDICTS:
        gaps.append("verdict must be confirm|downgrade|upgrade|keep_open")
    if data["sla"] and data["sla"] not in SLAS:
        gaps.append("sla must be now|this_week|follow_up")

    if len(data["why_this_severity"]) < 80:
        gaps.append("why_this_severity must cite the demonstrated packet (≥80 chars)")
    medium_plus = sev in {"critical", "high", "medium"}
    if medium_plus and len(data["why_not_higher"]) < 40:
        gaps.append("why_not_higher is required for medium+ (what was NOT shown)")
    if medium_plus and len(data["why_not_lower"]) < 40:
        gaps.append("why_not_lower is required for medium+ (why this is not noise)")
    if medium_plus and len(data["demonstrated"]) < 2:
        gaps.append("demonstrated needs ≥2 concrete asset/result rows")
    if medium_plus and len(data["not_demonstrated"]) < 1:
        gaps.append("not_demonstrated needs ≥1 bounded negative (IMDS, write, RCE, …)")
    if medium_plus and len(data["control_failures"]) < 1:
        gaps.append("control_failures needs ≥1 broken control (identity/filter/network/authz)")
    if medium_plus and len(data["business_risk"]) < 40:
        gaps.append("business_risk must name the workload/customer impact, not restate CVSS")
    if medium_plus:
        sequenced = [r for r in data["remediation_sequence"] if r.get("done_when")]
        if len(data["remediation_sequence"]) < 2:
            gaps.append("remediation_sequence needs ≥2 steps")
        elif len(sequenced) < 2:
            gaps.append("each remediation step needs done_when close criteria")
        if len(data["retest_criteria"]) < 3:
            gaps.append("retest_criteria needs ≥3 close-the-ticket checks")
        if len(data["ticket_title"]) < 12:
            gaps.append("ticket_title is required")
        if len(data["ra_note"]) < 40:
            gaps.append("ra_note (pasteable Guard/ticket note) is required")
        if data["cvss_score"] is None:
            gaps.append("cvss_score (0-10) scored on demonstrated evidence is required")
        elif not (0.0 <= float(data["cvss_score"]) <= 10.0):
            gaps.append("cvss_score must be 0-10")
        if not data["cvss_vector"] or not str(data["cvss_vector"]).upper().startswith("CVSS"):
            gaps.append("cvss_vector is required (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)")

    demo_blob = " ".join(
        f"{r.get('asset','')} {r.get('result','')}" for r in data["demonstrated"]
    )
    packet_blob = " ".join([
        demo_blob,
        data.get("why_this_severity") or "",
        data.get("why_not_lower") or "",
        data.get("ra_note") or "",
        data.get("business_risk") or "",
        data.get("ticket_title") or "",
    ])
    from app.services.agent.unauth_account_lookup import allows_critical_ra
    from app.services.agent.unauth_settings_write import caps_critical_as_high

    if sev == "critical" and caps_critical_as_high(packet_blob):
        gaps.append(
            "Unauth Settings/SaveSettings write is High on sibling 401 vs 200 void. "
            "Critical requires GetSettings round-trip of the canary AND a demonstrated "
            "security-control change. Do not inflate on void 200 alone."
        )
    elif sev == "critical" and not (
        _CRITICAL_PROOF.search(demo_blob) or allows_critical_ra(packet_blob)
    ):
        gaps.append(
            "Critical requires demonstrated write, RCE, or cloud credential theft, "
            "or unauth account lookup (security: {} + is_staff/role, or sibling 401 "
            "vs lookup 200/404/500). Non-blind SSRF / internal read / signup abuse "
            "is High unless that proof exists. Do not invent a 200 UserAccount body."
        )

    proposed = (proposed_severity or data.get("proposed_severity") or "").strip().lower()
    if data["verdict"] == "confirm" and proposed and sev and proposed != sev:
        gaps.append(
            f"verdict=confirm but confirmed_severity={sev} ≠ proposed {proposed} "
            "(use upgrade/downgrade)"
        )
    return (None if gaps else data), gaps


def pending_payload(*, title: str, severity: str, finding_id: Optional[int] = None) -> Dict[str, Any]:
    return {
        "status": "pending",
        "finding_id": finding_id,
        "title": title,
        "severity": (severity or "").lower(),
        "updated_at": _now_iso(),
        "assessor": "marcus",
    }


def complete_payload(
    assessment: Dict[str, Any],
    *,
    finding_id: Optional[int] = None,
    status: str = "complete",
) -> Dict[str, Any]:
    out = dict(assessment)
    out["status"] = status if status in RA_STATUSES else "complete"
    out["finding_id"] = finding_id or assessment.get("finding_id")
    out["updated_at"] = _now_iso()
    out["assessor"] = "marcus"
    return out


def attach_to_vulnerability(vuln: Any, ra: Dict[str, Any]) -> Dict[str, Any]:
    """Persist RA onto Vulnerability.metadata_['risk_assessment'] + CVSS columns."""
    meta = dict(getattr(vuln, "metadata_", None) or {})
    payload = dict(ra)
    payload["finding_id"] = getattr(vuln, "id", None)
    payload["updated_at"] = _now_iso()
    meta["risk_assessment"] = payload
    vuln.metadata_ = meta
    try:
        flag_modified(vuln, "metadata_")
    except Exception:
        pass
    if payload.get("status") == "complete":
        score = payload.get("cvss_score")
        if score is not None:
            try:
                vuln.cvss_score = float(score)
            except (TypeError, ValueError):
                pass
        if payload.get("cvss_vector"):
            vuln.cvss_vector = str(payload["cvss_vector"])[:100]
        confirmed = str(payload.get("confirmed_severity") or "").lower()
        if confirmed in SEVERITIES and hasattr(vuln, "severity"):
            current = getattr(getattr(vuln, "severity", None), "value", vuln.severity)
            if payload.get("verdict") in ("upgrade", "downgrade") and current != confirmed:
                try:
                    from app.models.vulnerability import Severity

                    vuln.severity = Severity(confirmed)
                except Exception:
                    pass
        cwes = payload.get("cwes") or []
        if cwes and not getattr(vuln, "cwe_id", None):
            vuln.cwe_id = str(cwes[0])[:50]
    return payload


def ra_status(vuln_or_meta: Any) -> str:
    meta = vuln_or_meta
    if not isinstance(meta, dict):
        meta = getattr(vuln_or_meta, "metadata_", None) or {}
    ra = (meta or {}).get("risk_assessment") or {}
    return str(ra.get("status") or "").lower()


def is_ra_complete(vuln_or_meta: Any) -> bool:
    return ra_status(vuln_or_meta) == "complete"


def severity_requires_ra(severity: Optional[str]) -> bool:
    return (severity or "info").strip().lower() in {"critical", "high", "medium"}


def queue_pending_ra(brain: Any, *, finding_id: int, title: str, severity: str) -> None:
    rows = list(getattr(brain, "pending_risk_assessments", None) or [])
    rows = [r for r in rows if not (isinstance(r, dict) and r.get("finding_id") == finding_id)]
    rows.append({
        "finding_id": finding_id,
        "title": title,
        "severity": (severity or "").lower(),
        "status": "pending",
    })
    brain.pending_risk_assessments = rows


def complete_pending_ra(brain: Any, finding_id: int) -> None:
    rows = [
        r for r in (getattr(brain, "pending_risk_assessments", None) or [])
        if not (isinstance(r, dict) and r.get("finding_id") == finding_id)
    ]
    brain.pending_risk_assessments = rows


def pending_ra_rows(brain: Any) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in getattr(brain, "pending_risk_assessments", None) or []:
        if isinstance(row, dict) and row.get("status") != "complete":
            out.append(row)
    return out


def format_gaps(gaps: Iterable[str]) -> str:
    items = [g for g in gaps if g]
    return "RA IMPROVE — " + " | ".join(items)


def finding_packet_for_marcus(vuln: Any, *, host: Optional[str] = None) -> str:
    """Compact demonstrated packet for Ask Marcus. No live retest instructions."""
    meta = dict(getattr(vuln, "metadata_", None) or {})
    detection = meta.get("agent_detection") or {}
    chain = detection.get("chain") or []
    steps = []
    for i, step in enumerate(chain[:12], 1):
        if not isinstance(step, dict):
            continue
        summary = step.get("summary") or step.get("tool") or f"step {i}"
        outcome = step.get("outcome") or ""
        steps.append(f"{i}. {summary}" + (f" — {outcome}" if outcome else ""))
    sev = getattr(getattr(vuln, "severity", None), "value", vuln.severity)
    refs = getattr(vuln, "references", None) or detection.get("references") or []
    return "\n".join([
        f"Finding id={getattr(vuln, 'id', '')}",
        f"Title: {getattr(vuln, 'title', '')}",
        f"Severity (proposed): {sev}",
        f"Target: {host or ''}",
        f"Description:\n{(getattr(vuln, 'description', None) or '')[:2500]}",
        f"Impact:\n{(getattr(vuln, 'impact', None) or '')[:1500]}",
        f"Remediation:\n{(getattr(vuln, 'remediation', None) or '')[:1200]}",
        f"Evidence:\n{(getattr(vuln, 'evidence', None) or '')[:2500]}",
        "Demonstrated chain:",
        "\n".join(steps) or "(none)",
        f"Not demonstrated:\n{(detection.get('not_demonstrated') or '')[:1200]}",
        f"References: {', '.join(str(r) for r in refs[:8])}",
        "Write the RA from this packet. Do not retest the live host. "
        "Do not invent writes, IMDS hits, or RCE. "
        "If this is unauth /api/auth/account/: confirm Critical on schema "
        "security: {} + is_staff/role OR sibling 401 vs lookup 200/404/500. "
        "Do not invent a 200 UserAccount body. 404 is the existence oracle. "
        "ACAO * is extra. Do not re-query emails.",
    ])


def marcus_question(packet: str, finding_id: int) -> str:
    return (
        "You are Marcus (risk_assessor). Complete a demonstrated-only risk "
        f"assessment for finding {finding_id}. Call assess_finding_risk with "
        f"finding_id={finding_id} and assessment JSON covering verdict, "
        "confirmed_severity, why_this_severity, why_not_higher, why_not_lower, "
        "cvss_score, cvss_vector, demonstrated[], not_demonstrated[], "
        "control_failures[], business_risk, remediation_sequence[] with "
        "done_when, retest_criteria[], ticket_title, ra_note, sla, cwes. "
        "If the tool returns RA IMPROVE, fix the gaps and retry once. "
        "Do not execute_curl, execute_browser, or otherwise retest.\n\n"
        + packet
    )
