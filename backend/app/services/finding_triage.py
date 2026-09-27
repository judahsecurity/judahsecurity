"""Analyst decisions and evidence provenance, independent of remediation status."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit


TASKS = (
    {"id": "evidence", "title": "Validate the detection", "context": "evidence",
     "guidance": "Compare the claim with the observed response and proof. Record what is demonstrated and what remains unverified."},
    {"id": "impact", "title": "Assess business impact", "context": "assets",
     "guidance": "Review the application, owner, data sensitivity, and potential business impact. Identify missing context instead of assuming it."},
    {"id": "scope", "title": "Review affected assets", "context": "assets",
     "guidance": "Check the linked asset and endpoints named in the writeup. A mention is not a confirmed asset association."},
    {"id": "priority", "title": "Review severity and exploitability", "context": "evidence",
     "guidance": "Compare severity, OPES, and the risk assessment against the demonstrated evidence. Explain any correction."},
)


def evidence_fingerprint(vuln):
    metadata = vuln.metadata_ or {}
    payload = {key: getattr(vuln, key, None) for key in (
        "asset_id", "title", "description", "impact", "evidence", "proof_of_concept",
        "steps_to_reproduce", "severity", "cvss_score", "last_detected",
        "business_app_id", "sev_score", "sev_level", "sev_exploit_realism",
        "sev_business_impact", "sev_network_location", "sev_vulnerability_severity",
        "sev_skill_level", "sev_ease_of_discovery", "sev_ease_of_exploit", "sev_awareness",
    )}
    payload["asset_business_app_id"] = getattr(getattr(vuln, "asset", None), "business_app_id", None)
    payload.update({key: metadata.get(key) for key in (
        "agent_detection", "risk_assessment", "oracle", "nuclei_matched_at", "detection",
        "risk_overrides",
    )})
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def triage_state(vuln):
    stored = deepcopy((vuln.metadata_ or {}).get("analyst_triage") or {})
    fingerprint = evidence_fingerprint(vuln)
    decisions = stored.get("decisions", {})
    items = []
    for task in TASKS:
        decision = decisions.get(task["id"])
        stale = bool(decision and decision.get("evidence_version") != fingerprint)
        reviewed = bool(decision and not stale and decision.get("state") == "reviewed"
                        and decision.get("decision") in ("confirm", "correct"))
        items.append({**task, "reviewed": reviewed, "stale": stale, "review": decision})
    pending = sum(not item["reviewed"] for item in items)
    return {
        "revision": stored.get("revision", 0), "evidence_version": fingerprint,
        "status": "reviewed" if pending == 0 else "in_review" if decisions else "needs_review",
        "pending": pending, "items": items, "history": stored.get("history", []),
        "last_reviewed_at": stored.get("last_reviewed_at") if pending == 0 else None,
    }


def record_decision(vuln, payload, reviewer, now=None):
    """Return replacement metadata; caller locks the row and commits it."""
    current = triage_state(vuln)
    if payload["expected_revision"] != current["revision"]:
        raise ValueError("The review changed. Reload the latest review before saving.")
    if payload["evidence_version"] != current["evidence_version"]:
        raise ValueError("The finding evidence changed. Reload it before saving your decision.")
    if payload["task_id"] not in {task["id"] for task in TASKS}:
        raise KeyError("Unknown review item")
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    entry = {key: payload.get(key) for key in (
        "task_id", "state", "decision", "rationale", "correction", "evidence_references",
    )}
    entry.update({"reviewer_id": reviewer.id,
                  "reviewer": reviewer.full_name or reviewer.email or reviewer.username,
                  "saved_at": stamp, "evidence_version": current["evidence_version"]})
    metadata = deepcopy(vuln.metadata_ or {})
    stored = metadata.setdefault("analyst_triage", {})
    stored.setdefault("decisions", {})[payload["task_id"]] = entry
    stored.setdefault("history", []).append(deepcopy(entry))
    stored["revision"] = current["revision"] + 1
    # Completion is derived from current-evidence decisions; a draft cannot close a review.
    complete = all(
        (review := stored["decisions"].get(task["id"], {})).get("state") == "reviewed"
        and review.get("decision") in ("confirm", "correct")
        and review.get("evidence_version") == current["evidence_version"]
        for task in TASKS
    )
    stored["last_reviewed_at"] = stamp if complete else None
    return metadata


def asset_mentions(vuln):
    """Only explicit agent targets and literal IPs in the description; no inferred links."""
    agent = (vuln.metadata_ or {}).get("agent_detection") or {}
    values = [v for v in agent.get("assets", []) if isinstance(v, str) and v.strip()]
    for candidate in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", vuln.description or ""):
        try:
            values.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            pass
    return list(dict.fromkeys(v.strip()[:2048] for v in values))[:200]


def target_host(value):
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def validate_capture_url(url, asset_value, live_url=None):
    """An explicit capture may select a path/port, never an unrelated host."""
    try:
        parsed = urlsplit(url)
        port = parsed.port  # Validate malformed/out-of-range ports too.
    except ValueError as exc:
        raise ValueError("Invalid screenshot URL") from exc
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username or parsed.password or parsed.fragment
            or any(ord(char) < 32 or char == "\\" for char in url)):
        raise ValueError("Use an HTTP(S) URL without credentials or a fragment")
    hosts = {target_host(asset_value), target_host(live_url or "")} - {""}
    if parsed.hostname.lower().rstrip(".") not in hosts:
        raise ValueError("Screenshot URL must belong to the linked asset")
    return url
