"""Go deeper on a route once a foothold is confirmed.

Coverage is the floor, not the aim. When the independent verifier confirms a
high-impact candidate (high/critical severity, or a class that opens a path:
injection, auth bypass, IDOR, SSRF, file read, default login, ...), its chain
follow-ups are queued at once at critical priority, so the next waves press
that route (credentials -> privileged API, SQLi -> data access, SSRF ->
internal services) ahead of shallow coverage of other surfaces. The coverage
lane keeps its reserved slot and the completion gate is unchanged.

Active routes are listed at the top of the planner's progress text.
"""

from __future__ import annotations

import time
from typing import Any

FOOTHOLD_CLASSES = {
    "sqli", "sql_injection", "rce", "cmdi", "command_injection", "ssti", "ssrf", "idor",
    "bola", "authz", "auth_bypass", "authentication_bypass", "default_login", "jwt",
    "deserialization", "lfi", "path_traversal", "xxe", "file_upload", "account_takeover",
    "privilege_escalation", "mass_assignment", "unauth_settings_write",
    "unauth_account_lookup", "elasticsearch_unauth", "keycloak_password_grant",
    "email_change_ato", "cors_credentials", "js_secrets",
}
MAX_ROUTES = 10


def is_foothold(candidate: Any) -> bool:
    severity = str(getattr(candidate, "severity", "") or "").lower()
    if severity in ("high", "critical"):
        return True
    classes = {str(getattr(candidate, field, "") or "").lower().replace("-", "_")
               for field in ("vulnerability_class", "test_type")}
    return bool(classes & FOOTHOLD_CLASSES)


def deepen_after_confirmation(brain: Any, candidate: Any) -> list[str]:
    """Queue the confirmed candidate's chain follow-ups at critical priority."""
    from app.services.agent.engagement_brain import (
        classify_finding_type,
        queue_followups_for_finding,
    )

    if not is_foothold(candidate):
        return []
    if any(route.get("candidate_id") == candidate.id for route in brain.attack_routes or []):
        return []
    vuln_type = (str(getattr(candidate, "vulnerability_class", "") or "")
                 or classify_finding_type(title=candidate.title, description=candidate.description))
    created = queue_followups_for_finding(
        brain, vuln_type=vuln_type, title=candidate.title, target=candidate.target,
        evidence=(candidate.verifier_summary or candidate.evidence or "")[:1000],
    )
    for hypothesis in created:
        hypothesis.priority = "critical"
        if not hypothesis.parent_finding:
            hypothesis.parent_finding = candidate.id
    brain.attack_routes = [*(brain.attack_routes or []), {
        "candidate_id": candidate.id,
        "title": str(candidate.title or "")[:160],
        "severity": candidate.severity,
        "vuln_class": vuln_type,
        "target": str(candidate.target or "")[:200],
        "followups": [h.id for h in created],
        "at": time.time(),
    }][-MAX_ROUTES:]
    return [h.id for h in created]


def routes_prompt_block(brain: Any) -> str:
    routes = [route for route in brain.attack_routes or [] if isinstance(route, dict)]
    if not routes:
        return ""
    open_ids = {h.id for h in brain.hypotheses if h.status in ("open", "in_progress")}
    lines = ["ACTIVE ATTACK ROUTES (confirmed footholds; press these deeper before "
             "shallow coverage elsewhere):"]
    for route in routes[-5:]:
        pending = [hid for hid in route.get("followups") or [] if hid in open_ids]
        lines.append(f"- [{route.get('severity')}] {route.get('title')} -> "
                     f"{len(pending)} open follow-up(s){': ' + ', '.join(pending[:4]) if pending else ''}")
    return "\n".join(lines)
