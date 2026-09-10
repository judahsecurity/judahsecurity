"""
Rules of Engagement (RoE) Service
=================================

Enforces per-organization RoE on every scan creation path and every agent
tool invocation. The RoE is stored as a row in ``project_settings`` under
module ``rules_of_engagement``.

Public API
----------

    load_roe(db, organization_id) -> dict
        Return the effective (merged with defaults) RoE config.

    check_target(db, organization_id, target, scan_type=None)
        -> (allowed: bool, reason: Optional[str])

    check_scan_type(db, organization_id, scan_type)
        -> (allowed: bool, reason: Optional[str])

    accept_roe(db, organization_id, actor_email, document_text)
        Hash the document and mark it accepted.

    ingest_markdown(document_text) -> dict
        Best-effort parse of a markdown RoE file into
        ``{scope_in, scope_out, notes, contacts}``.

Design
------
The guardrail is an AND of three checks:

    1. ``check_scan_type`` -- restricted scan types are rejected even if
       the target is explicitly in scope.
    2. ``check_target``    -- the target (hostname, URL, or IP) must match
       at least one ``scope_in`` entry AND must not match any
       ``scope_out`` entry.
    3. (Optional, applied by the agent) ``requires_agent_confirmation``
       flips the per-tool confirmation gate on.

We deliberately *fail-closed* when ``enabled: true`` but the document
text is missing -- the operator should either accept the RoE or disable
the module explicitly.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
from datetime import datetime
from typing import Iterable, Optional
from urllib.parse import urlparse

from app.models.project_settings import (
    MODULE_RULES_OF_ENGAGEMENT,
    ProjectSettings,
    get_default_config,
)

logger = logging.getLogger(__name__)


def load_roe(db, organization_id: int) -> dict:
    """Return the RoE config, merged with module defaults."""
    return ProjectSettings.get_config(db, organization_id, MODULE_RULES_OF_ENGAGEMENT)


def is_enabled(roe: dict) -> bool:
    return bool(roe.get("enabled"))


# ---------------------------------------------------------------------------
# Scope checks
# ---------------------------------------------------------------------------


def _normalize_target(target: str) -> str:
    """Return the bare hostname or IP extracted from ``target``."""
    if not target:
        return ""
    t = target.strip()
    if "://" in t:
        t = urlparse(t).netloc or t
    # Strip :port
    if t.startswith("["):
        # IPv6 literal in URL form
        end = t.find("]")
        if end > 0:
            t = t[1:end]
    else:
        t = t.split(":", 1)[0]
    return t.lower()


def _host_matches(target: str, rule: str) -> bool:
    """True iff ``target`` matches a scope rule (hostname, wildcard, or CIDR)."""
    if not target or not rule:
        return False
    target = _normalize_target(target)
    rule = rule.strip().lower()

    # CIDR
    try:
        net = ipaddress.ip_network(rule, strict=False)
        try:
            ip = ipaddress.ip_address(target)
            return ip in net
        except ValueError:
            return False
    except ValueError:
        pass

    # Bare IP
    try:
        if ipaddress.ip_address(rule) and ipaddress.ip_address(target):
            return rule == target
    except ValueError:
        pass

    # Wildcard
    if rule.startswith("*."):
        suffix = rule[2:]
        return target == suffix or target.endswith("." + suffix)

    # Apex hostname: implicit wildcard for subdomains so an operator's
    # ``example.com`` also covers ``api.example.com``.
    return target == rule or target.endswith("." + rule)


def check_target(
    db, organization_id: int, target: str, scan_type: Optional[str] = None
) -> tuple[bool, Optional[str]]:
    """Return ``(allowed, reason_if_blocked)``."""
    roe = load_roe(db, organization_id)
    if not is_enabled(roe):
        return True, None

    if not roe.get("document_text") and not roe.get("document_hash"):
        return False, "Rules of Engagement are enabled but no document has been accepted."

    if scan_type is not None:
        allowed, reason = _check_scan_type_against_roe(roe, scan_type)
        if not allowed:
            return False, reason

    scope_in = roe.get("scope_in") or []
    scope_out = roe.get("scope_out") or []

    if scope_in:
        if not any(_host_matches(target, rule) for rule in scope_in):
            return False, (
                f"Target '{target}' is not covered by any in-scope rule in the RoE. "
                f"Add an explicit scope_in entry or disable RoE enforcement."
            )

    for rule in scope_out:
        if _host_matches(target, rule):
            return False, f"Target '{target}' matches the explicitly excluded rule '{rule}'."

    return True, None


def _check_scan_type_against_roe(roe: dict, scan_type: str) -> tuple[bool, Optional[str]]:
    st = (scan_type or "").lower()
    allowed = [s.lower() for s in (roe.get("allowed_scan_types") or [])]
    restricted = [s.lower() for s in (roe.get("restricted_scan_types") or [])]

    if st in restricted:
        return False, f"Scan type '{scan_type}' is explicitly restricted by the RoE."
    if allowed and st not in allowed:
        return False, (
            f"Scan type '{scan_type}' is not in the RoE allow-list {allowed}."
        )
    return True, None


def check_scan_type(
    db, organization_id: int, scan_type: str
) -> tuple[bool, Optional[str]]:
    roe = load_roe(db, organization_id)
    if not is_enabled(roe):
        return True, None
    return _check_scan_type_against_roe(roe, scan_type)


def check_targets(
    db, organization_id: int, targets: Iterable[str], scan_type: Optional[str] = None
) -> tuple[bool, Optional[str], list[str]]:
    """Bulk check with one RoE load. Returns (allowed, reason, rejected)."""
    target_list = list(targets)
    roe = load_roe(db, organization_id)
    if not is_enabled(roe):
        return True, None, []

    if not roe.get("document_text") and not roe.get("document_hash"):
        return (
            False,
            "Rules of Engagement are enabled but no document has been accepted.",
            target_list,
        )

    if scan_type is not None:
        allowed, reason = _check_scan_type_against_roe(roe, scan_type)
        if not allowed:
            return False, reason, target_list

    scope_in = roe.get("scope_in") or []
    scope_out = roe.get("scope_out") or []
    rejected: list[str] = []
    first_reason: Optional[str] = None
    for target in target_list:
        reason = None
        if scope_in and not any(_host_matches(target, rule) for rule in scope_in):
            reason = f"Target '{target}' is not covered by any in-scope rule in the RoE."
        else:
            for rule in scope_out:
                if _host_matches(target, rule):
                    reason = f"Target '{target}' matches the explicitly excluded rule '{rule}'."
                    break
        if reason:
            rejected.append(target)
            if first_reason is None:
                first_reason = reason
    return (len(rejected) == 0), first_reason, rejected


# ---------------------------------------------------------------------------
# Document management
# ---------------------------------------------------------------------------


def accept_roe(
    db,
    organization_id: int,
    actor_email: str,
    document_text: str,
    document_name: str = "",
    scope_in: Optional[list[str]] = None,
    scope_out: Optional[list[str]] = None,
    allowed_scan_types: Optional[list[str]] = None,
    restricted_scan_types: Optional[list[str]] = None,
    max_rps_global: Optional[int] = None,
    max_concurrency: Optional[int] = None,
    requires_agent_confirmation: Optional[bool] = None,
    contacts: Optional[list[str]] = None,
    notes: Optional[str] = None,
    enabled: bool = True,
) -> dict:
    """Persist the RoE + metadata. Any ``None`` field is left untouched."""
    existing = ProjectSettings.get_config(db, organization_id, MODULE_RULES_OF_ENGAGEMENT)
    new: dict = dict(existing)

    new["enabled"] = bool(enabled)
    new["document_text"] = document_text or existing.get("document_text", "")
    new["document_name"] = document_name or existing.get("document_name", "")
    new["document_hash"] = hashlib.sha256(
        (document_text or "").encode("utf-8")
    ).hexdigest()
    new["accepted_by"] = actor_email
    new["accepted_at"] = datetime.utcnow().isoformat()

    if scope_in is not None:
        new["scope_in"] = _dedupe(scope_in)
    if scope_out is not None:
        new["scope_out"] = _dedupe(scope_out)
    if allowed_scan_types is not None:
        new["allowed_scan_types"] = _dedupe(allowed_scan_types)
    if restricted_scan_types is not None:
        new["restricted_scan_types"] = _dedupe(restricted_scan_types)
    if max_rps_global is not None:
        new["max_rps_global"] = int(max_rps_global)
    if max_concurrency is not None:
        new["max_concurrency"] = int(max_concurrency)
    if requires_agent_confirmation is not None:
        new["requires_agent_confirmation"] = bool(requires_agent_confirmation)
    if contacts is not None:
        new["contacts"] = _dedupe(contacts)
    if notes is not None:
        new["notes"] = notes

    ProjectSettings.set_config(db, organization_id, MODULE_RULES_OF_ENGAGEMENT, new)
    db.commit()
    return new


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if not it:
            continue
        s = str(it).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ---------------------------------------------------------------------------
# Markdown parser (best-effort)
# ---------------------------------------------------------------------------


# Scope section regex: capture the content between an ``In Scope``-like
# header and the next header or end-of-doc.
SCOPE_IN_HEADERS = ["in scope", "scope - in", "scope_in", "allowed targets", "targets"]
SCOPE_OUT_HEADERS = ["out of scope", "out-of-scope", "scope - out", "scope_out", "excluded", "do not test"]
CONTACT_HEADERS = ["contact", "contacts", "emergency contact", "authorized contacts"]


_HEADER_RE = re.compile(r"^\s*#{1,6}\s*(.+?)\s*$", re.MULTILINE)
_BULLET_RE = re.compile(r"^\s*(?:[-*]|\d+\.)\s+(.+?)\s*$", re.MULTILINE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def ingest_markdown(document_text: str) -> dict:
    """Best-effort parse of a markdown RoE. Returns a dict with the
    fields we can confidently extract (caller should review before accept).
    """
    if not document_text:
        return {"scope_in": [], "scope_out": [], "contacts": [], "notes": ""}

    sections = _split_sections(document_text)

    scope_in: list[str] = []
    scope_out: list[str] = []
    contacts: list[str] = []

    for header, body in sections.items():
        h = header.strip().lower()
        if any(k in h for k in SCOPE_IN_HEADERS):
            scope_in.extend(_extract_bullets_or_lines(body))
        elif any(k in h for k in SCOPE_OUT_HEADERS):
            scope_out.extend(_extract_bullets_or_lines(body))
        elif any(k in h for k in CONTACT_HEADERS):
            contacts.extend(_EMAIL_RE.findall(body))

    if not contacts:
        contacts = _EMAIL_RE.findall(document_text)

    return {
        "scope_in": _dedupe([_strip_tokens(s) for s in scope_in]),
        "scope_out": _dedupe([_strip_tokens(s) for s in scope_out]),
        "contacts": _dedupe(contacts),
        "notes": document_text[:2000],
    }


def _split_sections(text: str) -> dict[str, str]:
    """Split markdown into ``{header: body}`` pairs."""
    sections: dict[str, str] = {}
    indices: list[tuple[int, str]] = [(m.start(), m.group(1)) for m in _HEADER_RE.finditer(text)]
    if not indices:
        return {"body": text}
    for i, (start, header) in enumerate(indices):
        end = indices[i + 1][0] if i + 1 < len(indices) else len(text)
        body = text[start:end]
        # Strip the header line itself
        nl = body.find("\n")
        body = body[nl + 1:] if nl >= 0 else ""
        sections[header] = body
    return sections


def _extract_bullets_or_lines(body: str) -> list[str]:
    bullets = _BULLET_RE.findall(body)
    if bullets:
        return bullets
    return [ln.strip() for ln in body.splitlines() if ln.strip()]


def _strip_tokens(s: str) -> str:
    # Remove markdown emphasis / backticks / leading/trailing punctuation.
    s = re.sub(r"[`*_]", "", s).strip()
    s = re.sub(r"^\W+|\W+$", "", s)
    return s
