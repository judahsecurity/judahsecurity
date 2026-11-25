"""Engagement-boundary enforcement for leaked-credential ingest.

Every credential record — from a provider API or a stealer-log parse — must
fall under a domain the organization has authorized before it is stored. This
keeps the platform from holding data on people and companies outside the scope
a client signed off on.

The matcher is pure and cheap so it can gate each record during a bulk parse.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.models.identity import ExposureScope

AUDIENCE_EMPLOYEES = "employees"
AUDIENCE_CUSTOMERS = "customers"
AUDIENCE_BOTH = "both"


def normalize_domain(value: str) -> str:
    return (value or "").strip().lower().lstrip("@").rstrip(".")


def host_of(value: str) -> Optional[str]:
    """Hostname from a URL, a bare host, or the domain part of an email."""
    text = (value or "").strip().lower()
    if not text:
        return None
    if "@" in text and "://" not in text:
        return text.rsplit("@", 1)[1].rstrip(".") or None
    if "://" in text:
        host = urlsplit(text).hostname
        return host.rstrip(".") if host else None
    return text.split("/", 1)[0].split(":", 1)[0].rstrip(".") or None


@dataclass(frozen=True)
class ScopeRule:
    domain: str
    include_subdomains: bool
    audience_scope: str

    def host_matches(self, host: str) -> bool:
        if not host:
            return False
        if host == self.domain:
            return True
        return self.include_subdomains and host.endswith("." + self.domain)

    def audience_allowed(self, audience: Optional[str]) -> bool:
        if self.audience_scope == AUDIENCE_BOTH or not audience:
            return True
        # "employee"/"employees" and "customer"/"user"/"customers" all normalize.
        aud = audience.lower()
        if self.audience_scope == AUDIENCE_EMPLOYEES:
            return aud.startswith("employee")
        return aud.startswith("customer") or aud.startswith("user") or aud.startswith("client")


class ScopeMatcher:
    """In-memory view of one organization's active authorized domains."""

    def __init__(self, rules: Iterable[ScopeRule]):
        self.rules: List[ScopeRule] = list(rules)

    @property
    def is_empty(self) -> bool:
        return not self.rules

    def domains(self) -> List[str]:
        return [r.domain for r in self.rules]

    def allows(self, value: str, audience: Optional[str] = None) -> bool:
        """True if ``value`` (email, URL or host) is an in-scope, in-audience record."""
        host = host_of(value)
        if host is None:
            return False
        return any(r.host_matches(host) and r.audience_allowed(audience) for r in self.rules)

    def matching_rule(self, value: str) -> Optional[ScopeRule]:
        host = host_of(value)
        if host is None:
            return None
        for rule in self.rules:
            if rule.host_matches(host):
                return rule
        return None


def load_scope(db: Session, organization_id: int) -> ScopeMatcher:
    rows = (
        db.query(ExposureScope)
        .filter(
            ExposureScope.organization_id == organization_id,
            ExposureScope.is_active.is_(True),
        )
        .all()
    )
    return ScopeMatcher(
        ScopeRule(
            domain=normalize_domain(r.domain),
            include_subdomains=bool(r.include_subdomains),
            audience_scope=r.audience_scope or AUDIENCE_BOTH,
        )
        for r in rows
        if normalize_domain(r.domain)
    )


def add_scope(
    db: Session,
    organization_id: int,
    domain: str,
    *,
    authorized_by: Optional[str] = None,
    include_subdomains: bool = True,
    audience_scope: str = AUDIENCE_BOTH,
    note: Optional[str] = None,
) -> ExposureScope:
    domain = normalize_domain(domain)
    if not domain or "." not in domain:
        raise ValueError("A valid apex domain is required, e.g. rockwellautomation.com")
    if audience_scope not in (AUDIENCE_EMPLOYEES, AUDIENCE_CUSTOMERS, AUDIENCE_BOTH):
        raise ValueError("audience_scope must be employees, customers or both")
    row = (
        db.query(ExposureScope)
        .filter(
            ExposureScope.organization_id == organization_id,
            ExposureScope.domain == domain,
        )
        .first()
    )
    if row is None:
        row = ExposureScope(organization_id=organization_id, domain=domain)
        db.add(row)
    row.include_subdomains = include_subdomains
    row.audience_scope = audience_scope
    row.is_active = True
    row.authorized_by = authorized_by
    row.authorization_note = note
    row.updated_at = datetime.utcnow()
    db.flush()
    return row
