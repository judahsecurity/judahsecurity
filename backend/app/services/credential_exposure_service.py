"""Store, match and prioritize leaked-credential exposures.

Providers (XposedOrNot today; HIBP, Hudson Rock and others later) hand
normalized records to ``upsert_exposure``. Each exposure is matched to an
``Identity`` from the organization's system of record and scored with
``identity_risk.score_exposure``. Secrets are never stored, only fingerprints.
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.identity import (
    CREDENTIAL_EMAIL_ONLY,
    CREDENTIAL_PASSWORD,
    CREDENTIAL_PASSWORD_HASH,
    CREDENTIAL_PASSWORD_PLAINTEXT,
    EXPOSURE_SOURCE_BREACH,
    CredentialExposure,
    Identity,
)
from app.services.identity_risk import score_exposure
from app.services.secret_safety import secret_fingerprint

logger = logging.getLogger(__name__)

PROVIDER_XPOSEDORNOT = "xposedornot"


# ── Normalization helpers ────────────────────────────────────────────────────

def normalize_identifier(value: str) -> str:
    return (value or "").strip().lower()


def identifier_domain(identifier: str) -> Optional[str]:
    return identifier.rsplit("@", 1)[1] if "@" in identifier else None


def parse_leak_date(value: Any) -> Optional[datetime]:
    """Accept '2019', '2019-05', '2019-05-14', ISO datetimes or datetime."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        pass
    for fmt in ("%Y-%m", "%Y"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    match = re.search(r"\b(?:19|20)\d{2}\b", text)
    return datetime(int(match.group(0)), 1, 1) if match else None


def credential_type_from_data_classes(data_classes: Iterable[str]) -> str:
    """Infer the strongest credential a breach exposed from its data classes."""
    items = [d.strip().lower() for d in data_classes or [] if d]
    if any("plaintext password" in d or "plain text password" in d for d in items):
        return CREDENTIAL_PASSWORD_PLAINTEXT
    if any(re.search(r"password hash|hashed password|bcrypt|md5|sha-?1", d) for d in items):
        return CREDENTIAL_PASSWORD_HASH
    if any("password" in d and "hint" not in d for d in items):
        return CREDENTIAL_PASSWORD
    return CREDENTIAL_EMAIL_ONLY


def make_dedup_key(
    *,
    provider: str,
    source_name: Optional[str],
    identifier: str,
    credential_type: str,
    affected_url: Optional[str] = None,
    fingerprint: Optional[str] = None,
) -> str:
    parts = [provider, (source_name or "").lower(), identifier, credential_type,
             (affected_url or "").lower(), fingerprint or ""]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


# ── Identity matching ────────────────────────────────────────────────────────

class IdentityIndex:
    """In-memory lookup of an org's identities by every match key."""

    def __init__(self, identities: Iterable[Identity]):
        self.by_alias: Dict[str, Identity] = {}
        self.by_local_part: Dict[tuple[str, str], Identity] = {}
        for ident in identities:
            for alias in ident.aliases or []:
                self._put(self.by_alias, normalize_identifier(alias), ident)
            # Leaks often use first.last@domain while the record holds a login name.
            if ident.username and ident.email and "@" in ident.email:
                domain = ident.email.rsplit("@", 1)[1]
                self._put(self.by_local_part, (ident.username, domain), ident)

    @staticmethod
    def _put(index: dict, key: Any, ident: Identity) -> None:
        current = index.get(key)
        # Prefer active, then higher-risk records when keys collide.
        if current is None or (ident.is_active, ident.risk_score) > (current.is_active, current.risk_score):
            index[key] = ident

    def match(self, identifier: str) -> Optional[Identity]:
        identifier = normalize_identifier(identifier)
        hit = self.by_alias.get(identifier)
        if hit is not None:
            return hit
        if "@" in identifier:
            local, domain = identifier.rsplit("@", 1)
            return self.by_local_part.get((local, domain))
        return None


def build_identity_index(db: Session, organization_id: int) -> IdentityIndex:
    return IdentityIndex(
        db.query(Identity).filter(Identity.organization_id == organization_id).all()
    )


# ── Scoring ──────────────────────────────────────────────────────────────────

def apply_exposure_score(exposure: CredentialExposure, identity: Optional[Identity]) -> None:
    score, severity, factors = score_exposure(
        credential_type=exposure.credential_type,
        leak_date=exposure.leak_date,
        identity_score=identity.risk_score if identity is not None else None,
        identity_privileged=bool(identity.is_privileged) if identity is not None else False,
        asset_matched=exposure.asset_id is not None,
    )
    exposure.priority_score = score
    exposure.severity = severity
    exposure.score_factors = [f.to_dict() for f in factors]


def rescore_organization(db: Session, organization_id: int) -> int:
    """Re-link every exposure to identities and recompute priority."""
    index = build_identity_index(db, organization_id)
    count = 0
    for exposure in db.query(CredentialExposure).filter(
        CredentialExposure.organization_id == organization_id
    ):
        identity = index.match(exposure.identifier)
        exposure.identity_id = identity.id if identity is not None else None
        apply_exposure_score(exposure, identity)
        count += 1
    db.flush()
    return count


# ── Ingest ───────────────────────────────────────────────────────────────────

def upsert_exposure(
    db: Session,
    organization_id: int,
    index: IdentityIndex,
    *,
    identifier: str,
    provider: str,
    source_type: str,
    source_name: Optional[str],
    credential_type: str,
    data_classes: Optional[List[str]] = None,
    leak_date: Optional[datetime] = None,
    secret_value: Optional[str] = None,
    affected_url: Optional[str] = None,
    affected_host: Optional[str] = None,
    now: Optional[datetime] = None,
) -> tuple[CredentialExposure, bool]:
    """Create or refresh one exposure. ``secret_value`` is fingerprinted, never stored."""
    now = now or datetime.utcnow()
    identifier = normalize_identifier(identifier)
    fingerprint = secret_fingerprint(secret_value) if secret_value else None
    key = make_dedup_key(
        provider=provider, source_name=source_name, identifier=identifier,
        credential_type=credential_type, affected_url=affected_url, fingerprint=fingerprint,
    )
    exposure = (
        db.query(CredentialExposure)
        .filter(
            CredentialExposure.organization_id == organization_id,
            CredentialExposure.dedup_key == key,
        )
        .first()
    )
    created = exposure is None
    if created:
        exposure = CredentialExposure(
            organization_id=organization_id,
            dedup_key=key,
            identifier=identifier,
            identifier_domain=identifier_domain(identifier),
            provider=provider,
            source_type=source_type,
            source_name=source_name,
            credential_type=credential_type,
            secret_fingerprint=fingerprint,
            affected_url=affected_url,
            affected_host=affected_host,
            first_seen_at=now,
            status="open",
        )
        db.add(exposure)
    exposure.data_classes = sorted(set(data_classes or []))
    exposure.leak_date = leak_date or exposure.leak_date
    exposure.last_seen_at = now

    identity = index.match(identifier)
    exposure.identity_id = identity.id if identity is not None else None
    apply_exposure_score(exposure, identity)
    db.flush()
    return exposure, created


def ingest_email_breach_results(
    db: Session, organization_id: int, email_results: Dict[str, Dict[str, Any]]
) -> Dict[str, int]:
    """Turn ``EmailBreachResult.to_dict()`` output into exposures."""
    index = build_identity_index(db, organization_id)
    stats = {"created": 0, "refreshed": 0, "matched_identity": 0}
    for email, result in (email_results or {}).items():
        if not result or not result.get("breached"):
            continue
        for breach in result.get("breaches") or []:
            data_classes = list(breach.get("data_classes") or [])
            exposure, created = upsert_exposure(
                db,
                organization_id,
                index,
                identifier=email,
                provider=PROVIDER_XPOSEDORNOT,
                source_type=EXPOSURE_SOURCE_BREACH,
                source_name=breach.get("name") or "Unknown",
                credential_type=credential_type_from_data_classes(data_classes),
                data_classes=data_classes,
                leak_date=parse_leak_date(breach.get("date")),
            )
            stats["created" if created else "refreshed"] += 1
            if exposure.identity_id is not None:
                stats["matched_identity"] += 1
    return stats


def emails_to_check(db: Session, organization_id: int, limit: int) -> List[str]:
    """Pick which addresses to query providers for, riskiest identities first.

    Free providers rate-limit hard, so the cap goes to the people whose leaks
    matter most, then to email addresses discovered as assets.
    """
    picked: List[str] = []
    seen: set[str] = set()

    def add(email: Optional[str]) -> None:
        email = normalize_identifier(email or "")
        if "@" in email and email not in seen and len(picked) < limit:
            seen.add(email)
            picked.append(email)

    for ident in (
        db.query(Identity)
        .filter(Identity.organization_id == organization_id, Identity.email.isnot(None))
        .order_by(Identity.is_active.desc(), Identity.risk_score.desc(), Identity.id)
        .limit(limit)
    ):
        add(ident.email)

    if len(picked) < limit:
        for asset in (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.asset_type == AssetType.OTHER,
                Asset.value.like("%@%"),
            )
            .limit(limit)
        ):
            add(asset.value)
    return picked
