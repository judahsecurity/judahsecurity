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
    EXPOSURE_SOURCE_STEALER_LOG,
    StealerDomainSummary,
    StealerUrlExposure,
    CREDENTIAL_EMAIL_ONLY,
    CREDENTIAL_PASSWORD,
    CREDENTIAL_PASSWORD_HASH,
    CREDENTIAL_PASSWORD_PLAINTEXT,
    EXPOSURE_SOURCE_BREACH,
    CredentialExposure,
    Identity,
)
from app.models.organization import Organization
from app.services.identity_risk import score_exposure, score_stealer_url
from app.services.secret_safety import secret_fingerprint

logger = logging.getLogger(__name__)

PROVIDER_XPOSEDORNOT = "xposedornot"
PROVIDER_HUDSONROCK = "hudsonrock"


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


_PASSWORD_RISK_TYPES = {
    "plaintextpassword": CREDENTIAL_PASSWORD_PLAINTEXT,
    "easytocrack": CREDENTIAL_PASSWORD,
    "hardtocrack": CREDENTIAL_PASSWORD_HASH,
}


def credential_type_for_breach(breach: Dict[str, Any]) -> str:
    """Use XposedOrNot's password_risk when given, else the data classes."""
    from_data = credential_type_from_data_classes(breach.get("data_classes") or [])
    risk = _PASSWORD_RISK_TYPES.get(str(breach.get("password_risk") or "").lower())
    if risk == CREDENTIAL_PASSWORD_PLAINTEXT:
        return risk
    if from_data == CREDENTIAL_EMAIL_ONLY:
        # password_risk describes the breach overall, not that passwords leaked.
        return from_data
    return risk or from_data


def make_dedup_key(
    *,
    provider: str,
    source_name: Optional[str],
    identifier: str,
    credential_type: str,
    affected_url: Optional[str] = None,
    fingerprint: Optional[str] = None,
    extra: Optional[str] = None,
) -> str:
    parts = [provider, (source_name or "").lower(), identifier, credential_type,
             (affected_url or "").lower(), fingerprint or "", extra or ""]
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
    dedup_extra: Optional[str] = None,
    now: Optional[datetime] = None,
) -> tuple[CredentialExposure, bool]:
    """Create or refresh one exposure. ``secret_value`` is fingerprinted, never stored."""
    now = now or datetime.utcnow()
    identifier = normalize_identifier(identifier)
    fingerprint = secret_fingerprint(secret_value) if secret_value else None
    key = make_dedup_key(
        provider=provider, source_name=source_name, identifier=identifier,
        credential_type=credential_type, affected_url=affected_url, fingerprint=fingerprint,
        extra=dedup_extra,
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
                credential_type=credential_type_for_breach(breach),
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
        assets = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.asset_type.in_([AssetType.EMAIL, AssetType.OTHER]),
                Asset.value.like("%@%"),
            )
            .order_by(Asset.id)
            .limit(limit * 5)
            .all()
        )
        # Personal addresses before role mailboxes like info@ or hostmaster@.
        assets.sort(key=lambda a: bool((a.metadata_ or {}).get("role_account")))
        for asset in assets:
            add(asset.value)
    return picked


# ── Organization domains and hosts ───────────────────────────────────────────

def organization_domains(db: Session, organization_id: int, limit: int = 20) -> List[str]:
    """The org's primary domain plus root domains of its owned or in-scope assets."""
    from sqlalchemy import func, or_

    domains: List[str] = []
    org = db.get(Organization, organization_id)
    if org is not None and org.domain:
        domains.append(org.domain.strip().lower())
    rows = (
        db.query(Asset.root_domain, func.count(Asset.id))
        .filter(
            Asset.organization_id == organization_id,
            Asset.root_domain.isnot(None),
            or_(Asset.is_owned.is_(True), Asset.in_scope.is_(True)),
        )
        .group_by(Asset.root_domain)
        .order_by(func.count(Asset.id).desc())
        .limit(limit)
        .all()
    )
    for root, _count in rows:
        root = (root or "").strip().lower()
        if root and root not in domains:
            domains.append(root)
    return domains[:limit]


def host_asset_index(db: Session, organization_id: int) -> Dict[str, int]:
    """Map lowercase hostnames to the org's asset ids (domains, subdomains, URLs)."""
    from urllib.parse import urlsplit

    index: Dict[str, int] = {}
    for asset_id, value, live_url, asset_type in (
        db.query(Asset.id, Asset.value, Asset.live_url, Asset.asset_type)
        .filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL]),
        )
    ):
        for raw in (value, live_url):
            if not raw:
                continue
            raw = str(raw).strip().lower()
            host = urlsplit(raw).hostname if "://" in raw else raw.split("/", 1)[0].split(":", 1)[0]
            if host:
                # Prefer hostname assets over URL assets for the same host.
                if host not in index or asset_type != AssetType.URL:
                    index[host] = asset_id
    return index


# ── Hudson Rock ingest ───────────────────────────────────────────────────────

def ingest_hudsonrock_domain(
    db: Session, organization_id: int, result: Any, now: Optional[datetime] = None
) -> Dict[str, int]:
    """Store a ``DomainStealerResult``: the summary plus one row per login URL."""
    now = now or datetime.utcnow()
    hosts = host_asset_index(db, organization_id)
    stats = {"created": 0, "refreshed": 0, "asset_matched": 0}

    summary = (
        db.query(StealerDomainSummary)
        .filter_by(organization_id=organization_id, provider=PROVIDER_HUDSONROCK, domain=result.domain)
        .first()
    )
    if summary is None:
        summary = StealerDomainSummary(
            organization_id=organization_id, provider=PROVIDER_HUDSONROCK, domain=result.domain
        )
        db.add(summary)
    summary.summary = result.summary()
    summary.fetched_at = now

    existing = {
        (row.url, row.audience): row
        for row in db.query(StealerUrlExposure).filter_by(
            organization_id=organization_id, provider=PROVIDER_HUDSONROCK, domain=result.domain
        )
    }
    for item in result.urls:
        row = existing.get((item.url, item.audience))
        if row is None:
            row = StealerUrlExposure(
                organization_id=organization_id,
                provider=PROVIDER_HUDSONROCK,
                domain=result.domain,
                url=item.url,
                audience=item.audience,
                first_seen_at=now,
                status="open",
            )
            db.add(row)
            existing[(item.url, item.audience)] = row
            stats["created"] += 1
        else:
            stats["refreshed"] += 1
        row.host = item.host
        row.occurrence = item.occurrence
        row.last_seen_at = now
        row.last_compromised_at = (
            result.last_employee_compromised if item.audience == "employee"
            else result.last_user_compromised
        )
        row.asset_id = hosts.get(item.host or "")
        if row.asset_id is not None:
            stats["asset_matched"] += 1
        score, severity, category, factors = score_stealer_url(
            url=row.url,
            audience=row.audience,
            occurrence=row.occurrence,
            last_compromised=row.last_compromised_at,
            asset_matched=row.asset_id is not None,
            now=now,
        )
        row.priority_score = score
        row.severity = severity
        row.login_category = category
        row.score_factors = [f.to_dict() for f in factors]
    db.flush()
    return stats


def ingest_hudsonrock_email(
    db: Session,
    organization_id: int,
    index: IdentityIndex,
    email: str,
    infections: Iterable[Any],
) -> Dict[str, int]:
    """One exposure per infected machine tied to an address.

    Infostealers capture saved passwords in plaintext along with browser
    cookies, so these rank as plaintext credentials.
    """
    stats = {"created": 0, "refreshed": 0}
    for infection in infections:
        when = infection.date_compromised
        _, created = upsert_exposure(
            db,
            organization_id,
            index,
            identifier=email,
            provider=PROVIDER_HUDSONROCK,
            source_type=EXPOSURE_SOURCE_STEALER_LOG,
            source_name="Infostealer infection",
            credential_type=CREDENTIAL_PASSWORD_PLAINTEXT,
            data_classes=[
                "Saved passwords",
                "Browser cookies",
                f"{infection.corporate_services} corporate logins on the machine",
            ],
            leak_date=when,
            dedup_extra=(when.isoformat() if when else "unknown-date"),
        )
        stats["created" if created else "refreshed"] += 1
    return stats


# ── Full check ───────────────────────────────────────────────────────────────

async def run_credential_exposure_check(
    db: Session,
    organization_id: int,
    *,
    domains: Optional[List[str]] = None,
    emails: Optional[List[str]] = None,
    max_emails: int = 50,
    providers: Iterable[str] = (PROVIDER_XPOSEDORNOT, PROVIDER_HUDSONROCK),
    breach_service: Any = None,
    hudsonrock: Any = None,
) -> Dict[str, Any]:
    """Harvest addresses, query providers, store and score everything.

    1. Harvest addresses at the org's domains from stored data into EMAIL assets.
    2. Hudson Rock domain search: infostealer counts and login URLs per domain.
    3. Per address, riskiest identities first: XposedOrNot breaches and
       Hudson Rock infections, stored as identity-matched exposures.
    """
    from app.core.config import settings
    from app.services.email_breach_service import get_email_breach_service
    from app.services.email_harvest_service import (
        harvest_organization_emails,
        save_email_assets,
    )
    from app.services.hudsonrock_service import HudsonRockClient, HudsonRockError

    providers = set(providers)
    if not settings.HUDSONROCK_ENABLED:
        providers.discard(PROVIDER_HUDSONROCK)
    breach_service = breach_service or get_email_breach_service()
    if PROVIDER_HUDSONROCK in providers and hudsonrock is None:
        hudsonrock = HudsonRockClient()

    domains = [d.strip().lower() for d in (domains or organization_domains(db, organization_id)) if d]
    out: Dict[str, Any] = {"domains": domains, "providers": sorted(providers), "errors": []}

    harvested = harvest_organization_emails(db, organization_id, domains)
    out["email_harvest"] = {"found": len(harvested), **save_email_assets(db, organization_id, harvested)}
    db.commit()

    if PROVIDER_XPOSEDORNOT in providers and domains:
        out["xposedornot_domain"] = (await breach_service.check_domain_breach_exposure(domains[0])).to_dict()

    if PROVIDER_HUDSONROCK in providers:
        out["hudsonrock_domains"] = {}
        for domain in domains:
            try:
                result = await hudsonrock.search_by_domain(domain)
            except HudsonRockError as exc:
                out["errors"].append(f"hudsonrock {domain}: {exc}")
                continue
            stats = ingest_hudsonrock_domain(db, organization_id, result)
            out["hudsonrock_domains"][domain] = {
                "employees": result.employees,
                "users": result.users,
                "urls": len(result.urls),
                **stats,
            }
            db.commit()

    to_check = emails or emails_to_check(db, organization_id, max_emails)
    to_check = [normalize_identifier(e) for e in to_check][:max_emails]
    out["emails_checked"] = len(to_check)

    if to_check and PROVIDER_XPOSEDORNOT in providers:
        results = await breach_service.batch_check_emails(to_check)
        as_dicts = {email: r.to_dict() for email, r in results.items()}
        out["xposedornot_emails"] = {
            "breached": sum(1 for r in as_dicts.values() if r.get("breached")),
            "errors": sum(1 for r in as_dicts.values() if r.get("error")),
            **ingest_email_breach_results(db, organization_id, as_dicts),
        }
        db.commit()

    if to_check and PROVIDER_HUDSONROCK in providers:
        index = build_identity_index(db, organization_id)
        hr_stats = {"infected": 0, "created": 0, "refreshed": 0}
        for email in to_check:
            try:
                infections = await hudsonrock.search_by_email(email)
            except HudsonRockError as exc:
                out["errors"].append(f"hudsonrock email lookups stopped: {exc}")
                break
            if infections:
                hr_stats["infected"] += 1
                stats = ingest_hudsonrock_email(db, organization_id, index, email, infections)
                hr_stats["created"] += stats["created"]
                hr_stats["refreshed"] += stats["refreshed"]
        out["hudsonrock_emails"] = hr_stats
        db.commit()

    return out
