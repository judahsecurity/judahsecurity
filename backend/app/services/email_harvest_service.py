"""Harvest an organization's email addresses from data the platform already holds.

Sources: asset DNS records (SOA contacts, DMARC/TXT mailto), certificate
details, HTTP headers, asset metadata (WHOIS and integrations), and stored scan
results (crawler links, JavaScript mining). Only addresses at the
organization's own domains are kept. Each one is saved as an ``EMAIL`` asset so
breach and infostealer lookups have people to check.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.scan import Scan

EMAIL_RX = re.compile(r"(?<![\w.+-])([a-z0-9][a-z0-9._%+-]{0,63}@[a-z0-9-]+(?:\.[a-z0-9-]+)+)", re.I)

# Matches that are file names or asset references, not addresses.
_NOT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "js", "css", "ico", "woff", "woff2", "map"}

ROLE_LOCAL_PARTS = {
    "abuse", "admin", "administrator", "billing", "certs", "contact", "dmarc", "dns",
    "domains", "help", "pki", "registrar", "ssl",
    "helpdesk", "hostmaster", "hr", "info", "it", "jobs", "legal", "mail", "marketing",
    "media", "noc", "noreply", "no-reply", "office", "postmaster", "press", "privacy",
    "root", "sales", "security", "service", "support", "webmaster",
}

MAX_SCANS = 300
MAX_STRING_SCAN = 200_000


def _walk_strings(value: Any, budget: List[int]) -> Iterable[str]:
    """Yield strings nested anywhere in JSON-like data, bounded in total size."""
    stack = [value]
    while stack and budget[0] > 0:
        item = stack.pop()
        if isinstance(item, str):
            budget[0] -= len(item)
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def _soa_contacts(dns_records: Any) -> Iterable[str]:
    """SOA RNAME 'hostmaster.example.com.' means hostmaster@example.com."""
    if not isinstance(dns_records, dict):
        return []
    soa = dns_records.get("SOA") or dns_records.get("soa") or []
    out = []
    for rec in soa if isinstance(soa, list) else [soa]:
        parts = str(rec).split()
        if len(parts) >= 2 and "." in parts[1]:
            local, _, domain = parts[1].rstrip(".").partition(".")
            if local and domain:
                out.append(f"{local}@{domain}")
    return out


def extract_emails(text: str, domains: Iterable[str]) -> Set[str]:
    """Addresses in ``text`` at any of ``domains`` or their subdomains."""
    domains = [d.lower().lstrip(".") for d in domains if d]
    found: Set[str] = set()
    for match in EMAIL_RX.finditer(text or ""):
        email = match.group(1).lower().strip(".")
        host = email.rsplit("@", 1)[1]
        if host.rsplit(".", 1)[-1] in _NOT_TLDS:
            continue
        if any(host == d or host.endswith("." + d) for d in domains):
            found.add(email)
    return found


def is_role_account(email: str) -> bool:
    local = email.split("@", 1)[0].lower()
    return local in ROLE_LOCAL_PARTS or local.split("+", 1)[0] in ROLE_LOCAL_PARTS


def harvest_organization_emails(
    db: Session, organization_id: int, domains: List[str]
) -> Dict[str, Set[str]]:
    """Return ``{email: {source, ...}}`` found in stored assets and scans."""
    found: Dict[str, Set[str]] = {}

    def add(emails: Iterable[str], source: str) -> None:
        for email in emails:
            found.setdefault(email, set()).add(source)

    if not domains:
        return found

    for asset in (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            Asset.asset_type != AssetType.EMAIL,
        )
        .yield_per(500)
    ):
        add(extract_emails(" ".join(_soa_contacts(asset.dns_records)), domains), "dns_soa")
        for source, value in (
            ("dns", asset.dns_records),
            ("certificate", asset.ssl_info),
            ("http_headers", asset.http_headers),
            ("asset_metadata", asset.metadata_),
            ("asset_description", asset.description),
        ):
            if not value:
                continue
            budget = [MAX_STRING_SCAN]
            text = value if isinstance(value, str) else " ".join(_walk_strings(value, budget))
            add(extract_emails(text, domains), source)

    for scan in (
        db.query(Scan)
        .filter(Scan.organization_id == organization_id, Scan.results.isnot(None))
        .order_by(Scan.created_at.desc())
        .limit(MAX_SCANS)
    ):
        budget = [MAX_STRING_SCAN]
        text = " ".join(_walk_strings(scan.results, budget))
        add(extract_emails(text, domains), f"scan:{getattr(scan.scan_type, 'value', scan.scan_type)}")

    return found


def save_email_assets(
    db: Session,
    organization_id: int,
    harvested: Dict[str, Set[str]],
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Create or refresh one ``EMAIL`` asset per address."""
    now = now or datetime.utcnow()
    stats = {"created": 0, "refreshed": 0}
    if not harvested:
        return stats
    existing = {
        a.value.lower(): a
        for a in db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type == AssetType.EMAIL,
        )
    }
    for email, sources in sorted(harvested.items()):
        domain = email.rsplit("@", 1)[1]
        asset = existing.get(email)
        meta = {"sources": sorted(sources), "role_account": is_role_account(email)}
        if asset is None:
            asset = Asset(
                organization_id=organization_id,
                asset_type=AssetType.EMAIL,
                name=email,
                value=email,
                root_domain=domain,
                discovery_source="email_harvest",
                association_reason="Address at the organization's domain found in collected data",
                is_public=True,
                metadata_=meta,
                first_seen=now,
                last_seen=now,
            )
            db.add(asset)
            existing[email] = asset
            stats["created"] += 1
        else:
            previous = asset.metadata_ or {}
            meta["sources"] = sorted(set(previous.get("sources") or []) | sources)
            asset.metadata_ = {**previous, **meta}
            asset.last_seen = now
            stats["refreshed"] += 1
    db.flush()
    return stats
