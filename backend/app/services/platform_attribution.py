"""
Ownership attribution for shared / multi-tenant cloud hostnames.

Keyword discovery (SNI IP ranges, Common Crawl, etc.) uses substring matching.
That incorrectly pulls unrelated Azure App Service / Heroku / Vercel hosts into
inventory when a short or accidental keyword appears in the name.

Policy:
  - Non-shared hostnames: allow (existing discovery logic applies).
  - Shared PaaS hostnames (azurewebsites.net, herokuapp.com, …): only persist
    when the tenant label is attributable to the target org (brand token in the
    hostname), or the hostname is under an already-owned corporate domain.
  - Platform wildcards / apexes (*.canadacentral-01.azurewebsites.net): always reject.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence, Set
from urllib.parse import urlparse

# Multi-tenant PaaS / shared hosting suffixes. A hostname under these is NOT
# evidence of ownership by itself — only the tenant label can attribute it.
SHARED_PAAS_SUFFIXES: tuple[str, ...] = (
    "azurewebsites.net",
    "azurestaticapps.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "azurefd.net",
    "azurecontainer.io",
    "blob.core.windows.net",
    "web.core.windows.net",
    "trafficmanager.net",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "amazonaws.com",  # only accepted with brand token in labels
    "appspot.com",
    "firebaseapp.com",
    "web.app",
    "herokuapp.com",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "github.io",
    "gitlab.io",
    "azure-api.net",
    "cognitiveservices.azure.com",
)

# Tokens that must never alone attribute a shared-PaaS hostname to an org.
GENERIC_ATTRIBUTION_TOKENS: frozenset[str] = frozenset(
    {
        "app",
        "apps",
        "web",
        "www",
        "api",
        "test",
        "tests",
        "dev",
        "devel",
        "develop",
        "development",
        "prod",
        "production",
        "staging",
        "stage",
        "uat",
        "qa",
        "sit",
        "site",
        "sites",
        "cloud",
        "azure",
        "aws",
        "gcp",
        "admin",
        "portal",
        "service",
        "services",
        "server",
        "host",
        "hosting",
        "platform",
        "online",
        "system",
        "systems",
        "data",
        "demo",
        "temp",
        "tmp",
        "new",
        "old",
        "my",
        "the",
        "and",
        "for",
        "internal",
        "external",
        "public",
        "private",
        "corp",
        "corporate",
        "company",
        "inc",
        "llc",
        "ltd",
        "automation",  # too common alone (e.g. "Rockwell Automation")
        "digital",
        "software",
        "solutions",
        "technology",
        "technologies",
        "group",
        "global",
        "international",
        "north",
        "south",
        "east",
        "west",
        "central",
        "canada",
        "canadacentral",
        "northeurope",
        "eastus",
        "westus",
        "centralus",
        "westeurope",
    }
)

_MIN_TOKEN_LEN = 5
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class AttributionDecision:
    accept: bool
    reason: str
    paas_suffix: Optional[str] = None


def normalize_hostname(hostname: str) -> str:
    """Lowercase hostname, strip scheme/port/path/wildcard prefix noise."""
    h = (hostname or "").strip().lower()
    if not h:
        return ""
    if "://" in h:
        h = urlparse(h).netloc or h
    h = h.split("/")[0].split("?")[0].split("#")[0]
    h = h.split("@")[-1]
    h = h.split(":")[0]
    if h.startswith("*."):
        h = h[2:]
    return h.strip(".")


def _alnum(value: str) -> str:
    return _NON_ALNUM.sub("", (value or "").lower())


def shared_paas_suffix(hostname: str) -> Optional[str]:
    """Return the matching shared-PaaS suffix, if any."""
    h = normalize_hostname(hostname)
    if not h:
        return None
    # Prefer longest suffix match.
    for suffix in sorted(SHARED_PAAS_SUFFIXES, key=len, reverse=True):
        if h == suffix or h.endswith("." + suffix):
            return suffix
    return None


def is_shared_paas_hostname(hostname: str) -> bool:
    return shared_paas_suffix(hostname) is not None


def is_platform_wildcard(hostname: str) -> bool:
    raw = (hostname or "").strip().lower()
    return raw.startswith("*.") or raw.startswith("%2a.")


def build_attribution_tokens(
    *,
    org_name: Optional[str] = None,
    primary_domain: Optional[str] = None,
    keywords: Optional[Sequence[str]] = None,
    extra: Optional[Sequence[str]] = None,
) -> List[str]:
    """
    Build brand tokens used to attribute shared-PaaS hostnames to an org.

    Examples for Rockwell Automation / rockwellautomation.com:
      rockwellautomation, rockwell, factorytalk (from keywords), …
    """
    tokens: Set[str] = set()

    def _add(raw: Optional[str]) -> None:
        if not raw:
            return
        text = raw.strip().lower()
        if not text:
            return
        compact = _alnum(text)
        if len(compact) >= _MIN_TOKEN_LEN and compact not in GENERIC_ATTRIBUTION_TOKENS:
            tokens.add(compact)
        parts = [p.strip() for p in _NON_ALNUM.split(text) if p and p.strip()]
        # Multi-word brands ("allen-bradley", "Rockwell Automation") should
        # attribute via the compact form, not weak standalone pieces.
        # Only keep unusually long split parts (>=8) as extras.
        min_part = _MIN_TOKEN_LEN if len(parts) == 1 else 8
        for part in parts:
            part_alnum = _alnum(part)
            if len(part) >= min_part and part not in GENERIC_ATTRIBUTION_TOKENS:
                tokens.add(part)
            if len(part_alnum) >= min_part and part_alnum not in GENERIC_ATTRIBUTION_TOKENS:
                tokens.add(part_alnum)

    _add(org_name)
    if org_name:
        # Concatenate multi-word brand: "Rockwell Automation" → rockwellautomation
        _add(_alnum(org_name))

    if primary_domain:
        domain = normalize_hostname(primary_domain)
        _add(domain)
        labels = domain.split(".")
        if labels:
            _add(labels[0])

    for kw in keywords or []:
        _add(kw)
    for kw in extra or []:
        _add(kw)

    # Drop anything that collapsed into a generic token
    return sorted(
        t for t in tokens if t and len(t) >= _MIN_TOKEN_LEN and t not in GENERIC_ATTRIBUTION_TOKENS
    )


def tokens_from_organization(org) -> List[str]:
    """Extract attribution tokens from an Organization ORM/row-like object."""
    if org is None:
        return []
    keywords: List[str] = []
    for field in ("commoncrawl_keywords", "sni_keywords"):
        vals = getattr(org, field, None) or []
        if isinstance(vals, list):
            keywords.extend(str(v) for v in vals if v)

    primary = getattr(org, "domain", None) or getattr(org, "primary_domain", None)
    return build_attribution_tokens(
        org_name=getattr(org, "name", None),
        primary_domain=primary,
        keywords=keywords,
        extra=[getattr(org, "commoncrawl_org_name", None)] if getattr(org, "commoncrawl_org_name", None) else None,
    )


def _under_owned_domain(hostname: str, owned_domains: Iterable[str]) -> bool:
    h = normalize_hostname(hostname)
    for domain in owned_domains or []:
        d = normalize_hostname(domain)
        if not d or is_shared_paas_hostname(d):
            continue
        if h == d or h.endswith("." + d):
            return True
    return False


def _tenant_label(hostname: str, suffix: str) -> str:
    h = normalize_hostname(hostname)
    if h.endswith("." + suffix):
        return h[: -(len(suffix) + 1)]
    if h == suffix:
        return ""
    return h


def hostname_attributed_to_org(
    hostname: str,
    attribution_tokens: Sequence[str],
    *,
    owned_domains: Optional[Iterable[str]] = None,
) -> AttributionDecision:
    """
    Decide whether a discovered hostname should enter inventory for this org.
    """
    raw = (hostname or "").strip()
    if not raw:
        return AttributionDecision(False, "empty hostname")

    if is_platform_wildcard(raw):
        suffix = shared_paas_suffix(raw)
        return AttributionDecision(
            False,
            "rejected platform wildcard certificate/SNI name",
            paas_suffix=suffix,
        )

    h = normalize_hostname(raw)
    if not h:
        return AttributionDecision(False, "empty hostname")

    if owned_domains and _under_owned_domain(h, owned_domains):
        return AttributionDecision(True, "hostname under owned corporate domain")

    suffix = shared_paas_suffix(h)
    if not suffix:
        return AttributionDecision(True, "not a shared PaaS hostname")

    # Never ingest the shared platform apex itself.
    if h == suffix:
        return AttributionDecision(False, f"rejected shared PaaS apex ({suffix})", suffix)

    tokens = [
        t for t in (_alnum(tok) for tok in attribution_tokens or [])
        if t and len(t) >= _MIN_TOKEN_LEN and t not in GENERIC_ATTRIBUTION_TOKENS
    ]
    if not tokens:
        return AttributionDecision(
            False,
            f"rejected shared PaaS host without org brand tokens ({suffix})",
            suffix,
        )

    tenant = _tenant_label(h, suffix)
    tenant_norm = _alnum(tenant)
    if not tenant_norm:
        return AttributionDecision(False, f"rejected empty PaaS tenant label ({suffix})", suffix)

    for tok in tokens:
        if tok in tenant_norm:
            return AttributionDecision(
                True,
                f"shared PaaS host attributed via brand token '{tok}'",
                suffix,
            )

    return AttributionDecision(
        False,
        f"rejected unattributed shared PaaS host ({suffix})",
        suffix,
    )


def filter_attributed_hostnames(
    hostnames: Iterable[str],
    attribution_tokens: Sequence[str],
    *,
    owned_domains: Optional[Iterable[str]] = None,
) -> tuple[list[str], list[tuple[str, str]]]:
    """
    Split hostnames into (accepted, rejected_with_reason).
    """
    accepted: list[str] = []
    rejected: list[tuple[str, str]] = []
    seen: set[str] = set()

    for host in hostnames:
        key = normalize_hostname(host) or (host or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        decision = hostname_attributed_to_org(
            host,
            attribution_tokens,
            owned_domains=owned_domains,
        )
        if decision.accept:
            accepted.append(host)
        else:
            rejected.append((host, decision.reason))
    return accepted, rejected


def iter_unattributed_shared_paas_assets(
    assets: Iterable[Any],
    attribution_tokens: Sequence[str],
    *,
    owned_domains: Optional[Iterable[str]] = None,
) -> list[tuple[Any, AttributionDecision]]:
    """
    Return (asset, decision) pairs for shared-PaaS assets that fail ownership attribution.

    `assets` may be ORM rows or any objects with a string `.value` (or `.name`) hostname.
    """
    rejected: list[tuple[Any, AttributionDecision]] = []
    for asset in assets:
        host = getattr(asset, "value", None) or getattr(asset, "name", None) or ""
        if not host:
            continue
        if not is_shared_paas_hostname(host) and not is_platform_wildcard(str(host)):
            continue
        decision = hostname_attributed_to_org(
            str(host),
            attribution_tokens,
            owned_domains=owned_domains,
        )
        if not decision.accept:
            rejected.append((asset, decision))
    return rejected


def shared_paas_value_match_clause(column):
    """SQLAlchemy OR clause matching shared PaaS hostnames on a string column."""
    from sqlalchemy import or_

    clauses = []
    for suffix in SHARED_PAAS_SUFFIXES:
        clauses.append(column == suffix)
        clauses.append(column.ilike(f"%.{suffix}"))
    clauses.append(column.ilike("*.%"))
    return or_(*clauses)
