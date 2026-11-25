"""
Domain attribution - turn discovery results into scored ownership evidence.

Every root domain surfaced by external discovery gets a list of *evidence*
entries (one per independent reason we think the org owns it). The final
ownership score combines them with a noisy-OR over distinct signal classes,
so one fuzzy company-name match stays in review while M365 tenant membership
plus a matching registrant email is confirmed:

    score = 1 - prod(1 - p_signal)   (strongest entry per signal class)

Evidence found while pivoting from a discovered (not seed) domain is
discounted by that domain's own score, so a wrongly-attributed domain cannot
launder its neighbours into "confirmed".

Evidence dicts keep the existing ``Asset.discovery_chain`` shape (step,
source, match_type, match_value, query_domain, timestamp, confidence) and add
``signal`` and ``depth``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from app.services.ownership_pivots import registrable_domain

# signal -> (probability the domain is owned given this signal alone, label)
SIGNALS: Dict[str, Tuple[float, str]] = {
    "primary": (1.00, "primary domain"),
    "m365_tenant": (0.95, "same Microsoft 365 tenant"),
    "registrant_email_org": (0.90, "registrant email on the org's domain"),
    "registrant_email": (0.75, "registrant email"),
    "shared_mailserver": (0.85, "org-specific mail server"),
    "shared_nameserver": (0.80, "org-specific nameserver"),
    "cert_organization": (0.80, "TLS certificate issued to the organization"),
    "analytics_id": (0.80, "shared analytics / tag-manager ID"),
    "redirect": (0.80, "website redirects to an owned domain"),
    "associated_domain": (0.70, "SecurityTrails associated domain"),
    "registrant_company": (0.60, "registrant organization name"),
    "spf_include": (0.60, "referenced by the org's SPF record"),
    "dns_host": (0.60, "hosts the org's MX / NS"),
    "dmarc_report": (0.55, "receives the org's DMARC reports"),
    "registrar": (0.50, "scoped registrar"),
    "keyword_match": (0.45, "name matches org keywords"),
    "favicon_hash": (0.45, "identical favicon"),
    "other": (0.50, "external discovery source"),
}

CONFIRMED_THRESHOLD = 90
LIKELY_THRESHOLD = 70

TIER_CONFIRMED = "confirmed"
TIER_LIKELY = "likely"
TIER_REVIEW = "review"

# Map (source, raw_data key) -> signal for map-shaped raw data
# ({match_value: [domains...]}). Registrant email is special-cased.
_RAW_MAP_SIGNALS: Dict[str, List[Tuple[str, str]]] = {
    "whoxy": [("domains_by_email", "@email"), ("domains_by_company", "registrant_company")],
    "securitytrails": [
        ("domains_by_email", "@email"),
        ("domains_by_registrar", "registrar"),
        ("domains_by_ns", "shared_nameserver"),
        ("domains_by_mx", "shared_mailserver"),
    ],
    "reverse_dns": [("domains_by_ns", "shared_nameserver"), ("domains_by_mx", "shared_mailserver")],
    "crtsh_org": [("domains_by_org", "cert_organization")],
    "mail_auth": [
        ("domains_by_spf", "spf_include"),
        ("domains_by_dmarc", "dmarc_report"),
        ("domains_by_dns_host", "dns_host"),
    ],
    "web_fingerprint": [
        ("domains_by_tracking_id", "analytics_id"),
        ("domains_by_favicon", "favicon_hash"),
    ],
}

_FLAT_SOURCE_SIGNALS = {
    "m365": "m365_tenant",
    "commoncrawl": "keyword_match",
    "commoncrawl_comprehensive": "keyword_match",
    "sni_ip_ranges": "keyword_match",
}


@dataclass
class AttributionScore:
    score: int
    tier: str
    signals: List[str] = field(default_factory=list)

    @property
    def expandable(self) -> bool:
        """Strong enough to pivot from (recursive discovery)."""
        return self.tier in (TIER_CONFIRMED, TIER_LIKELY)


def tier_for(score: int) -> str:
    if score >= CONFIRMED_THRESHOLD:
        return TIER_CONFIRMED
    if score >= LIKELY_THRESHOLD:
        return TIER_LIKELY
    return TIER_REVIEW


def score_evidence(evidence: Iterable[Mapping[str, Any]]) -> AttributionScore:
    best: Dict[str, float] = {}
    for ev in evidence or []:
        sig = ev.get("signal") or "other"
        p = max(0.0, min(1.0, float(ev.get("confidence", 0)) / 100.0))
        if p > best.get(sig, 0.0):
            best[sig] = p
    if not best:
        return AttributionScore(score=0, tier=TIER_REVIEW, signals=[])
    miss = 1.0
    for p in best.values():
        miss *= 1.0 - p
    score = int(round((1.0 - miss) * 100))
    ordered = sorted(best, key=lambda s: -best[s])
    return AttributionScore(score=score, tier=tier_for(score), signals=ordered)


def _make_evidence(
    *,
    source: str,
    signal: str,
    query_domain: str,
    depth: int,
    parent_score: int,
    match_type: Optional[str] = None,
    match_value: Optional[str] = None,
) -> Dict[str, Any]:
    weight, label = SIGNALS.get(signal, SIGNALS["other"])
    # Seed-level evidence (depth 0) is taken at face value; pivots from a
    # discovered domain inherit that domain's uncertainty.
    trust = 1.0 if depth == 0 else max(0.0, min(1.0, parent_score / 100.0))
    ev: Dict[str, Any] = {
        "source": source,
        "signal": signal,
        "match_type": match_type or label,
        "query_domain": query_domain,
        "depth": depth,
        "timestamp": datetime.utcnow().isoformat(),
        "confidence": int(round(weight * trust * 100)),
    }
    if match_value is not None:
        ev["match_value"] = match_value
    return ev


def _email_signal(email: str, org_roots: Iterable[str]) -> str:
    dom = registrable_domain(email) if "@" in (email or "") else ""
    return "registrant_email_org" if dom and dom in set(org_roots) else "registrant_email"


def collect_evidence(
    results: Mapping[str, Any],
    query_domain: str,
    *,
    depth: int = 0,
    parent_score: int = 100,
    org_roots: Optional[Iterable[str]] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build ``{domain: [evidence, ...]}`` for every *root domain* in ``results``
    (a mapping of name -> DiscoveryResult). Subdomains are not handled here.
    """
    roots = set(org_roots or ()) | {registrable_domain(query_domain)}
    out: Dict[str, List[Dict[str, Any]]] = {}

    def add(domain: str, ev: Dict[str, Any]) -> None:
        d = (domain or "").strip().lower().rstrip(".")
        if not d or "." not in d:
            return
        out.setdefault(d, []).append(ev)

    for result in results.values():
        if not getattr(result, "success", False):
            continue
        source = str(getattr(result, "source", "") or "")
        raw = getattr(result, "raw_data", None) or {}
        evidenced: set = set()

        for raw_key, signal in _RAW_MAP_SIGNALS.get(source, []):
            for match_value, domains in (raw.get(raw_key) or {}).items():
                sig = _email_signal(match_value, roots) if signal == "@email" else signal
                mtype = "email" if signal == "@email" else None
                for d in domains or []:
                    add(d, _make_evidence(
                        source=source, signal=sig, query_domain=query_domain,
                        depth=depth, parent_score=parent_score,
                        match_type=mtype, match_value=match_value,
                    ))
                    evidenced.add(d)

        if source == "securitytrails":
            for d in raw.get("domains_associated") or []:
                add(d, _make_evidence(
                    source=source, signal="associated_domain", query_domain=query_domain,
                    depth=depth, parent_score=parent_score, match_value=query_domain,
                ))
                evidenced.add(d)

        flat_signal = _FLAT_SOURCE_SIGNALS.get(source, "other")
        for d in getattr(result, "domains", None) or []:
            if d in evidenced:
                continue
            add(d, _make_evidence(
                source=source, signal=flat_signal, query_domain=query_domain,
                depth=depth, parent_score=parent_score,
                match_value=query_domain if flat_signal == "m365_tenant" else None,
            ))

    return out


def merge_evidence(
    into: Dict[str, List[Dict[str, Any]]], new: Mapping[str, List[Dict[str, Any]]]
) -> List[str]:
    """Merge ``new`` into ``into``; return domains that were not present before."""
    added: List[str] = []
    for domain, evs in new.items():
        if domain not in into:
            into[domain] = []
            added.append(domain)
        seen = {(e.get("source"), e.get("signal"), e.get("match_value"), e.get("query_domain"))
                for e in into[domain]}
        for ev in evs:
            key = (ev.get("source"), ev.get("signal"), ev.get("match_value"), ev.get("query_domain"))
            if key not in seen:
                into[domain].append(ev)
                seen.add(key)
    return added


def number_steps(evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for i, ev in enumerate(evidence, start=1):
        ev["step"] = i
    return evidence


def describe(domain: str, evidence: List[Dict[str, Any]], score: AttributionScore) -> str:
    """Human-readable association reason listing each independent signal."""
    if "primary" in score.signals:
        return "Primary domain for organization"
    parts: List[str] = []
    seen = set()
    for ev in sorted(evidence, key=lambda e: -int(e.get("confidence", 0))):
        sig = ev.get("signal") or "other"
        label = SIGNALS.get(sig, SIGNALS["other"])[1]
        mv = ev.get("match_value")
        text = f"{label} '{mv}'" if mv else f"{label} ({ev.get('source')})"
        via = ev.get("query_domain")
        if ev.get("depth") and via and via not in (domain, mv):
            text += f" via {via}"
        if text not in seen:
            seen.add(text)
            parts.append(text)
    summary = "; ".join(parts[:4]) if parts else "external discovery"
    tail = f" (+{len(parts) - 4} more)" if len(parts) > 4 else ""
    return f"Ownership {score.tier} ({score.score}%): {summary}{tail}"
