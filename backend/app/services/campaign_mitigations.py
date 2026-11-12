"""Interim mitigations from active exploitation campaigns.

Source: the Rapid Threat Intel community feed
(https://github.com/daniyyell-dev/rapid-threat-intel, MIT licence), whose
analyst-reviewed ``site/feed.json`` describes threats seen in the last 90 days.
Each threat carries recommended actions and post-compromise behaviours.

The platform uses only the vulnerability/misconfiguration side of that feed:

* a finding whose CVE is named by an active threat gets that threat's
  recommended actions as *interim mitigations* (useful when patching alone is
  not enough, or no fix exists yet) and its behaviours as
  *check-for-compromise* steps;
* an exposure/misconfiguration finding whose product (exposed panel, detected
  technology) is the target of an active campaign gets the same, marked as a
  product match.

Indicator block lists are deliberately not ingested: they are SOC/EDR data.

Feed text is third-party, AI-assisted content. It is normalised to bounded
plain strings, links are limited to https URLs, and it must only ever be
rendered as text — never interpolated into prompts or executed.

The request path reads the disk cache only. ``refresh_campaign_feed`` is called
by the vuln-intel worker; a missing cache triggers one non-blocking background
refresh.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.services.vuln_intel_feeds import (
    _cache_dir,
    _cache_fresh,
    _http_get_json,
    _write_json,
    read_json_cache,
)

logger = logging.getLogger(__name__)

FEED_URL = (
    "https://raw.githubusercontent.com/daniyyell-dev/rapid-threat-intel/main/site/feed.json"
)
FEED_HOME = "https://github.com/daniyyell-dev/rapid-threat-intel"
CACHE_FILENAME = "campaign_intel_feed.json"
SOURCE_NAME = "Rapid Threat Intel"
SOURCE_LICENCE = "MIT"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_TEXT = 1500
_MAX_ITEMS = 12
_MAX_CAMPAIGNS_PER_FINDING = 5

# Internet-facing products whose exposure is itself the finding (panels,
# appliances, detected technologies). Aliases are matched on whole words after
# both sides are normalised to lowercase alphanumerics separated by spaces.
PRODUCT_ALIASES: Dict[str, Tuple[str, ...]] = {
    "N-able N-central": ("n central", "ncentral"),
    "Check Point Security Gateway": ("check point", "checkpoint"),
    "Ivanti Connect Secure": ("ivanti connect secure", "pulse connect secure", "pulse secure"),
    "Cisco BroadWorks": ("broadworks",),
    "ConnectWise ScreenConnect": ("screenconnect", "connectwise control"),
    "Xen Orchestra": ("xen orchestra", "xcp ng"),
    "VMware ESXi": ("esxi",),
    "VMware vCenter": ("vcenter",),
    "Ahsay Backup Server": ("ahsay", "ahsaycbs"),
    "Microsoft Exchange": ("microsoft exchange", "exchange server", "outlook web access", "owa"),
    "Microsoft SharePoint": ("sharepoint",),
    "OpenSSH": ("openssh",),
    "FreeSWITCH": ("freeswitch",),
    "Fortinet FortiGate": ("fortigate", "fortios", "fortiweb", "fortimanager"),
    "Citrix NetScaler": ("netscaler", "citrix adc", "citrix gateway"),
    "Palo Alto GlobalProtect": ("globalprotect", "pan os"),
    "SonicWall": ("sonicwall",),
    "F5 BIG-IP": ("big ip",),
    "Atlassian Confluence": ("confluence",),
    "GitLab": ("gitlab",),
    "Jenkins": ("jenkins",),
    "MOVEit Transfer": ("moveit",),
    "Cisco ASA": ("cisco asa", "anyconnect"),
}

_refresh_lock = threading.Lock()
_background_started = False
_memo: Dict[str, Any] = {"key": None, "index": None}


# ── Normalisation ────────────────────────────────────────────────────────────

def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = _CONTROL_RE.sub("", value).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 1].rstrip() + "…"
    return cleaned


def _url(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value.lower().startswith("https://") or len(value) > 2048:
        return None
    if any(ch.isspace() for ch in value) or _CONTROL_RE.search(value):
        return None
    return value


def _words(value: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", value.lower()).strip() + " "


def _cves(*values: Any) -> List[str]:
    found: Dict[str, None] = {}  # ordered set
    for value in values:
        if isinstance(value, (list, tuple)):
            found.update(dict.fromkeys(_cves(*value)))
        elif isinstance(value, str):
            found.update(dict.fromkeys(m.upper() for m in _CVE_RE.findall(value)))
    return list(found)


def _products(*values: str) -> List[str]:
    haystack = _words(" ".join(v for v in values if v))
    return [
        product
        for product, aliases in PRODUCT_ALIASES.items()
        if any(f" {alias} " in haystack for alias in aliases)
    ]


def _normalise_threat(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    name = _text(raw.get("name"), 300)
    if not name:
        return None
    actions = [
        _text(a) for a in (raw.get("recommended_actions") or [])[:_MAX_ITEMS] if _text(a)
    ]
    checks = []
    for ioa in (raw.get("ioas") or [])[:_MAX_ITEMS]:
        if not isinstance(ioa, dict):
            continue
        look_for = _text(ioa.get("artefact"))
        if not look_for:
            continue
        checks.append({
            "title": _text(ioa.get("title"), 200),
            "look_for": look_for,
            "log_source": _text(ioa.get("log_source"), 400),
            "why": _text(ioa.get("why")),
            "action": _text(ioa.get("action"), 20).lower() or "hunt",
            "source_url": _url(ioa.get("source_url")),
            "source_name": _text(ioa.get("source_name"), 120),
        })
    sources = []
    for src in (raw.get("sources") or [])[:_MAX_ITEMS]:
        if isinstance(src, dict) and _url(src.get("url")):
            sources.append({
                "label": _text(src.get("label") or src.get("name"), 200) or src["url"],
                "url": _url(src.get("url")),
            })
    queries = []
    for q in (raw.get("queries") or [])[:_MAX_ITEMS]:
        if isinstance(q, dict) and _url(q.get("url")):
            queries.append({
                "platform": _text(q.get("platform"), 60),
                "language": _text(q.get("language"), 20),
                "url": _url(q.get("url")),
            })
    targets = raw.get("targets") if isinstance(raw.get("targets"), dict) else {}
    summary = _text(raw.get("summary"), 3000)
    headline = _text(raw.get("headline"), 400)
    caveat = _text(raw.get("caveat"))
    short = _text(raw.get("short"), 120)
    return {
        "id": _text(raw.get("id"), 200),
        "name": name,
        "category": _text(raw.get("category"), 120),
        "published": _text(raw.get("published"), 20),
        "last_updated": _text(raw.get("last_updated"), 20),
        "headline": headline,
        "summary": summary,
        "caveat": caveat,
        "cves": _cves(name, headline, summary, actions, caveat),
        # Products are taken from the title fields only, so a passing mention
        # in a long summary does not tie a campaign to a product.
        "products": _products(name, short, headline),
        "mitigations": actions,
        "compromise_checks": checks,
        "mitre": [
            _text(m.get("id"), 20)
            for m in (raw.get("mitre") or [])[:20]
            if isinstance(m, dict) and _text(m.get("id"), 20)
        ],
        "sectors": [_text(s, 120) for s in (targets.get("sectors") or [])[:_MAX_ITEMS] if _text(s, 120)],
        "regions": [_text(r, 80) for r in (targets.get("regions") or [])[:_MAX_ITEMS] if _text(r, 80)],
        "sources": sources,
        "hunt_queries": queries,
        "url": _url(raw.get("repo_url")) or FEED_HOME,
    }


def normalise_feed(payload: Any) -> Dict[str, Any]:
    """Reduce the raw feed to campaigns relevant to vulnerabilities/exposures."""
    threats = payload.get("threats") if isinstance(payload, dict) else None
    campaigns = []
    for raw in threats or []:
        if not isinstance(raw, dict):
            continue
        threat = _normalise_threat(raw)
        if threat and (threat["cves"] or threat["products"]) and threat["mitigations"]:
            campaigns.append(threat)
    campaigns.sort(key=lambda t: t["last_updated"] or t["published"], reverse=True)
    return {
        "source": SOURCE_NAME,
        "source_url": FEED_HOME,
        "licence": SOURCE_LICENCE,
        "feed_last_updated": _text(payload.get("last_updated"), 40) if isinstance(payload, dict) else "",
        "fetched_at": int(time.time()),
        "campaigns": campaigns,
    }


# ── Fetch and cache ──────────────────────────────────────────────────────────

def _enabled() -> bool:
    return os.environ.get("CAMPAIGN_INTEL_ENABLED", "true").strip().lower() not in {"0", "false", "no", "off"}


def refresh_campaign_feed(*, force: bool = False, refresh_hours: float = 2.0) -> Dict[str, Any]:
    """Fetch and cache the feed; keep the stale cache when the fetch fails."""
    if not _enabled():
        return {"status": "disabled", "campaigns": 0}
    path = os.path.join(_cache_dir(), CACHE_FILENAME)
    with _refresh_lock:
        if not force and _cache_fresh(path, refresh_hours):
            cached = read_json_cache(CACHE_FILENAME) or {}
            return {"status": "fresh", "campaigns": len(cached.get("campaigns") or [])}
        url = os.environ.get("CAMPAIGN_INTEL_FEED_URL") or FEED_URL
        try:
            normalised = normalise_feed(_http_get_json(url, timeout=60))
        except Exception as exc:  # network or parse failure: keep what we have
            logger.warning("Campaign intel refresh failed: %s", exc)
            return {"status": "error", "error": str(exc)[:200]}
        _write_json(path, normalised)
        return {"status": "refreshed", "campaigns": len(normalised["campaigns"])}


def _start_background_refresh() -> None:
    global _background_started
    if _background_started or not _enabled():
        return
    _background_started = True
    threading.Thread(
        target=refresh_campaign_feed, name="campaign-intel-refresh", daemon=True
    ).start()


def _load_index() -> Optional[Dict[str, Any]]:
    cached = read_json_cache(CACHE_FILENAME)
    if not isinstance(cached, dict):
        _start_background_refresh()
        return None
    key = cached.get("fetched_at")
    if _memo["key"] == key and _memo["index"] is not None:
        return _memo["index"]
    by_cve: Dict[str, List[Dict[str, Any]]] = {}
    by_product: Dict[str, List[Dict[str, Any]]] = {}
    for campaign in cached.get("campaigns") or []:
        for cve in campaign.get("cves") or []:
            by_cve.setdefault(cve, []).append(campaign)
        for product in campaign.get("products") or []:
            by_product.setdefault(product, []).append(campaign)
    index = {"meta": cached, "by_cve": by_cve, "by_product": by_product}
    _memo.update(key=key, index=index)
    return index


# ── Lookup ───────────────────────────────────────────────────────────────────

def campaigns_for_finding(
    *,
    cve_id: Optional[str] = None,
    title: Optional[str] = None,
    template_id: Optional[str] = None,
    tags: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Active campaigns matching a finding's CVE(s) or exposed product.

    Never raises; returns ``{"campaigns": []}`` when there is no data.
    """
    empty: Dict[str, Any] = {"campaigns": [], "source": SOURCE_NAME, "source_url": FEED_HOME}
    try:
        index = _load_index()
        if not index:
            return empty
        tag_list = [t for t in (tags or []) if isinstance(t, str)]
        finding_cves = _cves(cve_id, title, template_id, tag_list)
        finding_products = _products(title or "", template_id or "", " ".join(tag_list))

        matches: List[Dict[str, Any]] = []
        seen: set = set()
        for cve in finding_cves:
            for campaign in index["by_cve"].get(cve, []):
                if campaign["id"] in seen:
                    continue
                seen.add(campaign["id"])
                matches.append({**campaign, "match": {"type": "cve", "value": cve}})
        for product in finding_products:
            for campaign in index["by_product"].get(product, []):
                if campaign["id"] in seen:
                    continue
                seen.add(campaign["id"])
                matches.append({**campaign, "match": {"type": "product", "value": product}})

        meta = index["meta"]
        return {
            "campaigns": matches[:_MAX_CAMPAIGNS_PER_FINDING],
            "source": SOURCE_NAME,
            "source_url": FEED_HOME,
            "licence": meta.get("licence", SOURCE_LICENCE),
            "feed_last_updated": meta.get("feed_last_updated"),
        }
    except Exception:
        logger.exception("Campaign intel lookup failed")
        return empty
