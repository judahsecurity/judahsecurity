"""Root-domain ownership discovery: pivots, scoring, recursive expansion."""

import asyncio
import os
from typing import Dict, List


os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-0123456789")

from app.services.domain_attribution import (  # noqa: E402
    TIER_CONFIRMED,
    TIER_LIKELY,
    TIER_REVIEW,
    collect_evidence,
    describe,
    merge_evidence,
    score_evidence,
)
from app.services.external_discovery_service import (  # noqa: E402
    DiscoveryResult,
    ExternalDiscoveryService,
)
from app.services.ownership_pivots import (  # noqa: E402
    candidate_domains_from_hosts,
    extract_tracking_ids,
    find_favicon_href,
    is_usable_registrant_email,
    murmur3_32,
    parse_dmarc,
    parse_spf,
    registrable_domain,
)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def test_registrable_domain():
    assert registrable_domain("sic.rockwellautomation.com") == "rockwellautomation.com"
    assert registrable_domain("www.rockwellautomation.co.jp") == "rockwellautomation.co.jp"
    assert registrable_domain("a.b.rockwellautomation.com.cn") == "rockwellautomation.com.cn"
    assert registrable_domain("dmarc@reports.Example.COM") == "example.com"
    assert registrable_domain("https://foo.example.org:8443/x") == "example.org"
    assert registrable_domain("*.example.net") == "example.net"


def test_parse_spf_includes_redirect_and_macros():
    recs = [
        '"v=spf1 include:_spf.rockwellautomation.com include:spf.protection.outlook.com "'
        ' "-include:%{i}._ip.%{h}._ehlo.%{d}._spf.vali.email redirect=_spf.ra-mail.net ~all"',
        "google-site-verification=abc",
    ]
    out = parse_spf(recs)
    assert "_spf.rockwellautomation.com" in out["includes"]
    assert "spf.protection.outlook.com" in out["includes"]
    assert "_spf.vali.email" in out["includes"]
    assert out["redirects"] == ["_spf.ra-mail.net"]


def test_parse_dmarc():
    rec = ["v=DMARC1; p=reject; rua=mailto:dmarc@ra-reports.com!10m,mailto:x@rua.agari.com; ruf=mailto:f@ra.com"]
    assert parse_dmarc(rec) == ["dmarc@ra-reports.com", "x@rua.agari.com", "f@ra.com"]


def test_candidates_filter_shared_providers_and_self():
    hosts = [
        "spf.protection.outlook.com", "_spf.google.com", "sendgrid.net",
        "mxa-001e2002.gslb.pphosted.com", "_spf.rockwellautomation.com",
        "spf.ra-mail.net", "x@rua.agari.com",
    ]
    assert candidate_domains_from_hosts(hosts, exclude=["rockwellautomation.com"]) == ["ra-mail.net"]


def test_registrant_email_filter():
    assert is_usable_registrant_email("domains@rockwellautomation.com")
    assert not is_usable_registrant_email("abuse@markmonitor.com")
    assert not is_usable_registrant_email("hostmaster@cscglobal.com")
    assert not is_usable_registrant_email("x@withheldforprivacy.com")
    assert not is_usable_registrant_email("not-an-email")


def test_tracking_ids_and_favicon():
    html = """
      <link rel="shortcut icon" href="/etc/ra/favicon.ico">
      <script>ga('create', 'UA-1234567-12', 'auto'); gtag('config', "G-ABCDEF1234");</script>
      <script src="https://www.googletagmanager.com/gtm.js?id=GTM-ABC12DE"></script>
      data-ad-client="ca-pub-1234567890123456"
    """
    ids = extract_tracking_ids(html)
    assert ids["ua"] == ["UA-1234567"]
    assert ids["ga4"] == ["G-ABCDEF1234"]
    assert ids["gtm"] == ["GTM-ABC12DE"]
    assert ids["adsense"] == ["pub-1234567890123456"]
    assert find_favicon_href(html) == "/etc/ra/favicon.ico"


def test_murmur3_matches_mmh3_reference_values():
    assert murmur3_32(b"") == 0
    assert murmur3_32(b"hello") == 613153351
    assert murmur3_32(b"foo") == -156908512


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def _ev(signal, conf, **kw):
    return {"source": kw.pop("source", "x"), "signal": signal, "confidence": conf, **kw}


def test_single_fuzzy_company_match_needs_review():
    s = score_evidence([_ev("registrant_company", 60)])
    assert s.tier == TIER_REVIEW and not s.expandable


def test_independent_signals_corroborate():
    s = score_evidence([_ev("m365_tenant", 95), _ev("registrant_email_org", 90)])
    assert s.tier == TIER_CONFIRMED and s.score == 100 - 0  # 1-(.05*.10)=.995 -> 100
    weak = score_evidence([_ev("spf_include", 60), _ev("dmarc_report", 55)])
    assert weak.tier == TIER_LIKELY  # 1-(.4*.45)=.82


def test_same_signal_class_does_not_stack():
    s = score_evidence([_ev("registrant_company", 60), _ev("registrant_company", 60, match_value="b")])
    assert s.score == 60


def test_collect_evidence_maps_sources_to_signals():
    results = {
        "whoxy": DiscoveryResult(
            source="whoxy", success=True, domains=["a.com", "b.com", "c.com"],
            raw_data={
                "domains_by_email": {"dns@rockwellautomation.com": ["a.com"], "ops@vendor.com": ["b.com"]},
                "domains_by_company": {"Rockwell Automation": ["c.com"]},
            },
        ),
        "m365": DiscoveryResult(source="m365", success=True, domains=["d.com"]),
        "crtsh_org": DiscoveryResult(
            source="crtsh_org", success=True, domains=["e.com"],
            raw_data={"domains_by_org": {"Rockwell Automation, Inc.": ["e.com"]}},
        ),
        "failed": DiscoveryResult(source="otx", success=False, domains=["zzz.com"]),
    }
    ev = collect_evidence(results, "rockwellautomation.com")
    sig = {d: [e["signal"] for e in evs] for d, evs in ev.items()}
    assert sig == {
        "a.com": ["registrant_email_org"],
        "b.com": ["registrant_email"],
        "c.com": ["registrant_company"],
        "d.com": ["m365_tenant"],
        "e.com": ["cert_organization"],
    }


def test_pivot_evidence_is_discounted_by_parent_score():
    results = {"m365": DiscoveryResult(source="m365", success=True, domains=["x.com"])}
    ev = collect_evidence(results, "acq.com", depth=1, parent_score=70)
    assert ev["x.com"][0]["confidence"] == round(95 * 0.7)


def test_merge_and_describe():
    into = {"a.com": [_ev("m365_tenant", 95, source="m365", match_value="seed.com", query_domain="seed.com")]}
    added = merge_evidence(into, {
        "a.com": [_ev("m365_tenant", 95, source="m365", match_value="seed.com", query_domain="seed.com")],
        "b.com": [_ev("spf_include", 60)],
    })
    assert added == ["b.com"] and len(into["a.com"]) == 1
    text = describe("a.com", into["a.com"], score_evidence(into["a.com"]))
    assert text.startswith("Ownership confirmed (95%)") and "seed.com" in text


# ---------------------------------------------------------------------------
# Recursive expansion
# ---------------------------------------------------------------------------

class _StubService(ExternalDiscoveryService):
    """ExternalDiscoveryService with network pivots replaced by fixtures."""

    def __init__(self, m365: Dict[str, List[str]], redirects: Dict[str, str], ids: Dict[str, List[str]]):
        self.db = None
        self.organization_id = 1
        self._api_configs = {}
        self.m365_map, self.redirects, self.ids = m365, redirects, ids
        self.calls: List[str] = []

    async def discover_m365(self, domain):
        self.calls.append(f"m365:{domain}")
        return DiscoveryResult(source="m365", success=True, domains=self.m365_map.get(domain, []))

    async def discover_mail_auth(self, domain, max_spf_lookups=10):
        return DiscoveryResult(source="mail_auth", success=True, raw_data={})

    async def discover_web_fingerprint(self, domain, reverse_lookups=True):
        return DiscoveryResult(
            source="web_fingerprint", success=True,
            raw_data={
                "redirect_domain": self.redirects.get(domain, domain),
                "tracking_ids": {"gtm": self.ids.get(domain, [])} if self.ids.get(domain) else {},
            },
        )


def test_expansion_recurses_and_corroborates():
    seed = "rockwellautomation.com"
    svc = _StubService(
        m365={
            seed: [seed, "allen-bradley.com"],
            # The acquisition's own tenant surfaces a domain the seed's did not
            "allen-bradley.com": ["allen-bradley.com", "ab-legacy.com"],
        },
        redirects={"rockwellbrand.net": seed},
        ids={seed: ["GTM-RA1234"], "ra-events.com": ["GTM-RA1234"]},
    )
    seed_results = {
        "m365": DiscoveryResult(source="m365", success=True, domains=[seed, "allen-bradley.com"]),
        "web_fingerprint": DiscoveryResult(
            source="web_fingerprint", success=True,
            raw_data={"tracking_ids": {"gtm": ["GTM-RA1234"]}},
        ),
        "whoxy": DiscoveryResult(
            source="whoxy", success=True, domains=["rockwellbrand.net", "ra-events.com", "unrelated.com"],
            raw_data={"domains_by_company": {
                "Rockwell": ["rockwellbrand.net", "ra-events.com", "unrelated.com"],
            }},
        ),
    }
    evidence = collect_evidence(seed_results, seed)
    evidence.setdefault(seed, []).insert(0, {"source": "seed", "signal": "primary", "confidence": 100})

    summary = asyncio.run(svc.expand_ownership(seed, evidence, seed_results, include_paid=False))

    # allen-bradley.com was pivoted from and its tenant yielded ab-legacy.com
    assert "allen-bradley.com" in summary["domains_pivoted"]
    assert "ab-legacy.com" in summary["new_domains"]
    ab_legacy = score_evidence(evidence["ab-legacy.com"])
    assert ab_legacy.tier == TIER_CONFIRMED and evidence["ab-legacy.com"][0]["depth"] == 1

    # Review-tier company matches get corroborated by redirect / shared GTM ID
    assert score_evidence(evidence["rockwellbrand.net"]).expandable
    assert "redirect" in score_evidence(evidence["rockwellbrand.net"]).signals
    assert "analytics_id" in score_evidence(evidence["ra-events.com"]).signals
    # ...while an uncorroborated fuzzy match stays in review
    assert score_evidence(evidence["unrelated.com"]).tier == TIER_REVIEW
    corroborated = {c["domain"] for c in summary["corroborated"]}
    assert corroborated == {"rockwellbrand.net", "ra-events.com"}


def test_expansion_respects_domain_budget():
    seed = "seed.com"
    svc = _StubService(
        m365={seed: [seed] + [f"d{i}.com" for i in range(10)]},
        redirects={}, ids={},
    )
    seed_results = {"m365": DiscoveryResult(source="m365", success=True, domains=svc.m365_map[seed])}
    evidence = collect_evidence(seed_results, seed)
    summary = asyncio.run(svc.expand_ownership(
        seed, evidence, seed_results, max_pivot_domains=3, include_paid=False, corroborate_limit=0,
    ))
    assert len(summary["domains_pivoted"]) == 3


# ---------------------------------------------------------------------------
# Whoxy: recursion must not re-spend credits
# ---------------------------------------------------------------------------

def test_whoxy_skip_terms_and_email_filter(monkeypatch):
    from app.services import whoxy_service as wmod

    svc = wmod.WhoxyService("k")
    searched: List[str] = []

    async def fake_whois(domain):
        return {
            "registrant_email": "domains@acq.com",
            "technical_email": "abuse@markmonitor.com",
            "registrant_company": "Rockwell Automation",
        }

    async def fake_rev(kind, value, max_pages):
        searched.append(value)
        return [{"domain_name": f"{value.split('@')[-1].replace(' ', '')}.example"}]

    monkeypatch.setattr(svc, "whois_lookup", fake_whois)
    monkeypatch.setattr(svc, "_reverse_whois_query", fake_rev)
    monkeypatch.setattr(wmod.time, "sleep", lambda *_: None)

    asyncio.run(svc.discover_related_domains(
        "acq.com", skip_terms={"rockwell automation"}, email_filter=is_usable_registrant_email,
    ))
    assert searched == ["domains@acq.com"]
