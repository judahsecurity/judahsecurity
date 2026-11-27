"""Threat-intel lookups (breach, DNS threat, URLhaus, BGP).

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    List,
    Optional,
    _tool_output_max_chars,
    asyncio,
    json,
)


class ThreatIntelToolsMixin:
    """Threat-intel lookups (breach, DNS threat, URLhaus, BGP)."""

    # ------------------------------------------------------------------
    # Email breach discovery (XposedOrNot)
    # ------------------------------------------------------------------

    async def check_email_breach(
        self,
        domain: Optional[str] = None,
        emails: Optional[List[str]] = None,
    ) -> str:
        """
        Check whether an organisation's email addresses have appeared in known
        data-breach dumps using the XposedOrNot public API (keyless, free).

        Provide a domain (e.g. "target.com") to get aggregate domain-level
        exposure, and/or a list of specific email addresses for per-address
        results.  Both can be supplied together.

        Returns breach names, data types exposed (passwords, credit cards…),
        and total breached-account counts.  A clean result means no known
        breach exposure was found — not a guarantee of safety.
        """
        from app.services.email_breach_service import get_email_breach_service

        service = get_email_breach_service()
        output: dict = {}

        if domain:
            dom_result = await service.check_domain_breach_exposure(domain)
            output["domain"] = dom_result.to_dict()

        if emails:
            email_results = await service.batch_check_emails(emails[:20])
            output["emails"] = {e: r.to_dict() for e, r in email_results.items()}

        if not output:
            return "Error: provide domain= and/or emails= to check."

        return json.dumps(output, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # DNS Threat / DNSBL check (Spamhaus + multi-DNSBL, keyless)
    # ------------------------------------------------------------------

    async def check_dns_threat(
        self,
        targets: Optional[List[str]] = None,
        target: Optional[str] = None,
    ) -> str:
        """
        Check whether discovered IPs or domains are listed on Spamhaus ZEN/DBL,
        Barracuda BRBL, SORBS, SpamCop, SURBL, URIBL, or other major DNSBLs.

        All lookups are pure DNS queries — keyless, free, and fast.
        Returns hit_count, severity (clean/low/medium/high), and which
        blocklists matched.  A "high" severity means Spamhaus or SURBL
        confirmed the target as malicious.

        Accepts a single target= string or a targets= list.
        """
        from app.services.dns_threat_service import get_dns_threat_service

        service = get_dns_threat_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets:
            return "Error: provide target= or targets= to check."

        results = await service.check_bulk(all_targets[:50])
        out = {t: r.to_dict() for t, r in results.items()}
        listed = [t for t, r in results.items() if r.is_listed]
        summary = {
            "targets_checked": len(all_targets),
            "listed_count": len(listed),
            "listed_targets": listed,
            "details": out,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # URLhaus active lookup (abuse.ch, free key or keyless)
    # ------------------------------------------------------------------

    async def lookup_urlhaus(
        self,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
    ) -> str:
        """
        Query abuse.ch URLhaus to check whether a URL, domain, IP, or file hash
        is associated with malware distribution.

        For URLs — checks if the exact URL serves/served malware.
        For domains/IPs — lists all malware URLs hosted on that host.
        For hashes (MD5/SHA256) — identifies the malware payload.

        Uses URLHAUS_KEY env var if set (fewer rate limits); works without it.
        Accepts a single target= or a list via targets=.
        """
        from app.services.urlhaus_lookup_service import get_urlhaus_lookup_service

        service = get_urlhaus_lookup_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets:
            return "Error: provide target= or targets= to query."

        sem = asyncio.Semaphore(5)

        async def _lookup(t: str) -> tuple[str, dict]:
            async with sem:
                await asyncio.sleep(0.2)
                return t, await service.lookup(t)

        pairs = await asyncio.gather(*[_lookup(t) for t in all_targets[:20]])
        results = dict(pairs)
        malicious = {t: r for t, r in results.items() if r.get("is_malicious")}

        summary = {
            "targets_checked": len(all_targets),
            "malicious_count": len(malicious),
            "malicious_targets": list(malicious.keys()),
            "details": results,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]

    # ------------------------------------------------------------------
    # BGP / ASN lookup (RIPEstat, keyless)
    # ------------------------------------------------------------------

    async def lookup_bgp(
        self,
        target: Optional[str] = None,
        targets: Optional[List[str]] = None,
        asn: Optional[str] = None,
    ) -> str:
        """
        Look up BGP routing context for discovered IPs or domains using RIPEstat
        (stat.ripe.net) — the authoritative Regional Internet Registry source.

        For IPs/domains — returns the covering prefix, owning ASN, and ASN name.
        For an ASN (e.g. "AS15169") — returns all announced IP prefixes, useful
        for discovering additional IP ranges owned by the target organisation.

        Keyless and free. Replaces bgpview.io which is no longer operational.
        """
        from app.services.ripestat_service import get_ripestat_service

        service = get_ripestat_service()
        all_targets = list(targets or [])
        if target:
            all_targets.insert(0, target)

        if not all_targets and not asn:
            return "Error: provide target=, targets=, or asn= to look up."

        results: dict = {}

        if asn:
            res = await service.lookup_asn(asn)
            results[asn] = res.to_dict()

        sem = asyncio.Semaphore(10)

        async def _lookup(t: str) -> tuple[str, dict]:
            async with sem:
                # Auto-detect ASN vs IP/domain
                if t.upper().startswith("AS") or (t.isdigit() and len(t) <= 10):
                    res = await service.lookup_asn(t)
                else:
                    try:
                        import ipaddress as _ip
                        _ip.ip_address(t)
                        res = await service.lookup_ip(t)
                    except ValueError:
                        res = await service.lookup_domain(t)
                return t, res.to_dict()

        if all_targets:
            pairs = await asyncio.gather(*[_lookup(t) for t in all_targets[:50]])
            results.update(dict(pairs))

        asn_distribution: dict[str, int] = {}
        for r in results.values():
            if isinstance(r, dict) and r.get("asn"):
                asn_distribution[r["asn"]] = asn_distribution.get(r["asn"], 0) + 1

        summary = {
            "targets_resolved": len(results),
            "unique_asns": len(asn_distribution),
            "asn_distribution": asn_distribution,
            "details": results,
        }
        return json.dumps(summary, indent=2)[:_tool_output_max_chars()]
