"""CVE / component research, web search, vulnx and fingerprinting.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Asset,
    Dict,
    List,
    Optional,
    SessionLocal,
    Vulnerability,
    _format_vulnx_search_output,
    _run_vulnx_binary,
    _tool_output_max_chars,
    asyncio,
    get_tenant_context,
    httpx,
    json,
    logger,
    os,
    settings,
)


class ResearchToolsMixin:
    """CVE / component research, web search, vulnx and fingerprinting."""
    
    async def search_cve(self, cve_id: str) -> str:
        """
        Search for CVE information in the database.
        
        Args:
            cve_id: CVE ID to search for (e.g., CVE-2021-44228)
        
        Returns:
            String with CVE information and affected assets
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset).filter(
                Vulnerability.cve_id.ilike(f"%{cve_id}%")
            )
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            vulns = query.all()
            
            if not vulns:
                return f"No findings for {cve_id} in your attack surface."
            
            result = f"# CVE Search: {cve_id}\n\n"
            result += f"Found {len(vulns)} affected assets:\n\n"
            
            for vuln in vulns[:20]:
                result += f"## {vuln.asset.value if vuln.asset else 'Unknown Asset'}\n"
                result += f"- **Severity**: {vuln.severity.value.upper()}\n"
                result += f"- **CVSS**: {vuln.cvss_score or 'N/A'}\n"
                result += f"- **Status**: {vuln.status.value if vuln.status else 'Unknown'}\n"
                if vuln.description:
                    result += f"- **Description**: {vuln.description[:200]}...\n"
                result += "\n"
            
            if len(vulns) > 20:
                result += f"... and {len(vulns) - 20} more affected assets.\n"
            
            return result
        except Exception as e:
            logger.exception("search_cve failed")
            return f"Error searching CVE: {e}"
        finally:
            db.close()

    def _research_query_target_host(self, query: str) -> str:
        """Return the target host if a third-party research query would disclose it."""
        from urllib.parse import urlsplit

        from app.services.agent.pilot_policy import current_pilot

        hosts = set()
        pilot = current_pilot()
        for raw in (getattr(pilot, "target", "") if pilot else "",
                    str(getattr(self, "_fallback_target", "") or "")):
            host = (urlsplit(raw if "://" in raw else f"https://{raw}").hostname or "").lower()
            if host:
                hosts.add(host)
                labels = host.split(".")
                if len(labels) > 2:
                    hosts.add(".".join(labels[-2:]))
        lowered = str(query or "").lower()
        for host in sorted(hosts, key=len, reverse=True):
            if len(host) >= 4 and host in lowered:
                return host
        return ""

    async def lookup_component_vulns(self, product: str, version: str = "", limit: int = 10) -> str:
        """Known vulnerabilities for one component and version (no target traffic).

        Use after recon reads a version (generator tag, readme "Stable tag",
        style.css "Version", ?ver=, Server header). Results are leads: compare the
        affected range and preconditions (auth, feature enabled) to what you saw,
        then prove with a probe before filing.
        """
        product = " ".join(str(product or "").split())[:80]
        version = " ".join(str(version or "").split())[:40]
        if not product:
            return json.dumps({"error": "product is required"})
        leaked = self._research_query_target_host(f"{product} {version}")
        if leaked:
            return json.dumps({"error": f"Query names the assessment target ({leaked}); use the component name"})
        limit = max(1, min(int(limit or 10), 25))
        slug = product.lower().replace(" ", "-")
        sections = [f"# Known vulnerabilities: {product} {version}".strip()]
        try:
            sections.append(await self.vulnx_query(
                query=f"{slug} && (severity:critical || severity:high || severity:medium)",
                limit=limit,
            ))
        except Exception as exc:
            sections.append(f"(vulnx lookup failed: {exc})")
        if getattr(settings, "TAVILY_API_KEY", None):
            sections.append(await self.web_search(
                f'"{product}" {version} vulnerability CVE affected versions fixed in'.strip(),
                max_results=5,
            ))
        sections.append(
            "Compare each affected range to the observed version. In range = lead; "
            "note auth/feature preconditions; prove before create_finding."
        )
        return "\n\n".join(sections)[:_tool_output_max_chars()]

    async def record_recon_inventory(
        self, inventory: Optional[Dict[str, Any]] = None,
        attack_ideas: Optional[List[Dict[str, Any]]] = None, target: str = "",
    ) -> str:
        """Record what recon shows the app is, plus ranked attack ideas.

        Each idea becomes an open hypothesis and an untested coverage cell.
        """
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.pilot_policy import current_pilot
        from app.services.agent.recon_inventory import record_recon_inventory
        from urllib.parse import urlsplit

        if isinstance(inventory, str):
            inventory = json.loads(inventory or "{}")
        if isinstance(attack_ideas, str):
            attack_ideas = json.loads(attack_ideas or "[]")
        pilot = current_pilot()
        scope = (pilot.target if pilot else "") or str(getattr(self, "_fallback_target", "") or "")
        target = _origin(target or scope) or str(target or scope)
        if scope and _origin(scope) and _origin(target) and (
            urlsplit(_origin(target)).hostname != urlsplit(_origin(scope)).hostname
        ):
            return json.dumps({"error": "target is outside the assessment scope"})
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if not brain.target:
            brain.target = target
        try:
            result = record_recon_inventory(
                brain, target=target, inventory=inventory or {}, attack_ideas=attack_ideas or [],
            )
        except ValueError as exc:
            return json.dumps({"error": str(exc)})
        self._engagement_brain = brain.to_dict()
        return json.dumps(result, indent=2)[:_tool_output_max_chars()]

    async def web_search(self, query: str, max_results: int = 5) -> str:
        """
        Search the web for CVE details, exploit info, or general security research (RedAmon-style).
        Uses Tavily API when TAVILY_API_KEY is set.
        
        Args:
            query: Search query (e.g. "CVE-2021-44228 exploit", "Log4j remediation")
            max_results: Max results to return (1-10, default 5)
        
        Returns:
            Summarized search results or an error message.
        """
        api_key = getattr(settings, "TAVILY_API_KEY", None)
        if not api_key:
            return "Web search is not configured. Set TAVILY_API_KEY in .env to enable (get a key at tavily.com)."
        leaked = self._research_query_target_host(query)
        if leaked:
            return (
                f"Web search refused: the query names the assessment target ({leaked}). "
                "Search by component and version only, e.g. 'Photo Gallery 1.8.31 CVE'."
            )
        max_results = max(1, min(10, max_results))
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "search_depth": "basic",
                        "max_results": max_results,
                    },
                )
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            logger.warning(f"Tavily API error: {e.response.status_code} - {e.response.text[:200]}")
            return f"Web search failed: HTTP {e.response.status_code}. Check TAVILY_API_KEY and quota."
        except Exception as e:
            logger.exception("Tavily web_search failed")
            return f"Web search failed: {e!s}"
        results = data.get("results") or []
        if not results:
            return f"No results for: {query}"
        out = [f"# Web search: {query}\n"]
        for i, hit in enumerate(results, 1):
            title = hit.get("title", "")
            url = hit.get("url", "")
            content = (hit.get("content") or "")[:_tool_output_max_chars() // max_results]
            out.append(f"## {i}. {title}\nURL: {url}\n{content}\n")
        return "\n".join(out)

    async def search_vulnx(self, cve_id: str) -> str:
        """
        Query the ProjectDiscovery vulnx API for rich CVE intelligence.

        Returns a comprehensive snapshot including:
          - CVSS score & vector, EPSS score & percentile
          - CISA KEV and VulnCheck KEV membership
          - Public PoC count, URLs, and normalized exploit maturity from read-only metadata
          - HackerOne disclosed report count and rank
          - Nuclei template name and raw YAML (when available)
          - Affected products with CPEs and deployment models
          - Internet exposure estimates (Shodan/Fofa min–max hosts)
          - Requirements / preconditions (structured attacker prerequisites)
          - Remediation guidance

        Uses PDCP_API_KEY when set (higher rate limits); works unauthenticated
        with stricter limits. Key is the same one used by other PD tools.

        Args:
            cve_id: CVE identifier, e.g. CVE-2021-44228
        """
        import re as _re
        cve_id = cve_id.strip().upper()
        if not _re.match(r"^CVE-\d{4}-\d+$", cve_id):
            return f"Invalid CVE ID format: {cve_id}. Expected CVE-YYYY-NNNNN."

        base_url = "https://api.projectdiscovery.io"
        headers = {"User-Agent": "prowl-research/1.0"}
        api_key = getattr(settings, "PDCP_API_KEY", None)
        if api_key:
            headers["X-PDCP-Key"] = api_key

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(
                    f"{base_url}/v2/vulnerability/{cve_id}",
                    headers=headers,
                )
                if r.status_code == 404:
                    return f"{cve_id} not found in the ProjectDiscovery vulnerability database."
                if r.status_code == 429:
                    return (
                        f"vulnx API rate limit hit for {cve_id}. "
                        "Set PDCP_API_KEY in .env for higher limits (free at cloud.projectdiscovery.io)."
                    )
                r.raise_for_status()
                data = r.json().get("data") or {}
        except httpx.HTTPStatusError as e:
            return f"vulnx API error for {cve_id}: HTTP {e.response.status_code}"
        except Exception as e:
            return f"vulnx lookup failed for {cve_id}: {e}"

        if not data:
            return f"No data returned for {cve_id}."

        exploit_intelligence: dict[str, Any] = {}
        try:
            from app.services.vuln_intel_enrichment import enrich_cve_catalog

            catalog = await asyncio.to_thread(
                enrich_cve_catalog, cve_id, use_cache=True, include_exploit_sources=True
            )
            exploit_intelligence = catalog.get("exploit_intelligence") or {}
        except Exception as exc:
            logger.debug("Public exploit maturity lookup failed for %s: %s", cve_id, type(exc).__name__)

        lines = [f"# vulnx — {cve_id}\n"]

        # Core severity
        lines.append(f"**Severity**: {data.get('severity', 'N/A').upper()}")
        lines.append(f"**CVSS Score**: {data.get('cvss_score', 'N/A')}  ({data.get('cvss_metrics', '')})")
        lines.append(f"**EPSS Score**: {data.get('epss_score', 'N/A')}  (percentile: {data.get('epss_percentile', 'N/A')})")
        lines.append(f"**Status**: {data.get('vuln_status', 'N/A')}")
        lines.append("")

        # Exploitation signals
        kev_entries = data.get("kev") or []
        is_kev = data.get("is_kev", False)
        is_vkev = data.get("is_vkev", False)
        lines.append(f"**CISA KEV**: {'YES ⚠️' if is_kev else 'No'}")
        lines.append(f"**VulnCheck KEV**: {'YES ⚠️' if is_vkev else 'No'}")
        if kev_entries:
            for k in kev_entries:
                added = k.get("added_date", "")[:10] if k.get("added_date") else ""
                ransomware = " (ransomware)" if k.get("known_ransomware_campaign_use") else ""
                lines.append(f"  - KEV source: {k.get('source', '?')}  added: {added}{ransomware}")

        poc_count = data.get("poc_count", 0)
        is_poc = data.get("is_poc", False)
        lines.append(f"**Public PoC**: {'YES' if is_poc else 'No'}  ({poc_count} PoC(s))")
        pocs = data.get("pocs") or []
        for p in pocs[:5]:
            added = p.get("added_at", "")[:10] if p.get("added_at") else ""
            lines.append(f"  - [{p.get('source','?')}] {p.get('url','')}  (added {added})")
        lines.append("")
        if exploit_intelligence:
            lines.append(f"**Public Exploit Maturity**: {exploit_intelligence.get('label', 'Unknown')}")
            lines.append(
                "  This is distinct from KEV/observed exploitation, EPSS probability, and detection coverage."
            )
            for artifact in (exploit_intelligence.get("artifacts") or [])[:5]:
                lines.append(
                    f"  - [{artifact.get('source', '?')}] {artifact.get('title') or artifact.get('artifact_id', '')} "
                    f"({artifact.get('maturity', 'unknown')}) {artifact.get('canonical_url', '')}"
                )
            lines.append("")

        # HackerOne
        h1 = data.get("h1") or {}
        if h1:
            lines.append(f"**HackerOne**: {h1.get('reports', 0)} reports  rank #{h1.get('rank', '?')}  (Δ reports: {h1.get('delta_reports', 0)})")
            lines.append("")

        # Nuclei template
        is_template = data.get("is_template", False)
        lines.append(f"**Nuclei Template**: {'YES — ' + data.get('filename','') if is_template else 'No'}")
        if is_template and data.get("tags"):
            lines.append(f"  Tags: {', '.join(data.get('tags', []))}")
        lines.append("")

        # Requirements / preconditions
        reqs = data.get("requirements", "")
        req_type = data.get("requirement_type", "")
        if reqs:
            lines.append(f"**Requirements (preconditions)**:")
            lines.append(f"  Type: {req_type}")
            lines.append(f"  {reqs}")
            lines.append("")

        # Internet exposure
        exposure = data.get("exposure") or {}
        exp_values = exposure.get("values") or []
        if exp_values:
            total_min = sum(v.get("min_hosts", 0) for v in exp_values)
            total_max = sum(v.get("max_hosts", 0) for v in exp_values)
            lines.append(f"**Internet Exposure**: ~{total_min:,}–{total_max:,} hosts (Shodan/Fofa)")
            lines.append("")

        # Affected products
        products = data.get("affected_products") or []
        if products:
            lines.append(f"**Affected Products** ({len(products)} total, showing first 5):")
            for p in products[:5]:
                vendor = p.get("vendor", "")
                product = p.get("product", "")
                deploy = p.get("deployment_model", "")
                cpes = ", ".join((p.get("cpe") or [])[:2])
                lines.append(f"  - {vendor} / {product}  [{deploy}]  CPE: {cpes}")
            lines.append("")

        # Description + remediation
        desc = data.get("description", "")
        if desc:
            lines.append(f"**Description**: {desc[:500]}{'...' if len(desc) > 500 else ''}")
        remediation = data.get("remediation", "")
        if remediation:
            lines.append(f"**Remediation**: {remediation[:400]}{'...' if len(remediation) > 400 else ''}")

        # CWEs
        cwes = data.get("cwe") or []
        if cwes:
            lines.append(f"**CWEs**: {', '.join(cwes)}")
            try:
                from app.services.vuln_intel_enrichment import build_cwe_intel
                for row in build_cwe_intel([str(c) for c in cwes])[:5]:
                    capecs = ", ".join(c.get("id", "") for c in (row.get("capec") or [])[:4])
                    lines.append(
                        f"  - {row.get('cwe_id')}: {row.get('name') or ''}"
                        + (f" → {capecs}" if capecs else "")
                    )
            except Exception:
                pass

        return "\n".join(lines)

    async def vulnx_query(self, query: str, limit: int = 10, sort_by: str = "cvss_score") -> str:
        """
        Search the ProjectDiscovery vulnerability database using a rich query string.

        Use this to DISCOVER CVEs relevant to a technology stack — for example when
        you've identified that a target runs Apache Tomcat 9.x and want to find all
        recent high-severity exploitable CVEs for it.

        Query syntax supports:
          - Boolean:  apache && severity:high && is_remote:true
          - Field:    affected_products.product:tomcat, cvss_score:>8.0, epss_score:>0.7
          - KEV/PoC:  is_kev:true, is_poc:true, is_template:true
          - Date:     cve_created_at:>=2024, age_in_days:<30
          - Vendor:   affected_products.vendor:microsoft

        Examples:
          - 'nodejs && severity:high && is_remote:true'
          - 'apache && is_kev:true'
          - 'severity:critical && is_poc:true && age_in_days:<30'
          - 'affected_products.product:spring && cvss_score:>8.0'

        Args:
            query:   vulnx query string (see syntax above)
            limit:   max results (default 10, max 25)
            sort_by: field to sort descending by (cvss_score, epss_score, cve_created_at)
        """
        import shutil

        if not query.strip():
            return "query is required"
        leaked = self._research_query_target_host(query)
        if leaked:
            return f"vulnx search refused: the query names the assessment target ({leaked})."
        if limit > 25:
            limit = 25

        base_url = "https://api.projectdiscovery.io"
        headers = {"User-Agent": "prowl-research/1.0"}
        api_key = getattr(settings, "PDCP_API_KEY", None)
        if api_key:
            headers["X-PDCP-Key"] = api_key

        # ── Try vulnx binary first (richest output) ──────────────────────────
        vulnx_path = shutil.which("vulnx")
        if vulnx_path:
            try:
                cmd = [
                    vulnx_path, "search", query,
                    "--json", "--silent", "--disable-update-check",
                    "--limit", str(limit),
                    "--sort-desc", sort_by,
                ]
                env = dict(os.environ)
                if api_key:
                    env["PDCP_API_KEY"] = api_key
                output = await _run_vulnx_binary(cmd, env=env)
                if output and output.strip():
                    return _format_vulnx_search_output(output, query)
            except Exception:
                pass  # fall through to HTTP API

        # ── Fall back to PDCP HTTP search API ────────────────────────────────
        from urllib.parse import quote
        search_url = (
            f"{base_url}/v2/vulnerability"
            f"?q={quote(query)}&limit={limit}&sort-desc={sort_by}"
        )
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(search_url, headers=headers)
                if r.status_code == 429:
                    return (
                        f"vulnx search rate limit hit for query '{query}'. "
                        "Set PDCP_API_KEY in .env for higher limits."
                    )
                if r.status_code == 401:
                    return "vulnx: unauthorized — PDCP_API_KEY may be invalid."
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            return f"vulnx search API error: HTTP {e.response.status_code}"
        except Exception as e:
            return f"vulnx search failed: {e}"

        # Normalise response envelope
        vulns = []
        if isinstance(data, dict):
            inner = data.get("data") or data
            if isinstance(inner, dict):
                vulns = inner.get("vulnerabilities") or inner.get("data") or []
            elif isinstance(inner, list):
                vulns = inner
        elif isinstance(data, list):
            vulns = data

        if not vulns:
            return f"No CVEs matched the query: '{query}'"

        return _format_vulnx_search_output(
            __import__("json").dumps(vulns), query
        )

    async def fingerprint_api(self, **kwargs: Any) -> str:
        """Fingerprint API hosts/tech from captured Interceptor/crawl samples (no Caido/Codex)."""
        from app.services.agent.api_fingerprint import fingerprint_from_map

        cmap = getattr(self, "_capability_map", None) or {}
        target = ""
        if isinstance(cmap, dict):
            target = str(cmap.get("target") or "")
        target = target or (getattr(self, "_fallback_target", None) or "")
        result = fingerprint_from_map(cmap if isinstance(cmap, dict) else {}, target=target)
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]

    async def fingerprint_passive_stack(self, url: str = "", **kwargs: Any) -> str:
        """GET the homepage and extract CMS/plugin/server versions (browser-visible only)."""
        from app.services.agent.cve_applicability import url_from_text
        from app.services.agent.passive_stack import (
            format_passive_stack,
            origin_from_url,
            parse_passive_stack,
        )

        target = origin_from_url(url or kwargs.get("args") or "") or url_from_text(
            str(getattr(self, "_fallback_target", "") or "")
        )
        if not target:
            return "Error: url is required (e.g. https://target.com)."
        html, headers, final = await self._fetch_homepage(target)
        products = parse_passive_stack(html, headers)
        return (
            f"URL: {final}\n"
            + format_passive_stack(products)
            + "\n\nVersioned products are CVE-applicability evidence. "
            "Next: check_cve_applicability (named CVE) or vulnx_query by product."
        )

    async def check_cve_applicability(
        self,
        cve_id: str = "",
        url: str = "",
        **kwargs: Any,
    ) -> str:
        """Look up a CVE (or versioned plugins) and compare to a live homepage fingerprint."""
        from app.services.agent.cve_applicability import (
            CVE_RE,
            cve_ids_in_text,
            format_applicability_report,
            match_cve_to_stack,
            url_from_text,
        )
        from app.services.agent.passive_stack import (
            origin_from_url,
            parse_passive_stack,
            versioned_products,
        )

        cve_id = (cve_id or kwargs.get("cve") or "").strip()
        url = (url or kwargs.get("target") or kwargs.get("args") or "").strip()
        if url and not url.startswith("http") and "cve-" in url.lower():
            # Model stuffed the CVE into url
            if not cve_id:
                ids = cve_ids_in_text(url)
                cve_id = ids[0] if ids else cve_id
            url = ""
        target = origin_from_url(url) or url_from_text(url)
        if not target:
            target = origin_from_url(str(getattr(self, "_fallback_target", "") or ""))
        if not target:
            return "Error: url is required (homepage to fingerprint)."

        html, headers, final = await self._fetch_homepage(target)
        products = parse_passive_stack(html, headers)

        if not cve_id:
            ids = cve_ids_in_text(str(getattr(self, "_current_objective", "") or ""))
            cve_id = ids[0] if ids else ""

        if cve_id:
            cve_id = cve_id.strip().upper()
            if not CVE_RE.match(cve_id):
                return f"Invalid CVE ID format: {cve_id}. Expected CVE-YYYY-NNNNN."
            intel, affected = await self._vulnx_record(cve_id)
            if not intel and getattr(settings, "TAVILY_API_KEY", None):
                intel = await self.web_search(f"{cve_id} vulnerability affected product version", max_results=5)
            match = match_cve_to_stack(
                cve_id=cve_id,
                intel_text=intel,
                products=products,
                affected_products=affected,
            )
            return format_applicability_report(
                url=final,
                products=products,
                match=match,
                intel=intel,
            )[:_tool_output_max_chars()]

        # No named CVE — map each versioned product via vulnx search (bounded).
        blocks = [
            format_applicability_report(url=final, products=products),
            "",
            "## vulnx search for versioned products (max 5)",
        ]
        applicable = []
        for prod in versioned_products(products)[:5]:
            slug = str(prod.get("name") or "").replace(" ", "-")
            query = f"{slug} && (severity:critical || severity:high || severity:medium)"
            try:
                intel = await self.vulnx_query(query=query, limit=8)
            except Exception as e:
                intel = f"(vulnx_query failed: {e})"
            ids = cve_ids_in_text(intel)[:6]
            for cid in ids:
                m = match_cve_to_stack(
                    cve_id=cid,
                    intel_text=intel,
                    products=[prod],
                )
                if m.get("verdict") == "applicable":
                    applicable.append(m)
            blocks.append(f"### {prod.get('name')} {prod.get('version')}\n{intel[:1800]}\n")
        if applicable:
            blocks.append("VERDICT: applicable")
            for m in applicable:
                blocks.append(f"- {m.get('cve_id')} on {m.get('hits')}")
            blocks.append(
                "File create_finding for each applicable CVE (quote version evidence + range)."
            )
        else:
            blocks.append(
                "No version-in-range CVE auto-matched from vulnx search. "
                "Named CVEs still need check_cve_applicability(cve_id=...)."
            )
        return "\n".join(blocks)[:_tool_output_max_chars()]

    async def _fetch_homepage(self, url: str) -> tuple:
        from app.services.agent.passive_stack import origin_from_url

        target = origin_from_url(url) or url
        from app.services.agent.pilot_policy import current_pilot

        if current_pilot() is not None:
            # Pilot traffic must use the budgeted, scope-checked exchange.
            try:
                exchange = await self._http_exchange(
                    "GET", target if target.endswith("/") else target + "/",
                    use_auth_session=False, timeout=15,
                )
                resp = exchange["response"]
                html = str(exchange.get("_body_text") or resp.get("body") or resp.get("body_preview") or "")
                headers = {str(k).lower(): str(v) for k, v in (resp.get("headers") or {}).items()}
                return html[:250_000], headers, str(resp.get("url") or target)
            except Exception as e:
                return "", {}, f"{target} (fetch failed: {e})"
        try:
            async with httpx.AsyncClient(
                verify=False,
                headers={"User-Agent": "JudahASM-Kickoff/1.0"},
                follow_redirects=True,
                timeout=15.0,
            ) as client:
                resp = await client.get(target if target.endswith("/") else target + "/")
                html = (resp.text or "")[:250_000]
                headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                return html, headers, str(resp.url)
        except Exception as e:
            return "", {}, f"{target} (fetch failed: {e})"

    async def _vulnx_record(self, cve_id: str) -> tuple:
        """Return (formatted intel text, affected_products list)."""
        cve_id = (cve_id or "").strip().upper()
        base_url = "https://api.projectdiscovery.io"
        headers = {"User-Agent": "prowl-research/1.0"}
        api_key = getattr(settings, "PDCP_API_KEY", None)
        if api_key:
            headers["X-PDCP-Key"] = api_key
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                r = await client.get(f"{base_url}/v2/vulnerability/{cve_id}", headers=headers)
                if r.status_code == 404:
                    text = await self.search_vulnx(cve_id)
                    return text, []
                if r.status_code >= 400:
                    text = await self.search_vulnx(cve_id)
                    return text, []
                data = (r.json() or {}).get("data") or {}
        except Exception:
            try:
                text = await self.search_vulnx(cve_id)
            except Exception as e:
                return f"vulnx lookup failed: {e}", []
            return text, []
        affected = data.get("affected_products") or []
        parts = [
            f"{cve_id} severity={data.get('severity')} cvss={data.get('cvss_score')}",
            str(data.get("description") or ""),
            str(data.get("requirements") or ""),
            str(data.get("remediation") or ""),
        ]
        for p in affected[:8]:
            if isinstance(p, dict):
                parts.append(f"{p.get('vendor','')} {p.get('product','')}")
        text = "\n".join(parts)
        try:
            formatted = await self.search_vulnx(cve_id)
            if formatted and "not found" not in formatted.lower():
                text = formatted + "\n" + text
        except Exception:
            pass
        return text, affected

    async def probe_registry_anonymous(
        self,
        host: Optional[str] = None,
        url: Optional[str] = None,
        args: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Read-only ACR anonymous-pull check (oauth2 token + catalog names).

        Never pulls image layers, never pushes, never authenticates recovered
        tokens against GitHub. If verdict=SUBMIT, call create_finding High.

        Args:
            host: *.azurecr.io hostname (required). URL form is accepted.
            url: Alias for host.
            args: Optional free-text hostname if the model omits host=.
        """
        from app.services.agent.registry_surface import probe_anonymous_pull

        raw = host or url or args or kwargs.get("target") or ""
        if not str(raw).strip():
            raw = getattr(self, "_fallback_target", None) or ""
        result = await probe_anonymous_pull(str(raw).strip())
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]
