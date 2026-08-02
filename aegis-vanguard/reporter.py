#!/usr/bin/env python3
"""
Aegis Vanguard Pentest Report Generator

Generates comprehensive markdown security assessment reports from
pentest pipeline results. Inspired by Shannon's report format.
"""

from datetime import datetime, timezone
from typing import Dict, List, Any, Optional


class PentestReporter:
    """Generates a comprehensive pentest report from pipeline results."""

    def __init__(
        self,
        target_url: str,
        scope_domain: str,
        started_at: str,
        pre_recon: dict,
        discovery: dict,
        vuln_analysis: dict,
        exploit_validation: dict,
        bridge_stats: dict,
    ):
        self.target_url = target_url
        self.scope_domain = scope_domain
        self.started_at = started_at
        self.finished_at = datetime.now(timezone.utc).isoformat()
        self.pre_recon = pre_recon
        self.discovery = discovery
        self.vuln = vuln_analysis
        self.exploits = exploit_validation
        self.stats = bridge_stats

    def generate(self) -> str:
        sections = [
            self._header(),
            self._executive_summary(),
            self._target_profile(),
            self._attack_surface(),
            self._vulnerability_findings(),
            self._exploit_validation_results(),
            self._security_posture(),
            self._recommendations(),
            self._methodology(),
            self._appendix(),
        ]
        return "\n\n".join(sections)

    # -----------------------------------------------------------------
    # Report Sections
    # -----------------------------------------------------------------

    def _header(self) -> str:
        return f"""# Comprehensive Security Assessment Report

**Target:** {self.target_url}
**Scope:** {self.scope_domain}
**Assessment Date:** {self.started_at[:10]} to {self.finished_at[:10]}
**Generated:** {self.finished_at}
**Agent:** Judah Security - Aegis Vanguard
**Classification:** CONFIDENTIAL

---"""

    def _executive_summary(self) -> str:
        # Count findings by severity
        sev = self._severity_counts()
        total_vulns = sum(sev.values())

        validated_sqli = len(self.exploits.get("injection_validated", []))
        validated_xss = len(self.exploits.get("xss_validated", []))
        validated_total = validated_sqli + validated_xss

        sub_count = len(self.discovery.get("subdomains", []))
        live_count = len(self.discovery.get("live_hosts", []))
        takeover_count = sum(
            1 for t in self.vuln.get("takeover", [])
            if t.get("status") in ("confirmed", "potential")
        )

        risk_level = "CRITICAL" if sev.get("critical", 0) > 0 else \
                     "HIGH" if sev.get("high", 0) > 0 else \
                     "MEDIUM" if sev.get("medium", 0) > 0 else "LOW"

        return f"""## Executive Summary

### Overall Risk: **{risk_level}**

This automated security assessment of **{self.target_url}** identified **{total_vulns} vulnerabilities**
across the target's attack surface, with **{validated_total} confirmed through exploit validation**.

| Metric | Count |
|--------|-------|
| Subdomains discovered | {sub_count} |
| Live HTTP hosts | {live_count} |
| Total vulnerabilities | {total_vulns} |
| Critical | {sev.get('critical', 0)} |
| High | {sev.get('high', 0)} |
| Medium | {sev.get('medium', 0)} |
| Low/Info | {sev.get('low', 0) + sev.get('info', 0)} |
| Validated exploits | {validated_total} |
| Takeover candidates | {takeover_count} |
| Findings submitted to platform | {self.stats.get('submitted', 0)} |

### Key Findings

{self._key_findings_bullets()}"""

    def _target_profile(self) -> str:
        services = self.pre_recon.get("services", [])
        techs = self.pre_recon.get("technologies", [])
        waf = self.pre_recon.get("waf")
        cms = self.pre_recon.get("cms")

        svc_table = ""
        if services:
            svc_table = "| Port | Service | Product | Version |\n|------|---------|---------|----------|\n"
            for s in services[:30]:
                svc_table += f"| {s.get('port', '')} | {s.get('service', '')} | {s.get('product', '')} | {s.get('version', '')} |\n"

        tech_list = ""
        if techs:
            for t in techs:
                plugins = t.get("plugins", {})
                tech_names = [k for k in plugins.keys() if k not in ("HttpOnly", "IP", "Country")]
                if tech_names:
                    tech_list += f"- {', '.join(tech_names[:10])}\n"

        return f"""## Target Profile

**URL:** {self.target_url}
**WAF:** {waf or 'None detected'}
**CMS:** {cms or 'None detected'}

### Open Services

{svc_table or '_No services enumerated_'}

### Technologies Detected

{tech_list or '_No technologies identified_'}"""

    def _attack_surface(self) -> str:
        subs = self.discovery.get("subdomains", [])
        crawled = self.discovery.get("crawled_urls", [])
        historical = self.discovery.get("historical_urls", [])
        fuzzed = self.discovery.get("fuzzed_paths", [])
        params = self.discovery.get("discovered_params", [])

        sub_sample = "\n".join(f"- `{s}`" for s in subs[:20])
        if len(subs) > 20:
            sub_sample += f"\n- _...and {len(subs) - 20} more_"

        return f"""## Attack Surface

### Subdomains ({len(subs)} discovered)

{sub_sample or '_None found_'}

### URL Inventory

| Source | URLs Found |
|--------|-----------|
| Web crawling (katana) | {len(crawled)} |
| Historical (waybackurls + gau) | {len(historical)} |
| Directory fuzzing (ffuf) | {len(fuzzed)} |
| Parameters discovered (arjun) | {len(params)} |"""

    def _vulnerability_findings(self) -> str:
        nuclei = self.vuln.get("nuclei_vulns", [])
        nikto = self.vuln.get("nikto_vulns", [])

        sections = ["## Vulnerability Findings"]

        if nuclei:
            critical = [v for v in nuclei if v.get("info", {}).get("severity") == "critical"]
            high = [v for v in nuclei if v.get("info", {}).get("severity") == "high"]
            medium = [v for v in nuclei if v.get("info", {}).get("severity") == "medium"]

            sections.append(f"### Nuclei Scan Results ({len(nuclei)} total)\n")

            if critical:
                sections.append("#### Critical\n")
                for v in critical:
                    sections.append(self._format_nuclei_vuln(v))

            if high:
                sections.append("#### High\n")
                for v in high[:15]:
                    sections.append(self._format_nuclei_vuln(v))
                if len(high) > 15:
                    sections.append(f"_...and {len(high) - 15} more high-severity findings_\n")

            if medium:
                sections.append(f"#### Medium ({len(medium)} findings)\n")
                for v in medium[:10]:
                    sections.append(self._format_nuclei_vuln(v))
                if len(medium) > 10:
                    sections.append(f"_...and {len(medium) - 10} more medium-severity findings_\n")
        else:
            sections.append("### Nuclei Scan\n_No vulnerabilities identified by nuclei templates._\n")

        if nikto:
            sections.append(f"### Nikto Findings ({len(nikto)})\n")
            for v in nikto[:10]:
                msg = v.get("msg", str(v))
                sections.append(f"- {msg}")

        return "\n\n".join(sections)

    def _exploit_validation_results(self) -> str:
        sqli = self.exploits.get("injection_validated", [])
        xss = self.exploits.get("xss_validated", [])
        cms = self.exploits.get("cms_vulns", [])
        tls = self.exploits.get("tls_issues", [])
        takeovers = self.exploits.get("confirmed_takeovers", [])

        sections = ["## Exploit Validation Results"]
        sections.append("_Only findings confirmed through active validation are listed below._\n")

        if sqli:
            sections.append(f"### SQL Injection ({len(sqli)} confirmed)\n")
            for s in sqli:
                sections.append(f"- **{s.get('url', 'Unknown URL')}** - Injection confirmed via sqlmap")
        else:
            sections.append("### SQL Injection\n_No SQL injection vulnerabilities confirmed._\n")

        if xss:
            sections.append(f"### Cross-Site Scripting ({len(xss)} confirmed)\n")
            for x in xss:
                sections.append(f"- **{x.get('url', 'Unknown URL')}** - XSS confirmed via XSStrike")
        else:
            sections.append("### Cross-Site Scripting\n_No XSS vulnerabilities confirmed._\n")

        if cms:
            sections.append(f"### CMS Vulnerabilities ({len(cms)} findings)\n")
            for c in cms:
                sections.append(f"- {c.get('type', c.get('msg', str(c)))}")

        if takeovers:
            sections.append(f"### Subdomain Takeover ({len(takeovers)} candidates)\n")
            for t in takeovers:
                sections.append(
                    f"- **{t.get('host', '')}** -> `{t.get('cname', '')}` "
                    f"({t.get('service', 'unknown')}, status: {t.get('status', 'unknown')})"
                )

        if tls:
            sections.append(f"### TLS/SSL Issues ({len(tls)} confirmed)\n")
            for t in tls[:10]:
                sections.append(f"- {t.get('id', t.get('finding', str(t)))}")

        return "\n\n".join(sections)

    def _security_posture(self) -> str:
        headers = self.vuln.get("security_headers", [])
        tls = self.vuln.get("tls_analysis", [])
        mail = self.vuln.get("mail_intel", [])
        vendors = self.vuln.get("vendor_intel", [])

        sections = ["## Security Posture Analysis"]

        # Headers
        if headers:
            missing_counts: Dict[str, int] = {}
            for h in headers:
                for m in h.get("missing", []):
                    missing_counts[m] = missing_counts.get(m, 0) + 1

            sections.append("### Security Headers\n")
            if missing_counts:
                sections.append("| Missing Header | Affected Hosts |")
                sections.append("|---------------|---------------|")
                for hdr, count in sorted(missing_counts.items(), key=lambda x: -x[1]):
                    sections.append(f"| `{hdr}` | {count} |")
            else:
                sections.append("_All required security headers present._")

            cors_issues = [h for h in headers if h.get("cors", {}).get("risky")]
            if cors_issues:
                sections.append(f"\n**CORS Issues:** {len(cors_issues)} hosts have risky CORS configurations "
                                "(wildcard origin with credentials)")

        # TLS
        if tls:
            grades: Dict[str, int] = {}
            for t in tls:
                g = t.get("grade", "?")
                grades[g] = grades.get(g, 0) + 1

            sections.append("### TLS Certificate Grades\n")
            sections.append("| Grade | Count |")
            sections.append("|-------|-------|")
            for g in ["A", "B", "C", "D", "F"]:
                if g in grades:
                    sections.append(f"| {g} | {grades[g]} |")

            poor = grades.get("D", 0) + grades.get("F", 0)
            if poor:
                sections.append(f"\n**{poor} hosts have D/F TLS grades requiring immediate attention.**")

        # Mail
        if mail:
            sections.append("### Email Security\n")
            for m in mail:
                domain = m.get("domain", "")
                score = m.get("risk_score", 0)
                provider = m.get("provider", "Unknown")
                records = m.get("records", {})

                spf_icon = "present" if records.get("spf") else "**MISSING**"
                dkim_icon = "present" if records.get("dkim") else "**MISSING**"
                dmarc_icon = "present" if records.get("dmarc") else "**MISSING**"

                sections.append(f"**{domain}** (Risk Score: {score}/100, Provider: {provider})")
                sections.append(f"- SPF: {spf_icon}")
                sections.append(f"- DKIM: {dkim_icon}")
                sections.append(f"- DMARC: {dmarc_icon}")
                sections.append(f"- MTA-STS: {'present' if records.get('mta_sts') else 'missing'}")
                sections.append(f"- DANE: {'present' if records.get('dane') else 'missing'}")

        # Vendors
        if vendors:
            all_vendors: Dict[str, set] = {}
            for v in vendors:
                for vname in v.get("vendors", []):
                    if vname not in all_vendors:
                        all_vendors[vname] = set()
                    all_vendors[vname].add(v.get("host", ""))

            sections.append(f"### Third-Party Vendors ({len(all_vendors)} detected)\n")
            sections.append("| Vendor | Hosts |")
            sections.append("|--------|-------|")
            for name, hosts in sorted(all_vendors.items()):
                sections.append(f"| {name} | {len(hosts)} |")

        return "\n\n".join(sections)

    def _recommendations(self) -> str:
        recs = []
        sev = self._severity_counts()

        if sev.get("critical", 0) > 0:
            recs.append("1. **IMMEDIATE:** Remediate all critical vulnerabilities. These represent "
                        "actively exploitable attack vectors that could lead to full system compromise.")

        sqli = self.exploits.get("injection_validated", [])
        if sqli:
            recs.append(f"2. **CRITICAL:** {len(sqli)} confirmed SQL injection points require immediate "
                        "patching. Implement parameterized queries and input validation.")

        xss = self.exploits.get("xss_validated", [])
        if xss:
            recs.append(f"3. **HIGH:** {len(xss)} confirmed XSS vulnerabilities. Implement output encoding "
                        "and Content-Security-Policy headers.")

        headers = self.vuln.get("security_headers", [])
        missing_hsts = sum(1 for h in headers if "strict-transport-security" in h.get("missing", []))
        if missing_hsts:
            recs.append(f"4. **MEDIUM:** Deploy HSTS headers on {missing_hsts} hosts to prevent "
                        "protocol downgrade attacks.")

        tls = self.vuln.get("tls_analysis", [])
        poor_tls = sum(1 for t in tls if t.get("grade") in ("D", "F"))
        if poor_tls:
            recs.append(f"5. **HIGH:** Upgrade TLS configuration on {poor_tls} hosts with D/F grades. "
                        "Disable legacy protocols (TLS 1.0/1.1) and weak cipher suites.")

        takeovers = self.vuln.get("takeover", [])
        risky = sum(1 for t in takeovers if t.get("status") in ("confirmed", "potential"))
        if risky:
            recs.append(f"6. **HIGH:** {risky} subdomains at risk of takeover. Remove dangling CNAME "
                        "records or reclaim the services.")

        mail = self.vuln.get("mail_intel", [])
        high_risk_mail = [m for m in mail if m.get("risk_score", 0) > 50]
        if high_risk_mail:
            recs.append("7. **MEDIUM:** Improve email security posture. Deploy SPF, DKIM, and DMARC "
                        "records to prevent email spoofing.")

        if not recs:
            recs.append("No critical recommendations at this time. Continue monitoring.")

        return "## Recommendations\n\n" + "\n\n".join(recs)

    def _methodology(self) -> str:
        return """## Methodology

This assessment was performed using Aegis Vanguard, Judah Security's autonomous
pentesting agent. The following 5-phase pipeline was executed:

| Phase | Description | Tools Used |
|-------|-------------|------------|
| 1. Pre-Reconnaissance | Infrastructure fingerprinting, tech stack identification | nmap, whatweb, wafw00f, cmseek |
| 2. Discovery | Attack surface mapping, subdomain enum, crawling, fuzzing | subfinder, dnsx, httpx, katana, waybackurls, gau, ffuf, arjun |
| 3. Vulnerability Analysis | Parallel scanning across vulnerability categories | nuclei, nikto, tlsx, httpx (headers), dig (mail) |
| 4. Exploit Validation | Targeted exploitation to confirm findings | sqlmap, XSStrike, wpscan, testssl.sh |
| 5. Reporting | Automated report generation with findings correlation | Aegis Vanguard reporter |

### Scan Depth Levels

- **Quick:** Phases 1-2 only (reconnaissance)
- **Standard:** Phases 1-4 (recon + vuln analysis + validation)
- **Full:** All phases with extended exploit validation and deep TLS testing"""

    def _appendix(self) -> str:
        return f"""## Appendix

### Platform Statistics

| Metric | Value |
|--------|-------|
| Findings submitted | {self.stats.get('submitted', 0)} |
| New findings created | {self.stats.get('created', 0)} |
| Batches sent | {self.stats.get('batches', 0)} |
| Errors | {self.stats.get('errors', 0)} |

### Disclaimer

This assessment was performed by an automated security agent. While significant
effort has been made to minimize false positives through exploit validation,
all findings should be verified by a qualified security professional before
remediation. This report does not guarantee completeness of vulnerability
coverage.

---

*Generated by Judah Security - Aegis Vanguard Agent*
*{self.finished_at}*"""

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    def _severity_counts(self) -> dict:
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in self.vuln.get("nuclei_vulns", []):
            sev = v.get("info", {}).get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        for v in self.vuln.get("nikto_vulns", []):
            counts["medium"] += 1

        for s in self.exploits.get("injection_validated", []):
            if s.get("vulnerable"):
                counts["critical"] += 1
        for x in self.exploits.get("xss_validated", []):
            counts["high"] += 1

        return counts

    def _key_findings_bullets(self) -> str:
        bullets = []
        sev = self._severity_counts()

        sqli = self.exploits.get("injection_validated", [])
        if sqli:
            bullets.append(f"- **SQL Injection confirmed** on {len(sqli)} endpoint(s) via sqlmap")

        xss = self.exploits.get("xss_validated", [])
        if xss:
            bullets.append(f"- **XSS confirmed** on {len(xss)} endpoint(s) via XSStrike")

        nuclei_crit = [v for v in self.vuln.get("nuclei_vulns", [])
                       if v.get("info", {}).get("severity") == "critical"]
        if nuclei_crit:
            names = list({v.get("info", {}).get("name", "Unknown") for v in nuclei_crit})[:3]
            bullets.append(f"- **{len(nuclei_crit)} critical vulnerabilities** detected: {', '.join(names)}")

        takeovers = [t for t in self.vuln.get("takeover", []) if t.get("status") in ("confirmed", "potential")]
        if takeovers:
            bullets.append(f"- **{len(takeovers)} subdomain(s) at risk of takeover**")

        tls_poor = [t for t in self.vuln.get("tls_analysis", []) if t.get("grade") in ("D", "F")]
        if tls_poor:
            bullets.append(f"- **{len(tls_poor)} hosts with failing TLS grades** (D/F)")

        headers = self.vuln.get("security_headers", [])
        missing_csp = sum(1 for h in headers if "content-security-policy" in h.get("missing", []))
        if missing_csp:
            bullets.append(f"- **{missing_csp} hosts missing Content-Security-Policy** header")

        if not bullets:
            bullets.append("- No critical or high-severity findings identified")

        return "\n".join(bullets)

    def _format_nuclei_vuln(self, vuln: dict) -> str:
        info = vuln.get("info", {})
        name = info.get("name", vuln.get("template-id", "Unknown"))
        sev = info.get("severity", "info")
        matched = vuln.get("matched-at", vuln.get("host", ""))
        desc = info.get("description", "")
        template = vuln.get("template-id", "")
        tags = ", ".join(info.get("tags", [])[:5])

        cve = info.get("classification", {}).get("cve-id", "")
        if isinstance(cve, list):
            cve = cve[0] if cve else ""

        lines = [f"**{name}** (`{sev}`)\n"]
        lines.append(f"- Target: `{matched}`")
        if template:
            lines.append(f"- Template: `{template}`")
        if cve:
            lines.append(f"- CVE: {cve}")
        if tags:
            lines.append(f"- Tags: {tags}")
        if desc:
            lines.append(f"- {desc[:200]}")
        lines.append("")
        return "\n".join(lines)
