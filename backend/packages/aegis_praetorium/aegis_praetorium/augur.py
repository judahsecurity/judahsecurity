"""
Augur — Aegis Vanguard's tool-output interpreter.

Named after the Roman augur (the priest who read meaningful signs from raw
signals — bird flight, lightning, entrails — and translated them into actionable
guidance), Augur is the **post-tool output filter** that turns raw scanner
output into:

  1. Compressed, high-signal text the LLM can actually reason about within a
     tight token budget (replaces blunt head-truncation).
  2. Structured "next-step" recommendations the agent should chain into next
     (e.g. nuclei detects WordPress on info severity → recommend execute_wpscan;
     nuclei discovers /admin → recommend execute_ffuf with an admin wordlist).

Key design point — info/low findings are NOT dropped by default. Many of
nuclei's most valuable hits arrive at info severity: tech-detect templates that
identify WordPress, Drupal, Jenkins; exposed-panel templates that surface
/admin, /actuator, /phpmyadmin; exposure templates that surface /.git, /.env,
/backup.zip. These are exactly the signals that should pivot the agent to a
deeper, technology-specific tool. Augur retains every info/low finding that
matches an "actionable signal" pattern and attaches a recommended follow-up.

Per-tool filters today:
  - nuclei  (JSONL): severity gate + actionable info/low retention + chained recs
  - nmap    (text):  drop banner garbage, keep host/port/service/version table
  - naabu   (JSON or text): dedupe + sort
  - ffuf    (JSON):  keep matched results only
  - amass / subfinder: dedupe + sort + count summary
  - prowler/themis (OCSF JSON): keep only failed checks
  - default: pass through (Lictor's hard cap still applies)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("aegis.augur")


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass
class NextStep:
    """A concrete follow-up tool invocation Augur recommends to the agent."""

    tool_name: str
    args: str
    rationale: str
    priority: int = 5            # 1=highest
    category: str = "augur_pivot"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "args": self.args,
            "rationale": self.rationale,
            "priority": self.priority,
            "category": self.category,
        }


@dataclass
class AugurReading:
    """The interpreted result Augur returns to the caller."""

    summary: str                          # human/agent-readable text block
    kept: int = 0
    dropped: int = 0
    actionable_signals: List[Dict[str, Any]] = field(default_factory=list)
    next_steps: List[NextStep] = field(default_factory=list)
    raw_truncated: bool = False

    def to_text(self) -> str:
        """Render as text for the LLM's context."""
        parts = [self.summary.rstrip()]
        if self.next_steps:
            parts.append("")
            parts.append("AUGUR RECOMMENDED NEXT STEPS")
            parts.append("(deterministic pivots derived from this scan output;"
                         " run with create_finding/save_note context as needed)")
            for i, ns in enumerate(self.next_steps, 1):
                parts.append(f"  {i}. {ns.tool_name}(args=\"{ns.args}\")")
                parts.append(f"     reason: {ns.rationale}")
        if self.dropped:
            parts.append("")
            parts.append(
                f"(augur: kept {self.kept}, dropped {self.dropped} low-signal "
                f"finding(s) — set AUGUR_VERBOSE=true for raw output)"
            )
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Actionable-signal rules for nuclei info/low findings.
# Each rule: (matches_finding -> bool, build_next_step -> NextStep | None,
#            human_label, category)
# ---------------------------------------------------------------------------


def _matched_at_host(finding: Dict[str, Any]) -> str:
    return (finding.get("matched-at") or finding.get("host") or "").strip()


def _info_tags(finding: Dict[str, Any]) -> List[str]:
    info = finding.get("info") or {}
    raw = info.get("tags") or []
    if isinstance(raw, str):
        return [t.strip().lower() for t in raw.split(",") if t.strip()]
    return [str(t).strip().lower() for t in raw]


def _template_id(finding: Dict[str, Any]) -> str:
    return (finding.get("template-id") or finding.get("templateID") or "").lower()


def _template_path(finding: Dict[str, Any]) -> str:
    return (finding.get("template") or finding.get("template-path") or "").lower()


def _hostname_only(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1) if m else url


def _root_url(url: str) -> str:
    m = re.match(r"(https?://[^/]+)", url)
    return m.group(1) if m else url


# WordPress: any wordpress tag or template-id starting with wordpress-/wp-
def _is_wordpress(f: Dict[str, Any]) -> bool:
    tags = _info_tags(f)
    tid = _template_id(f)
    matched = _matched_at_host(f).lower()
    return (
        "wordpress" in tags
        or tid.startswith("wordpress-")
        or tid.startswith("wp-")
        or "/wp-content/" in matched
        or "/wp-includes/" in matched
        or "/wp-login.php" in matched
        or "/wp-json" in matched
    )


def _wp_next(f: Dict[str, Any]) -> Optional[NextStep]:
    host = _hostname_only(_matched_at_host(f))
    if not host:
        return None
    return NextStep(
        tool_name="execute_wpscan",
        args=f"--url https://{host} --enumerate vp,vt,u",
        rationale=(
            "Augur: nuclei flagged a WordPress signal at "
            f"{_matched_at_host(f) or host}. Enumerate vulnerable plugins, "
            "themes, and users with WPScan to convert this fingerprint into "
            "concrete findings."
        ),
        priority=2,
        category="cms_followup",
    )


def _is_other_cms(f: Dict[str, Any]) -> Tuple[bool, str]:
    tags = _info_tags(f)
    tid = _template_id(f)
    for cms in ("drupal", "joomla", "magento", "ghost", "typo3", "umbraco"):
        if cms in tags or tid.startswith(f"{cms}-"):
            return True, cms
    return False, ""


def _other_cms_next(f: Dict[str, Any]) -> Optional[NextStep]:
    ok, cms = _is_other_cms(f)
    if not ok:
        return None
    host = _hostname_only(_matched_at_host(f))
    return NextStep(
        tool_name="execute_cmseek",
        args=f"-u https://{host} --batch",
        rationale=(
            f"Augur: nuclei detected {cms.title()} at {_matched_at_host(f)}. "
            f"CMSeeK fingerprints {cms.title()} version + plugin set and links "
            "known CVEs."
        ),
        priority=2,
        category="cms_followup",
    )


# Exposed admin / login panels
_PANEL_PATHS = (
    "/admin", "/administrator", "/wp-admin", "/login", "/manager",
    "/console", "/portal", "/dashboard", "/cpanel", "/phpmyadmin",
    "/pma", "/adminer", "/webmail", "/mail",
)


def _is_panel(f: Dict[str, Any]) -> bool:
    tags = _info_tags(f)
    tid = _template_id(f)
    matched = _matched_at_host(f).lower()
    return (
        "panel" in tags
        or "login" in tags
        or "exposed-panel" in tags
        or tid.startswith("exposed-panel-")
        or any(p in matched for p in _PANEL_PATHS)
    )


def _panel_next(f: Dict[str, Any]) -> Optional[NextStep]:
    matched = _matched_at_host(f)
    base = _root_url(matched)
    if not base:
        return None
    return NextStep(
        tool_name="execute_ffuf",
        args=(
            f"-u {base}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/"
            f"AdminPanels.txt -mc 200,301,302,401,403 -t 40"
        ),
        rationale=(
            f"Augur: panel/login surface discovered at {matched}. Brute-force "
            "the admin tree with an AdminPanels wordlist to enumerate sibling "
            "paths (often reveals /admin/api, /admin/backup, /admin/console)."
        ),
        priority=3,
        category="path_discovery",
    )


# Exposed sensitive files / dirs
_EXPOSURE_PATHS = (
    "/.git", "/.svn", "/.hg", "/.env", "/.aws/credentials",
    "/.htaccess", "/.htpasswd", "/web.config",
    "/backup", "/backups", "/dump.sql", "/db.sql", "/database.sql",
    "/config.php.bak", "/wp-config.php.bak", "/server-status",
    "/server-info", "/phpinfo.php", "/info.php",
)


def _is_exposure(f: Dict[str, Any]) -> Tuple[bool, str]:
    tags = _info_tags(f)
    tid = _template_id(f)
    matched = _matched_at_host(f).lower()
    # Panels are routed by _is_panel — exclude them here to avoid stealing
    # better pivots (ffuf with admin wordlist beats a single curl).
    if tid.startswith("exposed-panel"):
        return False, ""
    if "exposure" in tags or "disclosure" in tags or tid.startswith("exposed-"):
        return True, "exposure-tag"
    for p in _EXPOSURE_PATHS:
        if p in matched:
            return True, p
    if tid in {"git-config", "git-config-exposure", "env-file", "ds-store-file"}:
        return True, tid
    return False, ""


def _exposure_next(f: Dict[str, Any]) -> Optional[NextStep]:
    ok, kind = _is_exposure(f)
    if not ok:
        return None
    matched = _matched_at_host(f)

    # /.git → fetch /.git/config and consider git-dumper-style retrieval
    if "/.git" in matched.lower() or "git-config" in kind:
        base = _root_url(matched)
        return NextStep(
            tool_name="execute_curl",
            args=f"-s -i {base}/.git/config",
            rationale=(
                f"Augur: exposed .git surface at {matched}. Fetch /.git/config "
                "to confirm; if accessible, the full repo (and its history of "
                "secrets) is recoverable."
            ),
            priority=1,
            category="exposure_followup",
        )

    # /.env or env-file → fetch the file
    if "/.env" in matched.lower() or kind == "env-file":
        return NextStep(
            tool_name="execute_curl",
            args=f"-s -i {matched}",
            rationale=(
                f"Augur: exposed .env at {matched}. Fetch the file — env "
                "files routinely leak DB credentials, API keys, and secret "
                "keys; pipe the response through scan_js_urls_for_secrets if "
                "you want regex-based highlighting."
            ),
            priority=1,
            category="exposure_followup",
        )

    # phpinfo / server-status: confirm + capture
    if any(p in matched.lower() for p in ("phpinfo", "server-status", "server-info")):
        return NextStep(
            tool_name="execute_curl",
            args=f"-s {matched}",
            rationale=(
                f"Augur: information-disclosure surface at {matched}. Capture "
                "the full body — these endpoints leak internal IPs, env vars, "
                "loaded modules, and request internals useful for chaining."
            ),
            priority=2,
            category="exposure_followup",
        )

    # Generic backup / sql dump
    if any(p in matched.lower() for p in ("/backup", "/dump.sql", "/db.sql", "/database.sql")):
        return NextStep(
            tool_name="execute_curl",
            args=f"-sI {matched}",
            rationale=(
                f"Augur: backup/database dump surface at {matched}. HEAD the "
                "file first to gauge size, then GET if reasonable. Treat the "
                "contents as an asset themselves."
            ),
            priority=2,
            category="exposure_followup",
        )

    # Generic exposure: fall back to curl
    return NextStep(
        tool_name="execute_curl",
        args=f"-s -i {matched}",
        rationale=(
            f"Augur: exposure-class finding at {matched}. Fetch the response to "
            "verify the leak before raising a finding."
        ),
        priority=3,
        category="exposure_followup",
    )


# API surface: swagger / openapi / graphql / actuator
_API_HINTS = (
    "/swagger", "/openapi", "/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/actuator", "/actuator/env",
    "/actuator/heapdump", "/actuator/beans",
)


def _is_api(f: Dict[str, Any]) -> bool:
    tags = _info_tags(f)
    matched = _matched_at_host(f).lower()
    return (
        "api" in tags or "swagger" in tags or "graphql" in tags
        or "actuator" in tags
        or any(p in matched for p in _API_HINTS)
    )


def _api_next(f: Dict[str, Any]) -> Optional[NextStep]:
    matched = _matched_at_host(f)
    matched_lower = matched.lower()
    if "graphql" in matched_lower or "graphiql" in matched_lower:
        return NextStep(
            tool_name="execute_schemathesis",
            args=f"run {matched} --checks all --hypothesis-deadline=5000",
            rationale=(
                f"Augur: GraphQL endpoint at {matched}. Schemathesis introspects "
                "the schema and fuzzes resolvers for 500s, auth bypasses, and "
                "validation flaws."
            ),
            priority=3,
            category="api_followup",
        )
    if any(s in matched_lower for s in ("/openapi", "/swagger", "/api-docs", "/swagger-ui", "/redoc")):
        base = _root_url(matched)
        return NextStep(
            tool_name="discover_swagger_spec",
            args=f"target_url={base}",
            rationale=(
                f"Augur: Swagger/OpenAPI surface detected at {matched}. "
                "Run discover_swagger_spec to enumerate all documented endpoints, "
                "then test_swagger_api to check for unauthenticated access, "
                "PII leakage, and exposed secrets (AutoSwagger-style)."
            ),
            priority=2,
            category="api_followup",
        )
    if "/actuator" in matched_lower:
        base = _root_url(matched)
        return NextStep(
            tool_name="execute_nuclei",
            args=f"-u {base} -tags spring,actuator -severity info,low,medium,high,critical -jsonl",
            rationale=(
                f"Augur: Spring Boot actuator surface at {matched}. Run the "
                "spring/actuator nuclei tag set to enumerate every exposed "
                "actuator endpoint (env, heapdump, beans)."
            ),
            priority=2,
            category="api_followup",
        )
    # Generic API hint — try swagger discovery against the base origin
    base = _root_url(matched)
    if base:
        return NextStep(
            tool_name="discover_swagger_spec",
            args=f"target_url={base}",
            rationale=(
                f"Augur: API-tagged signal at {matched}. Run discover_swagger_spec "
                "to check if the target exposes an OpenAPI/Swagger spec; if found, "
                "follow with test_swagger_api for unauthenticated endpoint testing."
            ),
            priority=4,
            category="api_followup",
        )
    return None


# Default credentials
def _is_default_login(f: Dict[str, Any]) -> bool:
    tags = _info_tags(f)
    tid = _template_id(f)
    return (
        "default-login" in tags
        or tid.startswith("default-")
        or "/default-logins/" in _template_path(f)
    )


def _default_login_next(f: Dict[str, Any]) -> Optional[NextStep]:
    matched = _matched_at_host(f)
    return NextStep(
        tool_name="save_note",
        args=(
            f"category=credential content=Default-credentials surface at "
            f"{matched} — verify manually before brutus to avoid lockout"
        ),
        rationale=(
            "Augur: default-login template fired. Stash a credential note for "
            "the operator; do not auto-brutus until scope confirms."
        ),
        priority=1,
        category="credential_followup",
    )


# Specific high-value tech that pivots
def _is_jenkins(f: Dict[str, Any]) -> bool:
    return "jenkins" in _info_tags(f) or _template_id(f).startswith("jenkins-")


def _jenkins_next(f: Dict[str, Any]) -> Optional[NextStep]:
    base = _root_url(_matched_at_host(f))
    return NextStep(
        tool_name="execute_nuclei",
        args=f"-u {base} -tags jenkins -severity low,medium,high,critical -jsonl",
        rationale=(
            f"Augur: Jenkins surface at {_matched_at_host(f)}. Run the full "
            "jenkins nuclei tag (script-console, takeovers, auth bypasses)."
        ),
        priority=2,
        category="tech_followup",
    )


def _is_atlassian(f: Dict[str, Any]) -> Tuple[bool, str]:
    tags = _info_tags(f)
    tid = _template_id(f)
    for kw in ("jira", "confluence", "bitbucket"):
        if kw in tags or tid.startswith(f"{kw}-"):
            return True, kw
    return False, ""


def _atlassian_next(f: Dict[str, Any]) -> Optional[NextStep]:
    ok, kw = _is_atlassian(f)
    if not ok:
        return None
    base = _root_url(_matched_at_host(f))
    return NextStep(
        tool_name="execute_nuclei",
        args=f"-u {base} -tags {kw} -severity low,medium,high,critical -jsonl",
        rationale=(
            f"Augur: {kw.title()} surface at {_matched_at_host(f)}. Run the "
            f"full {kw} nuclei tag for known CVE coverage."
        ),
        priority=2,
        category="tech_followup",
    )


# AI / chatbot endpoints discovered passively
def _is_chatbot(f: Dict[str, Any]) -> bool:
    tags = _info_tags(f)
    tid = _template_id(f)
    matched = _matched_at_host(f).lower()
    return (
        any(t in tags for t in ("chatbot", "openai", "anthropic", "langchain"))
        or any(s in tid for s in ("chatbot", "openai", "anthropic", "langchain"))
        or any(p in matched for p in ("/chat", "/v1/chat/completions", "/api/chat"))
    )


def _chatbot_next(f: Dict[str, Any]) -> Optional[NextStep]:
    matched = _matched_at_host(f)
    base = _root_url(matched)
    return NextStep(
        tool_name="execute_llm_red_team",
        args=f"target_url={base} endpoint_url={matched}",
        rationale=(
            f"Augur: chatbot/AI surface at {matched}. Run OWASP LLM Top-10 "
            "checks (prompt injection, jailbreak, data exfil, SSRF tool abuse)."
        ),
        priority=2,
        category="ai_followup",
    )


# Ordered rule list: most specific first. Panels run before generic exposure so
# /admin → ffuf-with-admin-wordlist wins over a single curl.
_NUCLEI_ACTIONABLE_RULES = [
    ("wordpress", _is_wordpress, _wp_next),
    ("cms", lambda f: _is_other_cms(f)[0], _other_cms_next),
    ("default-login", _is_default_login, _default_login_next),
    ("jenkins", _is_jenkins, _jenkins_next),
    ("atlassian", lambda f: _is_atlassian(f)[0], _atlassian_next),
    ("api", _is_api, _api_next),
    ("panel", _is_panel, _panel_next),
    ("exposure", lambda f: _is_exposure(f)[0], _exposure_next),
    ("chatbot", _is_chatbot, _chatbot_next),
]


# ---------------------------------------------------------------------------
# Tool-specific filters
# ---------------------------------------------------------------------------


_HARD_FINDINGS = {"critical", "high", "medium"}


def filter_nuclei(raw: str, max_chars: int = 20000) -> AugurReading:
    """Filter nuclei JSONL output. Keep all medium+ severities; keep info/low
    only when they match an actionable signal pattern; emit next-step pivots."""
    if not raw or not raw.strip():
        return AugurReading(summary="(nuclei: no output)")

    kept_lines: List[str] = []
    actionable: List[Dict[str, Any]] = []
    next_steps: List[NextStep] = []
    dropped = 0
    seen_pivot_keys = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            f = json.loads(line)
        except json.JSONDecodeError:
            kept_lines.append(line)
            continue
        info = f.get("info") or {}
        sev = (info.get("severity") or "").lower()
        tid = _template_id(f)
        matched = _matched_at_host(f)
        name = info.get("name") or tid

        if sev in _HARD_FINDINGS or sev == "unknown":
            kept_lines.append(f"[{sev or 'unknown'}] {name} → {matched} (id={tid})")
            continue

        # info / low — apply actionable rules
        rule_hit = False
        for rule_name, predicate, builder in _NUCLEI_ACTIONABLE_RULES:
            try:
                if not predicate(f):
                    continue
            except Exception as e:
                logger.debug("augur rule %s crashed: %s", rule_name, e)
                continue
            rule_hit = True
            kept_lines.append(
                f"[{sev}] {name} → {matched} (signal={rule_name}, id={tid})"
            )
            actionable.append({
                "signal": rule_name,
                "severity": sev,
                "template_id": tid,
                "matched_at": matched,
                "name": name,
            })
            ns = builder(f) if builder else None
            if ns:
                key = (ns.tool_name, ns.args)
                if key not in seen_pivot_keys:
                    seen_pivot_keys.add(key)
                    next_steps.append(ns)
            break
        if not rule_hit:
            dropped += 1

    body = "NUCLEI SCAN — Augur-filtered\n"
    body += f"Findings kept: {len(kept_lines)} | dropped (low-signal): {dropped}\n"
    if actionable:
        signals = sorted({a["signal"] for a in actionable})
        body += f"Actionable info/low signals: {', '.join(signals)}\n"
    body += "\n" + "\n".join(kept_lines)
    truncated = False
    if len(body) > max_chars:
        body = body[: max_chars] + "\n\n... (augur: clipped, raise AGENT_TOOL_OUTPUT_MAX_CHARS for more)"
        truncated = True

    return AugurReading(
        summary=body,
        kept=len(kept_lines),
        dropped=dropped,
        actionable_signals=actionable,
        next_steps=next_steps,
        raw_truncated=truncated,
    )


def filter_nmap(raw: str, max_chars: int = 20000) -> AugurReading:
    """Strip nmap banner ASCII and progress lines; keep host/port/service table."""
    if not raw:
        return AugurReading(summary="(nmap: no output)")
    keep: List[str] = []
    dropped = 0
    skip_prefixes = (
        "Starting Nmap", "Host is up", "Read data files", "Initiating ",
        "Completed ", "NSE: ", "Stats: ", "Nmap done:", "Service Info:",
    )
    for ln in raw.splitlines():
        s = ln.rstrip()
        if not s:
            continue
        if s.startswith(skip_prefixes):
            dropped += 1
            continue
        if s.startswith("Nmap scan report") or s[:5].rstrip().isdigit() or "PORT" in s:
            keep.append(s)
            continue
        if "/tcp" in s or "/udp" in s or s.startswith("|") or "MAC Address" in s:
            keep.append(s)
            continue
        dropped += 1
    body = "NMAP — Augur-filtered\n" + "\n".join(keep)
    if len(body) > max_chars:
        body = body[: max_chars] + "\n... (clipped)"
    return AugurReading(
        summary=body,
        kept=len(keep),
        dropped=dropped,
    )


def filter_naabu(raw: str, max_chars: int = 20000) -> AugurReading:
    """naabu prints host:port per line; dedupe + sort + summarize."""
    if not raw:
        return AugurReading(summary="(naabu: no output)")
    rows: List[str] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        # JSON line?
        if ln.startswith("{"):
            try:
                obj = json.loads(ln)
                host = obj.get("host") or obj.get("ip")
                port = obj.get("port")
                if host and port:
                    rows.append(f"{host}:{port}")
                    continue
            except json.JSONDecodeError:
                pass
        rows.append(ln)
    rows = sorted(set(rows))
    body = f"NAABU — {len(rows)} unique host:port pairs\n" + "\n".join(rows)
    if len(body) > max_chars:
        body = body[: max_chars] + "\n... (clipped)"
    return AugurReading(summary=body, kept=len(rows))


def filter_ffuf(raw: str, max_chars: int = 20000) -> AugurReading:
    """ffuf JSON output: keep matched results only, surface admin/login/exposure
    hits as next-step pivots."""
    if not raw:
        return AugurReading(summary="(ffuf: no output)")
    try:
        obj = json.loads(raw)
        results = obj.get("results", [])
    except (json.JSONDecodeError, AttributeError):
        # Plain-text mode: keep lines with status codes
        keep = [ln for ln in raw.splitlines() if re.search(r"\[Status:\s*\d{3}\b", ln)]
        body = f"FFUF — {len(keep)} matched results\n" + "\n".join(keep)
        if len(body) > max_chars:
            body = body[: max_chars] + "\n... (clipped)"
        return AugurReading(summary=body, kept=len(keep))

    rows = []
    next_steps: List[NextStep] = []
    seen_pivot = set()
    for r in results:
        url = r.get("url") or ""
        status = r.get("status")
        length = r.get("length")
        rows.append(f"  {status} {length}b  {url}")
        url_lower = url.lower()
        if any(p in url_lower for p in (".git", ".env", "phpinfo", "server-status")):
            key = ("execute_curl", f"-s -i {url}")
            if key not in seen_pivot:
                seen_pivot.add(key)
                next_steps.append(NextStep(
                    tool_name="execute_curl",
                    args=f"-s -i {url}",
                    rationale=f"Augur: ffuf surfaced sensitive path {url}. Fetch to confirm leak.",
                    priority=2,
                    category="exposure_followup",
                ))

    body = f"FFUF — {len(rows)} matched results\n" + "\n".join(rows)
    if len(body) > max_chars:
        body = body[: max_chars] + "\n... (clipped)"
    return AugurReading(summary=body, kept=len(rows), next_steps=next_steps)


def filter_subdomain_list(raw: str, max_chars: int = 20000, source: str = "subfinder") -> AugurReading:
    """subfinder/amass/crtsh: dedupe + sort + count summary."""
    if not raw:
        return AugurReading(summary=f"({source}: no output)")
    domains: List[str] = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("{"):
            try:
                obj = json.loads(ln)
                d = obj.get("host") or obj.get("name") or obj.get("domain")
                if d:
                    domains.append(d.lower())
                    continue
            except json.JSONDecodeError:
                pass
        domains.append(ln.lower())
    domains = sorted(set(domains))
    head = "\n".join(domains[:200])
    more = ""
    if len(domains) > 200:
        more = f"\n... ({len(domains) - 200} more, truncated)"
    body = f"{source.upper()} — {len(domains)} unique hosts\n{head}{more}"
    if len(body) > max_chars:
        body = body[: max_chars] + "\n... (clipped)"
    return AugurReading(summary=body, kept=len(domains))


def filter_autoswagger(raw: str, max_chars: int = 20000) -> AugurReading:
    """Parse autoswagger JSON output and emit next-step pivots for flagged endpoints."""
    if not raw or not raw.strip():
        return AugurReading(summary="(autoswagger: no output)")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Plain-text fallback — pass through trimmed
        body = f"AUTOSWAGGER OUTPUT\n{raw[:max_chars]}"
        return AugurReading(summary=body, kept=1)

    specs_found = data.get("specs_found", data.get("spec_count", 0))
    specs = data.get("specs", [])
    endpoint_count = data.get("endpoint_count", data.get("endpoints_documented", 0))
    tested_count = data.get("endpoints_tested", 0)
    flagged = data.get("flagged_endpoints", [])
    tool_used = data.get("tool", "autoswagger")
    target = data.get("target", "")

    lines: List[str] = [
        f"AUTOSWAGGER — {tool_used}",
        f"Target: {target}",
        f"Specs discovered: {specs_found}",
        f"Endpoints documented: {endpoint_count}  |  Tested: {tested_count}  |  Flagged: {len(flagged)}",
    ]

    if specs:
        lines.append("\nDiscovered specs:")
        for s in specs:
            lines.append(
                f"  [{s.get('phase','?')}] {s.get('url','')}  "
                f"(v{s.get('version','?')}, {s.get('endpoint_count',0)} endpoints)"
            )

    next_steps: List[NextStep] = []
    seen_pivot: set = set()

    if flagged:
        lines.append("\nFlagged endpoints (PII / secrets / large responses):")
        for ep in flagged[:30]:
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            status = ep.get("status", "?")
            pii = ep.get("pii", {})
            secrets = ep.get("secrets", {})
            large = ep.get("large_response", False)
            flags = []
            if pii:
                flags.append(f"PII:{list(pii.keys())}")
            if secrets:
                flags.append(f"SECRETS:{list(secrets.keys())}")
            if large:
                flags.append("LARGE_RESPONSE")
            lines.append(f"  {method} {url} [{status}] → {', '.join(flags)}")

            # Recommend sqlmap for GET endpoints with parameters that returned data
            if method == "GET" and "?" in url and pii:
                key = ("execute_sqlmap", url)
                if key not in seen_pivot:
                    seen_pivot.add(key)
                    next_steps.append(NextStep(
                        tool_name="execute_sqlmap",
                        args=f"-u \"{url}\" --batch --level=2 --risk=1",
                        rationale=(
                            f"Augur: unauthenticated {method} {url} returned PII — "
                            "test for SQL injection to confirm data extraction path."
                        ),
                        priority=2,
                        category="api_exploit",
                    ))
            # Recommend manual review note for secret leakage
            if secrets:
                key = ("save_note", url)
                if key not in seen_pivot:
                    seen_pivot.add(key)
                    next_steps.append(NextStep(
                        tool_name="save_note",
                        args=(
                            f"category=secret_exposure content=Secret patterns detected in "
                            f"API response: {method} {url} — {list(secrets.keys())}"
                        ),
                        rationale=(
                            "Augur: autoswagger found secret-pattern matches in an API "
                            "response — log for manual triage and reporter."
                        ),
                        priority=1,
                        category="credential_followup",
                    ))

    if specs_found and not flagged:
        lines.append("\nSpec discovered but no flagged endpoints — all endpoints auth-gated or clean.")

    if not specs_found:
        lines.append("\nNo OpenAPI/Swagger spec found at the target.")

    body = "\n".join(lines)
    if len(body) > max_chars:
        body = body[:max_chars] + "\n... (augur: clipped)"

    return AugurReading(
        summary=body,
        kept=len(flagged),
        dropped=max(0, tested_count - len(flagged)),
        next_steps=next_steps,
    )


def filter_prowler(raw: str, max_chars: int = 20000) -> AugurReading:
    """Themis/Prowler OCSF JSON: keep only failed checks (status=FAIL)."""
    if not raw:
        return AugurReading(summary="(prowler: no output)")
    fails: List[str] = []
    total = 0
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or not ln.startswith("{"):
            continue
        total += 1
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        status = (obj.get("status") or obj.get("status_code") or
                  obj.get("StatusCode") or obj.get("status_detail") or "").upper()
        if "FAIL" not in status:
            continue
        check = obj.get("check_id") or obj.get("CheckID") or obj.get("finding_info", {}).get("title")
        sev = (obj.get("severity") or obj.get("Severity") or "").upper()
        resource = (obj.get("resource_id") or obj.get("ResourceArn")
                    or obj.get("resource", {}).get("uid", ""))
        fails.append(f"  [{sev}] {check} — {resource}")
    body = (f"PROWLER (Themis) — {len(fails)} FAIL of {total} checks (Augur dropped PASS/INFO)\n"
            + "\n".join(fails[:500]))
    if len(fails) > 500:
        body += f"\n... ({len(fails) - 500} more failures, truncated)"
    if len(body) > max_chars:
        body = body[: max_chars] + "\n... (clipped)"
    return AugurReading(summary=body, kept=len(fails), dropped=total - len(fails))


# ---------------------------------------------------------------------------
# Augur — the dispatcher
# ---------------------------------------------------------------------------


# Map of canonical scanner kind → filter function. Tool-name lookup strips
# common prefixes (``execute_``, ``scan_``, ``run_``) so platform-style
# ``execute_nuclei`` and sandboxed ``scan_nuclei`` both resolve here.
_FILTERS = {
    "nuclei": filter_nuclei,
    "nmap": filter_nmap,
    "naabu": filter_naabu,
    "ffuf": filter_ffuf,
    "subfinder": lambda r, m=20000: filter_subdomain_list(r, m, "subfinder"),
    "amass": lambda r, m=20000: filter_subdomain_list(r, m, "amass"),
    "crtsh": lambda r, m=20000: filter_subdomain_list(r, m, "crtsh"),
    "tldfinder": lambda r, m=20000: filter_subdomain_list(r, m, "tldfinder"),
    "themis": filter_prowler,
    "prowler": filter_prowler,
    "autoswagger": filter_autoswagger,
    "swagger_spec_discovery": filter_autoswagger,
    "autoswagger_native": filter_autoswagger,
}


def _canonical_tool(tool_name: str) -> str:
    """Strip ``execute_`` / ``scan_`` / ``run_`` prefixes for filter lookup."""
    for prefix in ("execute_", "scan_", "run_"):
        if tool_name.startswith(prefix):
            return tool_name[len(prefix):]
    return tool_name


class Augur:
    """Per-tool output interpreter. Returns AugurReading; never mutates raw."""

    def interpret(
        self,
        tool_name: str,
        raw_output: str,
        max_chars: int = 20000,
    ) -> Optional[AugurReading]:
        """Return a filtered reading, or None if no filter is registered.

        ``tool_name`` may be the canonical kind (``"nuclei"``) or a full
        platform / Aegis Vanguard tool name (``"execute_nuclei"`` / ``"scan_nuclei"``).
        """
        f = _FILTERS.get(_canonical_tool(tool_name))
        if not f:
            return None
        try:
            return f(raw_output, max_chars=max_chars)
        except Exception as e:
            logger.exception("augur: filter for %s crashed: %s — falling back", tool_name, e)
            return None


_augur: Optional[Augur] = None


def get_augur() -> Augur:
    global _augur
    if _augur is None:
        _augur = Augur()
    return _augur


__all__ = [
    "Augur",
    "AugurReading",
    "NextStep",
    "get_augur",
]
