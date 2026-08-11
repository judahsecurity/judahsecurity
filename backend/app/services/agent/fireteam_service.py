"""
Fireteam / Scatter-Gather ReAct pattern.

Purpose
-------
Spawn N *specialist* sub-agents in parallel, each given:

    * A tightly-scoped role (e.g. "web_recon", "cloud_audit", "secrets").
    * A restricted tool allowlist.
    * The same shared mission and targets.

Each specialist runs a short, focused ReAct loop and returns a compact
``SpecialistReport``. The orchestrator calling ``run_fireteam`` then
receives all reports in one shot so it can integrate their findings.

The implementation is deliberately self-contained -- it does not reuse the
main ``AgentOrchestrator`` because the sub-agents should be simpler, more
deterministic, and cheaper to run in bulk.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, Iterable, Optional

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Built-in specialist profiles
# ---------------------------------------------------------------------------


@dataclass
class SpecialistProfile:
    name: str
    role: str
    allowed_tools: list[str]
    max_iterations: int = 6
    max_tools_per_iteration: int = 4
    system_prompt_suffix: str = ""
    epithet: str = ""  # Aegis pantheon display name (Samson, Daniel, …)

    def __post_init__(self) -> None:
        if not self.epithet:
            try:
                from app.services.agent.aegis_pantheon import epithet_for

                self.epithet = epithet_for(self.name)
            except Exception:
                self.epithet = self.name.replace("_", " ").title()


DEFAULT_SPECIALISTS: list[SpecialistProfile] = [
    SpecialistProfile(
        name="web_recon",
        role=(
            "Passive web reconnaissance specialist. Enumerate assets, "
            "technologies, exposed ports and HTTP surface."
        ),
        allowed_tools=[
            "query_assets",
            "query_ports",
            "query_technologies",
            "analyze_attack_surface",
            "execute_httpx",
            "execute_naabu",
            "execute_subfinder",
            "execute_subfaster",
            "execute_crtsh",
            "execute_dnsx",
            "execute_uncover",
            "execute_whatweb",
            "execute_wappalyzer",
            "execute_katana",
            "execute_gau",
            "execute_feroxbuster",
        ],
        max_iterations=8,
    ),
    SpecialistProfile(
        name="content_api",
        role=(
            "Content and API discovery specialist. Crawl, fuzz dirs, mine "
            "historical URLs, find params and undocumented API routes."
        ),
        allowed_tools=[
            "query_assets",
            "execute_katana",
            "execute_gau",
            "execute_waybackurls",
            "execute_deep_crawl",
            "execute_ffuf",
            "execute_feroxbuster",
            "execute_kiterunner",
            "execute_arjun",
            "discover_parameters",
            "create_scan",
        ],
        max_iterations=8,
    ),
    SpecialistProfile(
        name="js_secrets",
        role=(
            "JavaScript recon specialist. Extract endpoints from bundles, "
            "find secrets, source maps, dep-confusion, and DOM sinks."
        ),
        allowed_tools=[
            "query_assets",
            "scan_js_urls_for_secrets",
            "execute_retirejs",
            "execute_gitleaks",
            "execute_hermes",
            "create_scan",
        ],
    ),
    SpecialistProfile(
        name="vuln_triage",
        role=(
            "Vulnerability triage specialist. Correlate findings with CVEs, "
            "exploit availability and blast radius. Never exploits anything."
        ),
        allowed_tools=[
            "query_vulnerabilities",
            "get_asset_details",
            "search_cve",
            "search_vulnx",
            "analyze_attack_surface",
            "rank_attack_surface",
        ],
    ),
    SpecialistProfile(
        name="secrets_hunter",
        role=(
            "Secrets & credential exposure specialist. Focus on leaked keys, "
            "exposed source maps, github secrets, and dependency-confusion."
        ),
        allowed_tools=[
            "execute_hermes",
            "execute_argus",
            "scan_js_urls_for_secrets",
            "execute_gitleaks",
            "query_assets",
        ],
    ),
    SpecialistProfile(
        name="cloud_audit",
        role=(
            "Cloud / CSPM specialist. Look for AWS/Azure/GCP misconfig, "
            "exposed buckets, IAM issues."
        ),
        allowed_tools=[
            "query_assets",
            "execute_themis",
            "search_cve",
            "analyze_attack_surface",
        ],
    ),
    SpecialistProfile(
        name="graphql_api",
        role=(
            "GraphQL / API specialist. Find GraphQL endpoints, probe them "
            "for introspection, verbose errors, CSRF, batching DoS."
        ),
        allowed_tools=[
            "execute_schemathesis",
            "execute_kiterunner",
            "execute_curl",
            "compare_requests",
            "create_scan",
            "query_assets",
            "update_hypothesis",
            "validate_finding",
            "create_finding",
        ],
    ),
    SpecialistProfile(
        name="takeover",
        role=(
            "Subdomain takeover specialist. Hunt dangling CNAMEs and "
            "provider fingerprints; only report confirmed/likely takeovers."
        ),
        allowed_tools=[
            "query_assets",
            "execute_dnsx",
            "execute_subfinder",
            "create_scan",
            "execute_nuclei",
        ],
    ),
    # ── Attack specialists (spawned from capability map after browser walkthrough) ──
    SpecialistProfile(
        name="app_mapper",
        role=(
            "Application mapper. You already have a browser capability map. "
            "Summarize features, trust boundaries, and the highest-value hunt "
            "queue. Do not spray scanners — reason about what a tester would try next."
        ),
        allowed_tools=[
            "query_assets",
            "analyze_attack_surface",
            "rank_attack_surface",
            "save_note",
            "execute_curl",
        ],
        max_iterations=4,
        system_prompt_suffix=(
            "Output a ranked hunt queue with concrete URLs/forms/APIs from the mission. "
            "Call save_note(category='artifact') with the map summary."
        ),
    ),
    SpecialistProfile(
        name="auth_logic",
        role=(
            "Auth / session / access-control specialist. Probe login, session cookies, "
            "forced browsing, and horizontal/vertical authz using concrete endpoints "
            "from the capability map and open engagement hypotheses."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_browser",
            "execute_httpx",
            "bypass_403",
            "test_saml_sso",
            "test_credential_spray",
            "execute_hydra",
            "execute_jwt",
            "compare_requests",
            "add_engagement_credential",
            "queue_finding_followups",
            "update_hypothesis",
            "log_engagement_approach",
            "save_note",
            "validate_finding",
            "create_finding",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Prefer compare_requests (anonymous vs auth). On default/weak login success: "
            "add_engagement_credential + queue_finding_followups(vuln_type='default_login'). "
            "Never invent credentials. Hand large sprays to credential_assault (Samson)."
        ),
    ),
    SpecialistProfile(
        name="credential_assault",
        role=(
            "Credential assault specialist (Samson). Prove default/weak/known credentials on "
            "mapped login forms with tiny lists; stash working creds and enqueue post-auth chains."
        ),
        allowed_tools=[
            "execute_httpx",
            "execute_curl",
            "execute_browser",
            "test_credential_spray",
            "execute_hydra",
            "add_engagement_credential",
            "queue_finding_followups",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Tiny lists only (defaults / known product creds). Always hydra -f / exit on success. "
            "On hit: add_engagement_credential + queue_finding_followups(vuln_type='default_login') "
            "+ validate_finding before create_finding. Never invent credentials; no rockyou."
        ),
    ),
    SpecialistProfile(
        name="api_authz",
        role=(
            "API authorization specialist. Test captured first-party APIs for IDOR, "
            "verb tampering, missing auth, and mass assignment on concrete paths."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_httpx",
            "execute_kiterunner",
            "execute_schemathesis",
            "discover_parameters",
            "execute_arjun",
            "compare_requests",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Prove with compare_requests across identities/object IDs. "
            "Status 200 alone is not a finding — show other-user fields."
        ),
    ),
    SpecialistProfile(
        name="host_tenant",
        role=(
            "Host-header / tenant-isolation specialist. Keep the same session and mutate "
            "Host or X-Forwarded-Host toward a peer tenant to prove cross-tenant access."
        ),
        allowed_tools=[
            "compare_requests",
            "execute_curl",
            "replay_http_request",
            "update_hypothesis",
            "queue_finding_followups",
            "log_engagement_approach",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Baseline = tenant A host + session A. Mutant = peer tenant Host/X-Forwarded-Host "
            "with the SAME cookies. PASS only if tenant B data appears. "
            "Kill on vhost reject or unchanged tenant A body. "
            "On proven: queue_finding_followups(vuln_type='host_header')."
        ),
    ),
    SpecialistProfile(
        name="business_logic",
        role=(
            "Business-logic specialist. Abuse workflows: step skipping, price/quantity "
            "tamper, mass assignment, insecure state transitions on mapped forms/APIs."
        ),
        allowed_tools=[
            "compare_requests",
            "replay_http_request",
            "execute_curl",
            "execute_browser",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Mutate one control at a time. Demonstrate expected vs actual state; "
            "do not complete fraudulent transactions — prove the bypass."
        ),
    ),
    SpecialistProfile(
        name="injection",
        role=(
            "Injection specialist (SQLi/XSS/SSTI/command). Use only parameters and "
            "forms discovered in the capability map or confirmed via arjun/discover_parameters."
        ),
        allowed_tools=[
            "discover_parameters",
            "execute_arjun",
            "execute_sqlmap",
            "execute_xsstrike",
            "execute_dalfox",
            "execute_commix",
            "execute_browser",
            "generate_injection_payloads",
            "execute_curl",
            "compare_requests",
            "update_hypothesis",
            "log_engagement_approach",
            "validate_finding",
            "create_finding",
        ],
        max_iterations=8,
    ),
    SpecialistProfile(
        name="file_upload",
        role=(
            "File upload specialist. Abuse upload forms/APIs from the map for "
            "content-type bypass, path issues, and stored XSS via uploaded content."
        ),
        allowed_tools=[
            "execute_curl",
            "execute_browser",
            "execute_httpx",
            "update_hypothesis",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=6,
    ),
    SpecialistProfile(
        name="saml_sso",
        role=(
            "SSO / SAML / OAuth specialist. Probe authorize/callback/SAML endpoints "
            "for open redirects, signature issues, and OIDC misconfig."
        ),
        allowed_tools=[
            "test_saml_sso",
            "execute_jwt",
            "execute_curl",
            "execute_browser",
            "compare_requests",
            "update_hypothesis",
            "validate_finding",
            "create_finding",
        ],
        max_iterations=6,
    ),
    SpecialistProfile(
        name="spa_client",
        role=(
            "SPA / client-side specialist. DOM XSS, hidden client routes, and "
            "JS-driven API abuse using the browsed pages and bundles."
        ),
        allowed_tools=[
            "execute_browser",
            "execute_deep_crawl",
            "scan_js_urls_for_secrets",
            "execute_retirejs",
            "execute_curl",
            "compare_requests",
            "update_hypothesis",
            "validate_finding",
            "create_finding",
        ],
        max_iterations=6,
    ),
    SpecialistProfile(
        name="coverage",
        role=(
            "Coverage / known-vuln specialist. Run Nuclei and related scanners AFTER "
            "logic hunts. If engagement credentials exist, prefer authenticated templates "
            "(-var username/password) for default-login and post-auth CVEs."
        ),
        allowed_tools=[
            "execute_nuclei",
            "execute_nikto",
            "execute_httpx",
            "execute_curl",
            "get_engagement_brain",
            "queue_finding_followups",
            "update_hypothesis",
            "add_engagement_credential",
            "validate_finding",
            "create_finding",
            "save_note",
        ],
        max_iterations=8,
        system_prompt_suffix=(
            "Check get_engagement_brain for credentials before nuclei. "
            "Example: execute_nuclei args='-u https://host -id grafana-default-login,CVE-2024-9264 "
            "-var username=admin -var password=prom-operator -jsonl'. "
            "On default-login hits: add_engagement_credential + queue_finding_followups. "
            "For Grafana admin sessions, ALSO prove datasource-proxy SSRF: create a temporary "
            "datasource aimed at https://kubernetes.default.svc or metadata, then "
            "GET /api/datasources/proxy/... — report only with internal response body evidence. "
            "Prefer read-only canaries; do not mutate cluster state."
        ),
    ),
    SpecialistProfile(
        name="finding_judge",
        role=(
            "Finding judge (Solomon). Adversarial review of proposed findings — "
            "require demonstrated impact, identity discipline for authz, and SUBMIT "
            "verdicts. Does not exploit; improves or kills weak cards."
        ),
        allowed_tools=[
            "validate_finding",
            "sanitize_evidence",
            "compare_requests",
            "get_engagement_brain",
            "update_hypothesis",
            "log_engagement_approach",
            "get_notes",
            "save_note",
            "create_finding",
        ],
        max_iterations=6,
        system_prompt_suffix=(
            "Re-score each proposed finding with validate_finding. Only create_finding "
            "after SUBMIT. Kill theoretical / status-only / identity-less IDOR claims. "
            "Prefer sanitize_evidence before publish."
        ),
    ),
]

_SPECIALISTS_BY_NAME: dict[str, SpecialistProfile] = {s.name: s for s in DEFAULT_SPECIALISTS}


def get_specialist(name: str) -> Optional[SpecialistProfile]:
    return _SPECIALISTS_BY_NAME.get(name)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@dataclass
class ToolInvocation:
    tool: str
    args: dict
    success: bool
    summary: str
    error: Optional[str] = None


@dataclass
class SpecialistReport:
    specialist: str
    role: str
    mission: str
    summary: str                          # LLM-written narrative
    key_findings: list[str] = field(default_factory=list)
    tool_calls: list[ToolInvocation] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class FireteamResult:
    mission: str
    specialists_run: list[str]
    reports: list[SpecialistReport]
    merged_summary: str = ""
    duration_seconds: float = 0.0
    total_tool_calls: int = 0


# ---------------------------------------------------------------------------
# Mini ReAct loop per specialist
# ---------------------------------------------------------------------------


_SPECIALIST_SYSTEM_PROMPT = """\
You are {epithet}, a specialist sub-agent in Judah Security's Aegis fireteam.
Other specialists run in parallel. Stay strictly in your lane.
You MUST NOT call fireteam_dispatch or spawn sub-agents.

EPITHET / ROLE: {epithet} — {role}

OPERATION DIRECTIVE:
{directive}

SHARED MISSION CONTEXT:
{mission}

TARGETS: {targets}

AVAILABLE TOOLS (allowlist -- you MAY NOT call anything else):
{tool_list}

INSTRUCTIONS:
1. Obey the operation directive (goal, PASS/KILL, hypothesis ids).
2. Think briefly about which tool(s) will most quickly prove or kill the hypothesis.
3. Respond ONLY with a JSON object of this shape:

   {{
     "tool_calls": [
       {{"tool": "<tool_name>", "args": {{...}}}}
     ],
     "done": false,
     "reasoning": "one-line rationale"
   }}

4. When you have enough evidence, respond with:

   {{
     "done": true,
     "summary": "1-3 paragraph narrative of what you found",
     "key_findings": ["bullet", "bullet", "bullet"]
   }}

5. Medium+ findings: call validate_finding first; create_finding only on SUBMIT.
6. Do not exceed {max_iter} iterations. If unsure, finish with done=true.

{suffix}
"""


async def _run_specialist(
    profile: SpecialistProfile,
    mission: str,
    targets: Iterable[str],
    llm: Any,
    tools_manager: Any,
    directive: Any = None,
) -> SpecialistReport:
    start = datetime.utcnow()
    report = SpecialistReport(
        specialist=profile.name,
        role=f"{profile.epithet}: {profile.role}",
        mission=mission,
        summary="",
    )

    from app.services.agent.operation_directive import (
        OperationDirective,
        merge_directive_into_mission,
    )
    from app.services.agent.specialist_skills import skill_pack_for

    skill_pack = skill_pack_for(profile.name)
    suffix_parts = [profile.system_prompt_suffix.strip()] if profile.system_prompt_suffix else []
    if skill_pack:
        suffix_parts.append(skill_pack)
    suffix = "\n\n".join(suffix_parts)

    if isinstance(directive, OperationDirective):
        directive_block = directive.to_prompt_block()
        mission_for_prompt = merge_directive_into_mission(mission, None)  # directive shown separately
        max_iter = directive.max_iterations or profile.max_iterations
    else:
        directive_block = (
            f"Goal: execute your role ({profile.epithet}) against the shared mission.\n"
            f"PASS: demonstrated impact with evidence.\n"
            f"KILL: no impact after disciplined probes."
        )
        mission_for_prompt = mission
        max_iter = profile.max_iterations

    sys_prompt = _SPECIALIST_SYSTEM_PROMPT.format(
        epithet=profile.epithet or profile.name,
        role=profile.role,
        directive=directive_block,
        mission=mission_for_prompt,
        targets=", ".join(targets) or "<see analyze_attack_surface output>",
        tool_list="\n".join(f"  - {t}" for t in profile.allowed_tools),
        max_iter=max_iter,
        suffix=suffix,
    )

    messages: list = [SystemMessage(content=sys_prompt)]
    messages.append(HumanMessage(content="Begin."))

    iteration = 0
    while iteration < profile.max_iterations:
        iteration += 1
        try:
            response = await llm.ainvoke(messages)
        except Exception as exc:
            logger.warning("fireteam %s: LLM failure: %s", profile.name, exc)
            report.error = f"LLM error: {exc}"
            break

        text = getattr(response, "content", "") or ""
        messages.append(AIMessage(content=text))

        payload = _extract_json(text)
        if not payload:
            report.summary = text[:2000]
            break

        if payload.get("done"):
            report.summary = (payload.get("summary") or "").strip()
            kf = payload.get("key_findings") or []
            if isinstance(kf, list):
                report.key_findings = [str(x) for x in kf][:20]
            break

        tool_calls = payload.get("tool_calls") or []
        if not tool_calls:
            report.summary = payload.get("reasoning") or text[:2000]
            break

        # Enforce allowlist + max parallelism per turn.
        tool_calls = [tc for tc in tool_calls if tc.get("tool") in profile.allowed_tools][: profile.max_tools_per_iteration]

        if not tool_calls:
            messages.append(HumanMessage(
                content="None of the tools you requested are allowed. "
                        "Pick from the allowlist or finish with done=true."
            ))
            continue

        tool_results = await asyncio.gather(*(
            _safe_invoke(tools_manager, tc.get("tool", ""), tc.get("args") or {})
            for tc in tool_calls
        ))

        for tc, tr in zip(tool_calls, tool_results):
            report.tool_calls.append(tr)

        feedback = {
            "tool_results": [
                {
                    "tool": tr.tool,
                    "success": tr.success,
                    "summary": tr.summary[:1500],
                    "error": tr.error,
                }
                for tr in tool_results
            ],
        }
        messages.append(HumanMessage(content=json.dumps(feedback)))

    report.duration_seconds = (datetime.utcnow() - start).total_seconds()
    if not report.summary and not report.error:
        report.summary = (
            f"{profile.name} exhausted {profile.max_iterations} iterations without "
            f"concluding. Last tool calls: "
            f"{[t.tool for t in report.tool_calls[-3:]]}"
        )
    return report


async def _safe_invoke(tools_manager: Any, tool_name: str, args: dict) -> ToolInvocation:
    try:
        result = await tools_manager.execute(tool_name, args or {})
        success = bool(result.get("success"))
        summary = _stringify_tool_result(result)
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=success,
            summary=summary,
            error=result.get("error") if not success else None,
        )
    except Exception as exc:
        return ToolInvocation(
            tool=tool_name,
            args=args or {},
            success=False,
            summary=f"invocation raised {type(exc).__name__}: {exc}",
            error=str(exc),
        )


def _stringify_tool_result(result: Any) -> str:
    if isinstance(result, dict):
        out = result.get("output")
        if isinstance(out, str):
            return out
        return json.dumps(result)[:3000]
    return str(result)[:3000]


def _extract_json(text: str) -> Optional[dict]:
    """Parse the first top-level JSON object from ``text``, tolerating code fences."""
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        newline = text.find("\n")
        if newline >= 0:
            text = text[newline + 1:]
        if text.endswith("```"):
            text = text[:-3]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start: end + 1])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def run_fireteam(
    mission: str,
    targets: Iterable[str],
    specialists: Iterable[str | SpecialistProfile],
    llm: Any,
    tools_manager: Any,
    max_parallel: int = 4,
    progress_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
    directives: Optional[Dict[str, Any]] = None,
) -> FireteamResult:
    """Run a fireteam in parallel and return the merged result.

    ``specialists`` may contain either string names from :data:`DEFAULT_SPECIALISTS`
    or fully custom :class:`SpecialistProfile` instances (for ad-hoc missions).
    ``directives`` maps specialist name → OperationDirective (optional).
    """
    start = datetime.utcnow()
    directives = directives or {}

    resolved: list[SpecialistProfile] = []
    for s in specialists:
        if isinstance(s, SpecialistProfile):
            resolved.append(s)
        elif isinstance(s, str):
            prof = get_specialist(s)
            if prof:
                resolved.append(prof)
            else:
                logger.warning("Fireteam: unknown specialist '%s' -- skipping", s)

    if not resolved:
        return FireteamResult(mission=mission, specialists_run=[], reports=[])

    targets_list = [t for t in targets if t]
    sem = asyncio.Semaphore(max(1, max_parallel))

    async def _run(p: SpecialistProfile) -> SpecialistReport:
        async with sem:
            label = f"{p.epithet} ({p.name})" if p.epithet else p.name
            if progress_callback:
                try:
                    await progress_callback(label, "started")
                except Exception:
                    pass
            rep = await _run_specialist(
                p,
                mission,
                targets_list,
                llm,
                tools_manager,
                directive=directives.get(p.name),
            )
            if progress_callback:
                try:
                    await progress_callback(label, "done")
                except Exception:
                    pass
            return rep

    reports = await asyncio.gather(*( _run(p) for p in resolved ))

    merged = _merge_reports(mission, reports)

    result = FireteamResult(
        mission=mission,
        specialists_run=[r.specialist for r in reports],
        reports=list(reports),
        merged_summary=merged,
        duration_seconds=(datetime.utcnow() - start).total_seconds(),
        total_tool_calls=sum(len(r.tool_calls) for r in reports),
    )
    logger.info(
        "Fireteam complete: %d specialists, %d tool calls, %.2fs",
        len(result.specialists_run), result.total_tool_calls, result.duration_seconds,
    )
    return result


def _merge_reports(mission: str, reports: list[SpecialistReport]) -> str:
    lines: list[str] = [f"# Aegis fireteam debrief (Joshua) — {mission}\n"]
    for r in reports:
        lines.append(f"## {r.specialist} ({r.role})")
        if r.error:
            lines.append(f"- status: **error** -- {r.error}")
        lines.append(f"- tool calls: {len(r.tool_calls)}  duration: {r.duration_seconds:.1f}s")
        if r.key_findings:
            lines.append("- key findings:")
            for kf in r.key_findings:
                lines.append(f"  * {kf}")
        if r.summary:
            lines.append(r.summary.strip())
        lines.append("")
    return "\n".join(lines)
