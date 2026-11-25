"""Surface-triggered stack and perimeter specialists.

Ported from the Vanguard hunter selection (``owasp_hunters._API_FRAMEWORK_SIGNALS``
and ``_ENTERPRISE_SIGNALS``). A specialist activates only when its fingerprint
appears in the observed capability map: page and API paths, script URLs,
response headers the crawler kept, cookie names and form actions. Vanguard
matched free recon text, so broad words (``iis``, ``pulse``, ``express``,
``aria``, ``origin``) are narrowed to paths, headers and product names here.

Each match becomes a methodology card for the specialist, so selection flows
through the usual hypothesis, task-graph and capability-map paths and stays
within the fireteam cap. Cards name the proof a candidate needs; classes
without a proof kind are leads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class SurfaceHunter:
    specialist: str
    patterns: Tuple[str, ...]
    title: str
    assumption: str
    test: str
    pass_criteria: str
    kill_criteria: str
    cwe_ids: Tuple[str, ...] = ()
    capec_ids: Tuple[str, ...] = ()
    owasp: str = ""
    priority: str = "medium"
    # Product fingerprints must come from the target itself; IdP and cloud
    # signals usually appear as third-party redirects and asset hosts.
    first_party_only: bool = True
    # Hosts that disqualify a match (for example SaaS-operated SharePoint).
    exclude_hosts: Tuple[str, ...] = ()

    @property
    def hunt(self) -> str:
        return self.specialist


_PERIMETER_OWASP = "A06:2021 Vulnerable and Outdated Components"
_MISCONFIG_OWASP = "A05:2021 Security Misconfiguration"

SURFACE_HUNTERS: Tuple[SurfaceHunter, ...] = (
    SurfaceHunter(
        specialist="grpc_api",
        patterns=(
            r"application/grpc", r"grpc-web", r"\bgrpc\b", r"grpc\.reflection",
            # /package.Service/Method (case-sensitive; not a //host prefix)
            r"(?-i:(?<!/)/[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.[A-Z][A-Za-z0-9]+/[A-Z][A-Za-z0-9]+)\b",
        ),
        title="gRPC reflection and unauthenticated methods",
        assumption="gRPC server reflection is enabled or methods run without auth metadata",
        test=(
            "One reflection list_services call; one read-only unary call per service "
            "without auth; gateway twin compared across two verified identities"
        ),
        pass_criteria="Authorization proof on another identity's object (reflection alone is a lead)",
        kill_criteria="Reflection disabled and methods return UNAUTHENTICATED/PERMISSION_DENIED",
        cwe_ids=("CWE-306", "CWE-200"),
        owasp="A01:2021 Broken Access Control",
        priority="high",
    ),
    SurfaceHunter(
        specialist="nodejs_express",
        patterns=(
            r"x-powered-by:\s*express", r"\bexpress(?:\.js)?\b", r"\bconnect\.sid\b",
            r"\bnode\.?js\b", r"__proto__", r"prototype.?pollution",
        ),
        title="Node/Express server-side prototype pollution and proxy trust",
        assumption="Merged JSON reaches Object.prototype, or trust proxy honours spoofed X-Forwarded-For",
        test=(
            "Unique __proto__ key reflected in the same response (no process-wide "
            "payloads); X-Forwarded-For differential on IP-gated paths"
        ),
        pass_criteria="Recorded lead; SSTI/traversal only with a scoped probe receipt",
        kill_criteria="Pollution key not inherited and XFF ignored",
        cwe_ids=("CWE-1321", "CWE-348"),
        owasp="A03:2021 Injection",
    ),
    SurfaceHunter(
        specialist="deserialization",
        patterns=(
            r"ObjectInputStream", r"\bysoserial\b", r"BinaryFormatter", r"LosFormatter",
            r"java\.io\.Serializable", r"application/x-java-serialized-object",
            r"\brO0AB[A-Za-z0-9+/]", r"javax\.faces\.ViewState", r"\.ser\b",
            r"\bpickle\b", r"\bphar://", r"\bjndi\b", r"\blog4j\b",
            r"/invoker/(?:JMXInvokerServlet|EJBInvokerServlet)", r"/jmx-console\b",
        ),
        title="Insecure deserialization sink / JNDI lookup",
        assumption="Serialized objects or ${jndi:} strings from the client are deserialized or resolved",
        test=(
            "Locate the sink in captured traffic; JNDI canary via run_oob_callback_workflow "
            "only when OOB is authorized; never gadget payloads"
        ),
        pass_criteria="Correlated oob_callback proof (filed as ssrf: outbound lookup)",
        kill_criteria="No sink in traffic, or no callback after the bounded poll",
        cwe_ids=("CWE-502", "CWE-917"),
        capec_ids=("CAPEC-586",),
        owasp="A08:2021 Software and Data Integrity Failures",
        priority="high",
    ),
    SurfaceHunter(
        specialist="m365_entra",
        patterns=(
            r"login\.microsoftonline\.com", r"\.onmicrosoft\.com", r"login\.windows\.net",
            r"sts\.windows\.net", r"aadcdn\.msauth\.net", r"aadcdn\.msftauth\.net",
            r"/adfs/(?:ls|services|oauth2)", r"\bautodiscover\.", r"GetCompanyInformation",
            r"\bazure\s*ad\b", r"\bentra\s+id\b",
        ),
        title="Entra ID / M365 tenant and enumeration posture",
        assumption="The in-scope domain federates to Entra/ADFS with enumerable users or legacy auth",
        test="Tenant metadata, getuserrealm federation, one canary + one observed user enumeration check",
        pass_criteria="Recorded tenant/federation notes and an enumeration lead (no proof kind)",
        kill_criteria="Domain not on Entra, or responses identical for canary and observed users",
        cwe_ids=("CWE-204", "CWE-200"),
        owasp="A07:2021 Identification and Authentication Failures",
        first_party_only=False,
    ),
    SurfaceHunter(
        specialist="okta_idp",
        patterns=(
            r"\.okta(?:preview|-emea)?\.com", r"\boktacdn\.com", r"okta-signin",
            r"/\.well-known/okta-organization", r"\bokta\b",
        ),
        title="Okta tenant and enumeration posture",
        assumption="The Okta tenant exposes enumerable authn responses, open registration or admin surfaces",
        test="OIDC metadata, okta-organization, authn posture with one canary + one observed username",
        pass_criteria="Recorded notes and enumeration lead; exposure only with a response_match proof",
        kill_criteria="Uniform authn responses and no exposed admin/agent surface",
        cwe_ids=("CWE-204", "CWE-200"),
        owasp="A07:2021 Identification and Authentication Failures",
        first_party_only=False,
    ),
    SurfaceHunter(
        specialist="sharepoint",
        patterns=(
            r"/_layouts/", r"/_vti_bin/", r"/_vti_pvt/", r"/_api/web\b",
            r"\bsharepoint\b", r"Authentication\.asmx", r"MicrosoftSharePoint",
            r"\btoolshell\b",
        ),
        title="SharePoint on-prem build, anonymous access and ToolShell preconditions",
        assumption="An internet-facing farm runs a KEV-listed build or serves list data anonymously",
        test="Build fingerprint, KEV-gated CVE applicability, anonymous _api/_vti_bin reads",
        pass_criteria="Anonymous data via response_match (exposure); a build in range is a low known_cve lead",
        kill_criteria="Patched build and every anonymous read is 401/403",
        cwe_ids=("CWE-1395", "CWE-284"),
        owasp=_PERIMETER_OWASP,
        priority="high",
        exclude_hosts=(".sharepoint.com",),
    ),
    SurfaceHunter(
        specialist="enterprise_vpn",
        patterns=(
            r"/\+CSCOE\+/", r"/\+webvpn\+", r"\banyconnect\b", r"\bcisco\s*asa\b",
            r"/remote/(?:login|logincheck|fgt_lang)", r"\bforti(?:gate|os|net)\b",
            r"/vpn/index\.html", r"/logon/LogonPoint/", r"\bnetscaler\b", r"\bcitrix\s+(?:adc|gateway)\b",
            r"/global-protect/", r"/ssl-vpn/", r"\bglobalprotect\b",
            r"/dana-na/", r"/dana-cached/", r"\bivanti\b", r"\bpulse\s*secure\b",
            r"/my\.policy\b", r"/tmui/", r"\bbig-?ip\b",
            r"/cgi-bin/welcome\b", r"\bsonicwall\b", r"\bssl\s*vpn\b",
        ),
        title="SSL VPN appliance build and KEV-listed CVE exposure",
        assumption="An internet-facing remote-access appliance runs a build inside a KEV-listed affected range",
        test="Product from portal path, build from version endpoint/asset hash, KEV-gated applicability",
        pass_criteria="Product + build evidence + in-range KEV CVE (known_cve lead, capped low)",
        kill_criteria="Build outside every affected range, or no build evidence",
        cwe_ids=("CWE-1395", "CWE-1104"),
        owasp=_PERIMETER_OWASP,
        priority="high",
    ),
    SurfaceHunter(
        specialist="vcenter",
        patterns=(
            r"\bvcenter\b", r"\bvsphere\b", r"/vsphere-client", r"/websso/", r"/vcsa\b",
            r"/sdk/vimService", r"/catalog-portal/", r"/SAAS/auth", r"\bworkspace\s*one\b",
            r"\bvrealize\b", r"\bvmware\b",
        ),
        title="vCenter / Aria / Workspace ONE build and CVE exposure",
        assumption="A management plane is internet-facing on a build with known unauthenticated CVEs",
        test="Read-only SDK AboutInfo/banners for build, KEV-gated CVE applicability",
        pass_criteria="Build evidence + in-range KEV CVE (known_cve lead, capped low)",
        kill_criteria="Patched build, or no build evidence",
        cwe_ids=("CWE-1395",),
        owasp=_PERIMETER_OWASP,
        priority="high",
    ),
    SurfaceHunter(
        specialist="spring_boot",
        patterns=(
            r"/actuator\b", r"whitelabel\s+error", r"\bjolokia\b", r"x-application-context",
            r"\bspring\s*boot\b", r"/h2-console\b",
        ),
        title="Spring Boot actuator exposure and SpEL evaluation",
        assumption="Actuator endpoints answer anonymously, or request data reaches a SpEL expression",
        test="Anonymous actuator GETs (no POST, heapdump HEAD only); SpEL via scoped ssti probe",
        pass_criteria="response_match exposure of actuator data, or scoped_ssti_eval receipt",
        kill_criteria="Actuator 401/403/404 and no SpEL evaluation",
        cwe_ids=("CWE-200", "CWE-917"),
        owasp=_MISCONFIG_OWASP,
        priority="high",
    ),
    SurfaceHunter(
        specialist="laravel",
        patterns=(
            r"\blaravel\b", r"\blaravel_session\b", r"/_ignition/", r"/telescope\b",
            r"/horizon\b", r"/_debugbar\b", r"/livewire/",
        ),
        title="Laravel debug, Telescope/Horizon and Ignition exposure",
        assumption="APP_DEBUG, Telescope, Horizon or debugbar is reachable anonymously",
        test="Anonymous GETs of debug dashboards and one ordinary error page; Ignition version-gated",
        pass_criteria="response_match exposure with secrets redacted",
        kill_criteria="Dashboards 401/403/404 and generic error pages",
        cwe_ids=("CWE-200", "CWE-489"),
        owasp=_MISCONFIG_OWASP,
        priority="high",
    ),
    SurfaceHunter(
        specialist="nextjs",
        patterns=(
            r"/_next/", r"__NEXT_DATA__", r"x-nextjs", r"\bnext-action\b",
            r"x-middleware-", r"\bnext\.js\b",
        ),
        title="Next.js middleware bypass, image proxy SSRF and Server Actions",
        assumption="Middleware-only auth, a loose image remotePatterns, or Server Actions skip server-side checks",
        test="Version-gated x-middleware-subrequest differential; /_next/image via OOB workflow; action replay",
        pass_criteria="Authorization, oob_callback (ssrf) or state_change proof",
        kill_criteria="Patched version, middleware not used for auth, image proxy restricted",
        cwe_ids=("CWE-285", "CWE-918"),
        owasp="A01:2021 Broken Access Control",
    ),
    SurfaceHunter(
        specialist="aspnet_iis",
        patterns=(
            r"\.aspx\b", r"\.ashx\b", r"\.asmx\b", r"\.axd\b", r"__VIEWSTATE",
            r"x-aspnet(?:mvc)?-version", r"x-powered-by:\s*asp\.net", r"\basp\.net\b",
        ),
        title="ASP.NET/IIS elmah/trace exposure, ViewState MAC and NTLM disclosure",
        assumption="elmah.axd/trace.axd answer anonymously, ViewState lacks a MAC, or NTLM leaks domain info",
        test="Anonymous axd GETs, local ViewState decode, one NTLM Type 1 negotiate",
        pass_criteria="response_match exposure of logged requests/errors (ViewState and NTLM are leads)",
        kill_criteria="axd handlers 403/404, MAC-protected ViewState, no NTLM",
        cwe_ids=("CWE-200", "CWE-642"),
        owasp=_MISCONFIG_OWASP,
    ),
    # Thin Vanguard lanes folded into existing specialists.
    SurfaceHunter(
        specialist="cloud_audit",
        patterns=(
            r"\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com", r"\bs3\.amazonaws\.com",
            r"storage\.googleapis\.com", r"firebaseio\.com", r"firebasestorage\.",
            r"\.blob\.core\.windows\.net", r"\bAKIA[0-9A-Z]{16}\b", r"\bASIA[0-9A-Z]{16}\b",
        ),
        title="Cloud storage exposure and leaked-key classification",
        assumption="Referenced buckets/containers list anonymously, or a leaked cloud key has broad privilege",
        test="Anonymous list of referenced buckets/containers; classify leaked keys by shape without using them",
        pass_criteria="Anonymous listing via response_match (exposure); key classification is a lead",
        kill_criteria="Listing denied and no cloud key shapes in leaks",
        cwe_ids=("CWE-284", "CWE-798"),
        owasp=_MISCONFIG_OWASP,
        first_party_only=False,
    ),
)

_BY_SPECIALIST: Dict[str, SurfaceHunter] = {h.specialist: h for h in SURFACE_HUNTERS}

# Specialists whose lane exists only for these fingerprints (cloud_audit is an
# existing generalist lane, so it is not forced into a wave).
PORTED_SPECIALISTS: Tuple[str, ...] = tuple(
    h.specialist for h in SURFACE_HUNTERS if h.specialist != "cloud_audit"
)

# hunt-queue name -> specialist for capability_map selection.
SURFACE_HUNT_SPECIALISTS: Dict[str, str] = {
    **{h.hunt: h.specialist for h in SURFACE_HUNTERS},
    "websocket": "api_authz",
}


def _getter(cmap: Any) -> Callable[..., Any]:
    if isinstance(cmap, dict):
        return cmap.get
    return lambda key, default=None: getattr(cmap, key, default)


def _host(value: str) -> str:
    match = re.match(r"[a-z][a-z0-9+.-]*://([^/?#:]+)", value, re.I)
    return match.group(1).lower() if match else ""


def surface_items(cmap: Any) -> Tuple[List[str], List[str]]:
    """Return (first-party, third-party) strings from the observed map."""
    if cmap is None:
        return [], []
    g = _getter(cmap)
    first: List[str] = []
    target = str(g("target") or "")
    if target:
        first.append(target)
    first.extend(str(p) for p in (g("pages_visited") or []))
    for e in g("api_endpoints") or []:
        if isinstance(e, dict):
            first.append(f"{e.get('method', '')} {e.get('path', '')} {e.get('host', '')}".strip())
    first.extend(str(j) for j in (g("js_files") or []))
    first.extend(str(j) for j in (g("js_endpoints") or []))
    first.extend(str(w) for w in (g("websockets") or []))
    for f in g("forms") or []:
        if isinstance(f, dict):
            first.append(f"{f.get('action', '')} {' '.join(str(i) for i in (f.get('inputs') or []))}")
    for s in g("api_samples") or []:
        if not isinstance(s, dict):
            continue
        # Header names and selected response headers only; request header values
        # can carry credentials and are not needed for a fingerprint.
        bits = [str(s.get("method") or ""), str(s.get("url") or "")]
        bits.extend(str(k) for k in (s.get("headers") or {}) if isinstance(s.get("headers"), dict))
        rh = s.get("response_headers")
        if isinstance(rh, dict):
            bits.extend(f"{k}: {v}" for k, v in rh.items())
        if s.get("set_cookie"):
            bits.append(str(s["set_cookie"]))
        first.append(" ".join(b for b in bits if b))
    first.extend(str(n) for n in (g("notes") or []))
    third = [str(t) for t in (g("third_party") or [])]
    return [x for x in first if x], [x for x in third if x]


def _match(hunter: SurfaceHunter, items: Sequence[str]) -> Optional[str]:
    for item in items:
        host = _host(item)
        if host and any(host.endswith(ex) for ex in hunter.exclude_hosts):
            continue
        for pattern in hunter.patterns:
            if re.search(pattern, item, re.I):
                return item[:240]
    return None


def detect_surface_hunters(cmap: Any) -> Dict[str, str]:
    """Map each triggered specialist to the first observed item that matched."""
    first, third = surface_items(cmap)
    target_host = _host(str(_getter(cmap)("target") or "")) if cmap is not None else ""
    out: Dict[str, str] = {}
    for hunter in SURFACE_HUNTERS:
        if target_host and any(target_host.endswith(ex) for ex in hunter.exclude_hosts):
            continue
        items = first if hunter.first_party_only else first + third
        evidence = _match(hunter, items)
        if evidence:
            out[hunter.specialist] = evidence
    # A SharePoint farm is ASP.NET too; its own lane covers the IIS checks.
    if "sharepoint" in out:
        out.pop("aspnet_iis", None)
    return out


def surface_hunter_methodologies(cmap: Any) -> List[Any]:
    """Methodology cards for every triggered surface specialist."""
    from app.services.agent.methodology_catalog import Methodology

    cards = []
    for name, evidence in detect_surface_hunters(cmap).items():
        hunter = _BY_SPECIALIST[name]
        cards.append(Methodology(
            id=f"surface_{name}",
            title=hunter.title,
            hunt=hunter.hunt,
            specialist=hunter.specialist,
            priority=hunter.priority,
            assumption=hunter.assumption,
            test=hunter.test,
            pass_criteria=hunter.pass_criteria,
            kill_criteria=hunter.kill_criteria,
            cwe_ids=list(hunter.cwe_ids),
            capec_ids=list(hunter.capec_ids),
            owasp=hunter.owasp,
            evidence=evidence,
            why=f"{name} fingerprint observed",
        ))
    ws = [str(w) for w in (_getter(cmap)("websockets") or [])] if cmap is not None else []
    if ws:
        cards.append(Methodology(
            id="websocket_cswsh",
            title="Cross-site WebSocket hijacking (CSWSH)",
            hunt="websocket",
            specialist="api_authz",
            priority="medium",
            assumption="A cookie-authenticated WebSocket handshake does not check Origin",
            test="Upgrade with a canary Origin vs the app Origin; cross-user room joins with two identities",
            pass_criteria="Canary-Origin 101 is a lead; cross-user data needs the authorization proof",
            kill_criteria="Canary Origin rejected, or the socket authenticates by token, not cookie",
            cwe_ids=["CWE-1385", "CWE-346"],
            capec_ids=["CAPEC-111"],
            owasp="A01:2021 Broken Access Control",
            evidence=ws[0][:240],
            why="WebSocket endpoint observed",
        ))
    return cards
