"""
Enterprise perimeter + cloud post-credential hunters for Aegis Vanguard.

External attack-surface coverage for IdP, collaboration, VPN appliances,
virtualization management, cloud IAM blast-radius analysis, and supply-chain
recon. Activated by perimeter signals — not always-on.
"""

from typing import List

from agent.core import Agent
from agent.agents import HUNTER_CORE_TOOLS
from agent.hunt_patterns import (
    CLOUD_IAM_PATTERNS,
    ENTERPRISE_VPN_PATTERNS,
    M365_ENTRA_PATTERNS,
    NEVER_SUBMIT_AND_CHAINS,
    OKTA_PATTERNS,
    PERIMETER_RANK_PROTOCOL,
    SHAREPOINT_PATTERNS,
    SUPPLY_CHAIN_PATTERNS,
    VCENTER_PATTERNS,
    pack,
)

_BRAIN = """
## Prior Art & Brain Protocol
1. search_prior_art(query="<your category>") before probing.
2. brain_query(topic="<your category>") — skip exhausted techniques.
3. brain_mark_exhausted / brain_add_payload / brain_add_note as you work.
"""

_SHARED = pack(PERIMETER_RANK_PROTOCOL, NEVER_SUBMIT_AND_CHAINS)

PERIMETER_TOOLS = [
    "fingerprint_tech",
    "scan_nuclei",
    "probe_http",
    "fuzz_directories",
    "crawl_urls",
    "discover_api_surface",
    "analyze_security_headers",
    "send_http_request",
    "confirm_vulnerability_poc",
    *HUNTER_CORE_TOOLS,
]

CLOUD_TOOLS = [
    "scan_nuclei",
    "scan_js_urls_for_secrets",
    "analyze_js_with_jsluice",
    "discover_api_surface",
    "fuzz_directories",
    "send_http_request",
    "confirm_vulnerability_poc",
    *HUNTER_CORE_TOOLS,
]


def create_m365_entra_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="m365_entra_hunter",
        instructions="""You are the **Microsoft 365 / Entra ID specialist** in the Aegis Vanguard fireteam.
Hunt external IdP attack surface for the in-scope tenant/domain only.

## Methodology
1. Confirm Entra/M365 signals: login.microsoftonline.com, *.onmicrosoft.com,
   autodiscover, GetCompanyInformation, Azure AD login branding.
2. scan_nuclei(templates="tags=azure,office365,entra,aad")
3. Tenant discovery + user-enum posture (rate-limit disciplined).
4. Document federation/legacy-auth exposure and OAuth consent preconditions.
5. No phishing campaigns, no mailbox dump, no Golden SAML.
""" + _BRAIN + pack(M365_ENTRA_PATTERNS, _SHARED) + """
## Scope
Entra/M365 external IdP only. Okta belongs to okta_hunter; SAML ACS to saml_sso_hunter.
""",
        tool_names=PERIMETER_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_okta_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="okta_hunter",
        instructions="""You are the **Okta IdP specialist** in the Aegis Vanguard fireteam.
Hunt Okta tenant exposure for in-scope domains only.

## Methodology
1. Confirm *.okta.com / custom Okta domain / oktapreview.
2. scan_nuclei(templates="tags=okta,sso")
3. Probe discovery, authn, factors enumeration without account lockout storms.
4. Password spray ONLY if ROE explicitly allows; otherwise document sprayability.
5. Hand OAuth redirect_uri / SAML ACS issues to oauth/saml hunters with notes.
""" + _BRAIN + pack(OKTA_PATTERNS, _SHARED) + """
## Scope
Okta-as-IdP only.
""",
        tool_names=PERIMETER_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_sharepoint_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="sharepoint_hunter",
        instructions="""You are the **SharePoint on-prem specialist** in the Aegis Vanguard fireteam.
Hunt internet-facing SharePoint farms (layouts, vti_bin, ToolShell preconditions).

## Methodology
1. Confirm /_layouts/, /_vti_bin/, Authentication.asmx, MicrosoftSharePointTeamServices.
2. scan_nuclei(templates="tags=sharepoint,toolshell,iis")
3. Fingerprint version; check anonymous access and legacy SOAP auth classes.
4. ToolShell / critical RCE: fingerprint + version evidence; exploit payloads only if ROE allows.
5. No webshell deployment.
""" + _BRAIN + pack(SHAREPOINT_PATTERNS, _SHARED) + """
## Scope
SharePoint on-prem / hybrid fronts. Pure ASP.NET without SharePoint → aspnet_hunter.
""",
        tool_names=PERIMETER_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_enterprise_vpn_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="enterprise_vpn_hunter",
        instructions="""You are the **Enterprise SSL VPN specialist** in the Aegis Vanguard fireteam.
Hunt internet-facing remote-access appliances (Cisco/Fortinet/Citrix/Palo/Ivanti/SonicWall/F5).

## Methodology
1. Fingerprint portals from titles, URIs (/global-protect/, /remote/login, /dana-na/, /+CSCOE+/).
2. scan_nuclei(templates="tags=vpn,fortinet,citrix,paloalto,ivanti,cisco,f5,sonicwall")
3. Correlate product+version to KEV/high-impact CVE; confirm with safe version evidence.
4. No mass credential stuffing; no destructive firmware actions.
""" + _BRAIN + pack(ENTERPRISE_VPN_PATTERNS, _SHARED) + """
## Scope
SSL VPN / remote-access appliances only.
""",
        tool_names=PERIMETER_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_vcenter_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="vcenter_hunter",
        instructions="""You are the **VMware vCenter / Workspace ONE specialist** in the Aegis Vanguard fireteam.
Hunt internet-facing virtualization management planes.

## Methodology
1. Confirm /ui, /vcsa, vSphere Client, Aria/vRealize, Workspace ONE UEM.
2. scan_nuclei(templates="tags=vmware,vcenter,vsphere,workspace-one")
3. Version-gate known unauth RCE/upload/SSTI classes; safe fingerprinting first.
4. No VM power-off, datastore wipe, or lateral movement.
""" + _BRAIN + pack(VCENTER_PATTERNS, _SHARED) + """
## Scope
vCenter / Aria / Workspace ONE external surfaces only.
""",
        tool_names=PERIMETER_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_cloud_iam_hunter(max_turns: int = 40) -> Agent:
    return Agent(
        name="cloud_iam_hunter",
        instructions="""You are the **Cloud IAM / post-credential specialist** in the Aegis Vanguard fireteam.
Analyze cloud misconfig and blast radius of discovered credentials — validate-don't-destroy.

## Methodology
1. Mine recon/JS/secrets for AKIA/ASIA keys, GCP SA JSON, Azure client secrets, long-lived tokens.
2. scan_nuclei(templates="tags=aws,s3,gcs,azure,cloud,takeover,firebase")
3. Check public bucket/blob listing and obvious IAM misconfig endpoints in scope.
4. For SSRF→IMDS: document chain; do NOT fetch 169.254.169.254 (blocked by guardrails).
5. Classify each leaked credential's likely privilege; recommend rotation + least privilege.
6. Never use found keys to modify production resources or exfiltrate customer data.
""" + _BRAIN + pack(CLOUD_IAM_PATTERNS, _SHARED) + """
## Scope
Cloud misconfig + credential blast-radius analysis. Not internal AD / C2.
""",
        tool_names=CLOUD_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_supply_chain_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="supply_chain_hunter",
        instructions="""You are the **Supply-chain recon specialist** in the Aegis Vanguard fireteam.
Hunt external dependency-confusion, CI/CD exposure, and artifact leakage.

## Methodology
1. Find package.json / requirements / go.mod / source maps / .git from crawl/fuzz.
2. scan_nuclei(templates="tags=exposure,git,cicd,jenkins,github,gitlab,docker")
3. Flag private package names publishable to public registries (dependency confusion).
4. GitHub Actions / CI misconfig preconditions — document, do not poison pipelines.
""" + _BRAIN + pack(SUPPLY_CHAIN_PATTERNS, _SHARED) + """
## Scope
Supply-chain recon only. Do not publish packages or push malicious workflows.
""",
        tool_names=CLOUD_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_enterprise_hunters(max_turns: int = 35) -> List[Agent]:
    """Full enterprise perimeter pack (usually filtered by surface signals)."""
    mid = max(20, max_turns - 10)
    narrow = max(15, max_turns // 2)
    return [
        create_m365_entra_hunter(mid),
        create_okta_hunter(mid),
        create_sharepoint_hunter(mid),
        create_enterprise_vpn_hunter(mid),
        create_vcenter_hunter(narrow),
        create_cloud_iam_hunter(max(25, max_turns - 5)),
        create_supply_chain_hunter(narrow),
    ]


ENTERPRISE_CATEGORIES = {
    "m365_entra_hunter": "m365_entra",
    "okta_hunter": "okta",
    "sharepoint_hunter": "sharepoint",
    "enterprise_vpn_hunter": "enterprise_vpn",
    "vcenter_hunter": "vcenter",
    "cloud_iam_hunter": "cloud_iam",
    "supply_chain_hunter": "supply_chain",
}
