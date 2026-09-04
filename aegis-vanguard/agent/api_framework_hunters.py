"""
API-depth and framework specialist hunters for Aegis Vanguard.

Activated by surface signals (GraphQL/gRPC/WebSocket or stack fingerprints)
so the fireteam does not burn turns on irrelevant framework paths.
"""

from typing import List

from agent.core import Agent
from agent.agents import HUNTER_CORE_TOOLS
from agent.hunt_patterns import (
    ASPNET_PATTERNS,
    DESERIALIZATION_PATTERNS,
    GRAPHQL_PATTERNS,
    GRPC_PATTERNS,
    IDENTITY_PROTOCOL,
    LARAVEL_PATTERNS,
    NEVER_SUBMIT_AND_CHAINS,
    NEXTJS_PATTERNS,
    NODEJS_PATTERNS,
    SPRING_PATTERNS,
    SURFACE_RANK_PROTOCOL,
    WEBSOCKET_PATTERNS,
    pack,
)

_BRAIN = """
## Prior Art & Brain Protocol
1. search_prior_art(query="<your category>") before spraying payloads.
2. brain_query(topic="<your category>") — skip exhausted techniques.
3. brain_mark_exhausted / brain_add_payload / brain_add_note as you work.
"""

_SHARED = pack(SURFACE_RANK_PROTOCOL, NEVER_SUBMIT_AND_CHAINS)

API_TOOLS = [
    "discover_api_surface",
    "scan_nuclei",
    "crawl_urls",
    "discover_parameters",
    "fuzz_directories",
    "probe_graphql",
    "probe_jwt",
    "send_http_request",
    "confirm_vulnerability_poc",
    *HUNTER_CORE_TOOLS,
]

FRAMEWORK_TOOLS = [
    "fingerprint_tech",
    "discover_api_surface",
    "scan_nuclei",
    "fuzz_directories",
    "crawl_urls",
    "send_http_request",
    "confirm_vulnerability_poc",
    *HUNTER_CORE_TOOLS,
]


def create_graphql_hunter(max_turns: int = 40) -> Agent:
    return Agent(
        name="graphql_hunter",
        instructions="""You are the **GraphQL specialist** in the Aegis Vanguard fireteam.
Hunt: introspection abuse with impact, BOLA via node()/global IDs, batching/alias
abuse, nested DoS (measured), cookie-auth CSRF on GraphQL POST, unauth mutations.

## Methodology
1. Locate /graphql, /api/graphql, /gql, /graphiql from recon/API inventory.
2. scan_nuclei(templates="tags=graphql")
3. Probe introspection; if ON, map mutations/queries touching users, files, payments.
4. Test IDOR on node(id:) / viewer / user(id:) across identities when creds exist.
5. Alias/batch abuse for rate-limit bypass — prove with concrete data access.
6. Introspection alone is NEVER a high finding — pair with authz/mutation impact.
""" + _BRAIN + pack(GRAPHQL_PATTERNS, IDENTITY_PROTOCOL, _SHARED) + """
## Scope
GraphQL only. REST IDOR belongs to authz_hunter; OAuth to oauth_hunter.
""",
        tool_names=API_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_grpc_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="grpc_hunter",
        instructions="""You are the **gRPC specialist** in the Aegis Vanguard fireteam.
Hunt: server reflection, missing method auth, plaintext gRPC, descriptor leakage.

## Methodology
1. From recon, find :443/h2, grpc subdomains, /grpc.reflection paths, Envoy gRPC-Web.
2. scan_nuclei(templates="tags=grpc,protobuf")
3. If reflection works, enumerate services; attempt one unauthorized method call as PoC.
4. Check HTTP/JSON gateway twins for weaker auth than the gRPC front.
""" + _BRAIN + pack(GRPC_PATTERNS, IDENTITY_PROTOCOL, _SHARED) + """
## Scope
gRPC/gRPC-Web only. Do not unbounded-stream DoS.
""",
        tool_names=API_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_websocket_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="websocket_hunter",
        instructions="""You are the **WebSocket specialist** in the Aegis Vanguard fireteam.
Hunt: CSWSH, missing Origin checks, subscribe IDOR, socket.io ACL gaps.

## Methodology
1. Find ws/wss endpoints from discover_api_surface / JS bundles / Network hints.
2. scan_nuclei(templates="tags=websocket,socketio")
3. Handshake with Origin: https://evil.example and cookie-bearing browser context if available.
4. Attempt subscribe/join to other-user rooms/channels; prove data access.
""" + _BRAIN + pack(WEBSOCKET_PATTERNS, IDENTITY_PROTOCOL, _SHARED) + """
## Scope
WebSocket/socket.io only.
""",
        tool_names=API_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_nextjs_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="nextjs_hunter",
        instructions="""You are the **Next.js specialist** in the Aegis Vanguard fireteam.
Only hunt when Next.js fingerprint (`/_next/`, x-powered-by, RSC) is present.

## Methodology
1. Confirm Next.js via fingerprint_tech / `/_next/static`.
2. scan_nuclei(templates="tags=nextjs,react")
3. Test middleware bypass paths, `/_next/image` SSRF, Server Action invocation, ISR cache.
""" + _BRAIN + pack(NEXTJS_PATTERNS, _SHARED) + """
## Scope
Next.js-specific only.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_spring_hunter(max_turns: int = 35) -> Agent:
    return Agent(
        name="spring_hunter",
        instructions="""You are the **Spring Boot specialist** in the Aegis Vanguard fireteam.
Only hunt when Spring/actuator fingerprint is present.

## Methodology
1. Confirm via fingerprint_tech / Whitelabel / actuator headers.
2. scan_nuclei(templates="tags=springboot,spring,actuator,jolokia")
3. Probe /actuator/env, heapdump, mappings, gateway — report only with evidence of sensitive data or RCE precondition.
""" + _BRAIN + pack(SPRING_PATTERNS, _SHARED) + """
## Scope
Spring Boot only.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_laravel_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="laravel_hunter",
        instructions="""You are the **Laravel specialist** in the Aegis Vanguard fireteam.
Only hunt when Laravel fingerprint (laravel_session, XSRF-TOKEN, Ignition) is present.

## Methodology
1. Confirm Laravel fingerprint.
2. scan_nuclei(templates="tags=laravel,ignition,php")
3. Probe Telescope/Horizon/debug/.env; Ignition RCE only with version evidence.
""" + _BRAIN + pack(LARAVEL_PATTERNS, _SHARED) + """
## Scope
Laravel only.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_aspnet_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="aspnet_hunter",
        instructions="""You are the **ASP.NET / IIS specialist** in the Aegis Vanguard fireteam.
Only hunt when ASP.NET/IIS fingerprint (X-AspNet-Version, __VIEWSTATE, .aspx) is present.

## Methodology
1. Confirm ASP.NET/IIS.
2. scan_nuclei(templates="tags=aspnet,iis,viewstate,ntlm")
3. Check ViewState MAC, elmah/trace, NTLM info leak — validate-don't-destroy.
""" + _BRAIN + pack(ASPNET_PATTERNS, _SHARED) + """
## Scope
ASP.NET/IIS only. SharePoint farms belong to sharepoint_hunter.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_nodejs_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="nodejs_hunter",
        instructions="""You are the **Node.js / Express specialist** in the Aegis Vanguard fireteam.
Only hunt when Node/Express fingerprint is present.

## Methodology
1. Confirm Node/Express (X-Powered-By, express signatures).
2. scan_nuclei(templates="tags=nodejs,express,prototype-pollution")
3. Probe prototype pollution sinks, trust-proxy IP bypass, template SSTI, path traversal.
""" + _BRAIN + pack(NODEJS_PATTERNS, _SHARED) + """
## Scope
Node/Express only. Next.js-specific paths belong to nextjs_hunter.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_deserialization_hunter(max_turns: int = 30) -> Agent:
    return Agent(
        name="deserialization_hunter",
        instructions="""You are the **Insecure Deserialization specialist** in the Aegis Vanguard fireteam.
Hunt: Java/.NET/PHP/Python deserialization sinks with safe canary proof.

## Methodology
1. Find .ser uploads, ViewState, pickle/yaml endpoints, Java content-types from recon.
2. scan_nuclei(templates="tags=deserialization,ysoserial,viewstate,log4j,jndi")
3. Prove with canary/callback or property disclosure — never OS shell / ransomware payloads.
""" + _BRAIN + pack(DESERIALIZATION_PATTERNS, _SHARED) + """
## Scope
Deserialization only. SSTI/SQLi belong to injection_hunter.
""",
        tool_names=FRAMEWORK_TOOLS,
        max_turns=max_turns,
        temperature=0.0,
    )


def create_api_framework_hunters(max_turns: int = 35) -> List[Agent]:
    """All API + framework specialists (usually filtered by surface signals)."""
    narrow = max(15, max_turns // 2)
    mid = max(20, max_turns - 10)
    return [
        create_graphql_hunter(mid),
        create_grpc_hunter(narrow),
        create_websocket_hunter(narrow),
        create_nextjs_hunter(mid),
        create_spring_hunter(mid),
        create_laravel_hunter(narrow),
        create_aspnet_hunter(narrow),
        create_nodejs_hunter(narrow),
        create_deserialization_hunter(narrow),
    ]


API_FRAMEWORK_CATEGORIES = {
    "graphql_hunter": "graphql",
    "grpc_hunter": "grpc",
    "websocket_hunter": "websocket",
    "nextjs_hunter": "nextjs",
    "spring_hunter": "spring",
    "laravel_hunter": "laravel",
    "aspnet_hunter": "aspnet",
    "nodejs_hunter": "nodejs",
    "deserialization_hunter": "deserialization",
}
