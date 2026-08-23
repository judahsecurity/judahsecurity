"""
Finding publication gate — Solomon / judge receipts.

Medium+ findings require a prior ``validate_finding`` verdict of SUBMIT.
This mirrors Praetorian's demonstrated-compromise bar (no scanner-only noise).
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, Optional, Tuple


_GATE_SEVERITIES = frozenset({"critical", "high", "medium"})

# Demonstrated-compromise writeup (injected into create_finding / specialist prompts).
# Login success or a Nuclei template hit is a foothold, not a finding.
FINDING_WRITEUP_GUIDANCE = """Write findings as demonstrated-compromise reports, not scanner hits.
Required sections (map onto create_finding fields):
- description (Vulnerability Description): how access was obtained (product, version, credential/pattern), how it was found, rate-limit/lockout notes, which privileged APIs were used
- impact: what was retrieved (config, topology, tokens, user hashes/PII, internal services) — not merely 'login succeeded'. Use concrete counts.
- target: full affected URL (scheme + host + port) — shown as Assets Affected
- remediation (Recommendation): rotate creds immediately, restrict network access, force resets, raise PBKDF2/Argon2 cost, add rate limits
- evidence: redacted request/response proving the privileged API (sanitize_evidence first)
- demonstrated_chain: ordered live tool calls with args + observed stdout that prove impact
- not_demonstrated: what was not attempted (hash cracking, data modification, lateral movement)
- references: CWE (e.g. CWE-1393 default credentials) and vendor hardening docs
Default/weak login or a client_secret sitting in a JS bundle is IMPROVE until privileged impact is proven.
Chain steps must be successful proof only — failed attempts (e.g. AuthSession HMAC with
_users derived_key → 401) belong in not_demonstrated, not the chain.
CouchDB after _admin: GET /_node/_local/_config (secret, timeout, admins salts) then prove
AuthSession forgery with secret+admin salt (not _users derived_key). Password rotation does
not kill this; rotating couch_httpd_auth.secret does. sanitize_evidence on secret/salts/cookies.
Elasticsearch :9200 / xpack.security off: unauthenticated banner is a foothold. Prove
(1) cluster/node metadata (2) index enumeration + limited sample read size=1
(3) write via PUT then DELETE of aegis_test_index. Do not dump all documents, do not run
Painless/scripting RCE, do not pivot. not_demonstrated must state those bounds. CWE-306.
Anonymous Azure Function env dump (authLevel:anonymous Tester): IMPROVE until leaked secret
classes are named (Cosmos, Storage, MACHINEKEY, EasyAuth, AAD, App Insights) — not merely
'environment variables leaked'. Do not claim managed-identity code execution unless it was
demonstrated; otherwise list ACE / Key Vault write / Graph+ARM Owner under not_demonstrated.
Rotate AAD secrets last after the trigger is removed. CWE-526.
Grafana CVE-2024-9264 (SQL expressions): Viewer+ POST /api/ds/query type=sql that forks
DuckDB is demonstrated compromise — including fork/exec '... duckdb: no such file or
directory'. Missing DuckDB and sqlExpressions=0 in /metrics are NOT kills (UI toggle ≠
backend in 11.0.x). Kill only if patched >=11.2.2 or the engine rejects SQL without
forking. Do not install DuckDB; do not run shell extensions. Patch: upgrade Grafana;
disable SQL expressions in backend config; least-privilege SA tokens. CWE-89 / CWE-94 / CWE-863.
OpenAPI/DRF mass assignment (API3 / CWE-915): GET /api/schema/ and count request
serializers where id, created, updated, user, owner, schedule, or periodic_task are
writable (not readOnly). Quote list operations that say 'shared across all users'.
That schema contract is demonstrated compromise even if the database is down (500 /
OperationalError) — do not kill. One bounded canary write if the DB is up; do not
enable ICS/OT schedules; do not dump the object hierarchy. Remediation: read_only=True
/ extra_kwargs on server-managed fields; object-level permissions; tenant-scope lists.
Unauth OpenAPI account lookup (CWE-204 / CWE-200 / CWE-862): GET /api/auth/account/
?email= documented with security: {} ('without authentication') returning email,
is_active, valid_through, is_staff, role. Schema-unauth + privilege fields is SUBMIT
Critical. Unauth lookup that is 200, 404 ('User does not exist!'), or 500 while
/api/auth/profile/ and /users/me/ are 401 also SUBMIT — a down database is not an
auth rejection; 404 is an existence oracle, not a kill. One canary email
(aegis-enum-canary@example.invalid); do not spray employee inboxes; do not dump ICS
users. Do not claim a 200 UserAccount payload (is_staff/role bytes) unless that
body is in demonstrated_chain stdout — schema + 401-vs-404/500 is enough. Detection
step claims must match tool stdout. ACAO * is extra, not the CORS-credentials
finding. File Critical (not Open High). Kill only if the lookup 401/403 like
siblings, the schema requires JWT, or the body is a non-enumerating boolean.
Remediation: require JWT; if a pre-login check is needed, boolean is_active
only + rate limit; do not confirm account existence.
Unauthenticated ASP.NET / API settings write (CWE-306 / CWE-862): paired proof is
the finding. POST a sibling write that enforces auth (e.g. /api/TaskAdmin/UpdateTask)
with no Authorization header — expect 401. Then POST /api/Settings/SaveSettings (or
mapped Save*/Write* config endpoint) with no Authorization and a JSON body matching
the settings schema. HTTP 200 with Content-Length: 0 is the standard ASP.NET Core
void-action success — the write was accepted. That 401-vs-200 differential is SUBMIT
(High). GET /GetSettings returning 500 / NullReferenceException is NOT a kill (no
read-back). One canary key only (aegis-verify-<rand>); do not replace the full
settings collection; do not flip production flags (enableNotifications,
createPlannerTasks, powerBIReportId) unless already known. Do not claim persistence
unless GetSettings round-trips the canary. Hosting on *.azurewebsites.net is App
Service, not an Azure Function env dump. Remediation: [Authorize] on the controller
(or a global FallbackPolicy so missing attributes deny) plus
[Authorize(Roles="Admin")] on SaveSettings. Follow-up other controllers that process
without 401 (LogQuery, Audit, ReadTasks, OpenDocument) as a sibling missing-auth
card — empty-array 200s and Graph-downstream 500s are not this High write.
Unauth email-change ATO (djoser reset_email, CWE-306 / CWE-640): unauth POST
/api/auth/users/reset_email/ 204 while set_password 401 is SUBMIT. Confirm with
uid=MQ (user 1) + garbage token enumerating 'Invalid token for given user' vs
'Invalid user id' is extra. One canary email (aegis-ato-canary@example.invalid);
do not complete ATO on a real mailbox; do not spray. OPTIONS 401 or schema jwtAuth
is NOT a kill. Remediation: IsAuthenticated on both views; bind the change to the
session user; consistent errors; rate limit.
Auth middleware skip when Authorization is absent (CWE-287 / CWE-306): compare
no-header vs Authorization: Bearer aegis-invalid. No-header 200/400 (controller
ran) AND invalid-bearer 401 is SUBMIT. 400 missing required params is a bypass —
the middleware never ran. Do not dump. Kill only if missing header is 401/403.
Remediation: disable ByPassAuthorization; fail closed when the header is missing
(global FallbackPolicy / unconditional OIDC).
Socket.IO get_stream IDOR (CWE-639 / CWE-306): anonymous Engine.IO polling +
42["get_stream", fabricated siteId] returning url_key is SUBMIT. Do not fetch
the video stream. Do not send null/malformed crash loops against ICS. Video not
downloaded is NOT a kill. CORS on /socket.io/ is the sibling cors_credentials
card; hardcoded siteId/userType=Admin is js_secrets. Remediation: auth on the
handshake; authorize siteId/analyzerId server-side; allowlist origins; upgrade
Socket.IO.
ML pipeline missing RBAC (CWE-285 / CWE-863): self-registered or low-priv JWT
can POST /api/v1/train/ or DELETE /api/v1/celery-task/. Do not delete production
models; one canary train or OPTIONS/authz probe. Open signup is the internet
exposure, not a second finding. Remediation: admin/ML-engineer roles on train/
delete/celery; email verification on signup.
Guard-catalog data stores and tokens: ArangoDB root+empty password, MongoDB anon listDatabases,
EMQX admin:public, Auth0 /api/token, GitLab /api/v4/projects, Docker /v2/_catalog, Django
DEBUG traceback, unauth /api/chat — banners/tokens are footholds until a bounded list/sample
(per_page=1 / size=1 / catalog names). Do not dump PII, clone all repos, push images,
FLUSHALL, burn tokens, or upload plugins.
Azure Container Registry anonymous pull (CWE-306 / CWE-798 / CWE-540): *.azurecr.io
anonymousPullEnabled is proven when the registry issues an anonymous oauth2 bearer
for registry:catalog:* and GET /v2/_catalog returns repository names. That catalog
is SUBMIT High — not a scanner banner. Then a bounded secret scan: tags/list +
config/history for at most 1–3 first-party repos (prefer *-graphql*, *-enrollment*,
:latest). Do not pull the whole catalog. Do not push. Do not delete tags.
Classic GitHub PATs (ghp_*) in package-lock.json resolved git+https URLs, or
admin/workflow/write:packages on a first-party repo, raise the card to Critical.
Expired ghs_* in .git/config extraheader is a recurring leak pattern, not currently
live. Internal-only keys (Artifactory host that does not resolve, NATS/Keycloak/
Postgres in cluster images) still count as recovered secrets — rotate; do not hunt
those internal hosts from the internet. Do not authenticate recovered PATs against
api.github.com; do not list Actions secrets; cite a prior live /user 200 if already
in evidence. Remediation: disable anonymousPullEnabled; private endpoint / firewall;
revoke PATs; rotate NPM/Actions/Artifactory/NATS; rebuild without lockfile git
URLs or .git; delete old secret-bearing tags. Retest bar is deny-only (anonymous
token refused, catalog 401, revoked PAT 401) — not another public pull.
When reviewing a pasted finding (Ask Marcus): Verdict (keep/raise/drop severity
and Demonstrated); What is proven; What is not proven; why Critical vs High;
Ticket guidance; defensive retest bar. Do not re-probe live registries or reuse
recovered credentials unless the operator explicitly asks for a deny-check.
Wiki open self-registration: IMPROVE until a throwaway account can write a sandbox page or
read one internal page. Do not deface production wiki articles.
Hardcoded creds in a public binary: IMPROVE until strings extract a production secret
(optional one live login). Do not reverse for exploits.
Client-side-only admin/eLogbook auth: IMPROVE until an API returns privileged data without
a server session — UI hide-only is not a finding.
CORS (CWE-942): a canary Origin reflected in Access-Control-Allow-Origin WITH
Access-Control-Allow-Credentials: true is demonstrated compromise — including on
Keycloak token, userinfo, JWKS, and /auth/admin/realms/*/users. Header proof is enough;
do not require a victim browser tab; do not dump the user directory; do not ship an
HTML exploit page. ACAO=* without credentials is NOT this bug. Keycloak fix: client
webOrigins explicit allowlist or '+' (valid redirect URIs), never '*'; audit reverse
proxies that inject blanket CORS.
Keycloak admin-cli password grant (CWE-307): POST
/auth/realms/{realm}/protocol/openid-connect/token with grant_type=password,
client_id=admin-cli, and no client_secret. invalid_grant (not invalid_client) proves
a public Direct Access Grant. A bounded probe of at most 8 failed attempts with no
429/lockout is SUBMIT — do not hydra/rockyou; do not kill because a valid password
was not guessed. Master realm is full admin. Disable Direct Access Grants on admin-cli;
enable Brute Force Detection; if the grant must stay, make the client confidential and
network-restrict the token endpoint.
WordPress unauth GET /wp-json/wp/v2/users returning slug/name is SUBMIT
(CWE-200 user enumeration). Do not require WPScan or a privileged API.
Kill 401/403/empty list with that evidence. WordPress admin-ajax nested
tax_query timing (elapsed delta ≥1.5s that scales with SLEEP) is SUBMIT
with the timing table; status 200 without delay is DROP.
After publish: Marcus risk assessment (assess_finding_risk) is required for
medium+. Score the demonstrated packet only — confirm vs inflate vs
downgrade, CVSS on demonstrated evidence, why_not_higher, control failures,
remediation with done_when, retest_criteria. Critical requires demonstrated
write/RCE/cloud credential theft. Non-blind SSRF with IMDS blocked is High.
Do not live-retest for RA. Complete is blocked while RA is pending."""


FINDING_REVIEW_GUIDANCE = """When the operator pastes an existing finding (Ask Marcus / review):
Do not re-probe the live target unless they explicitly request a deny-check retest.
Write, in this order:
- Verdict: keep / raise / drop severity and Demonstrated vs foothold — one sentence why
- What is proven (only evidence already in the writeup)
- What is not proven (and must not be re-proven on production)
- Severity rationale (why Critical vs High vs Medium)
- Ticket guidance (owner-actionable remediations, named owners/systems)
- Retest bar: secure-behavior checks only (anonymous token denied, catalog 401,
  revoked credential 401). Do not re-pull images or reuse recovered secrets.
Raise High→Critical when anonymously pullable images contained live privileged
tokens (classic GitHub PAT with repo/workflow/admin). Expired ghs_* is a leak
pattern, not currently live. Internal-only secrets still count — rotate; do not
hunt internal hostnames from the internet.
Unauth /api/auth/account/ (Ask Marcus): keep Demonstrated. Raise High→Critical
when schema security: {} quotes is_staff/role OR sibling 401 vs lookup 200/404/500
is in the packet. Do not drop because the 200 UserAccount body was not captured.
Do not treat 404 'User does not exist!' as a kill — that is the existence oracle.
Do not mix ACAO * into cors_credentials (ACAC is absent). why_not_higher: no RCE,
no ATO, no sprayed ICS users, no inferred role bytes. Retest bar: unauth lookup
returns 401 like /api/auth/profile/. Do not re-query live emails; do not spray.
Unauth SaveSettings (Ask Marcus): keep Demonstrated High. Do not raise to
Critical on void 200 alone — Critical needs GetSettings round-trip of the
canary AND a demonstrated security-control change. Do not drop because
GetSettings is 500 / NRE (no read-back). Do not mix *.azurewebsites.net
App Service with an Azure Function env dump. why_not_higher: no proven
persistence, no flag flip, no BFLA with a low-priv session. Retest bar:
unauth POST SaveSettings returns 401 like UpdateTask. Do not re-POST a
replacement settings collection; do not flip production flags."""


def acr_anonymous_pull_signals(text: Optional[str]) -> Dict[str, bool]:
    """Keyword signals for ACR / Docker Registry anonymous-pull findings."""
    t = (text or "").lower()
    is_finding = (
        "azurecr" in t
        or "anonymous pull" in t
        or "anonymouspullenabled" in t
        or "anonymous pull enabled" in t
        or "/v2/_catalog" in t
        or "docker registry" in t
        or (
            "container registry" in t
            and any(s in t for s in ("anonymous", "unauth", "catalog", "oauth2"))
        )
    )
    has_anon_proof = any(
        s in t
        for s in (
            "access_token",
            "anonymous bearer",
            "anonymous token",
            "registry:catalog",
            "repositories",
            "/v2/_catalog",
            "catalog",
        )
    )
    has_secret_class = any(
        s in t
        for s in (
            "ghp_",
            "github pat",
            "personal access token",
            "package-lock",
            "ghs_",
            "artifactory",
            "akcp",
            "nats",
            "git+https",
        )
    )
    live_privileged = has_secret_class and any(
        s in t
        for s in (
            "ghp_",
            "classic personal",
            "write:packages",
            "permissions admin",
            "admin=true",
            "repo, workflow",
            "workflow",
        )
    )
    return {
        "is_finding": is_finding,
        "has_anon_proof": has_anon_proof,
        "has_secret_class": has_secret_class,
        "live_privileged_token": live_privileged,
    }


def normalize_target(target: Optional[str]) -> str:
    t = (target or "").strip().lower()
    if t.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse

            p = urlparse(t)
            t = (p.netloc or p.path.split("/")[0] or t).lower()
        except Exception:
            pass
    return t.rstrip("/").split("/")[0].split(":")[0]


def receipt_key(title: str, target: Optional[str]) -> str:
    blob = f"{(title or '').strip().lower()}|{normalize_target(target)}"
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:20]


def severity_requires_gate(severity: Optional[str]) -> bool:
    return (severity or "info").strip().lower() in _GATE_SEVERITIES


def record_submit_receipt(
    store: Dict[str, Dict[str, Any]],
    *,
    title: str,
    target: Optional[str],
    severity: str,
    score: str,
) -> str:
    key = receipt_key(title, target)
    store[key] = {
        "title": title,
        "target": normalize_target(target),
        "severity": (severity or "").lower(),
        "score": score,
        "verdict": "SUBMIT",
        "ts": time.time(),
    }
    return key


def consume_or_check_receipt(
    store: Dict[str, Dict[str, Any]],
    *,
    title: str,
    target: Optional[str],
    severity: str,
    require: bool = True,
) -> Tuple[bool, str]:
    """Return (ok, message). Does not delete receipts (re-submit allowed)."""
    if not require or not severity_requires_gate(severity):
        return True, "gate_skipped"
    key = receipt_key(title, target)
    receipt = store.get(key)
    if not receipt:
        return False, (
            "JUDGE GATE: medium+ findings require validate_finding → verdict SUBMIT "
            f"for this title/target first (receipt key={key}). "
            "Call validate_finding with the same title/target/evidence, then retry "
            "create_finding only if verdict is SUBMIT."
        )
    if receipt.get("verdict") != "SUBMIT":
        return False, f"JUDGE GATE: receipt exists but verdict={receipt.get('verdict')}"
    return True, f"gate_ok:{key}"
