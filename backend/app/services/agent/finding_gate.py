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
is_active, valid_through, is_staff, role. Schema-unauth + privilege fields is SUBMIT.
Unauth lookup that is 200 or 500 while /api/auth/profile/ and /users/me/ are 401 also
SUBMIT — a down database is not an auth rejection. One canary email
(aegis-enum-canary@example.invalid); do not spray employee inboxes; do not dump ICS
users. ACAO * is extra, not the CORS-credentials finding. Kill only if the lookup
401/403 like siblings, the schema requires JWT, or the body is a non-enumerating
boolean. Remediation: require JWT; if a pre-login check is needed, boolean is_active
only + rate limit; do not confirm account existence.
Guard-catalog data stores and tokens: ArangoDB root+empty password, MongoDB anon listDatabases,
EMQX admin:public, Auth0 /api/token, GitLab /api/v4/projects, Docker /v2/_catalog, Django
DEBUG traceback, unauth /api/chat — banners/tokens are footholds until a bounded list/sample
(per_page=1 / size=1 / catalog names). Do not dump PII, clone all repos, push images,
FLUSHALL, burn tokens, or upload plugins.
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
network-restrict the token endpoint."""


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
