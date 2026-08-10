"""
Thin per-specialist skill packs (Praetorian-style lane prompts).

These are NOT full main-agent ``/skill`` packages. Each pack is a short protocol
injected into the fireteam specialist system prompt so sub-agents stay bounded
but still know how to prove impact in their lane.
"""

from __future__ import annotations

from typing import Dict

# specialist name → skill-pack body (appended after system_prompt_suffix)
SPECIALIST_SKILL_PACKS: Dict[str, str] = {
    "app_mapper": (
        "SKILL PACK — map first:\n"
        "- Prefer execute_deep_crawl / execute_browser to capture forms, APIs, auth surfaces.\n"
        "- Persist a compact capability summary via save_note(artifact=capability_map).\n"
        "- Do not spray Nuclei; hand off to attack specialists."
    ),
    "auth_logic": (
        "SKILL PACK — authentication testing (Ezra):\n"
        "- Enumerate login/session/password-reset from the map.\n"
        "- Prove with compare_requests (anonymous vs auth; role A vs role B).\n"
        "- Default/weak login: prefer handing sprays to credential_assault (Samson); "
        "if you hit creds yourself: add_engagement_credential + queue_finding_followups("
        "vuln_type='default_login').\n"
        "- Auth bypass: path/header/method mutations one at a time; bypass_403 only "
        "on concrete 403 paths.\n"
        "- Never invent credentials; never spray large dictionaries."
    ),
    "credential_assault": (
        "SKILL PACK — credential assault (Samson):\n"
        "- Only mapped login forms / known product default lists (Grafana, Tomcat, …).\n"
        "- test_credential_spray or execute_hydra with tiny lists + -f.\n"
        "- On success: add_engagement_credential + queue_finding_followups("
        "vuln_type='default_login') + validate_finding → create_finding.\n"
        "- No rockyou, no unbounded hydra, no invented passwords."
    ),
    "finding_judge": (
        "SKILL PACK — finding judge (Solomon):\n"
        "- Re-run validate_finding on each proposed medium+ finding.\n"
        "- Authz/IDOR: require anon/A/B identity discipline.\n"
        "- DROP theoretical / status-only / missing-evidence cards.\n"
        "- create_finding only after SUBMIT; sanitize_evidence first when secrets present."
    ),
    "api_authz": (
        "SKILL PACK — IDOR / BOLA proof:\n"
        "- Pick mapped object APIs with IDs (users, orgs, files, invoices).\n"
        "- compare_requests across anonymous / user A / user B (or adjacent IDs).\n"
        "- PASS only if other-user fields appear; status 200 alone is not a finding.\n"
        "- On proven read IDOR: queue_finding_followups(vuln_type='idor') for write/export."
    ),
    "host_tenant": (
        "SKILL PACK — tenant isolation:\n"
        "- Baseline: session A + Host=tenant A.\n"
        "- Mutant: same cookies + Host or X-Forwarded-Host = peer tenant B.\n"
        "- PASS only if tenant B data/PII appears; kill on vhost reject / unchanged A body."
    ),
    "business_logic": (
        "SKILL PACK — business logic:\n"
        "- Mutate one control at a time (price, quantity, step order, role field).\n"
        "- Demonstrate expected vs actual state with compare_requests / replay.\n"
        "- Prove the bypass; do not complete fraudulent checkout or irreversible actions."
    ),
    "injection": (
        "SKILL PACK — injection / XSS:\n"
        "- Only probe ranked params/forms from the map (or arjun/discover_parameters hits).\n"
        "- SQLi: canary → execute_sqlmap --batch on confirmed candidates.\n"
        "- XSS: execute_xsstrike and/or execute_dalfox; confirm with execute_browser when needed.\n"
        "- Command injection: execute_commix only on high-signal params; no blind spray.\n"
        "- Report with payload + response evidence; no status-only findings."
    ),
    "file_upload": (
        "SKILL PACK — upload abuse:\n"
        "- Content-type / extension / path tricks on mapped upload forms.\n"
        "- Prefer stored XSS or path disclosure proofs; avoid destructive webshells."
    ),
    "saml_sso": (
        "SKILL PACK — SSO:\n"
        "- Probe authorize/callback/SAML endpoints for open redirect, weak state, JWT issues.\n"
        "- Use test_saml_sso / execute_jwt; prove with redirect or token impact."
    ),
    "spa_client": (
        "SKILL PACK — SPA / DOM:\n"
        "- Hunt DOM XSS sinks, hidden client routes, and JS-driven APIs missing auth.\n"
        "- Confirm DOM XSS in browser; hidden APIs → hand off to api_authz."
    ),
    "coverage": (
        "SKILL PACK — coverage leftovers:\n"
        "- Run AFTER logic specialists.\n"
        "- get_engagement_brain for creds; prefer authenticated nuclei -var.\n"
        "- Chain default-login → authenticated CVE / admin SSRF cards via queue_finding_followups."
    ),
    "js_secrets": (
        "SKILL PACK — JS secrets:\n"
        "- scan_js_urls_for_secrets / execute_hermes / execute_gitleaks on first-party bundles.\n"
        "- Prefer verified credentials; redact secrets in create_finding evidence."
    ),
    "secrets_hunter": (
        "SKILL PACK — secrets:\n"
        "- Prefer execute_hermes / execute_argus / gitleaks with verification when available.\n"
        "- CRITICAL only for verified live credentials; LOW for unverified strings."
    ),
    "cloud_audit": (
        "SKILL PACK — cloud posture:\n"
        "- Use execute_themis (Prowler) read-only against configured cloud credentials.\n"
        "- Report high-impact public exposure / IAM findings with resource IDs."
    ),
    "graphql_api": (
        "SKILL PACK — GraphQL:\n"
        "- Probe /graphql paths; check introspection, suggestions, batching, CSRF on GET.\n"
        "- Prefer execute_schemathesis + execute_curl; prove authz with compare_requests."
    ),
    "web_recon": (
        "SKILL PACK — recon:\n"
        "- subfinder/httpx/whatweb/katana inventory; feroxbuster/ffuf only on high-value hosts.\n"
        "- No exploit tools in this lane."
    ),
    "vuln_triage": (
        "SKILL PACK — triage:\n"
        "- Correlate vulns with CVE/exploit context; do not exploit.\n"
        "- Rank blast radius; suggest which specialist should prove impact next."
    ),
    "takeover": (
        "SKILL PACK — takeover:\n"
        "- Confirm dangling CNAME + provider fingerprint before HIGH severity."
    ),
    "content_api": (
        "SKILL PACK — content/API enum:\n"
        "- Crawl + parameter discovery; feed map for authz/injection specialists."
    ),
}


def skill_pack_for(specialist: str) -> str:
    """Return the skill-pack body for a specialist, or empty string."""
    return (SPECIALIST_SKILL_PACKS.get(specialist) or "").strip()
