"""
Aegis pantheon — Judah Security display names for agent roles.

Praetorian uses Roman emperors/officials (Marcus, Brutus, Titus…).
Judah Security uses the **Aegis** family with biblical / divine epithets for
real-world bug lanes (not CTF). Snake_case IDs stay stable for code; epithets
are for prompts, fireteam debriefs, and UI.

Orchestrator epithet: **Joshua** (commander who sends specialists into the field).
"""

from __future__ import annotations

from typing import Dict, Optional

# Internal specialist / role id → (epithet, one-line vocation)
PANTHEON: Dict[str, tuple[str, str]] = {
    "orchestrator": ("Joshua", "Engagement commander — delegates bounded fronts"),
    "app_mapper": ("Raphael", "Guide of the road — maps apps, forms, and APIs"),
    "web_recon": ("Caleb", "Scout of the land — passive recon and inventory"),
    "content_api": ("Baruch", "Scribe of surfaces — crawl, fuzz, parameter mine"),
    "js_secrets": ("Uri", "Light in the bundles — JS secrets and sinks"),
    "secrets_hunter": ("Uriel", "Flame of God — verified credential exposure"),
    "vuln_triage": ("Solomon", "Judge of severity — triage without exploitation"),
    "cloud_audit": ("Nehemiah", "Wall inspector — cloud posture and exposure"),
    "graphql_api": ("Nathan", "Prophet of the API — GraphQL authz and abuse"),
    "takeover": ("Gideon", "Breaker of false strongholds — subdomain takeover"),
    "auth_logic": ("Ezra", "Keeper of the covenant — session and auth boundaries"),
    "credential_assault": ("Samson", "Strength at the gates — default/weak credential assault"),
    "api_authz": ("Daniel", "Judgment in the den — IDOR / BOLA proof"),
    "host_tenant": ("Judah", "Tribe identity — Host/tenant isolation differentials"),
    "business_logic": ("Joseph", "Steward of the storehouse — workflow / logic abuse"),
    "injection": ("David", "Sling against the giant — SQLi / XSS / command injection (legacy combined lane)"),
    "xss": ("Jonathan", "Arrow of the bow — reflected / stored / DOM XSS"),
    "sqli": ("Joab", "Captain of the host — SQL / template / command injection"),
    "ssrf": ("Asher", "Bread of the king — SSRF / URL-fetch / webhook"),
    "file_upload": ("Bezaleel", "Craftsman of the sanctuary — upload abuse"),
    "saml_sso": ("Melchizedek", "Priest of the covenant — SSO / SAML / OAuth"),
    "spa_client": ("Miriam", "Song in the client — DOM XSS and hidden routes"),
    "coverage": ("Nehemiah", "Builder who finds gaps — authenticated coverage scans"),
    "finding_judge": ("Solomon", "Wisdom gate — evidence judgment before publish"),
    "risk_assessor": ("Marcus", "Risk counsel — demonstrated-only RA after publish"),
    "agent_tools": ("Isaiah", "Voice of the model — chatbot tools and unauth LLM proxies"),
    "code_sast": ("Huldah", "Prophetess of the checkout — threat-shaped SAST"),
    "independent_verifier": ("Deborah", "Second witness — independent proof of candidates"),
    # Existing branded tools (already first-class)
    "atlas": ("Atlas", "Cartographer of the heavens — org attack-surface map"),
    "argus": ("Argus", "All-seeing — local secrets scanner"),
    "hermes": ("Hermes", "Messenger — remote secrets finder"),
    "janus": ("Janus", "Two-faced gatekeeper — DAST baseline/full"),
    "themis": ("Themis", "Scale of justice — cloud compliance oracle"),
}


def epithet_for(role_id: str) -> str:
    """Return display epithet for a role/specialist id."""
    entry = PANTHEON.get(role_id)
    return entry[0] if entry else role_id.replace("_", " ").title()


def vocation_for(role_id: str) -> str:
    entry = PANTHEON.get(role_id)
    return entry[1] if entry else ""


def pantheon_line(role_id: str) -> str:
    """Single prompt line: 'Samson (credential_assault) — …'."""
    epi = epithet_for(role_id)
    voc = vocation_for(role_id)
    if voc:
        return f"{epi} ({role_id}) — {voc}"
    return f"{epi} ({role_id})"


def pantheon_table() -> Dict[str, Dict[str, str]]:
    return {
        rid: {"epithet": epi, "vocation": voc}
        for rid, (epi, voc) in PANTHEON.items()
    }


def resolve_epithet(role_id: str, override: Optional[str] = None) -> str:
    return (override or "").strip() or epithet_for(role_id)
