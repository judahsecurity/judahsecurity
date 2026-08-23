"""Interactsh is the OOB collaborator — not Canarytokens.

Blind SSRF/XXE/SQLi/RCE and webhook/email sinks prove impact by planting a
``payload_url`` (or ``aegis@payload_domain`` mailbox) from
``execute_interactsh register``, then ``poll <session_id>``. A DNS/HTTP/SMTP
interaction in poll stdout is demonstrated compromise. Do not use
canarytokens.org, Burp Collaborator SaaS, or an operator inbox as the primary
channel — those never land in demonstrated_chain.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

WRITEUP_RULES = (
    "Blind SSRF/XXE/OOB (CWE-918 / CWE-611): IMPROVE until execute_interactsh "
    "poll shows a DNS/HTTP/SMTP interaction on the planted payload_url. Register "
    "first, plant payload_url (or aegis@payload_domain for mail/webhooks), poll. "
    "Do not use Canarytokens or an operator inbox as the primary OOB channel. "
    "Non-blind SSRF with an internal HTTP body is SUBMIT without OOB. OOB DNS "
    "without an internal body is High, not Critical. Never 169.254.169.254 / "
    "localhost if Lictor blocks."
)

REVIEW_RULES = (
    "Blind SSRF/XXE (Ask Marcus): keep Demonstrated High when poll stdout has a "
    "DNS/HTTP/SMTP hit on the Interactsh payload. Do not drop because IMDS was "
    "not reached. Do not ask hunters to switch to Canarytokens. Retest bar: "
    "planted payload_url gets no new_interactions. Do not re-hit metadata."
)

VERIFIER_ADDENDUM = (
    "This is a blind SSRF/XXE/OOB candidate. Re-derive ONLY with Interactsh:\n"
    "1) execute_interactsh(args='register') → payload_url / payload_domain.\n"
    "2) Plant that URL (or aegis@payload_domain for mail) in the claimed sink.\n"
    "3) execute_interactsh(args='poll <session_id>').\n"
    "confirmed if poll returns new_interactions ≥ 1 (dns/http/smtp). "
    "An internal HTTP body without OOB is also confirmed. "
    "refuted if poll is empty AND the response has no internal content.\n"
    "Do not use canarytokens.org. Do not fetch 169.254.169.254 / localhost."
)

HUNTER_RULES = (
    "OOB proof is Interactsh only: execute_interactsh register → plant "
    "payload_url → poll. Any DNS/HTTP/SMTP callback is SUBMIT High. For mail/"
    "EmailJS use aegis@<payload_domain>, not an operator inbox, not "
    "Canarytokens. Never metadata/localhost. "
    "queue_finding_followups(vuln_type='ssrf')."
)

_FINDING_HINTS = (
    "ssrf",
    "server-side request",
    "blind xxe",
    "out-of-band",
    "oob dns",
    "oob http",
    "interactsh",
    "oast.",
    "url-fetch",
    "url fetch",
    "webhook fetch",
    "requesturl",
)

_INTERNAL_BODY_HINTS = (
    "internal body",
    "internal html",
    "metadata credential",
    "iam/security-credentials",
    "computeMetadata",
    "169.254.169.254",
    "prometheus targets",
    "datasources/proxy",
)


def is_oob_finding(text: str) -> bool:
    blob = (text or "").lower()
    return any(h in blob for h in _FINDING_HINTS)


def has_interactsh_proof(text: str) -> bool:
    """Poll stdout: new_interactions, protocol dns/http/smtp, oast payload."""
    blob = (text or "").lower()
    if "canarytokens.org" in blob and "interactsh" not in blob and "oast." not in blob:
        return False
    poll_hit = any(
        t in blob
        for t in (
            "new_interactions",
            '"protocol": "dns"',
            '"protocol": "http"',
            '"protocol": "smtp"',
            "protocol': 'dns'",
            "dns callback",
            "http callback",
            "smtp callback",
            "oob hit",
            "oast.fun",
            "oast.pro",
            "oast.live",
            "oast.site",
            "interact.sh",
        )
    )
    planted = "payload_url" in blob or "payload_domain" in blob or "oast." in blob
    return poll_hit and (planted or "interactsh" in blob or "poll " in blob)


def has_internal_ssrf_body(text: str) -> bool:
    blob = (text or "").lower()
    return any(h.lower() in blob for h in _INTERNAL_BODY_HINTS)


def has_ssrf_proof(text: str) -> bool:
    return has_interactsh_proof(text) or has_internal_ssrf_body(text)


def mailbox_for_domain(payload_domain: str) -> str:
    host = (payload_domain or "").strip().lstrip("@")
    return f"aegis@{host}" if host else ""


def annotate_register(result: Dict[str, Any]) -> Dict[str, Any]:
    """Add mailbox + plant/poll guidance to a successful register payload."""
    if not result.get("success"):
        return result
    domain = str(result.get("payload_domain") or "")
    if domain and "payload_email" not in result:
        result["payload_email"] = mailbox_for_domain(domain)
    result.setdefault(
        "next",
        (
            "Plant payload_url in the sink (SSRF/XXE/webhook) or payload_email "
            "as the mail recipient. Then execute_interactsh poll "
            f"{result.get('session_id')}. Do not use Canarytokens."
        ),
    )
    return result
