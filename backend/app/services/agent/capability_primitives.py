"""Capability primitives: chain proven low-impact results into impact hypotheses.

Adapted from the capability-primitive idea in CyberStrikeAI (Apache-2.0,
``skills/capability-primitive-search``), rewritten for Prowl's proof rules.

A finding is recorded twice in a tester's head: as a vulnerability, and as a
*capability* it grants ("I can read files under /var/www", "I can make the
victim's browser send a request"). Several low-severity capabilities often add
up to real impact even when no single one does. This module maps proven brain
hypotheses (and stored credentials) to primitives, then checks a fixed set of
combination patterns. A satisfied pattern becomes a chain hypothesis card;
a pattern missing exactly one primitive is returned as a "one step away" lead.

Everything here is a hypothesis. A chain is proven only when each step has its
own execution receipt and the chain is filed through the normal finding gate.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Set, Tuple

# Primitive names (what the tester can do now).
READ_FILE = "read_file"            # arbitrary/limited file read
SOURCE_OR_CONFIG = "source_config"  # source, config, backup, stack trace leak
SECRET = "secret"                  # API key, token, connection string
CREDENTIAL = "credential"          # working username/password or session
READ_DATA = "read_data"            # read records the tester should not see
OTHER_OBJECT = "other_object"      # access another user's object (IDOR/BOLA)
VICTIM_BROWSER = "victim_browser"  # run script / send requests as a victim
CROSS_ORIGIN_READ = "cross_origin_read"  # credentialed CORS read
REDIRECT = "redirect"              # attacker-controlled redirect
SERVER_FETCH = "server_fetch"      # SSRF
FORGE_IDENTITY = "forge_identity"  # JWT forgery / session forgery
ADMIN_SURFACE = "admin_surface"    # reachable admin/management panel
USER_LIST = "user_list"            # valid account identifiers
WRITE_FIELD = "write_field"        # mass assignment / unauth settings write
TEMPLATE_EVAL = "template_eval"    # SSTI expression evaluation
COMMAND_EXEC = "command_exec"      # proven command execution
HOST_POISON = "host_poison"        # Host header controls generated links

# Text signals -> primitives. Checked against title + evidence of proven
# hypotheses. Class names come from proof_policy.inferred_vulnerability_class.
_CLASS_PRIMITIVES: Dict[str, Tuple[str, ...]] = {
    "path_traversal": (READ_FILE,),
    "sql_injection": (READ_DATA,),
    "nosql": (READ_DATA,),
    "xss": (VICTIM_BROWSER,),
    "csrf": (VICTIM_BROWSER,),
    "cors": (CROSS_ORIGIN_READ,),
    "open_redirect": (REDIRECT,),
    "dom_open_redirect": (REDIRECT,),
    "ssrf": (SERVER_FETCH,),
    "xxe": (SERVER_FETCH, READ_FILE),
    "jwt": (FORGE_IDENTITY,),
    "authorization": (OTHER_OBJECT,),
    "ssti": (TEMPLATE_EVAL,),
    "command_injection": (COMMAND_EXEC,),
    "account_enumeration": (USER_LIST,),
    "exposure": (SOURCE_OR_CONFIG,),
}

_KEYWORD_PRIMITIVES: Tuple[Tuple[str, str], ...] = (
    (r"\b(idor|bola|other user'?s|cross[- ]tenant)\b", OTHER_OBJECT),
    (r"\b(default|weak) (login|credential|password)s?\b|\blogin succeeded\b", CREDENTIAL),
    (r"\b(api[_ -]?key|secret key|access[_ -]?token|bearer token|client[_ -]?secret|"
     r"connection string|private key|hardcoded credential)\b", SECRET),
    (r"\.git\b|\bbackup file\b|\bstack trace\b|\b\.env\b|\bphpinfo\b|\bsource map\b|"
     r"\bdirectory (listing|index)\b", SOURCE_OR_CONFIG),
    (r"\b(admin|management|console|dashboard) (panel|interface|portal|ui)\b|"
     r"\bwp-admin\b|\bjenkins\b|\bgrafana\b|\bkibana\b", ADMIN_SURFACE),
    (r"\bmass[- ]assignment\b|\bsettings write\b|\bunauth(enticated)? .*write\b", WRITE_FIELD),
    (r"\bhost header\b|\bpassword reset poisoning\b", HOST_POISON),
    (r"\buser (enumeration|lookup)\b|\baccount enumeration\b", USER_LIST),
    (r"\b(oauth|sso|openid)\b.*\bredirect_uri\b|\bredirect_uri\b", REDIRECT),
)


@dataclass(frozen=True)
class ChainPattern:
    id: str
    requires: FrozenSet[str]
    impact: str
    test: str
    specialist: str


# Impact patterns. Each step must be demonstrated on the target; tests stay
# non-destructive (read-back, canary objects, own test identities).
PATTERNS: Tuple[ChainPattern, ...] = (
    ChainPattern("read_to_login", frozenset({READ_FILE, ADMIN_SURFACE}),
                 "file read exposes credentials or keys that log in to the admin surface",
                 "Read config/env files the read primitive reaches; test any found credential "
                 "once against the admin login with a read-only action.", "auth_logic"),
    ChainPattern("leak_to_api", frozenset({SECRET}),
                 "leaked secret grants direct API access beyond the public client",
                 "Call one read-only endpoint with the leaked key and compare against an "
                 "unauthenticated request.", "js_secrets"),
    ChainPattern("leak_to_login", frozenset({SOURCE_OR_CONFIG, ADMIN_SURFACE}),
                 "source/config leak reveals credentials or bypass for the admin surface",
                 "Extract credentials, routes or auth logic from the leak; test the admin "
                 "surface with them using a read-only action.", "auth_logic"),
    ChainPattern("cred_to_admin", frozenset({CREDENTIAL, ADMIN_SURFACE}),
                 "working credential reaches a management feature with privileged effect",
                 "Log in once; enumerate privileged features (users, export, plugins, "
                 "webhooks) and prove access with a read of their configuration.", "auth_logic"),
    ChainPattern("sqli_to_account", frozenset({READ_DATA, ADMIN_SURFACE}),
                 "injection reads account data (hashes, reset tokens, API keys) usable at login",
                 "Read one row of the users/token table with the injection; show the field "
                 "type that grants access. Do not crack hashes or log in as real users.",
                 "sqli"),
    ChainPattern("xss_to_admin_action", frozenset({VICTIM_BROWSER, ADMIN_SURFACE}),
                 "script in an admin's browser performs a privileged action",
                 "Show the XSS fires on a page an admin visits and that a same-origin request "
                 "to a privileged endpoint succeeds with your own admin test identity.",
                 "xss"),
    ChainPattern("cors_data_theft", frozenset({CROSS_ORIGIN_READ, OTHER_OBJECT}),
                 "credentialed CORS read exfiltrates another user's object",
                 "From an attacker origin, read the IDOR-reachable object with credentials "
                 "using test identities only.", "api_authz"),
    ChainPattern("cors_session_data", frozenset({CROSS_ORIGIN_READ, READ_DATA}),
                 "credentialed CORS read exposes sensitive account data to any origin",
                 "Read the sensitive endpoint cross-origin with a test identity and show "
                 "the response body is readable.", "api_authz"),
    ChainPattern("redirect_token_theft", frozenset({REDIRECT, FORGE_IDENTITY}),
                 "open redirect in an auth flow leaks or accepts a forged token",
                 "Check whether OAuth/SSO redirect_uri accepts the redirect; observe the "
                 "token/code reaching a callback you control.", "auth_logic"),
    ChainPattern("redirect_oauth", frozenset({REDIRECT, CREDENTIAL}),
                 "open redirect in the login/OAuth flow sends codes or tokens off-site",
                 "Use the redirect as redirect_uri or post-login next= with your own test "
                 "account; capture the code at an Interactsh URL.", "auth_logic"),
    ChainPattern("ssrf_internal", frozenset({SERVER_FETCH, SOURCE_OR_CONFIG}),
                 "SSRF reaches an internal service named in the leaked config",
                 "Fetch the internal host from the leak via SSRF (in-scope, read-only "
                 "GET); show a response that is not publicly reachable.", "ssrf"),
    ChainPattern("forge_to_admin", frozenset({FORGE_IDENTITY, ADMIN_SURFACE}),
                 "forged identity reaches admin functions",
                 "Forge a token for your own test user with an elevated role claim and "
                 "read one admin-only resource.", "api_authz"),
    ChainPattern("idor_write_escalation", frozenset({OTHER_OBJECT, WRITE_FIELD}),
                 "object access plus writable fields changes another account's role or owner",
                 "On a second test identity you own, set a role/owner field via the "
                 "writable field and read it back; revert afterwards.", "api_authz"),
    ChainPattern("enum_to_reset", frozenset({USER_LIST, HOST_POISON}),
                 "known accounts plus Host poisoning sends reset links to an attacker host",
                 "Trigger a reset for your own test account with a poisoned Host; observe "
                 "the link domain in the received email or an Interactsh hit.", "auth_logic"),
    ChainPattern("template_to_exec", frozenset({TEMPLATE_EVAL}),
                 "template evaluation reaches code execution",
                 "Show a deterministic arithmetic or environment read through the template "
                 "engine; do not run system commands beyond a harmless id/echo marker.",
                 "server_injection"),
)


def primitives_from_text(text: str) -> Set[str]:
    from types import SimpleNamespace

    from app.services.agent.proof_policy import inferred_vulnerability_class

    found: Set[str] = set()
    blob = text or ""
    try:
        klass = inferred_vulnerability_class(SimpleNamespace(title=blob, description=""))
    except Exception:
        klass = ""
    found.update(_CLASS_PRIMITIVES.get(klass, ()))
    lowered = blob.lower()
    for pattern, primitive in _KEYWORD_PRIMITIVES:
        if re.search(pattern, lowered):
            found.add(primitive)
    return found


def brain_primitives(brain) -> Dict[str, List[str]]:
    """Primitive -> ids of the proven hypotheses (or credentials) providing it."""
    held: Dict[str, List[str]] = {}
    for hyp in getattr(brain, "hypotheses", []) or []:
        if getattr(hyp, "status", "") != "proven":
            continue
        for primitive in primitives_from_text(f"{hyp.title} {hyp.evidence}"):
            held.setdefault(primitive, []).append(hyp.id)
    for index, cred in enumerate(getattr(brain, "credentials", []) or []):
        if getattr(cred, "valid_on", None):
            held.setdefault(CREDENTIAL, []).append(f"credential:{index}")
    return held


def evaluate_patterns(held: Iterable[str]) -> Tuple[List[ChainPattern], List[Tuple[ChainPattern, str]]]:
    have = set(held)
    complete, near = [], []
    for pattern in PATTERNS:
        missing = pattern.requires - have
        if not missing:
            complete.append(pattern)
        elif len(missing) == 1 and len(pattern.requires) > 1:
            near.append((pattern, next(iter(missing))))
    return complete, near


def queue_chain_hypotheses(brain, *, target: str = "") -> Dict[str, list]:
    """Add chain cards for satisfied patterns. Idempotent per pattern id."""
    from app.services.agent.engagement_brain import Hypothesis

    held = brain_primitives(brain)
    complete, near = evaluate_patterns(held)
    existing = {h.methodology_id for h in brain.hypotheses if h.source == "chain"}
    queued = []
    for pattern in complete:
        marker = f"primitive_chain:{pattern.id}"
        if marker in existing:
            continue
        parents = sorted({pid for p in pattern.requires for pid in held.get(p, [])})
        hyp = Hypothesis(
            id=f"chain-{uuid.uuid4().hex[:8]}",
            title=f"Chain: {pattern.impact}",
            assumption=("Proven capabilities " + " + ".join(sorted(pattern.requires))
                        + " combine into this impact."),
            test=pattern.test,
            pass_criteria=("Each step has its own execution receipt (evidence_id) and the "
                           "final step shows the impact on the target."),
            kill_criteria="Any step cannot be reproduced, or the impact is out of scope.",
            specialist=pattern.specialist,
            priority="high",
            target=target,
            evidence="Built from: " + ", ".join(parents),
            source="chain",
            parent_finding=",".join(parents)[:500],
            methodology_id=marker,
        )
        brain.hypotheses.append(hyp)
        queued.append(hyp)
    return {
        "primitives": {k: v[:5] for k, v in sorted(held.items())},
        "queued": queued,
        "one_step_away": [
            {"pattern": p.id, "impact": p.impact, "missing": missing,
             "have": sorted(p.requires - {missing})}
            for p, missing in near
        ],
    }
