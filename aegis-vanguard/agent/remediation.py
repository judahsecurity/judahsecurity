"""
Remediation advisor — the finding→fix half of Raptor, in our idiom.

Raptor confirms whether a finding is real and then generates proof-of-concept
code *and patches*. We already own the "is it real" half (validate_finding.py,
the /triage gate, confirm_vulnerability_poc). What was missing is the
defensive, ASM-aligned half: turning a confirmed finding into an actionable,
methodology-grounded remediation instead of the reporter's generic per-category
boilerplate.

This is deliberately *deep, not broad*: a curated CWE-keyed knowledge base of
web vulnerability classes, each carrying a root cause, concrete fix steps, a
correct-by-construction secure pattern, a verification step, and references —
the kind of guidance a senior tester writes, encoded once. A classifier maps a
finding onto a class; ``advise()`` renders the remediation and enriches it with
the finding's own endpoint and any matching prior-art reference.

Consumers:
  * ``suggest_remediation`` (@security_tool in agent/agents.py) so the ReAct
    agent and report agent can request a fix for any confirmed finding.
  * The reporter's per-finding remediation section.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent.remediation")


# ---------------------------------------------------------------------------
# Remediation knowledge base — one curated entry per vulnerability class.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FixTemplate:
    vuln_class: str
    cwe_id: str
    cwe_name: str
    root_cause: str
    fix_steps: List[str]
    secure_pattern: str          # short correct-by-construction snippet
    verification: str            # how to confirm the fix holds
    references: List[str]


# Order matters for the classifier: more specific classes are matched first.
_KB: Dict[str, FixTemplate] = {
    "sqli": FixTemplate(
        "sqli", "CWE-89", "SQL Injection",
        "User-controlled input is concatenated into a SQL statement, so the "
        "input can alter the query's structure rather than only its data.",
        [
            "Use parameterized queries / prepared statements for every query "
            "that touches user input — never string-format SQL.",
            "Where an ORM is available, use its parameter binding; avoid raw "
            "query escapes.",
            "Apply allow-list validation to identifiers that can't be "
            "parameterized (column/table names, ORDER BY direction).",
            "Run the app's DB account with least privilege (no DDL, no "
            "cross-database access).",
        ],
        "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
        "Re-issue the original payload and a boolean/time pair; the response "
        "must no longer differ on the injected condition.",
        ["OWASP SQL Injection Prevention Cheat Sheet", "CWE-89"],
    ),
    "xss": FixTemplate(
        "xss", "CWE-79", "Cross-Site Scripting",
        "Untrusted input is reflected into an HTML/JS context without "
        "context-appropriate output encoding.",
        [
            "Encode output for the exact sink context (HTML body, attribute, "
            "JS string, URL) at render time.",
            "Prefer a framework that auto-escapes by default; treat any "
            "raw/dangerouslySetInnerHTML sink as a review gate.",
            "Deploy a strict Content-Security-Policy (nonce/hash based, no "
            "'unsafe-inline') as defense in depth.",
            "Set HttpOnly on session cookies so script cannot read them.",
        ],
        "element.textContent = userInput;  // not .innerHTML",
        "Re-inject the reflection payload; it must render as inert text and no "
        "script must execute (confirm in a real browser).",
        ["OWASP XSS Prevention Cheat Sheet", "CWE-79"],
    ),
    "ssrf": FixTemplate(
        "ssrf", "CWE-918", "Server-Side Request Forgery",
        "The server fetches a URL derived from user input, letting an attacker "
        "reach internal services or cloud metadata.",
        [
            "Allow-list the exact hosts/schemes the feature legitimately needs; "
            "reject everything else.",
            "Resolve the hostname and block private, loopback, link-local and "
            "cloud-metadata ranges (169.254.169.254, 100.100.100.200) — after "
            "resolution, to defeat DNS rebinding.",
            "Disable unneeded URL schemes (file:, gopher:, dict:).",
            "Send outbound fetches through an egress proxy with its own "
            "allow-list; strip credentials from redirects.",
        ],
        "if resolved_ip not in ALLOWED or is_private(resolved_ip): reject()",
        "Point the parameter at an internal/metadata address and a collaborator "
        "host; both must be refused with no outbound request made.",
        ["OWASP SSRF Prevention Cheat Sheet", "CWE-918"],
    ),
    "idor": FixTemplate(
        "idor", "CWE-639", "Insecure Direct Object Reference / Broken Object-Level Authorization",
        "An object identifier from the request is trusted without checking that "
        "the caller is authorized for that specific object.",
        [
            "Enforce an object-level authorization check on every request, "
            "server-side, using the session identity — not a client-supplied "
            "owner id.",
            "Scope every data query by the authenticated principal "
            "(WHERE owner_id = :session_user).",
            "Prefer unguessable, non-sequential identifiers, but treat that as "
            "defense in depth, never the control itself.",
        ],
        "row = db.get(obj_id); assert row.owner_id == session.user_id",
        "Authenticate as user A and request user B's object id; the response "
        "must be 403/404, not B's data.",
        ["OWASP Access Control Cheat Sheet", "CWE-639", "OWASP API1:2023 BOLA"],
    ),
    "csrf": FixTemplate(
        "csrf", "CWE-352", "Cross-Site Request Forgery",
        "A state-changing request is accepted on the basis of ambient "
        "credentials (cookies) alone, so another origin can forge it.",
        [
            "Require a per-session, per-form anti-CSRF token on every "
            "state-changing request and verify it server-side.",
            "Set SameSite=Lax or Strict on session cookies.",
            "For APIs, require a custom header the browser only sends "
            "same-origin, and verify Origin/Referer.",
        ],
        "SameSite=Strict; + verify request.csrf_token == session.csrf_token",
        "Replay the form from a foreign origin without the token; it must be "
        "rejected.",
        ["OWASP CSRF Prevention Cheat Sheet", "CWE-352"],
    ),
    "open_redirect": FixTemplate(
        "open_redirect", "CWE-601", "Open Redirect",
        "A redirect target is taken from user input without validation, "
        "enabling phishing and OAuth token theft.",
        [
            "Redirect only to an allow-list of internal paths or vetted hosts.",
            "Accept a relative path or an opaque key that maps server-side to a "
            "URL — never the raw URL from the request.",
            "Reject absolute URLs, protocol-relative (//evil), and userinfo "
            "tricks.",
        ],
        "target = ALLOWED_PATHS.get(key, '/'); redirect(target)",
        "Set the redirect param to an external host; the app must not navigate "
        "off-origin.",
        ["OWASP Unvalidated Redirects Cheat Sheet", "CWE-601"],
    ),
    "rce": FixTemplate(
        "rce", "CWE-78", "OS Command Injection / Remote Code Execution",
        "User input reaches a shell or code evaluator, letting an attacker run "
        "arbitrary commands.",
        [
            "Never pass user input to a shell; call binaries directly with an "
            "argument array and no shell interpolation.",
            "Allow-list the specific operations/arguments the feature needs.",
            "Remove eval/exec of dynamic input entirely; redesign around a safe "
            "API.",
            "Run the process with least privilege and in a sandbox.",
        ],
        "subprocess.run([\"ping\", \"-c\", \"1\", host], shell=False)",
        "Re-send the command-separator payload; injected commands must not "
        "execute (no OOB callback, no timing shift).",
        ["OWASP Command Injection Prevention Cheat Sheet", "CWE-78"],
    ),
    "path_traversal": FixTemplate(
        "path_traversal", "CWE-22", "Path Traversal",
        "A file path built from user input escapes the intended directory via "
        "../ sequences or absolute paths.",
        [
            "Resolve the requested path and verify it stays within the intended "
            "base directory (canonicalize, then prefix-check).",
            "Map user input to an allow-listed key rather than a raw filename.",
            "Reject path separators and encoded traversal sequences.",
        ],
        "p = (BASE / name).resolve(); assert str(p).startswith(str(BASE))",
        "Request ../../etc/passwd (and encoded variants); all must be denied.",
        ["OWASP Path Traversal Cheat Sheet", "CWE-22"],
    ),
    "ssti": FixTemplate(
        "ssti", "CWE-1336", "Server-Side Template Injection",
        "User input is evaluated as part of a server-side template, exposing "
        "the template engine's execution context.",
        [
            "Never build templates from user input; pass user data only as "
            "rendering variables.",
            "Use a logic-less or sandboxed template engine for any "
            "user-influenced template.",
        ],
        "render_template('page.html', name=user_input)  # data, not template",
        "Re-send the polynomial probe ({{7*7}} / ${7*7}); it must render "
        "literally, not as 49.",
        ["PortSwigger SSTI", "CWE-1336"],
    ),
    "xxe": FixTemplate(
        "xxe", "CWE-611", "XML External Entity",
        "An XML parser resolves external entities from untrusted documents, "
        "enabling file read and SSRF.",
        [
            "Disable DTDs and external entity resolution in the XML parser.",
            "Prefer a data format without entity expansion (JSON) where "
            "possible.",
        ],
        "parser.setFeature('http://apache.org/xml/features/disallow-doctype-decl', True)",
        "Submit a document with an external entity; it must not be resolved or "
        "reflected.",
        ["OWASP XXE Prevention Cheat Sheet", "CWE-611"],
    ),
    "deserialization": FixTemplate(
        "deserialization", "CWE-502", "Insecure Deserialization",
        "Untrusted data is deserialized into live objects, allowing gadget "
        "chains and code execution.",
        [
            "Do not deserialize untrusted input with native object "
            "serializers (pickle, Java serialization, PHP unserialize).",
            "Use a data-only format (JSON) with an explicit schema.",
            "If native serialization is unavoidable, sign the payload and "
            "verify before deserializing.",
        ],
        "json.loads(data)  # not pickle.loads(data)",
        "Re-send the crafted serialized object; no gadget should execute.",
        ["OWASP Deserialization Cheat Sheet", "CWE-502"],
    ),
    "cors": FixTemplate(
        "cors", "CWE-942", "Overly Permissive CORS",
        "The CORS policy reflects arbitrary origins (or uses '*') together with "
        "credentials, exposing authenticated data cross-origin.",
        [
            "Reflect only an allow-list of trusted origins; never echo the "
            "request Origin blindly.",
            "Never combine Access-Control-Allow-Credentials: true with a "
            "wildcard or reflected origin.",
            "Scope allowed methods/headers to the minimum required.",
        ],
        "if origin in ALLOWED_ORIGINS: resp['Access-Control-Allow-Origin']=origin",
        "Send Origin: https://evil.example; the response must not grant it with "
        "credentials.",
        ["OWASP CORS guidance", "CWE-942"],
    ),
    "security_headers": FixTemplate(
        "security_headers", "CWE-693", "Missing Security Headers",
        "Protective response headers are absent, weakening defense in depth "
        "against transport downgrade, clickjacking, and MIME sniffing.",
        [
            "Add Strict-Transport-Security with a long max-age and "
            "includeSubDomains.",
            "Add a strict Content-Security-Policy.",
            "Add X-Content-Type-Options: nosniff and a frame-ancestors CSP "
            "directive (or X-Frame-Options).",
        ],
        "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
        "Re-fetch and confirm each header is present with the intended value.",
        ["OWASP Secure Headers Project", "CWE-693"],
    ),
    "tls": FixTemplate(
        "tls", "CWE-326", "Weak TLS Configuration",
        "The endpoint negotiates legacy protocols or weak ciphers, exposing "
        "traffic to downgrade and interception.",
        [
            "Disable TLS 1.0/1.1 and SSLv3; serve TLS 1.2+ only.",
            "Restrict to strong AEAD cipher suites; disable RC4/3DES/export "
            "ciphers.",
            "Deploy HSTS and renew certificates before expiry.",
        ],
        "ssl_protocols TLSv1.2 TLSv1.3;  # nginx",
        "Re-grade with testssl.sh / tlsx; the grade must be A- or better with "
        "no legacy protocol offered.",
        ["Mozilla TLS config generator", "CWE-326"],
    ),
    "subdomain_takeover": FixTemplate(
        "subdomain_takeover", "CWE-350", "Subdomain Takeover",
        "A DNS record points at a deprovisioned third-party service an attacker "
        "can claim.",
        [
            "Remove the dangling DNS record, or reclaim the target service "
            "immediately.",
            "Add DNS hygiene checks to decommissioning runbooks so records are "
            "retired with the service.",
        ],
        "# delete the CNAME to the unclaimed *.service.example target",
        "Re-resolve the record; it must no longer point at an unclaimed "
        "provider endpoint.",
        ["OWASP Subdomain Takeover", "CWE-350"],
    ),
    "secrets_exposure": FixTemplate(
        "secrets_exposure", "CWE-200", "Sensitive Data / Secret Exposure",
        "Secrets or sensitive files are reachable over the web (e.g. .git, "
        ".env, API keys in JS).",
        [
            "Remove the exposed path from the web root and block it at the "
            "server/CDN.",
            "Treat any exposed secret as compromised — rotate it now.",
            "Move secrets to a secrets manager; keep them out of the repo and "
            "client bundles.",
        ],
        "location ~ /\\.(git|env) { deny all; }  # nginx",
        "Re-request the path (must be 403/404) and confirm the leaked "
        "credential has been rotated.",
        ["OWASP Secrets Management Cheat Sheet", "CWE-200"],
    ),
    "default_credentials": FixTemplate(
        "default_credentials", "CWE-1392", "Use of Default Credentials",
        "A service is reachable with shipped default credentials.",
        [
            "Change the default credentials immediately and enforce a strong "
            "password policy.",
            "Restrict the admin interface to trusted networks / VPN.",
            "Enable MFA on privileged accounts.",
        ],
        "# rotate admin:admin → a strong unique secret; scope access by network",
        "Retry the default login; it must fail, and the interface must not be "
        "publicly reachable.",
        ["CWE-1392", "OWASP Authentication Cheat Sheet"],
    ),
    "auth": FixTemplate(
        "auth", "CWE-287", "Broken Authentication",
        "The authentication mechanism can be bypassed, brute-forced, or its "
        "tokens abused.",
        [
            "Enforce server-side session/token validation on every protected "
            "route.",
            "Rate-limit and lock out credential stuffing; add MFA.",
            "Use vetted session management; rotate identifiers on privilege "
            "change and logout.",
        ],
        "require_auth(); assert token.valid and not token.expired",
        "Re-run the bypass path; access to protected resources must require "
        "valid authentication.",
        ["OWASP Authentication Cheat Sheet", "CWE-287"],
    ),
    "jwt": FixTemplate(
        "jwt", "CWE-347", "Improper JWT Verification",
        "JWTs are accepted without proper signature/claim verification "
        "(alg:none, key confusion, unchecked exp/aud).",
        [
            "Pin the expected algorithm; reject 'none' and unexpected algs.",
            "Verify the signature against the correct key and validate exp, "
            "aud, and iss.",
            "Do not trust claims (roles, user id) without server-side checks.",
        ],
        "jwt.decode(tok, key, algorithms=['RS256'], audience=AUD)",
        "Replay an alg:none / tampered token; it must be rejected.",
        ["OWASP JWT Cheat Sheet", "CWE-347"],
    ),
    "file_upload": FixTemplate(
        "file_upload", "CWE-434", "Unrestricted File Upload",
        "Uploaded files are accepted and served without adequate type/location "
        "controls, enabling web-shell or content abuse.",
        [
            "Allow-list content types by verified magic bytes, not the "
            "client-supplied extension or MIME.",
            "Store uploads outside the web root and serve them via a handler "
            "that sets a safe Content-Type and Content-Disposition.",
            "Randomize stored filenames; strip execute permissions.",
        ],
        "assert sniff_magic(bytes) in ALLOWED; store_outside_webroot(rand_name)",
        "Re-upload a polyglot/script file; it must be rejected or served inert "
        "and non-executable.",
        ["OWASP File Upload Cheat Sheet", "CWE-434"],
    ),
    "host_header": FixTemplate(
        "host_header", "CWE-644", "Host Header Injection",
        "The app trusts the Host header for absolute URLs, cache keys, or "
        "password-reset links, enabling poisoning.",
        [
            "Validate the Host header against an allow-list of expected "
            "domains; reject others.",
            "Build absolute URLs from server config, not the request Host.",
            "Set an explicit server_name/default vhost that rejects unknown "
            "hosts.",
        ],
        "if request.host not in ALLOWED_HOSTS: abort(400)",
        "Send a spoofed Host; generated links / cache keys must not reflect it.",
        ["PortSwigger Host header attacks", "CWE-644"],
    ),
    "business_logic": FixTemplate(
        "business_logic", "CWE-840", "Business Logic Flaw",
        "A workflow can be driven into an unintended state (negative amounts, "
        "step-skipping, race conditions) because invariants aren't enforced "
        "server-side.",
        [
            "Enforce every business invariant server-side (amounts, quantities, "
            "state transitions, ownership).",
            "Make multi-step flows resistant to reordering and replay; validate "
            "the whole transition, not each step in isolation.",
            "Guard shared-state operations against races with atomic "
            "operations / locking.",
        ],
        "assert amount > 0 and state_transition_allowed(cur, next)",
        "Re-run the abuse sequence; the illegal state must now be rejected.",
        ["OWASP Business Logic Testing", "CWE-840"],
    ),
}


# ---------------------------------------------------------------------------
# Classifier — map a finding onto a KB class from its type/category/title.
# ---------------------------------------------------------------------------

# (vuln_class, keyword-tokens). First class whose token matches wins; ordered
# most-specific first so "sql injection" beats a bare "injection".
_CLASS_KEYWORDS: List[tuple] = [
    ("sqli", ("sqli", "sql injection", "sql-injection", "sqlmap")),
    ("ssti", ("ssti", "template injection")),
    ("xxe", ("xxe", "xml external", "external entity")),
    ("deserialization", ("deserial", "insecure deserialization", "pickle", "gadget")),
    ("rce", ("rce", "command injection", "os command", "remote code", "code exec")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting", "dom xss")),
    ("ssrf", ("ssrf", "server-side request", "server side request")),
    ("idor", ("idor", "bola", "object-level", "object level", "broken object",
              "authorization", "authz", "access control", "privilege")),
    ("csrf", ("csrf", "cross-site request", "cross site request")),
    ("open_redirect", ("open redirect", "open-redirect", "unvalidated redirect")),
    ("path_traversal", ("path traversal", "directory traversal", "lfi",
                        "local file inclusion", "file read")),
    ("jwt", ("jwt", "json web token", "alg none", "alg:none")),
    ("file_upload", ("file upload", "unrestricted upload", "web shell", "webshell")),
    ("host_header", ("host header", "host-header")),
    ("cors", ("cors", "cross-origin resource")),
    ("subdomain_takeover", ("takeover", "dangling", "subdomain takeover")),
    ("default_credentials", ("default credential", "default-login", "default login",
                             "default password")),
    ("secrets_exposure", ("secret", "api key", "api-key", ".env", ".git",
                          "credential leak", "exposed", "exposure", "disclosure",
                          "information disclosure", "sensitive data")),
    ("tls", ("tls", "ssl", "cipher", "certificate", "hsts downgrade")),
    ("security_headers", ("security header", "missing header", "csp", "clickjack",
                          "x-frame", "content-security-policy", "hsts")),
    ("auth", ("auth bypass", "authentication", "broken auth", "login bypass",
              "session")),
    ("business_logic", ("business logic", "race condition", "logic flaw",
                        "workflow", "price manipulation")),
]


def classify(finding: Dict[str, Any]) -> Optional[str]:
    """Return the KB class for a finding, or None if nothing matches."""
    hay = " ".join(
        str(finding.get(k, "")) for k in
        ("vuln_type", "type", "category", "subcategory", "title", "name",
         "template_id", "template-id")
    ).lower()
    if not hay.strip():
        return None
    for vuln_class, tokens in _CLASS_KEYWORDS:
        if any(tok in hay for tok in tokens):
            return vuln_class
    return None


# ---------------------------------------------------------------------------
# Advisor
# ---------------------------------------------------------------------------

# Generic fallback when the class is unknown — still useful, never a blank.
_FALLBACK = FixTemplate(
    "generic", "CWE-707", "Improper Neutralization / Missing Control",
    "The finding indicates untrusted input or an unenforced control reaching a "
    "sensitive operation.",
    [
        "Validate and canonicalize all untrusted input against an allow-list "
        "at the trust boundary.",
        "Enforce authorization server-side on every sensitive operation.",
        "Apply output encoding / safe APIs appropriate to the sink.",
        "Fail closed and log the rejection.",
    ],
    "# validate at the boundary; enforce authz server-side; use safe sinks",
    "Re-run the exact reproduction from the finding; it must now be rejected.",
    ["OWASP Top 10", "OWASP ASVS"],
)


@dataclass
class Remediation:
    finding_title: str
    endpoint: str
    severity: str
    vuln_class: str
    cwe_id: str
    cwe_name: str
    root_cause: str
    fix_steps: List[str]
    secure_pattern: str
    verification: str
    references: List[str] = field(default_factory=list)
    matched: bool = True         # False when the generic fallback was used

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_title": self.finding_title,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "vuln_class": self.vuln_class,
            "cwe": {"id": self.cwe_id, "name": self.cwe_name},
            "root_cause": self.root_cause,
            "fix_steps": self.fix_steps,
            "secure_pattern": self.secure_pattern,
            "verification": self.verification,
            "references": self.references,
            "matched": self.matched,
        }

    def to_markdown(self) -> str:
        lines = [
            f"### Remediation — {self.finding_title or self.cwe_name}",
            f"**{self.cwe_id}: {self.cwe_name}**"
            + (f"  ·  `{self.endpoint}`" if self.endpoint else "")
            + (f"  ·  severity: {self.severity}" if self.severity else ""),
            "",
            f"**Root cause.** {self.root_cause}",
            "",
            "**Fix.**",
        ]
        lines += [f"{i}. {s}" for i, s in enumerate(self.fix_steps, 1)]
        lines += [
            "",
            "**Secure pattern.**",
            f"```\n{self.secure_pattern}\n```",
            "",
            f"**Verify.** {self.verification}",
        ]
        if self.references:
            lines += ["", "**References.** " + " · ".join(self.references)]
        return "\n".join(lines)


def advise(finding: Dict[str, Any]) -> Remediation:
    """Build a structured remediation for a (confirmed) finding dict.

    Accepts the finding shapes the fireteam and reporter use: keys like
    ``title``/``name``, ``vuln_type``/``type``/``category``, ``severity``,
    ``url``/``endpoint``/``matched_at``.
    """
    vuln_class = classify(finding)
    tmpl = _KB.get(vuln_class) if vuln_class else None
    matched = tmpl is not None
    if tmpl is None:
        tmpl = _FALLBACK

    endpoint = (
        finding.get("endpoint")
        or finding.get("url")
        or finding.get("matched_at")
        or finding.get("matched-at")
        or ""
    )
    references = list(tmpl.references)
    ref = _prior_art_reference(vuln_class or "", finding)
    if ref:
        references.append(ref)

    return Remediation(
        finding_title=finding.get("title") or finding.get("name") or "",
        endpoint=endpoint,
        severity=str(finding.get("severity") or "").lower(),
        vuln_class=tmpl.vuln_class,
        cwe_id=tmpl.cwe_id,
        cwe_name=tmpl.cwe_name,
        root_cause=tmpl.root_cause,
        fix_steps=list(tmpl.fix_steps),
        secure_pattern=tmpl.secure_pattern,
        verification=tmpl.verification,
        references=references,
        matched=matched,
    )


def _prior_art_reference(vuln_class: str, finding: Dict[str, Any]) -> str:
    """Best-effort: name a matching prior-art technique so the fix cites the
    same knowledge base the hunters used. Never fatal if the KB is absent."""
    try:
        from agent import prior_art
    except Exception:
        return ""
    query = " ".join(
        str(finding.get(k, "")) for k in ("vuln_type", "type", "title", "name")
    ).strip() or vuln_class
    if not query:
        return ""
    try:
        hits = prior_art.search(query, top_k=1)
    except Exception:
        return ""
    if hits:
        h = hits[0]
        return f"prior-art:{h.get('id', '?')} ({h.get('name', '')})"
    return ""


def advise_json(finding_json: str) -> str:
    """String in / string out helper for the @security_tool wrapper."""
    try:
        finding = json.loads(finding_json)
    except (json.JSONDecodeError, TypeError) as exc:
        return json.dumps({"error": f"invalid finding JSON: {exc}"})
    if not isinstance(finding, dict):
        return json.dumps({"error": "finding must be a JSON object"})
    return json.dumps(advise(finding).to_dict(), default=str)


__all__ = [
    "FixTemplate",
    "Remediation",
    "classify",
    "advise",
    "advise_json",
]
