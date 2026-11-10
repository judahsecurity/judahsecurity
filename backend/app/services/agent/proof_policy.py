"""Minimum deterministic proof requirements, independent of hunter prompts."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit


PROOF_GUIDANCE = """Evidence policy (applies to every product and specialist):
HTTP errors, schema fields, a version in range, and differing status codes are leads.
Do not label them demonstrated authorization bypass, mass assignment, or Critical.
Authorization requires distinct test identities accessing a known protected object.
State changes require a bounded canary write and an independent readback.
Account enumeration requires controlled existing/nonexisting accounts and a repeatable
difference; a single nonexistent-account response is inconclusive.
Severity follows demonstrated impact and preconditions; do not auto-escalate by keyword.
Keep observations, candidates, confirmed findings, refutations, and inconclusive tests distinct.
"""

# A proof recipe demonstrates a particular mechanism. A response containing a
# marker, for example, cannot establish SQL execution or an authorization bypass.
# Keep unsupported classes inconclusive until they have their own validator.
PROOFS_BY_CLASS = {
    "exposure": frozenset({"response_match", "public_directory_index"}),
    "sql_injection": frozenset({"numeric_boolean_sqli", "string_boolean_sqli", "string_error_sqli", "string_time_sqli", "string_union_sqli", "post_error_sqli", "post_boolean_sqli", "oob_callback"}),
    "xss": frozenset({"browser_xss", "scoped_browser_xss", "scoped_browser_form_xss", "scoped_browser_xhr_xss", "scoped_browser_stored_xss", "upload_xss"}),
    "authorization": frozenset({"authorization", "owner_only", "state_change", "workflow"}),
    "ssrf": frozenset({"oob_callback"}),
    "xxe": frozenset({"oob_callback"}),
    "crlf": frozenset({"scoped_response_crlf"}),
    "open_redirect": frozenset({"scoped_response_redirect"}),
    "cors": frozenset({"scoped_cors_credentialed"}),
    "race_condition": frozenset({"scoped_race_overrun"}),
    "dom_open_redirect": frozenset({"scoped_browser_client"}),
    "client_template_injection": frozenset({"scoped_browser_client"}),
    "client_prototype_pollution": frozenset({"scoped_browser_client"}),
    # Only an OOB callback that carries a shell-evaluated label; see validate_proof.
    "command_injection": frozenset({"oob_callback"}),
    "path_traversal": frozenset({"file_read"}),
    "csrf": frozenset({"csrf_state_change"}),
    "ssti": frozenset({"template_eval"}),
    "nosql_injection": frozenset({"nosql_operator"}),
    "known_cve": frozenset(),
    "account_enumeration": frozenset({"account_oracle"}),
}


def _post_xhr_match_valid(row: dict) -> bool:
    from app.services.agent.scoped_assessment.body_probe import VOLATILE_POST_FIELDS

    mode = row.get("xhr_body_match_mode", "exact")
    fields = row.get("xhr_volatile_fields") or []
    if mode == "exact":
        return fields == []
    return (mode == "volatile_fields" and isinstance(fields, list)
            and 1 <= len(fields) <= 3
            and all(isinstance(field, str)
                    and field.lower().replace("-", "_") in VOLATILE_POST_FIELDS
                    for field in fields)
            and len(fields) == len(set(fields)))

_CLAIM_PATTERNS = (
    ("ssti", r"\bSSTI\b|server[ -]?side template injection"),
    ("nosql_injection", r"\bNoSQL(?:i| injection)\b|\bMongo(?:DB)? (?:query |operator )?injection\b|"
     r"\bquery operator injection\b"),
    ("sql_injection", r"\bSQLi\b|\bSQL\s+injection\b"),
    ("xss", r"\bXSS\b|cross[ -]?site scripting|\bscript injection\b"),
    ("crlf", r"\bCRLF\b|\bresponse header injection\b|\bHTTP response splitting\b"),
    ("dom_open_redirect", r"\bDOM[ -]?based open redirect\b"),
    ("open_redirect", r"\bopen redirect\b"),
    ("cors", r"\bCORS\b|cross[- ]origin resource sharing|\bACAO\b|"
     r"access-control-allow-origin"),
    ("race_condition", r"\brace condition\b|\bTOCTOU\b|\bdouble[- ]spend\b|"
     r"\bconcurrenc(?:y|e) (?:bug|flaw|abuse)\b|\blimit overrun\b"),
    ("client_template_injection", r"\bclient[ -]?side template injection\b|\bCSTI\b"),
    ("client_prototype_pollution", r"\bclient[ -]?side prototype pollution\b"),
    ("ssrf", r"\bSSRF\b|server[ -]?side request forgery"),
    ("xxe", r"\bXXE\b|XML external entity"),
    ("command_injection", r"\b(?:OS|shell|command) injection\b|\bRCE\b|remote code execution"),
    ("path_traversal", r"\bpath traversal\b|\bdirectory traversal\b|\bLFI\b|local file inclusion"),
    ("csrf", r"\bCSRF\b|cross[ -]?site request forgery"),
    ("account_enumeration", r"\baccount enumeration\b|\buser enumeration\b"),
    ("authorization", r"\bIDOR\b|\bBOLA\b|\b(?:unauthorized|unauthenticated)\b.{0,50}"
     r"\b(?:mutation|write|update|change|access|action|request|operation)\b|"
     r"\bauthori[sz]ation bypass\b|\bauthentication bypass\b|\bcross[ -]?(?:tenant|user)\b|"
     r"\bmass assignment\b|\baccount takeover\b|\bprivilege escalation\b"),
    ("known_cve", r"\bCVE-\d{4}-\d{4,}\b|\bknown CVE\b"),
    ("exposure", r"\bexpos(?:ed|ure)\b|\bdisclos(?:ed|ure)\b|\bdirectory index\b|"
     r"\bdirectory listing\b|\bpublicly accessible\b"),
)


def inferred_vulnerability_class(candidate) -> str:
    """Infer only an obvious claim; ambiguous claims need an explicit class."""
    title = str(getattr(candidate, "title", "") or "")
    description = str(getattr(candidate, "description", "") or "")
    for source in (title, description):
        for name, pattern in _CLAIM_PATTERNS:
            if re.search(pattern, source, re.IGNORECASE):
                return name
    return ""


def proof_kind_allowed(candidate, kind: str) -> tuple[bool, str]:
    explicit = str(getattr(candidate, "vulnerability_class", "") or "").strip().lower()
    inferred = inferred_vulnerability_class(candidate)
    if explicit and explicit not in PROOFS_BY_CLASS:
        return False, f"Unsupported vulnerability class: {explicit}"
    if explicit and inferred and explicit != inferred:
        return False, f"Vulnerability class {explicit} conflicts with the {inferred} claim"
    claim_class = explicit or inferred
    if not claim_class:
        return False, "Specify a supported vulnerability class or an unambiguous claim"
    if kind not in PROOFS_BY_CLASS[claim_class]:
        return False, f"{kind or 'Missing proof'} cannot confirm {claim_class}; use a class-specific validator"
    return True, ""


def _json(row):
    try:
        value = json.loads(row["payload"]["response"].get("body") or "")
        return value if isinstance(value, dict) else {}
    except (ValueError, KeyError, TypeError):
        return {}


def _object_field(data: dict, path: str):
    """Read a named object field, including GraphQL data.node.ownerId paths."""
    if not isinstance(path, str) or not re.fullmatch(
        r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*){0,7}", path
    ):
        return None
    value = data
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            return None
        value = value[segment]
    return value


_SHELL_SUBSTITUTION = re.compile(r"\$\(|`")

# Files whose content has an unambiguous, non-secret-bearing signature. Each
# entry: (name the probe request must reference, content patterns that must
# all match). /etc/passwd lines carry no password hashes on modern systems.
FILE_READ_SIGNATURES = {
    "/etc/passwd": ("passwd", (re.compile(r"(?m)^root:[^:\n]*:0:0:"),)),
    "win.ini": ("win.ini", (re.compile(r"(?mi)^\[fonts\]"),
                            re.compile(r"(?mi)^\[extensions\]"))),
}
# A relative traversal, an absolute POSIX path given as a value, or a Windows path.
_TRAVERSAL = re.compile(r"\.\.[/\\]|[=:]\s*\"?/(?:etc|proc)/|[a-z]:[/\\]windows", re.IGNORECASE)


def _request_text(request: dict) -> str:
    """URL and body with up to three rounds of percent-decoding."""
    from urllib.parse import unquote

    text = f"{request.get('url') or ''}\n{request.get('body') or ''}"
    for _ in range(3):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


# Arithmetic inside a template delimiter: {{a*b}}, ${a*b}, <%= a*b %>, #{a*b},
# *{a*b}, @(a*b). The validator computes the product itself.
_TEMPLATE_EXPR = re.compile(
    r"(?:\{\{|\$\{|<%=?|#\{|\*\{|@\()\s*(\d{2,6})\s*\*\s*(\d{2,6})\s*(?:\}\}|\}|%>|\))"
)


def _template_eval_proof(candidate, baseline, probes: list) -> tuple[bool, str]:
    """Two template expressions evaluate server-side; the control shows neither product."""
    from app.services.agent.evidence_store import origin

    if not baseline or baseline.get("kind") != "http_exchange":
        return False, "template_eval needs a fresh control exchange with the ordinary value"
    if len(probes) < 2 or not all(p and p.get("kind") == "http_exchange" for p in probes):
        return False, "template_eval needs two fresh probe exchanges with different expressions"
    b_req = baseline["payload"].get("request", {})
    control_body = str(baseline["payload"].get("response", {}).get("body") or "")
    products = set()
    for probe in probes:
        p_req = probe["payload"].get("request", {})
        try:
            same = ((origin(p_req["url"]), urlsplit(p_req["url"]).path or "/")
                    == (origin(b_req["url"]), urlsplit(b_req["url"]).path or "/")
                    == (origin(candidate.target), urlsplit(candidate.target).path or "/"))
        except (KeyError, ValueError, TypeError):
            same = False
        if (not same or p_req.get("method") != b_req.get("method")
                or probe.get("identity") != baseline.get("identity")):
            return False, "Control and probes must hit the candidate endpoint with the same method and identity"
        text = _request_text(p_req)
        found = _TEMPLATE_EXPR.search(text)
        if not found:
            return False, "Each probe must carry a template arithmetic expression such as {{7919*13}}"
        product = str(int(found.group(1)) * int(found.group(2)))
        if len(product) < 5:
            return False, "Use operands whose product has at least five digits"
        if product in text:
            return False, "The product must not appear in the probe request"
        if product in control_body:
            return False, "The control response already contains the product"
        if product not in str(probe["payload"].get("response", {}).get("body") or ""):
            return False, f"The probe response does not contain the evaluated product {product}"
        products.add(product)
    if len(products) < 2:
        return False, "Use two different expressions so a coincidental number cannot confirm"
    return True, ""


_NOSQL_TRUE = re.compile(r"\$ne\b")
_NOSQL_FALSE = re.compile(r"\$eq\b")


def _nosql_operator_proof(candidate, true_rows: list, false_rows: list) -> tuple[bool, str]:
    """$ne and $eq against the same fresh value give consistently different answers.

    Nothing equals the fresh aegis-verify value, so {$eq: v} matches no record
    and {$ne: v} matches every record. If the requests differ only in that
    operator and the responses split, the application evaluated it as a query.
    """
    from app.services.agent.evidence_store import origin

    if len(true_rows) < 2 or len(false_rows) < 2 or not all(true_rows + false_rows):
        return False, "Cite at least two fresh $ne exchanges and two fresh $eq exchanges"
    rows = true_rows + false_rows
    if any(item.get("kind") != "http_exchange" for item in rows):
        return False, "NoSQL operator evidence must be HTTP exchanges"
    marker = "aegis-verify-" + candidate.nonce
    shapes = set()
    try:
        endpoint = (origin(candidate.target), urlsplit(candidate.target).path or "/")
        for index, item in enumerate(rows):
            req = item["payload"].get("request", {})
            text = _request_text(req)
            wanted, other = ((_NOSQL_TRUE, _NOSQL_FALSE) if index < len(true_rows)
                             else (_NOSQL_FALSE, _NOSQL_TRUE))
            if marker not in text or not wanted.search(text) or other.search(text):
                return False, ("True probes must use $ne and false probes $eq, each against "
                               "this candidate's aegis-verify value")
            if (origin(req["url"]), urlsplit(req["url"]).path or "/") != endpoint:
                return False, "Every NoSQL probe must hit the candidate endpoint"
            shapes.add((req.get("method"), item.get("identity"),
                        re.sub(r"\$(?:ne|eq)\b", "$op", text)))
    except (KeyError, ValueError, TypeError):
        return False, "NoSQL proof contains an invalid request URL"
    if len(shapes) != 1:
        return False, "The requests must be identical apart from the $ne/$eq operator"

    def fingerprint(item):
        status, body = _response_fingerprint(item, [marker])
        return status, re.sub(r"\$?\b(?:ne|eq)\b", "<op>", body)

    true_fp = {fingerprint(item) for item in true_rows}
    false_fp = {fingerprint(item) for item in false_rows}
    if len(true_fp) != 1 or len(false_fp) != 1:
        return False, "Responses are not stable within each operator group"
    if true_fp == false_fp:
        return False, "$ne and $eq get the same response, so the operator was not evaluated"
    t_times = [item["created_at"] for item in true_rows]
    f_times = [item["created_at"] for item in false_rows]
    if not (min(t_times) < max(f_times) and min(f_times) < max(t_times)):
        return False, "Interleave $ne and $eq probes so drift over time cannot explain the split"
    return True, ""


def _response_fingerprint(item: dict, identifiers: list[str]) -> tuple[int, str]:
    """Status plus body with the probed identifier and volatile values removed."""
    from urllib.parse import quote

    response = item["payload"].get("response", {})
    body = str(response.get("body") or "")
    for ident in identifiers:
        for form in {ident, quote(ident), quote(ident, safe="")}:
            body = re.sub(re.escape(form), "<account>", body, flags=re.IGNORECASE)
    body = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", body, flags=re.I)
    body = re.sub(r"[0-9a-f]{16,}", "<hex>", body, flags=re.I)
    body = re.sub(r"\d+", "<n>", body)
    return int(response.get("status") or 0), re.sub(r"\s+", " ", body).strip()[:4000]


def _account_oracle_proof(candidate, existing: str, existing_rows: list, missing_rows: list,
                          controlled: frozenset[str]) -> tuple[bool, str]:
    """A controlled account and fresh nonexistent accounts get consistently different answers."""
    from app.services.agent.evidence_store import origin

    if not existing or existing not in controlled:
        return False, ("existing_account must be the login of a verified test identity; "
                       "never probe real users")
    if len(existing_rows) < 2 or len(missing_rows) < 2 or not all(existing_rows + missing_rows):
        return False, "Cite at least two fresh exchanges for the existing account and two for missing ones"
    rows = existing_rows + missing_rows
    if any(item.get("kind") != "http_exchange" for item in rows):
        return False, "Account oracle evidence must be HTTP exchanges"
    marker = "aegis-verify-" + candidate.nonce
    texts = [_request_text(item["payload"].get("request", {})) for item in rows]
    if not all(existing in text.lower() for text in texts[:len(existing_rows)]):
        return False, "Each existing-account request must carry the controlled login"
    missing_ids = []
    for text in texts[len(existing_rows):]:
        found = re.search(re.escape(marker) + r"[\w.+@-]*", text)
        if not found or existing in text.lower():
            return False, "Each missing-account request must carry a fresh aegis-verify-<nonce> account"
        missing_ids.append(found.group(0))
    if len(set(missing_ids)) != len(missing_ids):
        return False, "Use a distinct nonexistent account in each missing-account request"
    first = rows[0]["payload"]["request"]
    try:
        endpoint = (origin(candidate.target), urlsplit(candidate.target).path or "/")
        shapes = set()
        for item, text in zip(rows, texts):
            req = item["payload"]["request"]
            if (origin(req["url"]), urlsplit(req["url"]).path or "/") != endpoint:
                return False, "Every account probe must hit the candidate endpoint"
            shape = re.sub(re.escape(marker) + r"[\w.+@-]*", "<account>", text)
            shapes.add((req.get("method"), item.get("identity"),
                        re.sub(re.escape(existing), "<account>", shape, flags=re.IGNORECASE)))
    except (KeyError, ValueError, TypeError):
        return False, "Account oracle proof contains an invalid request URL"
    if len(shapes) != 1 or not first:
        return False, "The requests must be identical apart from the account identifier"
    idents = [existing, *missing_ids]
    existing_fp = {_response_fingerprint(item, idents) for item in existing_rows}
    missing_fp = {_response_fingerprint(item, idents) for item in missing_rows}
    if len(existing_fp) != 1 or len(missing_fp) != 1:
        return False, "Responses are not stable within each group (rate limiting or volatile content)"
    if existing_fp == missing_fp:
        return False, "Existing and missing accounts get the same response"
    e_times = [item["created_at"] for item in existing_rows]
    m_times = [item["created_at"] for item in missing_rows]
    if not (min(e_times) < max(m_times) and min(m_times) < max(e_times)):
        return False, "Interleave existing and missing probes so drift over time cannot explain the split"
    return True, ""


_CSRF_TOKEN = re.compile(
    r"(?i)csrf|xsrf|authenticity_token|requestverificationtoken|anti.?forgery|(?:^|[&\"'\s{,])_token\b"
)


def _csrf_state_change_proof(candidate, rows: dict, value) -> tuple[bool, str]:
    """A browser-faithful cross-site write lands in the victim's account.

    write: cross_site replay for a named identity (only cross-site-eligible
    cookies, foreign Origin, no custom headers) that succeeds and carries the
    canary; control: the same request with no cookies is rejected, so the
    endpoint is not simply public; read: the victim's own session shows the
    canary; cleanup removes it.
    """
    from app.services.agent.cross_site import FOREIGN_ORIGIN, simple_request
    from app.services.agent.evidence_store import origin

    write, control, read, cleanup = (rows.get(k) for k in ("write", "control", "read", "cleanup"))
    if not all(item and item.get("kind") == "http_exchange"
               for item in (write, control, read, cleanup)):
        return False, "CSRF proof needs fresh write, no-cookie control, readback, and cleanup exchanges"
    wreq, creq = write["payload"]["request"], control["payload"]["request"]
    rreq, xreq = read["payload"]["request"], cleanup["payload"]["request"]

    def ok(item):
        return 200 <= int(item["payload"]["response"].get("status") or 0) < 300

    victim = write.get("identity")
    if victim in (None, "", "anonymous", "legacy") or not wreq.get("identity_verified"):
        return False, "The cross-site write must use a verified named victim identity"
    sent = wreq.get("cross_site_sent_names")
    if wreq.get("cross_site") is not True or not isinstance(sent, list) or not sent:
        return False, ("Send the write with cross_site=true; it must still carry a victim cookie "
                       "a browser would attach cross-site")
    if (wreq.get("headers") or {}).get("origin") != FOREIGN_ORIGIN:
        return False, "The cross-site write must present the foreign Origin"
    if not simple_request(wreq.get("method"), wreq.get("headers")):
        return False, ("The write needs a CORS preflight (method, content type, or header), "
                       "so a foreign page cannot send it")
    header_names = " ".join(str(name) for name in (wreq.get("headers") or {}))
    if _CSRF_TOKEN.search(str(wreq.get("body") or "")) or _CSRF_TOKEN.search(header_names):
        return False, "The write carries an anti-CSRF token, which a foreign page cannot read"
    if not isinstance(value, str) or value != "aegis-verify-" + candidate.nonce:
        return False, "Use this candidate's fresh aegis-verify canary value"
    if value not in str(wreq.get("body") or "") + str(wreq.get("url") or ""):
        return False, "The cross-site write must carry the canary"
    if not ok(write):
        return False, "The cross-site write was not accepted"
    try:
        target = (origin(candidate.target), urlsplit(candidate.target).path or "/")
        if (origin(wreq["url"]), urlsplit(wreq["url"]).path or "/") != target:
            return False, "The cross-site write must hit the candidate endpoint"
        if len({origin(r["url"]) for r in (wreq, creq, rreq, xreq)}) != 1:
            return False, "All CSRF proof requests must stay on one origin"
    except (KeyError, ValueError, TypeError):
        return False, "CSRF proof contains an invalid request URL"
    if (control.get("identity") != "anonymous" or creq.get("method") != wreq.get("method")
            or creq.get("url") != wreq.get("url")):
        return False, "The control must replay the same write with no cookies"
    redirected = (urlsplit(str(control["payload"]["response"].get("url") or "")).path
                  != urlsplit(creq["url"]).path)
    if ok(control) and not redirected:
        return False, "The write also succeeds with no session, so this is a public endpoint, not CSRF"
    if read.get("identity") != victim or rreq.get("method") != "GET" or rreq.get("cross_site"):
        return False, "Read the canary back with the victim's own session"
    if not ok(read) or value not in str(read["payload"]["response"].get("body") or ""):
        return False, "The victim's readback does not show the canary"
    if cleanup.get("identity") != victim or not ok(cleanup):
        return False, "A successful cleanup with the victim's session is required"
    if not write["created_at"] < read["created_at"] < cleanup["created_at"]:
        return False, "Readback and cleanup must follow the write in order"
    return True, ""


def _file_read_proof(candidate, baseline: dict | None, probe: dict | None,
                     file_name: str) -> tuple[bool, str]:
    """A traversal request returns a known file; a control on the same endpoint does not."""
    from app.services.agent.evidence_store import origin

    signature = FILE_READ_SIGNATURES.get(str(file_name or ""))
    if not signature:
        return False, ("file_read needs file: one of " + ", ".join(sorted(FILE_READ_SIGNATURES)))
    needle, patterns = signature
    if (not baseline or not probe or baseline.get("kind") != "http_exchange"
            or probe.get("kind") != "http_exchange"):
        return False, "file_read needs a fresh control exchange and a fresh traversal exchange"
    b_req, p_req = baseline["payload"].get("request", {}), probe["payload"].get("request", {})
    b_body = str(baseline["payload"].get("response", {}).get("body") or "")
    p_resp = probe["payload"].get("response", {})
    try:
        same_endpoint = (
            origin(b_req.get("url", "")) == origin(p_req.get("url", "")) == origin(candidate.target)
            and urlsplit(b_req.get("url", "")).path == urlsplit(p_req.get("url", "")).path
            == (urlsplit(candidate.target).path or "/")
        )
    except (AttributeError, ValueError, TypeError):
        same_endpoint = False
    if (not same_endpoint or b_req.get("method") != p_req.get("method")
            or baseline.get("identity") != probe.get("identity")):
        return False, "Control and traversal must hit the candidate endpoint with the same method and identity"
    probe_text, control_text = _request_text(p_req), _request_text(b_req)
    if needle not in probe_text.lower() or not _TRAVERSAL.search(probe_text):
        return False, f"The traversal request must contain a path sequence that names {file_name}"
    if needle in control_text.lower():
        return False, "The control request must use the ordinary value, not a file path"
    if not 200 <= int(p_resp.get("status") or 0) < 300:
        return False, "The traversal response was not successful"
    body = str(p_resp.get("body") or "")
    if not all(pattern.search(body) for pattern in patterns):
        return False, f"The traversal response does not contain {file_name} content"
    if any(pattern.search(b_body) for pattern in patterns):
        return False, "The control response already contains the file signature"
    return True, ""


def _command_execution_callback(
    proof: dict, request_text: str, domain: str, events: list,
) -> tuple[bool, str]:
    """Require a callback label that only shell evaluation could produce.

    A lookup of the canary domain alone also happens when an application
    legitimately resolves a supplied host (ping/webhook features) or when a
    proxy prefetches domains seen in traffic. The plant must compute a label
    with a shell substitution, for example ``$((7919*13))`` or
    ``$(echo 2k7sigea|rev)``, and the callback must carry the computed value,
    which never appears literally in the planted request.
    """
    label = str(proof.get("evaluated_label") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9]{4,32}", label):
        return False, ("Command injection needs proof.evaluated_label: the 4-32 character "
                       "label a shell substitution in the plant computes")
    if label in request_text.lower():
        return False, ("The evaluated label appears literally in the planted request; use an "
                       "expression whose output differs from its text, such as $((7919*13))")
    if not _SHELL_SUBSTITUTION.search(request_text):
        return False, "The plant must contain a $(...) or backtick substitution that computes the label"
    pattern = re.compile(
        r"(?<![a-z0-9-])" + re.escape(label) + r"\.(?:[a-z0-9-]+\.)*" + re.escape(domain.lower())
    )
    for event in events:
        seen = " ".join(str(event.get(key) or "")
                        for key in ("raw_request", "full_id", "unique_id")).lower()
        if event.get("protocol") in ("dns", "http") and pattern.search(seen):
            return True, ""
    return False, ("No callback carries the shell-evaluated label; a plain lookup of the "
                   "canary does not prove command execution")


def validate_proof(
    store, candidate, proof: dict, evidence_ids: list[str],
    *, controlled_accounts: frozenset[str] = frozenset(),
) -> tuple[bool, str]:
    def row(key):
        artifact_id = proof.get(key)
        return store.records.get(artifact_id) if artifact_id in evidence_ids else None

    def successful(item):
        return bool(item and 200 <= item["payload"]["response"].get("status", 0) < 300)

    kind = proof.get("kind")
    allowed, reason = proof_kind_allowed(candidate, kind)
    if not allowed:
        return False, reason
    if kind in ("numeric_boolean_sqli", "string_boolean_sqli", "string_error_sqli", "string_time_sqli", "string_union_sqli", "post_error_sqli", "post_boolean_sqli", "owner_only", "public_directory_index", "scoped_browser_xss", "scoped_browser_form_xss", "scoped_browser_xhr_xss", "scoped_browser_stored_xss", "scoped_response_crlf", "scoped_response_redirect", "scoped_cors_credentialed", "scoped_race_overrun", "scoped_browser_client"):
        hunter_id = proof.get("hunter_artifact_id")
        verifier = row("artifact_id")
        hunter = (store.records.get(hunter_id)
                  if isinstance(hunter_id, str) and hunter_id in (candidate.evidence_ids or []) else None)
        expected_kind = {
            "numeric_boolean_sqli": "scoped_numeric_sqli",
            "string_boolean_sqli": "scoped_string_sqli",
            "string_error_sqli": "scoped_string_sqli",
            "string_time_sqli": "scoped_string_sqli",
            "string_union_sqli": "scoped_string_sqli",
            "post_error_sqli": "scoped_body_sqli_error",
            "post_boolean_sqli": "scoped_body_sqli_boolean",
            "owner_only": "scoped_owner_only",
            "public_directory_index": "scoped_http_get",
            "scoped_browser_xss": "scoped_browser_check_xss",
            "scoped_browser_form_xss": "scoped_browser_check_form_xss",
            "scoped_browser_xhr_xss": "scoped_browser_check_xhr_xss",
            "scoped_browser_stored_xss": "scoped_browser_check_stored_xss",
            "scoped_response_crlf": "scoped_response_probe",
            "scoped_response_redirect": "scoped_response_probe",
            "scoped_cors_credentialed": "scoped_response_probe",
            "scoped_race_overrun": "scoped_race_probe",
            "scoped_browser_client": "scoped_browser_check_client",
        }[kind]
        if (not hunter or not verifier or hunter["id"] == verifier["id"]
                or hunter["kind"] != expected_kind or verifier["kind"] != expected_kind
                or hunter["created_at"] >= verifier["created_at"]):
            return False, "Distinct ordered hunter and verifier execution evidence is required"
        first, second = hunter["payload"], verifier["payload"]
        if hunter["target"] != verifier["target"] or hunter["target"] != candidate.target:
            return False, "Both actors must prove the same candidate target"
        if kind in {"numeric_boolean_sqli", "string_boolean_sqli", "string_error_sqli", "string_time_sqli", "string_union_sqli"} and (
            first.get("replay_mode") == "browser_live_get"
            or second.get("replay_mode") == "browser_live_get"
        ) and (
            first.get("replay_mode") != second.get("replay_mode")
            or not first.get("source_artifact_id")
            or first.get("source_artifact_id") != second.get("source_artifact_id")
        ):
            return False, "Independent browser GET replay must use the same observed request"
        if kind in {"scoped_response_crlf", "scoped_response_redirect", "scoped_cors_credentialed"}:
            expected_type = {
                "scoped_response_crlf": "crlf",
                "scoped_response_redirect": "open_redirect",
                "scoped_cors_credentialed": "cors",
            }[kind]
            signal = {"crlf": "header_marker", "open_redirect": "redirect_canary",
                      "cors": "cors_canary"}[expected_type]
            if (candidate.vulnerability_class != expected_type
                    or hunter["identity"] != verifier["identity"]
                    or first.get("operation") != "scoped_response_probe"
                    or second.get("operation") != "scoped_response_probe"
                    or first.get("test_type") != expected_type
                    or second.get("test_type") != expected_type
                    or not first.get("nonce") or first.get("nonce") == second.get("nonce")
                    or first.get("parameter") != second.get("parameter")
                    or first.get("request_context") != second.get("request_context")
                    or any(row.get("requests_sent") != 2
                           or row.get("proof_confirmed") is not True
                           or row.get("control", {}).get(signal) is not False
                           or row.get("probe", {}).get(signal) is not True
                           for row in (first, second))):
                return False, "Independent response-header, redirect, or CORS canary proof is required"
            return True, ""
        if kind == "scoped_race_overrun":
            if (candidate.vulnerability_class != "race_condition"
                    or hunter["identity"] != verifier["identity"]
                    or first.get("operation") != "scoped_race_probe"
                    or second.get("operation") != "scoped_race_probe"
                    or first.get("test_type") != "race_condition"
                    or second.get("test_type") != "race_condition"
                    or first.get("field") != second.get("field")
                    or any(row.get("proof_confirmed") is not True
                           or row.get("cleanup_confirmed") is not True
                           or row.get("control", {}).get("single_use_enforced") is not True
                           or row.get("control", {}).get("readback_count") != 1
                           or row.get("probe", {}).get("overrun") is not True
                           or int(row.get("probe", {}).get("readback_count") or 0) < 2
                           or int(row.get("probe", {}).get("successes") or 0) < 2
                           for row in (first, second))
                    # The two runs must use distinct nonce-bound canaries.
                    or first.get("probe", {}).get("canary") == second.get("probe", {}).get("canary")):
                return False, "Independent sequential-vs-concurrent overrun proof is required"
            return True, ""
        if kind == "scoped_browser_client":
            claim = candidate.vulnerability_class
            signal = {"dom_open_redirect": "blocked_marker_navigation",
                      "client_template_injection": "template_evaluated",
                      "client_prototype_pollution": "prototype_polluted"}.get(claim)
            if (not signal or hunter["identity"] != verifier["identity"]
                    or first.get("operation") != "check_client"
                    or second.get("operation") != "check_client"
                    or first.get("client_test_type") != claim
                    or second.get("client_test_type") != claim
                    or not first.get("nonce") or first.get("nonce") == second.get("nonce")
                    or first.get("target_template") != second.get("target_template")
                    or any(row.get("behavior_observed") is not True
                           or row.get("observations", {}).get("initial_document_ok") is not True
                           or row.get("observations", {}).get(signal) is not True
                           for row in (first, second))):
                return False, "Independent client-side browser behavior is required"
            if claim == "client_template_injection" and any(
                row.get("observations", {}).get("server_body_checked") is not True
                or row.get("observations", {}).get("server_template_evaluated") is not False
                for row in (first, second)
            ):
                return False, "Client template expression must execute after the HTTP response"
            return True, ""
        if kind == "numeric_boolean_sqli":
            from app.services.agent.scoped_assessment.sqli_boolean import numeric_sql_proof_valid
            if (not numeric_sql_proof_valid(first) or not numeric_sql_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first.get("nonce") == second.get("nonce")
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching numeric Boolean SQLi proof is required"
            return True, ""
        if kind == "string_boolean_sqli":
            from app.services.agent.scoped_assessment.sqli_string import string_sql_proof_valid
            same_recipe = first.get("proof_recipe") == second.get("proof_recipe")
            matching_keys = (
                ("baseline_first", "true_first", "false_first")
                if first.get("proof_recipe") == "string_and_boolean_v1" else
                ("baseline_first", "escaped_quote", "true_first", "false_first")
            )
            valid_first = string_sql_proof_valid(first)
            valid_second = string_sql_proof_valid(second)
            json_rows_match = (
                all(first["checks"][key].get("json_array_lengths")
                    == second["checks"][key].get("json_array_lengths")
                    for key in matching_keys)
                if first.get("proof_recipe") == "string_or_json_rows_v1"
                and second.get("proof_recipe") == "string_or_json_rows_v1"
                and valid_first and valid_second
                else first.get("proof_recipe") != "string_or_json_rows_v1"
            )
            if (not valid_first or not valid_second
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True):
                return False, "Independent matching string Boolean SQLi proof is required"
            if not same_recipe:
                return False, "Hunter and verifier used different SQLi proof recipes"
            if first.get("input_encoding", "plain") != second.get("input_encoding", "plain"):
                return False, "Hunter and verifier tested different query encodings"
            if not json_rows_match:
                return False, "Independent SQLi JSON result counts changed"
            if first.get("parameter") != second.get("parameter"):
                return False, "Independent SQLi probe tested a different parameter"
            if first.get("nonce") == second.get("nonce"):
                return False, "Independent SQLi probe reused the hunter nonce"
            if hunter["identity"] != verifier["identity"]:
                return False, "Independent SQLi probe used a different identity"
            # Each run already requires stable controls and a repeated Boolean
            # differential. Absolute HTML sizes can legitimately change between
            # runs as catalog content or page chrome changes; comparing them
            # across actors rejects a fresh, independently valid proof.
            return True, ""
        if kind == "string_error_sqli":
            from app.services.agent.scoped_assessment.sqli_string import string_error_proof_valid
            if (not string_error_proof_valid(first) or not string_error_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first["checks"]["quote_first"]["sql_error_family"]
                        != second["checks"]["quote_first"]["sql_error_family"]
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching SQL error proof is required"
            return True, ""
        if kind == "string_time_sqli":
            from app.services.agent.scoped_assessment.sqli_time import time_sql_proof_valid
            if (not time_sql_proof_valid(first) or not time_sql_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first.get("sql_family") != second.get("sql_family")
                    or first.get("input_encoding", "plain") != second.get("input_encoding", "plain")
                    or first.get("nonce") == second.get("nonce")
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching time-based SQLi proof is required"
            return True, ""
        if kind == "string_union_sqli":
            from app.services.agent.scoped_assessment.sqli_union import union_sql_proof_valid
            if (not union_sql_proof_valid(first) or not union_sql_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first.get("sql_family") != second.get("sql_family")
                    or first.get("column_count") != second.get("column_count")
                    or first.get("reflected_position") != second.get("reflected_position")
                    or first.get("input_encoding", "plain") != second.get("input_encoding", "plain")
                    or first.get("nonce") == second.get("nonce")
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching UNION SQLi proof is required"
            return True, ""
        if kind == "post_error_sqli":
            from app.services.agent.scoped_assessment.body_probe import post_sql_error_proof_valid
            if (not post_sql_error_proof_valid(first) or not post_sql_error_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first.get("proof_recipe") != second.get("proof_recipe")
                    or first.get("location") != second.get("location")
                    or first.get("source_artifact_id") != second.get("source_artifact_id")
                    or first.get("baseline_request_sha256") != second.get("baseline_request_sha256")
                    or first["checks"]["quote_first"]["sql_error_family"]
                        != second["checks"]["quote_first"]["sql_error_family"]
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching POST SQL error proof is required"
            return True, ""
        if kind == "post_boolean_sqli":
            from app.services.agent.scoped_assessment.body_probe import post_sql_boolean_proof_valid
            if (not post_sql_boolean_proof_valid(first) or not post_sql_boolean_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("parameter") != second.get("parameter")
                    or first.get("location") != second.get("location")
                    or first.get("source_artifact_id") != second.get("source_artifact_id")
                    or first.get("baseline_request_sha256") != second.get("baseline_request_sha256")
                    or first.get("nonce") == second.get("nonce")
                    or hunter["identity"] != verifier["identity"]):
                return False, "Independent matching POST Boolean proof with a fresh nonce is required"
            return True, ""
        if kind == "owner_only":
            from app.services.agent.scoped_assessment.authz_proof import owner_only_proof_valid
            if (not owner_only_proof_valid(first) or not owner_only_proof_valid(second)
                    or first.get("proof_confirmed") is not True
                    or second.get("proof_confirmed") is not True
                    or first.get("owner_identity") != second.get("owner_identity")
                    or first.get("other_identity") != second.get("other_identity")
                    or not first.get("captured_artifact_id")
                    or not second.get("captured_artifact_id")
                    or first["captured_artifact_id"] == second["captured_artifact_id"]):
                return False, "Independent owner-only proof with separate browser captures is required"
            return True, ""
        if kind == "public_directory_index":
            if (hunter["identity"] != verifier["identity"] or hunter["identity"] != "anonymous"
                    or first.get("target_template") != second.get("target_template")
                    or any(row.get("operation") != "http_get" or row.get("status") != 200
                           or row.get("content_type") != "text/html"
                           or row.get("directory_index") is not True
                           or row.get("truncated") is not False
                           or row.get("redirected") is not False for row in (first, second))):
                return False, "Two complete anonymous directory index observations are required"
            return True, ""
        expected_operation = {"scoped_browser_form_xss": "check_form_xss",
                              "scoped_browser_xhr_xss": "check_xhr_xss",
                              "scoped_browser_stored_xss": "check_stored_xss"}.get(kind, "check_xss")
        if (first.get("operation") != second.get("operation")
                or first.get("operation") != expected_operation
                or first.get("executed") is not True or second.get("executed") is not True
                or hunter["identity"] != verifier["identity"]
                or not first.get("nonce") or first.get("nonce") == second.get("nonce")
                or first.get("target_template") != second.get("target_template")):
            return False, "Two fresh browser execution nonces are required"
        if kind == "scoped_browser_form_xss" and (
            first.get("form_action") != candidate.target
            or second.get("form_action") != candidate.target
            or first.get("form_field") != second.get("form_field")
            or first.get("form_payload_template") != second.get("form_payload_template")
            or first.get("post_submitted") is not True
            or second.get("post_submitted") is not True
            or first.get("post_response_seen") is not True
            or second.get("post_response_seen") is not True
        ):
            return False, "Two matching approved POST form executions are required"
        if kind == "scoped_browser_xhr_xss" and (
            first.get("xhr_path") != urlsplit(candidate.target).path
            or second.get("xhr_path") != urlsplit(candidate.target).path
            or first.get("xhr_parameter") != second.get("xhr_parameter")
            or not first.get("xhr_parameter")
            or first.get("xhr_query_keys") != second.get("xhr_query_keys")
            or not isinstance(first.get("xhr_query_keys"), list)
            or first.get("xhr_method", "GET") != second.get("xhr_method", "GET")
            or (first.get("xhr_query_keys") != [] if first.get("xhr_method", "GET") == "POST"
                else first.get("xhr_parameter") not in first["xhr_query_keys"])
            or (first.get("xhr_method", "GET") == "POST" and (
                first.get("xhr_capture_id") != second.get("xhr_capture_id")
                or not first.get("xhr_capture_id")
                or first.get("xhr_body_location") != second.get("xhr_body_location")
                or first.get("xhr_body_location") not in {"body_form", "body_json"}
                or first.get("xhr_baseline_request_sha256") != second.get("xhr_baseline_request_sha256")
                or not first.get("xhr_baseline_request_sha256")
                or not all(_post_xhr_match_valid(row) for row in (first, second))
                or (first.get("xhr_body_match_mode") == second.get("xhr_body_match_mode") == "volatile_fields"
                    and first.get("xhr_volatile_fields") != second.get("xhr_volatile_fields"))
                or (candidate.parameter and candidate.parameter !=
                    f"{first.get('xhr_body_location')}:{first.get('xhr_parameter')}")
            ))
            or first.get("xhr_payload_template") != second.get("xhr_payload_template")
            or first.get("xhr_actions", []) != second.get("xhr_actions", [])
            or any(not isinstance(row.get("xhr_actions", []), list)
                   or len(row.get("xhr_actions", [])) > 6
                   or row.get("xhr_actions_replayed", 0) != len(row.get("xhr_actions", []))
                   for row in (first, second))
            or "__PROWL_NONCE__" not in str(first.get("xhr_payload_template") or "")
            or first.get("xhr_mutated") is not True
            or second.get("xhr_mutated") is not True
            or first.get("xhr_response_seen") is not True
            or second.get("xhr_response_seen") is not True
        ):
            return False, "Two matching rendered XHR executions are required"
        if kind == "scoped_browser_stored_xss" and (
            first.get("form_action") != candidate.target
            or second.get("form_action") != candidate.target
            or first.get("form_field") != second.get("form_field")
            or first.get("form_payload_template") != second.get("form_payload_template")
            or "__PROWL_NONCE__" not in str(first.get("form_payload_template") or "")
            or first.get("readback_url") != second.get("readback_url")
            or first.get("cleanup_url_template") != second.get("cleanup_url_template")
            or not first.get("readback_url") or not first.get("cleanup_url_template")
            or any(row.get("post_submitted") is not True
                   or row.get("post_response_seen") is not True
                   or row.get("readback_response_seen") is not True
                   or row.get("readback_final_exact") is not True
                   or not isinstance(row.get("readback_status"), int)
                   or not 200 <= row["readback_status"] < 300
                   or row.get("readback_executed") is not True
                   or row.get("cleanup_success") is not True
                   for row in (first, second))
        ):
            return False, "Two matching readback executions and successful cleanups are required"
        return True, ""
    if kind == "browser_xss":
        item = row("artifact_id")
        if not item or item["kind"] != "browser_xss":
            return False, "Browser execution evidence required"
        marker = "aegis-verify-" + candidate.nonce
        if item["payload"].get("alert_text") != marker or not item["payload"].get(
            "dialog_triggered"
        ):
            return (
                False,
                "A dialog with the fresh verifier canary must execute; reflection is only a lead",
            )
        return True, ""
    if kind == "upload_xss":
        upload, read, browser, cleanup = (
            row("upload_id"), row("read_id"), row("browser_id"), row("cleanup_id")
        )
        if (not successful(upload) or not successful(read) or not successful(cleanup)
                or not browser or browser.get("kind") != "browser_xss"):
            return False, "Upload, retrieval, browser execution, and cleanup evidence are required"
        if any(item.get("kind") != "http_exchange" for item in (upload, read, cleanup)):
            return False, "Upload, retrieval, and cleanup must be recorded HTTP exchanges"
        ureq, rreq, creq = (item["payload"]["request"] for item in (upload, read, cleanup))
        marker = "aegis-verify-" + candidate.nonce
        if (ureq.get("method") not in ("POST", "PUT") or rreq.get("method") != "GET"
                or creq.get("method") != "DELETE"):
            return False, "Expected upload, GET retrieval, and DELETE cleanup"
        if not upload["created_at"] < read["created_at"] < browser["created_at"] < cleanup["created_at"]:
            return False, "Upload, retrieval, execution, and cleanup must occur in order"
        if (marker not in str(ureq.get("body") or "")
                or marker not in str(read["payload"]["response"].get("body") or "")
                or browser["payload"].get("alert_text") != marker
                or not browser["payload"].get("dialog_triggered")):
            return False, "The uploaded verifier canary must be retrieved and execute in a browser"
        from app.services.agent.evidence_store import origin

        try:
            if (len({origin(ureq["url"]), origin(rreq["url"]), origin(creq["url"])}) != 1
                    or rreq["url"] != creq["url"]
                    or browser["payload"].get("url") != rreq["url"]):
                return False, "The browser and cleanup must target the uploaded same-origin object"
        except (KeyError, ValueError):
            return False, "Upload proof contains an invalid URL"
        if not re.search(r"(?i)upload|attachment|file", candidate.title + " " + candidate.description):
            return False, "Upload proof must match a file-upload claim"
        return True, ""
    if kind == "oob_callback":
        register, plant, poll = row("register_id"), row("plant_id"), row("poll_id")
        if (
            not register
            or not plant
            or not poll
            or register["kind"] != "oob_register"
            or plant["kind"] != "http_exchange"
            or poll["kind"] != "oob_poll"
        ):
            return (
                False,
                "Fresh registration, planted HTTP request, and callback poll are required",
            )
        r, p = register["payload"], poll["payload"]
        domain = r.get("payload_domain") or ""
        if r.get("reused") or not domain or r.get("session_id") != p.get("session_id"):
            return False, "Use a newly registered collaborator session"
        from app.services.agent.evidence_store import origin

        planted_url = plant["payload"].get("request", {}).get("url", "")
        try:
            if (origin(planted_url) != origin(candidate.target)
                    or urlsplit(planted_url).hostname == domain.lower()):
                return False, "Plant the callback URL in the candidate endpoint, not as the request destination"
        except (AttributeError, ValueError, TypeError):
            return False, "Callback proof requires a valid candidate endpoint"
        from urllib.parse import unquote

        request_text = unquote(json.dumps(plant["payload"]["request"]))
        if (
            domain not in request_text
            or not register["created_at"] < plant["created_at"] < poll["created_at"]
        ):
            return (
                False,
                "Callback must follow the planted payload from this registration",
            )
        events = p.get("interactions") or []
        if not any(
            e.get("protocol") in ("dns", "http", "smtp")
            and domain.split(".")[0] in str(e.get("unique_id") or "")
            for e in events
        ):
            return False, "No matching callback for this canary"
        claim_class = (getattr(candidate, "vulnerability_class", "")
                       or inferred_vulnerability_class(candidate))
        if claim_class == "command_injection":
            ok, why = _command_execution_callback(proof, request_text, domain, events)
            if not ok:
                return False, why
        if (getattr(candidate, "vulnerability_class", "") or inferred_vulnerability_class(candidate)) == "xxe":
            hunter_id = proof.get("hunter_artifact_id")
            hunter = (store.records.get(hunter_id)
                      if isinstance(hunter_id, str)
                      and hunter_id in (candidate.evidence_ids or []) else None)
            request = plant["payload"].get("request") or {}
            headers = {str(k).lower(): str(v).lower()
                       for k, v in (request.get("headers") or {}).items()}
            body = str(request.get("body") or "")
            xml_mime = headers.get("content-type", "").split(";", 1)[0]
            xml_request = (
                request.get("method") == "POST"
                and request.get("url") == candidate.target
                and (xml_mime in {"application/xml", "text/xml"}
                     or xml_mime.endswith("+xml"))
                and re.search(r"<!DOCTYPE\s+[A-Za-z_][\w:.-]*\s+\[", body)
                and re.search(r"<!ENTITY\s+prowl\s+SYSTEM\s+[\"'][^\"']*"
                              + re.escape(domain) + r"[^\"']*[\"']", body)
                and "&prowl;" in body
            )
            if (not hunter or hunter.get("kind") != "scoped_xml_xxe"
                    or hunter.get("target") != candidate.target
                    or hunter.get("identity") != plant.get("identity")
                    or hunter.get("created_at", 0) >= register.get("created_at", 0)
                    or hunter.get("payload", {}).get("callback_observed") is not True
                    or not xml_request):
                return False, "XXE requires an observed XML capture and a fresh external-entity callback"
        return True, ""
    if kind in ("template_eval", "nosql_operator"):
        def listed(key):
            ids = proof.get(key) if isinstance(proof.get(key), list) else []
            return [store.records.get(i) if i in evidence_ids else None for i in ids]
        if kind == "template_eval":
            return _template_eval_proof(candidate, row("baseline_id"), listed("artifact_ids"))
        return _nosql_operator_proof(candidate, listed("true_ids"), listed("false_ids"))
    if kind == "account_oracle":
        def rows_for(key):
            ids = proof.get(key) if isinstance(proof.get(key), list) else []
            return [store.records.get(i) if i in evidence_ids else None for i in ids]
        return _account_oracle_proof(
            candidate, str(proof.get("existing_account") or "").strip().lower(),
            rows_for("existing_ids"), rows_for("missing_ids"), controlled_accounts,
        )
    if kind == "csrf_state_change":
        return _csrf_state_change_proof(candidate, {
            "write": row("write_id"), "control": row("control_id"),
            "read": row("read_id"), "cleanup": row("cleanup_id"),
        }, proof.get("value"))
    if kind == "file_read":
        return _file_read_proof(candidate, row("baseline_id"), row("artifact_id"), proof.get("file"))
    if kind == "response_match":
        item, marker = row("artifact_id"), proof.get("contains")
        claim = candidate.title + " " + candidate.description
        if re.search(
            r"(?i)xss|cross.?site.?script|ssrf|xxe|idor|bola|sql.?injection|sqli|"
            r"(?:os|shell|command).?injection|\brce\b|path.?traversal|\blfi\b|"
            r"\bcsrf\b|\bcve-\d{4}-\d{4,}\b|"
            r"auth(?:entication|orization)?\s*(?:bypass|skip)|mass.?assignment|"
            r"account.?takeover|account.?lookup|enumeration|settings.?write|cross.?(?:tenant|user)",
            claim,
        ):
            return (
                False,
                "This impact claim requires differential or state-change proof",
            )
        if item:
            request, response = item["payload"].get("request", {}), item["payload"].get("response", {})
            headers = {str(name).lower() for name in (request.get("headers") or {})}
            if (item.get("kind") != "http_exchange" or item.get("identity") != "anonymous"
                    or request.get("method") != "GET"
                    or request.get("url") != response.get("url")
                    or headers & {"authorization", "cookie", "proxy-authorization", "x-api-key"}):
                return False, "Exposure requires a direct anonymous GET observation"
        if successful(item) and isinstance(marker, str) and len(marker.strip()) >= 12:
            if marker in item["payload"]["response"].get("body", ""):
                return True, ""
        return (
            False,
            "Cite a substantial literal observation from the successful response",
        )
    if kind == "authorization":
        baseline, mutant = row("baseline_id"), row("mutant_id")
        field = proof.get("field")
        if not successful(baseline) or not successful(mutant) or not field:
            return (
                False,
                "Two successful identity-specific responses and an object field are required",
            )
        b, m = baseline["payload"]["request"], mutant["payload"]["request"]
        if baseline["identity"] == mutant["identity"] or "legacy" in (
            baseline["identity"],
            mutant["identity"],
        ):
            return False, "Use two distinct explicit identities"
        if (b.get("url") != m.get("url") or b.get("method") != m.get("method")
                or b.get("body") != m.get("body")):
            return (
                False,
                "Replay the same protected object/action under both identities",
            )
        if not b.get("identity_verified") or (
            mutant["identity"] != "anonymous" and not m.get("identity_verified")
        ):
            return False, "Verify test identities before testing the boundary"
        bdata, mdata = _json(baseline), _json(mutant)
        owner = _object_field(bdata, field)
        if (
            owner in (None, "")
            or _object_field(mdata, field) != owner
        ):
            return (
                False,
                "Both responses must contain the same known protected object field",
            )
        if owner != b.get("principal_id"):
            return (
                False,
                "The ownership field must identify the verified owner principal",
            )
        if mutant["identity"] != "anonymous" and b.get("principal_id") == m.get(
            "principal_id"
        ):
            return False, "Both sessions represent the same principal"
        return True, ""
    if kind == "state_change":
        write, read, cleanup = row("write_id"), row("read_id"), row("cleanup_id")
        field, value = proof.get("field"), proof.get("value")
        if not successful(write) or not successful(read):
            return False, "A successful canary write and readback are required"
        if not successful(cleanup):
            return False, "A successful cleanup request is required for state-change proof"
        wreq, rreq = write["payload"]["request"], read["payload"]["request"]
        creq = cleanup["payload"]["request"]
        if (
            wreq.get("method") not in ("POST", "PUT", "PATCH")
            or rreq.get("method") != "GET"
            or creq.get("method") not in ("DELETE", "PUT", "PATCH")
        ):
            return False, "Expected a mutation, readback, and cleanup"
        if not write["created_at"] < read["created_at"] < cleanup["created_at"]:
            return False, "Readback and cleanup must follow the write in order"
        if (
            not isinstance(value, str)
            or value != "aegis-verify-" + candidate.nonce
        ):
            return False, "Use this candidate's fresh aegis-verify canary value"
        if (
            value not in str(wreq.get("body", ""))
            or not field
            or _json(read).get(field) != value
        ):
            return False, "The written canary must round-trip in the readback field"
        from app.services.agent.evidence_store import origin

        try:
            if len({origin(wreq["url"]), origin(rreq["url"]), origin(creq["url"])}) != 1:
                return False, "Write, readback, and cleanup must remain on one origin"
        except (KeyError, ValueError):
            return False, "State-change proof contains an invalid request URL"
        claim = f"{candidate.title} {candidate.description}".lower()
        actor = write.get("identity")
        if actor == "legacy":
            return False, "State-change proof requires an explicit identity"
        if actor == "anonymous":
            if not re.search(r"unauthenticated|without auth|anonymous|public write", claim):
                return False, "Anonymous state change must match an unauthenticated-write claim"
        else:
            owner = proof.get("owner_identity")
            if not owner or owner == actor or read.get("identity") != owner:
                return False, "Cross-identity state change requires a distinct owner readback"
            if not wreq.get("identity_verified") or not rreq.get("identity_verified"):
                return False, "Verify both state-change identities first"
            if wreq.get("principal_id") == rreq.get("principal_id"):
                return False, "Actor and owner sessions represent the same principal"
            if not re.search(
                r"cross.?user|cross.?tenant|idor|bola|authorization|mass.?assignment|other user",
                claim,
            ):
                return False, "Cross-identity proof must match an authorization-boundary claim"
        return True, ""
    return False, "Unsupported proof kind; keep this candidate inconclusive"
