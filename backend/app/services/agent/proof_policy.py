"""Minimum deterministic proof requirements, independent of hunter prompts."""

from __future__ import annotations

import json
import re


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


def validate_proof(
    store, candidate, proof: dict, evidence_ids: list[str]
) -> tuple[bool, str]:
    def row(key):
        artifact_id = proof.get(key)
        return store.records.get(artifact_id) if artifact_id in evidence_ids else None

    def successful(item):
        return bool(item and 200 <= item["payload"]["response"].get("status", 0) < 300)

    kind = proof.get("kind")
    if kind in ("numeric_boolean_sqli", "owner_only", "public_directory_index", "scoped_browser_xss"):
        hunter_id = proof.get("hunter_artifact_id")
        verifier = row("artifact_id")
        hunter = (store.records.get(hunter_id)
                  if isinstance(hunter_id, str) and hunter_id in (candidate.evidence_ids or []) else None)
        expected_kind = {
            "numeric_boolean_sqli": "scoped_numeric_sqli",
            "owner_only": "scoped_owner_only",
            "public_directory_index": "scoped_http_get",
            "scoped_browser_xss": "scoped_browser_check_xss",
        }[kind]
        if (not hunter or not verifier or hunter["id"] == verifier["id"]
                or hunter["kind"] != expected_kind or verifier["kind"] != expected_kind
                or hunter["created_at"] >= verifier["created_at"]):
            return False, "Distinct ordered hunter and verifier execution evidence is required"
        first, second = hunter["payload"], verifier["payload"]
        if hunter["target"] != verifier["target"] or hunter["target"] != candidate.target:
            return False, "Both actors must prove the same candidate target"
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
        if (first.get("operation") != second.get("operation")
                or first.get("operation") != "check_xss"
                or first.get("executed") is not True or second.get("executed") is not True
                or not first.get("nonce") or first.get("nonce") == second.get("nonce")
                or first.get("target_template") != second.get("target_template")):
            return False, "Two fresh browser execution nonces are required"
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
        return True, ""
    if kind == "response_match":
        item, marker = row("artifact_id"), proof.get("contains")
        claim = candidate.title + " " + candidate.description
        if re.search(
            r"(?i)xss|cross.?site.?script|ssrf|blind.?xxe|idor|bola|auth(?:entication|orization)?\s*(?:bypass|skip)|mass.?assignment|account.?takeover|account.?lookup|enumeration|settings.?write|cross.?(?:tenant|user)",
            claim,
        ):
            return (
                False,
                "This impact claim requires differential or state-change proof",
            )
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
