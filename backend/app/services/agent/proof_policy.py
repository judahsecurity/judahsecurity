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


def validate_proof(
    store, candidate, proof: dict, evidence_ids: list[str]
) -> tuple[bool, str]:
    def row(key):
        artifact_id = proof.get(key)
        return store.records.get(artifact_id) if artifact_id in evidence_ids else None

    def successful(item):
        return bool(item and 200 <= item["payload"]["response"].get("status", 0) < 300)

    kind = proof.get("kind")
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
        if b.get("url") != m.get("url") or b.get("method") != m.get("method"):
            return (
                False,
                "Replay the same protected object/action under both identities",
            )
        if not b.get("identity_verified") or (
            mutant["identity"] != "anonymous" and not m.get("identity_verified")
        ):
            return False, "Verify test identities before testing the boundary"
        bdata, mdata = _json(baseline), _json(mutant)
        if (
            field not in bdata
            or bdata[field] in (None, "")
            or mdata.get(field) != bdata[field]
        ):
            return (
                False,
                "Both responses must contain the same known protected object field",
            )
        if bdata[field] != b.get("principal_id"):
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
