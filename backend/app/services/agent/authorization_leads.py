"""Authorization leads without query or body values from owned captures.

These observations prioritize review. They never imply a deny policy or prove
that a reference belongs to a protected object.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

_OBJECT_NAME = re.compile(
    r"(?:^id$|(?:^|[_\[.])id(?:$|\])|uuid|object|record|item|user|account|"
    r"tenant|org|order|invoice|project|owner|document|file|photo|ticket|profile)",
    re.IGNORECASE,
)
_RESOURCE = re.compile(
    r"^(?:users?|accounts?|tenants?|orgs?|organizations?|objects?|orders?|records?|"
    r"items?|invoices?|projects?|documents?|files?|photos?|tickets?|profiles?)$",
    re.IGNORECASE,
)
_LOW_SIGNAL = re.compile(
    r"^(?:page|limit|offset|sort|filter|search|q|view|locale|lang)$", re.IGNORECASE
)
_STATIC = frozenset(
    {"api", "v1", "v2", "v3", "new", "edit", "list", "search", "me", "self", "current"}
)
_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.IGNORECASE,
)
_HEX = re.compile(r"[0-9a-f]{16,64}\Z", re.IGNORECASE)


def _shape(value: str) -> str:
    if value.isdecimal() and len(value) <= 20:
        return "numeric"
    if _UUID.fullmatch(value):
        return "uuid"
    if _HEX.fullmatch(value):
        return "opaque_hex"
    return "string"


def _lead_id(capture_id: str, reference: str, path_index: int | None) -> str:
    key = f"{capture_id}:{reference}:{path_index}"
    return "authz-lead-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def leads_for_capture(capture: dict) -> list[dict]:
    """Return bounded reference locations, never query values or request bodies."""
    spec = capture["request"]
    parts = urlsplit(spec["url"])
    base_url = urlunsplit(parts._replace(query="", fragment=""))
    common = {
        "capture_id": capture["id"],
        "operation_id": capture["operation_id"],
        "owner_identity": capture["identity"],
        "method": spec["method"],
    }
    leads = []
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    for name in sorted({name for name, value in pairs if value}):
        values = [value for key, value in pairs if key == name]
        name_hint = bool(_OBJECT_NAME.search(name))
        shape = _shape(values[0])
        score = (3 if name_hint else 0) + (2 if shape != "string" else 0)
        if _LOW_SIGNAL.fullmatch(name):
            score = max(0, score - 2)
        reference = "query:" + name
        leads.append(
            {
                **common,
                "id": _lead_id(capture["id"], reference, None),
                "target": base_url,
                "reference": reference,
                "matrix_parameter": reference,
                "path_index": None,
                "value_shape": shape,
                "priority_score": score,
                "replayable": len(values) == 1,
                "reason": "object-like field" if name_hint else "observed query field",
            }
        )
    segments = parts.path.split("/")
    for index, raw in enumerate(segments):
        value = unquote(raw)
        if index == 0 or not value or value.lower() in _STATIC:
            continue
        shape = _shape(value)
        resource_hint = index > 0 and bool(_RESOURCE.fullmatch(segments[index - 1]))
        if shape == "string" and (not resource_hint or len(value) < 2):
            continue
        if shape == "string" and not re.fullmatch(r"[A-Za-z0-9_.~-]{2,80}", value):
            continue
        score = (3 if resource_hint else 0) + (2 if shape != "string" else 0)
        reference = "path:" + str(index)
        template = list(segments)
        template[index] = "{{object_id}}"
        leads.append(
            {
                **common,
                "id": _lead_id(capture["id"], reference, index),
                "target": urlunsplit(
                    parts._replace(path="/".join(template), query="", fragment="")
                ),
                "reference": reference,
                "matrix_parameter": "",
                "path_index": index,
                "value_shape": shape,
                "priority_score": score,
                "replayable": True,
                "reason": "resource path segment"
                if resource_hint
                else "identifier-shaped path segment",
            }
        )
    return sorted(leads, key=lambda row: (-row["priority_score"], row["reference"]))[:8]


def rank_leads(captures: list[dict]) -> list[dict]:
    """Keep the newest active capture for each operation, owner and reference."""
    unique = {}
    for capture in captures:
        for lead in leads_for_capture(capture):
            key = (lead["operation_id"], lead["owner_identity"], lead["reference"])
            unique[key] = lead
    return sorted(
        unique.values(),
        key=lambda row: (
            -row["priority_score"],
            row["method"],
            row["target"],
            row["reference"],
        ),
    )


def handoff_report(leads: list[dict], brain, plans: dict) -> dict:
    """Join leads to explicit policy and execution state without inventing access rules."""
    matrix = getattr(brain, "authorization_matrix", []) or []
    counts = {
        "candidates": len(leads),
        "replayable": 0,
        "needs_policy": 0,
        "blocked": 0,
        "policy_set": 0,
        "proof_prepared": 0,
        "proof_attempted": 0,
        "independently_confirmed": 0,
    }
    result = []
    for lead in leads:
        row = dict(lead)
        if not row["replayable"]:
            status, next_action = "blocked", "Select an unambiguous observed reference"
        else:
            counts["replayable"] += 1
            matches = [
                cell
                for cell in matrix
                if cell.get("operation_id") == row["operation_id"]
                and cell.get("parameter", "") == row["matrix_parameter"]
                and cell.get("identity") != row["owner_identity"]
                and cell.get("expected") == "deny"
            ]
            verified = [
                cell for cell in matches if cell.get("verifier_verdict") == "confirmed"
            ]
            attempted = [cell for cell in matches if cell.get("proof_run_id")]
            prepared = [cell for cell in matches if cell.get("hypothesis_id") in plans]
            ready = [cell for cell in matches if cell.get("status") != "blocked"]
            if verified:
                status, next_action = (
                    "independently_confirmed",
                    "Review the verified finding",
                )
            elif attempted:
                status, next_action = (
                    "proof_attempted",
                    "Review the proof verdict and independent verification",
                )
            elif prepared:
                status, next_action = (
                    "proof_prepared",
                    "Run the registered authorization proof",
                )
            elif ready:
                status, next_action = (
                    "policy_set",
                    "Prepare a controlled fresh-object proof",
                )
            elif matches:
                status, next_action = "blocked", "Verify the distinct test identity"
            else:
                status, next_action = (
                    "needs_policy",
                    "Establish owner, other identity and expected deny policy",
                )
            row["hypothesis_ids"] = [cell["hypothesis_id"] for cell in matches[:5]]
        row["status"] = status
        row["next_action"] = next_action
        counts[status] += 1
        result.append(row)
    order = {
        "policy_set": 0,
        "proof_prepared": 1,
        "needs_policy": 2,
        "blocked": 3,
        "proof_attempted": 4,
        "independently_confirmed": 5,
    }
    result.sort(
        key=lambda row: (order[row["status"]], -row["priority_score"], row["reference"])
    )
    return {"summary": counts, "leads": result}
