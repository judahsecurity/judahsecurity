"""Object-reference (IDOR / BOLA) lead extraction from value-free captured traffic.

Leads only. A lead is a captured endpoint that carries an object identifier and
is therefore a *candidate* for operator-declared cross-identity replay. It is not
a finding and never a proof. Confirming a lead still requires an operator to
declare the exact resource and two named test identities, then run
``scoped_owner_only`` (read) or ``scoped_owner_only_write`` (write) and pass the
independent verifier gate. Nothing in this module reaches the network, mutates
state, reads request/response values, or escalates a lead to evidence.

This mirrors the request metadata that also appears in the optional Caido
analyst view, but Prowl's own value-free capability map and capture receipts are
the source of truth: a lead is derived only from input locations, paths, methods,
and identity labels that are already in the agent-visible ledger.
"""

from __future__ import annotations

import re

# A path segment that is a bare positive integer is an enumerable object id.
_NUMERIC_SEGMENT = re.compile(r"[1-9][0-9]{0,17}\Z")
# RFC 4122-shaped identifiers and other opaque handles observed in REST paths.
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_MONGO_OBJECTID = re.compile(r"[0-9a-fA-F]{24}\Z")
_LONG_HEX = re.compile(r"[0-9a-fA-F]{32,64}\Z")
# Parameter names that commonly carry an object reference even when the value
# itself was not observed as an integer (e.g. a slug, a hashed id, a uuid body).
_ID_NAME = re.compile(
    r"(?:^|[_\-./])(?:id|ids|uid|guid|uuid|pk|ref|key|slug|handle|number|no|num|"
    r"account|acct|customer|client|tenant|org|organisation|organization|company|"
    r"user|member|owner|profile|order|invoice|payment|transaction|txn|cart|"
    r"booking|reservation|ticket|case|record|object|entity|resource|document|"
    r"doc|file|upload|attachment|image|photo|folder|project|workspace|team|"
    r"group|role|node|item|product|sku|post|comment|message|thread|conversation|"
    r"session|device|subscription|plan|address|card)(?:[_\-./]?id|_?no|_?num)?\Z",
    re.I,
)
_ID_LOCATIONS = {"query", "form", "body_json", "body_form", "body_xml"}
MAX_LEADS = 200
# Methods whose cross-identity misuse is a read-style vs write-style IDOR.
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _segment_kind(segment: str) -> str:
    """Classify one concrete path segment as an object-id shape, or ''."""
    if _NUMERIC_SEGMENT.fullmatch(segment):
        return "numeric"
    if _UUID.fullmatch(segment):
        return "uuid"
    if _MONGO_OBJECTID.fullmatch(segment):
        return "objectid"
    if _LONG_HEX.fullmatch(segment):
        return "opaque"
    return ""


def _name_kind(value_type: str, name: str) -> str:
    """Classify a query/body parameter as an object reference, or ''."""
    if value_type == "positive_integer":
        return "numeric"
    tail = name.rsplit("/", 1)[-1] if name.startswith("/") else name
    return "name_hint" if _ID_NAME.search(tail) else ""


def _template_path(path: str) -> tuple[str, list[dict]]:
    """Return a ``{id}``-templated path and the id segments it carried.

    The concrete path already appears in the value-free ledger; templating only
    groups ``/users/1`` and ``/users/2`` into one enumerable-object lead.
    """
    if not path.startswith("/"):
        return path, []
    segments = path.split("/")
    ids: list[dict] = []
    for index, segment in enumerate(segments):
        kind = _segment_kind(segment) if segment else ""
        if not kind:
            continue
        collection = ""
        for prior in range(index - 1, 0, -1):
            if segments[prior] and not _segment_kind(segments[prior]):
                collection = segments[prior]
                break
        ids.append({"position": index, "kind": kind, "collection": collection})
        segments[index] = "{id}"
    return "/".join(segments), ids


def _merge(leads: dict, key: tuple, builder) -> None:
    lead = leads.get(key)
    if lead is None:
        if len(leads) >= MAX_LEADS:
            return
        leads[key] = builder()
    else:
        identity = builder().get("_identity")
        if identity and identity not in lead["identities_observed"]:
            lead["identities_observed"].append(identity)


def identifier_leads(inventory_rows: list[dict] | None,
                     observed_endpoints: list[dict] | None = None) -> list[dict]:
    """Derive IDOR/BOLA replay candidates from value-free observations.

    ``inventory_rows`` are rows from ``collect_parameter_inventory`` (method,
    host, path, name, location, value_type, identity, testable). ``observed_endpoints``
    is an optional list of ``{method, path, identity}`` for endpoints that had no
    parameter row (e.g. ``GET /api/users/42`` with no query string). Only inputs
    that are testable (not CSRF/session/token-like) become leads.
    """
    leads: dict[tuple, dict] = {}
    endpoints: dict[tuple[str, str], set[str]] = {}

    def note_endpoint(method: str, path: str, identity: str) -> None:
        endpoints.setdefault((method, path), set()).add(identity or "anonymous")

    for row in inventory_rows or []:
        if not isinstance(row, dict):
            continue
        method = str(row.get("method") or "GET").upper()
        path = row.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        identity = str(row.get("identity") or "anonymous")[:80]
        note_endpoint(method, path, identity)
        location = row.get("location")
        name = row.get("name")
        if (location not in _ID_LOCATIONS or not isinstance(name, str)
                or not row.get("testable", True)):
            continue
        kind = _name_kind(str(row.get("value_type") or ""), name)
        if not kind:
            continue
        where = "query" if location == "query" else "body"
        key = (method, path, where, name)
        _merge(leads, key, lambda m=method, p=path, w=where, n=name, k=kind, i=identity: {
            "method": m,
            "path": p,
            "path_template": p,
            "identifier": {"location": w, "name": n, "position": None, "kind": k},
            "collection": "",
            "identities_observed": [i],
            "enumerable": k == "numeric",
            "access": "write" if m in _WRITE_METHODS else "read",
            "rationale": f"{w} parameter {n!r} carries an object reference ({k}); "
                         "replay across two identities to check object-level authorization.",
            "lead_only": True,
            "_identity": i,
        })

    for endpoint in observed_endpoints or []:
        if not isinstance(endpoint, dict):
            continue
        method = str(endpoint.get("method") or "GET").upper()
        path = endpoint.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        note_endpoint(method, path, str(endpoint.get("identity") or "anonymous")[:80])

    for (method, path), identities in endpoints.items():
        template, ids = _template_path(path)
        for id_segment in ids:
            key = (method, template, "path", id_segment["position"])
            observed = sorted(identities)
            _merge(leads, key, lambda m=method, t=template, seg=id_segment,
                   obs=observed, concrete=path: {
                "method": m,
                "path": concrete,
                "path_template": t,
                "identifier": {"location": "path", "name": "",
                               "position": seg["position"], "kind": seg["kind"]},
                "collection": seg["collection"],
                "identities_observed": list(obs),
                "enumerable": seg["kind"] == "numeric",
                "access": "write" if m in _WRITE_METHODS else "read",
                "rationale": f"path segment #{seg['position']} is an object id "
                             f"({seg['kind']}" + (f", collection {seg['collection']!r}"
                             if seg["collection"] else "") + "); replay across two "
                             "identities to check object-level authorization.",
                "lead_only": True,
                "_identity": "",
            })

    ordered = sorted(
        leads.values(),
        key=lambda lead: (
            0 if lead["access"] == "write" else 1,   # write-style IDOR first
            0 if lead["enumerable"] else 1,           # enumerable ids first
            -len(lead["identities_observed"]),        # seen under more identities
            lead["path_template"],
        ),
    )
    for lead in ordered:
        lead.pop("_identity", None)
    return ordered[:MAX_LEADS]


def summarize_leads(leads: list[dict]) -> dict:
    """A small, value-free rollup for the agent and the operator."""
    return {
        "lead_count": len(leads),
        "write_access_count": sum(1 for lead in leads if lead["access"] == "write"),
        "enumerable_count": sum(1 for lead in leads if lead["enumerable"]),
        "note": ("Leads are replay candidates only. Confirming object-level "
                 "authorization still requires an operator-declared resource, two "
                 "named identities, and the owner-only proof plus verifier gate."),
    }
