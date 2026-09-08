"""Bounded, passive application operations from observed browser/HTTP traffic.

Protocol hints describe surfaces, never vulnerability evidence. Request values,
credentials and response bodies are deliberately excluded from the inventory.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qs, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

MAX_BODY = 262144
MAX_OPERATIONS = 1000


def stable_id(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:24]


def normalize_request(
    request: dict, *, identity: str = "anonymous", source: str = "runtime"
) -> list[dict]:
    url = urlsplit(str(request.get("url", "")))
    if (
        url.scheme not in ("http", "https", "ws", "wss")
        or not url.hostname
        or url.username
        or url.password
    ):
        return []
    try:
        port = url.port
    except ValueError:
        return []
    host = url.hostname.lower()
    authority = f"[{host}]" if ":" in host else host
    if port and port != (443 if url.scheme in ("https", "wss") else 80):
        authority += f":{port}"
    path = url.path or "/"
    endpoint = urlunsplit((url.scheme, authority, path, "", ""))
    method = str(request.get("method") or "GET").upper()
    headers = {
        str(k).lower(): str(v) for k, v in (request.get("headers") or {}).items()
    }
    content_type = headers.get("content-type", "").lower()
    query = parse_qs(url.query, keep_blank_values=True)
    parameters = {"query:" + key for key in query}
    body = request.get("body", request.get("post_data", "")) or ""
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    truncated = len(str(body)) > MAX_BODY
    body = str(body)[:MAX_BODY]
    try:
        parsed = json.loads(body) if body else {}
    except (ValueError, TypeError):
        parsed = {}
    operations = []
    if url.scheme in ("ws", "wss") or headers.get("upgrade", "").lower() == "websocket":
        operations = [("websocket", "connect", set(), "handshake_only")]
    elif "grpc-web" in content_type:
        operations = [
            ("grpc-web", path.rsplit("/", 1)[-1], set(), "method_only_no_descriptors")
        ]
    elif "soap" in content_type or "soapaction" in headers:
        action = headers.get("soapaction", "").strip('"')
        if (
            len(body) <= MAX_BODY
            and "<!DOCTYPE" not in body.upper()
            and "<!ENTITY" not in body.upper()
        ):
            try:
                root = ET.fromstring(body)
                soap_body = next(
                    (e for e in root.iter() if e.tag.rsplit("}", 1)[-1] == "Body"), None
                )
                if soap_body is not None and len(soap_body):
                    action = action or soap_body[0].tag
                    parameters.update(
                        "body:" + child.tag.rsplit("}", 1)[-1] for child in soap_body[0]
                    )
            except ET.ParseError:
                pass
        operations = [("soap", action or path, set(), "observed_envelope")]
    else:
        items = parsed if isinstance(parsed, list) else [parsed]
        for item in items[:100]:
            if not isinstance(item, dict):
                continue
            gql = item.get("query") or (query.get("query") or [""])[0]
            if not isinstance(gql, str) or not re.search(
                r"\b(query|mutation|subscription)\b|^\s*\{", gql
            ):
                continue
            match = re.search(r"\b(query|mutation|subscription)\s+(\w+)", gql)
            name = item.get("operationName") or (query.get("operationName") or [""])[0]
            name = name or (match.group(2) if match else "anonymous")
            # Preserve two different operations at the same /graphql endpoint, including anonymous operations.
            fingerprint = stable_id(gql)
            variables = item.get("variables") or {}
            keys = set(variables) if isinstance(variables, dict) else set()
            operations.append(
                (
                    "graphql",
                    f"{name}:{fingerprint}",
                    {"variable:" + k for k in keys},
                    "observed_query",
                )
            )
        if not operations:
            if isinstance(parsed, dict):
                parameters.update("body:" + key for key in parsed)
            if "application/x-www-form-urlencoded" in content_type:
                parameters.update(
                    "body:" + key for key in parse_qs(body, keep_blank_values=True)
                )
            operations = [("rest", method + " " + path, set(), "observed_request")]
    return [
        dict(
            id=stable_id(endpoint, method, protocol, operation),
            url=endpoint,
            host=host,
            path=path,
            method=method,
            protocol=protocol,
            operation=operation,
            parameters=sorted(parameters | extra),
            identities=[identity],
            sources=[source],
            fidelity=("truncated_body:" if truncated else "") + fidelity,
            discovery_only=True,
        )
        for protocol, operation, extra, fidelity in operations
    ]


def merge_operations(existing: list[dict], incoming: list[dict]) -> list[dict]:
    rows = {row["id"]: dict(row) for row in existing}
    for item in incoming:
        if item["id"] not in rows:
            if len(rows) < MAX_OPERATIONS:
                rows[item["id"]] = dict(item)
            continue
        row = rows[item["id"]]
        for key in ("identities", "sources", "parameters"):
            row[key] = sorted(set(row.get(key, [])) | set(item.get(key, [])))
    return list(rows.values())


def ingest_operations(
    brain, requests: list[dict], *, identity="anonymous", source="runtime"
) -> list[dict]:
    from app.services.agent.engagement_brain import Hypothesis
    from app.services.agent.penetration_task_graph import sync_graph_from_brain

    incoming = [
        op
        for req in requests[:MAX_OPERATIONS]
        if isinstance(req, dict)
        for op in normalize_request(req, identity=identity, source=source)
    ]
    brain.application_operations = merge_operations(
        brain.application_operations, incoming
    )
    known = {h.id for h in brain.hypotheses}
    for op in brain.application_operations:
        hid = "operation-" + op["id"]
        if hid in known:
            continue
        brain.hypotheses.append(
            Hypothesis(
                id=hid,
                title=f"Assess {op['protocol']} {op['method']} {op['path']}",
                assumption="Observed operation requires authorization and input-boundary assessment",
                test="Generate identity matrix; establish controlled objects and explicit access expectations",
                pass_criteria="Independent reproduction with a content or persisted-state proof",
                kill_criteria="Controlled test refutes this specific operation and identity hypothesis",
                specialist="auth_logic",
                target=op["url"],
                source="runtime",
                operation_id=op["id"],
            )
        )
    brain.task_graph = sync_graph_from_brain(brain).to_dict()
    return incoming
