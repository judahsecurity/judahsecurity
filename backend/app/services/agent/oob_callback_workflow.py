"""Correlated Interactsh workflow for custom HTTP probes.

Nuclei owns registration, payload placement, polling, and result correlation for
OAST templates. Custom verifier probes need the same lifecycle while retaining
the product agent's scope checks and execution-owned evidence records.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CALLBACK_PLACEHOLDER = "{{callback_url}}"


def _inject_callback(
    *,
    url: str,
    payload_url: str,
    location: str,
    field: str,
    headers: dict[str, str] | None,
    body: Any | None,
) -> tuple[str, dict[str, str], Any | None]:
    """Place one fresh callback URL into a bounded request shape."""
    location = (location or "query").strip().lower()
    field = (field or "").strip()
    request_headers = {str(k): str(v) for k, v in (headers or {}).items()}

    if location == "query":
        if not field:
            raise ValueError("field is required for query callback injection")
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        pairs = [(key, value) for key, value in pairs if key != field]
        pairs.append((field, payload_url))
        return (
            urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment)
            ),
            request_headers,
            body,
        )

    if location == "header":
        if not field:
            raise ValueError("field is required for header callback injection")
        request_headers[field] = payload_url
        return url, request_headers, body

    if location == "body_json":
        if not field:
            raise ValueError("field is required for JSON callback injection")
        data = json.loads(body) if isinstance(body, str) else dict(body or {})
        if not isinstance(data, dict):
            raise ValueError("body_json requires a JSON object")
        data[field] = payload_url
        request_headers.setdefault("Content-Type", "application/json")
        return url, request_headers, data

    if location == "body_form":
        if not field:
            raise ValueError("field is required for form callback injection")
        if isinstance(body, dict):
            pairs = [(str(key), str(value)) for key, value in body.items()]
        else:
            pairs = parse_qsl(str(body or ""), keep_blank_values=True)
        pairs = [(key, value) for key, value in pairs if key != field]
        pairs.append((field, payload_url))
        request_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return url, request_headers, urlencode(pairs)

    if location == "raw":
        raw = str(body or "")
        if CALLBACK_PLACEHOLDER not in raw:
            raise ValueError(
                f"raw callback bodies must contain {CALLBACK_PLACEHOLDER}"
            )
        return url, request_headers, raw.replace(CALLBACK_PLACEHOLDER, payload_url)

    raise ValueError("location must be query, header, body_json, body_form, or raw")


async def run_callback_workflow(
    manager: Any,
    *,
    url: str,
    method: str = "GET",
    location: str = "query",
    field: str = "url",
    headers: dict[str, str] | None = None,
    body: Any | None = None,
    identity: str | None = None,
    use_auth_session: bool = True,
    hypothesis_id: str = "",
    poll_attempts: int = 4,
    poll_interval_seconds: float = 2.0,
    server: str | None = None,
    token: str | None = None,
    keep_session: bool = False,
) -> dict[str, Any]:
    """Register, plant, poll, and return a verifier-ready OAST proof bundle."""
    from app.services import interactsh_service
    from app.services.agent.evidence_store import evidence_store, redact_artifact

    attempts = max(1, min(int(poll_attempts or 1), 8))
    interval = max(0.25, min(float(poll_interval_seconds or 0.25), 30.0 / attempts))
    store = evidence_store(manager)

    registration = await asyncio.to_thread(interactsh_service.register, server, token)
    if not registration.get("success"):
        return {
            "success": False,
            "error": registration.get("error") or "Interactsh registration failed",
            "callback_observed": False,
        }

    session_id = str(registration.get("session_id") or "")
    payload_url = str(registration.get("payload_url") or "")
    if not session_id or not payload_url:
        if session_id:
            await asyncio.to_thread(interactsh_service.stop, session_id)
        return {
            "success": False,
            "error": "Interactsh registration returned no session or payload URL",
            "callback_observed": False,
        }

    register_id = store.record(
        "oob_register", registration, target=url, hypothesis_id=hypothesis_id
    )
    try:
        request_url, request_headers, request_body = _inject_callback(
            url=url,
            payload_url=payload_url,
            location=location,
            field=field,
            headers=headers,
            body=body,
        )
        exchange = await manager._http_exchange(
            method=method,
            url=request_url,
            headers=request_headers,
            body=request_body,
            use_auth_session=use_auth_session,
            identity=identity,
            hypothesis_id=hypothesis_id,
            follow_redirects=False,
        )
    except Exception:
        await asyncio.to_thread(interactsh_service.stop, session_id)
        raise

    plant_id = exchange["evidence_id"]
    poll_ids: list[str] = []
    matched_poll_id = ""
    matched_poll: dict[str, Any] = {}
    for attempt in range(attempts):
        if attempt:
            await asyncio.sleep(interval)
        polled = await asyncio.to_thread(interactsh_service.poll, session_id)
        observed = bool(polled.get("success") and polled.get("interactions"))
        poll_id = store.record(
            "oob_poll",
            polled,
            target=url,
            hypothesis_id=hypothesis_id,
            success=observed,
        )
        poll_ids.append(poll_id)
        if observed:
            matched_poll_id = poll_id
            matched_poll = polled
            break

    if not keep_session:
        await asyncio.to_thread(interactsh_service.stop, session_id)

    proof = None
    if matched_poll_id:
        proof = {
            "kind": "oob_callback",
            "register_id": register_id,
            "plant_id": plant_id,
            "poll_id": matched_poll_id,
        }

    public_exchange = {
        "request": exchange.get("request"),
        "response": exchange.get("response"),
    }
    return {
        "success": True,
        "callback_observed": bool(matched_poll_id),
        "session_id": session_id if keep_session else None,
        "payload_domain": registration.get("payload_domain"),
        "evidence_ids": [register_id, plant_id, *poll_ids],
        "proof": proof,
        "request": redact_artifact(public_exchange),
        "interactions": redact_artifact(matched_poll.get("interactions") or []),
        "poll_attempts": len(poll_ids),
        "note": (
            "Pass evidence_ids and proof to record_verify_verdict."
            if proof
            else "No callback observed during the bounded polling window; keep the claim inconclusive."
        ),
    }
