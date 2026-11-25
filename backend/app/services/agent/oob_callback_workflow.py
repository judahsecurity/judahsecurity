"""Correlated out-of-band callback workflow for custom HTTP probes.

Nuclei owns registration, payload placement, polling, and result correlation for
OAST templates. Custom verifier probes need the same lifecycle while retaining
the product agent's scope checks and execution-owned evidence records.

The callback collector (Interactsh by default, or an operator's self-hosted
HTTP-poll collector) comes from operator settings via ``oob_collectors``; the
agent cannot select it. Every call registers a fresh callback host, so one
registration maps to exactly one planted probe.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

CALLBACK_PLACEHOLDER = "{{callback_url}}"
CALLBACK_HOST_PLACEHOLDER = "{{callback_host}}"
_TEMPLATE_LOCATIONS = ("query", "header", "body_json", "body_form")


def _apply_placeholders(text: str, payload_url: str, payload_host: str) -> str:
    return text.replace(CALLBACK_PLACEHOLDER, payload_url).replace(
        CALLBACK_HOST_PLACEHOLDER, payload_host,
    )


def _inject_callback(
    *,
    url: str,
    payload_url: str,
    location: str,
    field: str,
    headers: dict[str, str] | None,
    body: Any | None,
    payload_host: str = "",
    value_template: str = "",
) -> tuple[str, dict[str, str], Any | None]:
    """Place one fresh callback URL into a bounded request shape.

    ``value_template`` (server-owned, e.g. a JNDI lookup) replaces the plain
    callback URL as the injected value for query/header/body_json/body_form.
    """
    location = (location or "query").strip().lower()
    field = (field or "").strip()
    request_headers = {str(k): str(v) for k, v in (headers or {}).items()}
    if value_template:
        if location not in _TEMPLATE_LOCATIONS:
            raise ValueError("payload templates inject into query, header, body_json, or body_form")
        if CALLBACK_HOST_PLACEHOLDER not in value_template and CALLBACK_PLACEHOLDER not in value_template:
            raise ValueError("payload template must contain a callback placeholder")
        payload_url = _apply_placeholders(value_template, payload_url, payload_host)

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

    if location == "query_template":
        # The field's value is a caller-built template (e.g. a SQL payload) that
        # embeds {{callback_url}} and/or {{callback_host}}. Unlike plain query
        # injection, the observed value is preserved inside the template rather
        # than replaced, so the callback can ride inside an injection payload.
        if not field:
            raise ValueError("field is required for query_template callback injection")
        template = body if isinstance(body, str) else ""
        if CALLBACK_PLACEHOLDER not in template and CALLBACK_HOST_PLACEHOLDER not in template:
            raise ValueError("query_template body must contain a callback placeholder")
        value = _apply_placeholders(template, payload_url, payload_host)
        parsed = urlsplit(url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        pairs = [(key, existing) for key, existing in pairs if key != field]
        pairs.append((field, value))
        return (
            urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), parsed.fragment)
            ),
            request_headers,
            None,
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
        if CALLBACK_PLACEHOLDER not in raw and CALLBACK_HOST_PLACEHOLDER not in raw:
            raise ValueError(
                f"raw callback bodies must contain {CALLBACK_PLACEHOLDER}"
            )
        return url, request_headers, _apply_placeholders(raw, payload_url, payload_host)

    raise ValueError(
        "location must be query, query_template, header, body_json, body_form, or raw"
    )


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
    value_template: str = "",
    payload_label: str = "",
    intent_id: str = "",
    coverage_cell_id: str = "",
    collector: Any | None = None,
) -> dict[str, Any]:
    """Register, plant, poll, and return a verifier-ready OAST proof bundle.

    ``collector`` is for tests; runs use the operator-configured provider.
    With ``intent_id`` or ``coverage_cell_id`` the outcome is also recorded as
    an attack-graph fact (``callback`` when a correlated callback arrived).
    """
    from app.services.agent.evidence_store import evidence_store, redact_artifact
    from app.services.oob_collectors import get_collector

    attempts = max(1, min(int(poll_attempts or 1), 8))
    interval = max(0.25, min(float(poll_interval_seconds or 0.25), 30.0 / attempts))
    store = evidence_store(manager)

    if collector is None:
        try:
            collector = get_collector()
        except ValueError as exc:
            return {"success": False, "error": str(exc), "callback_observed": False}
    provider = str(getattr(collector, "name", "") or "interactsh")
    if provider != "interactsh":
        # server/token are Interactsh options; other providers are fixed by
        # operator settings and cannot be redirected per call.
        server = token = None

    registration = await asyncio.to_thread(collector.register, server, token)
    if not registration.get("success"):
        return {
            "success": False,
            "error": registration.get("error") or f"{provider} registration failed",
            "callback_observed": False,
        }

    session_id = str(registration.get("session_id") or "")
    payload_url = str(registration.get("payload_url") or "")
    if not session_id or not payload_url:
        if session_id:
            await asyncio.to_thread(collector.stop, session_id)
        return {
            "success": False,
            "error": f"{provider} registration returned no session or payload URL",
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
            payload_host=str(registration.get("payload_domain") or ""),
            value_template=value_template,
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
        await asyncio.to_thread(collector.stop, session_id)
        raise

    plant_id = exchange["evidence_id"]
    poll_ids: list[str] = []
    matched_poll_id = ""
    matched_poll: dict[str, Any] = {}
    for attempt in range(attempts):
        if attempt:
            await asyncio.sleep(interval)
        polled = await asyncio.to_thread(collector.poll, session_id)
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
        await asyncio.to_thread(collector.stop, session_id)

    proof = None
    if matched_poll_id:
        proof = {
            "kind": "oob_callback",
            "register_id": register_id,
            "plant_id": plant_id,
            "poll_id": matched_poll_id,
        }

    graph_fact = None
    if intent_id or coverage_cell_id:
        graph_fact = _record_graph_fact(
            manager,
            url=url,
            intent_id=intent_id,
            coverage_cell_id=coverage_cell_id,
            observed=bool(matched_poll_id),
            evidence_ids=[register_id, plant_id,
                          *([matched_poll_id] if matched_poll_id else poll_ids[-1:])],
            data={
                "provider": provider,
                "payload_domain": registration.get("payload_domain"),
                "location": location,
                "field": field,
                "payload": payload_label or "callback_url",
                "protocols": sorted({str(i.get("protocol") or "")
                                     for i in (matched_poll.get("interactions") or [])}),
                "coverage_cell_id": coverage_cell_id,
            },
        )

    public_exchange = {
        "request": exchange.get("request"),
        "response": exchange.get("response"),
    }
    return {
        "success": True,
        "provider": provider,
        "callback_observed": bool(matched_poll_id),
        "session_id": session_id if keep_session else None,
        "payload_domain": registration.get("payload_domain"),
        "evidence_ids": [register_id, plant_id, *poll_ids],
        "proof": proof,
        "request": redact_artifact(public_exchange),
        "interactions": redact_artifact(matched_poll.get("interactions") or []),
        "poll_attempts": len(poll_ids),
        **({"graph_fact": graph_fact} if graph_fact else {}),
        "note": (
            "Pass evidence_ids and proof to record_verify_verdict."
            if proof
            else "No callback observed during the bounded polling window; keep the claim inconclusive."
        ),
    }


def _record_graph_fact(
    manager: Any,
    *,
    url: str,
    intent_id: str,
    coverage_cell_id: str,
    observed: bool,
    evidence_ids: list[str],
    data: dict[str, Any],
) -> dict[str, Any]:
    """Record the workflow outcome on the attack graph. Never raises.

    The parent is the intent (given directly, or the one backing the coverage
    cell), else the engagement origin. A correlated callback is a ``callback``
    fact; a silent window is an ``observation`` so the intent can still be
    completed with a result. Neither is proof; the evidence records are.
    """
    from app.services.agent import attack_graph
    from app.services.agent.engagement_brain import engagement_brain_from_dict

    try:
        brain = engagement_brain_from_dict(getattr(manager, "_engagement_brain", None))
        if not brain.target:
            brain.target = str(getattr(manager, "_fallback_target", "") or "") or url
        parent = ""
        if intent_id:
            if not attack_graph.get_intent(brain, intent_id):
                return {"error": f"unknown intent {intent_id}; fact not recorded"}
            parent = intent_id
        elif coverage_cell_id:
            # The intent backed by this cell, preferring one still being worked.
            backing = [i for i in (brain.intents or []) if isinstance(i, dict)
                       and i.get("coverage_cell_id") == coverage_cell_id]
            backing.sort(key=lambda i: i.get("status") not in ("claimed", "open"))
            if backing:
                parent = str(backing[0].get("id") or "")
        domain = str(data.get("payload_domain") or "")
        where = f"{data.get('location')}:{data.get('field')} of {url}"
        if observed:
            summary = f"Out-of-band callback to {domain} after planting it in {where}"
        else:
            summary = f"No out-of-band callback to {domain} within the polling window for {where}"
        fact = attack_graph.record_fact(
            brain,
            kind="callback" if observed else "observation",
            summary=summary,
            target=url,
            evidence_ids=evidence_ids,
            parents=[parent] if parent else [],
            source="run_oob_callback_workflow",
            data={**data, "intent_id": parent, "callback_observed": observed},
            key=f"oob:{domain}",
        )
        manager._engagement_brain = brain.to_dict()
        return {"id": fact["id"], "kind": fact["kind"], "parents": fact["parents"]}
    except Exception as exc:  # noqa: BLE001 — graph state never blocks the proof
        return {"error": f"fact not recorded: {exc}"}
