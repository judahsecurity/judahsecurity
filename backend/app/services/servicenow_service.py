"""ServiceNow Scripted REST + Table API client for ASM ITSM sync.

Outbound:
  - Praetorian-style webhook POST for new findings
  - Table API PATCH when ASM status changes (close / reopen)

Inbound:
  - Table API GET to refresh incident state
  - Optional close-claim validation: when ServiceNow closes an incident,
    queue Aegis Vanguard before accepting the close in ASM.
"""

from __future__ import annotations

import base64
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse

import httpx

from app.models.servicenow_integration import ServiceNowDelivery, ServiceNowIntegration
from app.models.vulnerability import Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

CLOSING_STATUSES = {"resolved", "accepted", "false_positive", "mitigated"}
REOPENING_STATUSES = {"open", "in_progress"}

# Incident state display names (defaults; instances may customize)
DEFAULT_STATE_LABELS = {
    "1": "New",
    "2": "In Progress",
    "3": "On Hold",
    "6": "Resolved",
    "7": "Closed",
    "8": "Canceled",
}


def _auth_header(username: Optional[str], password: Optional[str]) -> Optional[str]:
    if not username or password is None:
        return None
    credentials = f"{username}:{password}"
    return "Basic " + base64.b64encode(credentials.encode()).decode()


def _headers(integration: ServiceNowIntegration) -> Dict[str, str]:
    h = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Judah-Security-ASM/1.0",
    }
    auth = _auth_header(integration.username, integration.get_password())
    if auth:
        h["Authorization"] = auth
    return h


def _instance_base(webhook_url: str) -> Optional[str]:
    """Extract https://instance.service-now.com from the webhook URL."""
    try:
        parsed = urlparse(webhook_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass
    return None


def _table_api_base(integration: ServiceNowIntegration) -> str:
    base = _instance_base(integration.webhook_url)
    if not base:
        raise ValueError("Could not derive ServiceNow instance URL from webhook_url")
    table = (integration.table_name or "incident").strip() or "incident"
    return f"{base}/api/now/table/{table}"


def _record_url(webhook_url: str, table: str, sys_id: Optional[str], number: Optional[str]) -> Optional[str]:
    base = _instance_base(webhook_url)
    if not base:
        return None
    table = table or "incident"
    if sys_id:
        return f"{base}/nav_to.do?uri={table}.do?sys_id={sys_id}"
    if number:
        return f"{base}/nav_to.do?uri={table}.do?sysparm_query=number={quote(number)}"
    return None


def _extract_identifiers(data: Any, webhook_url: str, table: str = "incident") -> Dict[str, Optional[str]]:
    """Best-effort parse of sys_id / number / URL from customer handler responses."""
    sys_id: Optional[str] = None
    number: Optional[str] = None
    snow_url: Optional[str] = None
    state: Optional[str] = None
    state_label: Optional[str] = None

    if not isinstance(data, dict):
        return {
            "sys_id": None, "number": None, "url": None,
            "state": None, "state_label": None,
        }

    candidates: List[Dict[str, Any]] = [data]
    result = data.get("result")
    if isinstance(result, dict):
        candidates.append(result)
    elif isinstance(result, list) and result and isinstance(result[0], dict):
        candidates.append(result[0])

    for obj in candidates:
        sys_id = sys_id or obj.get("sys_id") or obj.get("sysId")
        number = number or obj.get("number") or obj.get("incident_number") or obj.get("task_number")
        link = obj.get("url") or obj.get("link") or obj.get("record_url")
        if link and not snow_url:
            snow_url = str(link)
        raw_state = obj.get("state")
        if isinstance(raw_state, dict):
            state = state or str(raw_state.get("value") or "") or None
            state_label = state_label or raw_state.get("display_value")
        elif raw_state is not None and state is None:
            state = str(raw_state)
        if obj.get("state.display_value"):
            state_label = state_label or obj.get("state.display_value")

    if not snow_url:
        snow_url = _record_url(webhook_url, table, sys_id, number)
    if state and not state_label:
        state_label = DEFAULT_STATE_LABELS.get(state, state)

    return {
        "sys_id": str(sys_id) if sys_id else None,
        "number": str(number) if number else None,
        "url": snow_url,
        "state": state,
        "state_label": state_label,
    }


def _closed_states(integration: ServiceNowIntegration) -> set[str]:
    states = integration.remote_closed_states or ["6", "7"]
    return {str(s) for s in states}


def build_vulnerability_payload(
    vuln: Vulnerability,
    *,
    include_description: bool = True,
    include_evidence: bool = True,
    include_remediation: bool = True,
    include_references: bool = True,
    include_enrichment: bool = True,
) -> Dict[str, Any]:
    """Build the JSON body posted to ServiceNow.

    Includes Praetorian-compatible top-level keys (dns, name, finding, source)
    plus richer ASM fields. Handlers should return ``sys_id`` / ``number`` so
    bidirectional sync can update the created record.
    """
    asset = vuln.asset
    asset_value = asset.value if asset else "unknown"
    ip = None
    if asset:
        ip = asset.ip_address
        if not ip and isinstance(asset.ip_addresses, list) and asset.ip_addresses:
            ip = asset.ip_addresses[0]

    finding_slug = vuln.template_id or (vuln.title or "unknown").lower().replace(" ", "-")[:120]
    severity = vuln.severity.value if vuln.severity else "unknown"
    status = vuln.status.value if vuln.status else "open"

    payload: Dict[str, Any] = {
        "dns": asset_value,
        "name": ip or asset_value,
        "finding": finding_slug,
        "source": "judah-security-asm",
        "event": "vulnerability.discovered",
        "finding_id": vuln.id,
        "title": vuln.title,
        "severity": severity,
        "status": status,
        "detected_by": vuln.detected_by,
        "template_id": vuln.template_id,
        "cve_id": vuln.cve_id,
        "cwe_id": vuln.cwe_id,
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector,
        "tags": list(vuln.tags or []) if hasattr(vuln, "tags") else [],
        "asset": {
            "id": asset.id if asset else None,
            "value": asset_value,
            "asset_type": asset.asset_type.value if asset and asset.asset_type else None,
            "ip_address": ip,
        },
        "created_at": vuln.created_at.isoformat() if getattr(vuln, "created_at", None) else None,
        # Hint for Scripted REST handlers that want sync
        "return_identifiers": True,
    }

    if include_description and vuln.description:
        payload["description"] = vuln.description

    if include_evidence:
        if vuln.evidence:
            payload["evidence"] = vuln.evidence[:4000]
        if vuln.proof_of_concept:
            payload["proof_of_concept"] = vuln.proof_of_concept[:4000]
        if vuln.steps_to_reproduce:
            payload["steps_to_reproduce"] = vuln.steps_to_reproduce

    if include_remediation and vuln.remediation:
        payload["remediation"] = vuln.remediation

    if include_references and vuln.references:
        payload["references"] = list(vuln.references)[:20]

    if include_enrichment and isinstance(vuln.metadata_, dict):
        enrichment: Dict[str, Any] = {}
        delphi = vuln.metadata_.get("delphi")
        if delphi:
            enrichment["delphi"] = delphi
        oracle = vuln.metadata_.get("oracle")
        if oracle:
            enrichment["oracle"] = {
                k: oracle.get(k)
                for k in (
                    "opes_category",
                    "opes_score",
                    "opes_label",
                    "attack_path_class",
                    "recommendation_text",
                )
                if oracle.get(k) is not None
            }
        if enrichment:
            payload["enrichment"] = enrichment

    return payload


# ── Connection / Table API ───────────────────────────────────────────────────

async def test_connection(integration: ServiceNowIntegration) -> Dict[str, Any]:
    """POST a test event to the webhook; optionally probe Table API when sync is on."""
    body = {
        "source": "judah-security-asm",
        "event": "integration.test",
        "message": "Judah Security ASM ServiceNow integration connectivity test",
    }
    table_api_ok: Optional[bool] = None
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                integration.webhook_url,
                headers=_headers(integration),
                json=body,
            )

            if integration.sync_enabled and integration.username:
                try:
                    table_url = f"{_table_api_base(integration)}?sysparm_limit=1"
                    tresp = await client.get(table_url, headers=_headers(integration))
                    table_api_ok = tresp.status_code == 200
                except Exception:
                    table_api_ok = False

        if resp.status_code in (200, 201, 202, 204):
            msg = "Connection successful — ServiceNow accepted the test webhook."
            if integration.sync_enabled:
                if table_api_ok is True:
                    msg += " Table API access OK."
                elif table_api_ok is False:
                    msg += " Warning: Table API probe failed — sync needs table read/write ACL."
            return {
                "ok": True,
                "message": msg,
                "http_status": resp.status_code,
                "table_api_ok": table_api_ok,
            }
        if resp.status_code == 401:
            return {
                "ok": False,
                "message": "Authentication failed — check the service account username and password.",
                "http_status": resp.status_code,
                "table_api_ok": table_api_ok,
            }
        if resp.status_code == 403:
            return {
                "ok": False,
                "message": "Forbidden — the service account may lack access to this Scripted REST API.",
                "http_status": resp.status_code,
                "table_api_ok": table_api_ok,
            }
        if resp.status_code == 404:
            return {
                "ok": False,
                "message": "Endpoint not found — verify the Scripted REST API URL and /notification path.",
                "http_status": resp.status_code,
                "table_api_ok": table_api_ok,
            }
        return {
            "ok": False,
            "message": f"ServiceNow returned HTTP {resp.status_code}: {resp.text[:300]}",
            "http_status": resp.status_code,
            "table_api_ok": table_api_ok,
        }
    except httpx.ConnectError:
        return {
            "ok": False,
            "message": "Could not connect to the webhook URL — verify the hostname.",
            "http_status": None,
            "table_api_ok": None,
        }
    except Exception as exc:
        logger.exception("ServiceNow test_connection error")
        return {"ok": False, "message": str(exc), "http_status": None, "table_api_ok": None}


async def get_record(
    integration: ServiceNowIntegration,
    *,
    sys_id: Optional[str] = None,
    number: Optional[str] = None,
) -> Dict[str, Any]:
    """Fetch an incident/task via Table API by sys_id or number."""
    if not sys_id and not number:
        raise ValueError("sys_id or number is required")

    headers = _headers(integration)
    async with httpx.AsyncClient(timeout=20) as client:
        if sys_id:
            url = (
                f"{_table_api_base(integration)}/{sys_id}"
                f"?sysparm_display_value=all&sysparm_fields=sys_id,number,state,short_description"
            )
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            ids = _extract_identifiers(data, integration.webhook_url, integration.table_name or "incident")
            return ids

        query = f"number={number}"
        url = (
            f"{_table_api_base(integration)}"
            f"?sysparm_query={quote(query)}&sysparm_limit=1"
            f"&sysparm_display_value=all&sysparm_fields=sys_id,number,state,short_description"
        )
        resp = await client.get(url, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        result = data.get("result")
        if not result:
            raise ValueError(f"No ServiceNow record found with number {number}")
        return _extract_identifiers(
            {"result": result[0] if isinstance(result, list) else result},
            integration.webhook_url,
            integration.table_name or "incident",
        )


def _parse_update_response(
    resp: httpx.Response,
    integration: ServiceNowIntegration,
    state: str,
    work_notes: Optional[str],
) -> Dict[str, Any]:
    if resp.status_code not in (200, 204):
        raise ValueError(f"ServiceNow Table API error {resp.status_code}: {resp.text[:500]}")
    parsed = None
    try:
        parsed = resp.json()
    except Exception:
        parsed = None
    ids = _extract_identifiers(parsed or {}, integration.webhook_url, integration.table_name or "incident")
    return {
        "ok": True,
        "state": ids.get("state") or str(state),
        "state_label": ids.get("state_label") or DEFAULT_STATE_LABELS.get(str(state), str(state)),
        "work_note_added": bool(work_notes),
    }


async def update_record_state(
    integration: ServiceNowIntegration,
    sys_id: str,
    state: str,
    work_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """PATCH incident state (+ optional work notes) via Table API."""
    body: Dict[str, Any] = {"state": str(state)}
    if work_notes:
        body["work_notes"] = work_notes

    url = f"{_table_api_base(integration)}/{sys_id}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.patch(url, headers=_headers(integration), json=body)
    return _parse_update_response(resp, integration, state, work_notes)


def update_record_state_sync(
    integration: ServiceNowIntegration,
    sys_id: str,
    state: str,
    work_notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Sync variant for use from sync workers (avoids asyncio.run in a running loop)."""
    body: Dict[str, Any] = {"state": str(state)}
    if work_notes:
        body["work_notes"] = work_notes
    url = f"{_table_api_base(integration)}/{sys_id}"
    with httpx.Client(timeout=20) as client:
        resp = client.patch(url, headers=_headers(integration), json=body)
    return _parse_update_response(resp, integration, state, work_notes)


async def add_work_note(
    integration: ServiceNowIntegration,
    sys_id: str,
    note: str,
) -> bool:
    """Append a work note without changing state."""
    url = f"{_table_api_base(integration)}/{sys_id}"
    async with httpx.AsyncClient(timeout=20) as client:
        resp = await client.patch(
            url,
            headers=_headers(integration),
            json={"work_notes": note},
        )
    return resp.status_code in (200, 204)


def add_work_note_sync(
    integration: ServiceNowIntegration,
    sys_id: str,
    note: str,
) -> bool:
    url = f"{_table_api_base(integration)}/{sys_id}"
    with httpx.Client(timeout=20) as client:
        resp = client.patch(
            url,
            headers=_headers(integration),
            json={"work_notes": note},
        )
    return resp.status_code in (200, 204)


# ── Push (create) ────────────────────────────────────────────────────────────

async def push_vulnerability(
    integration: ServiceNowIntegration,
    vuln: Vulnerability,
    *,
    include_description: bool = True,
    include_evidence: bool = True,
    include_remediation: bool = True,
    include_references: bool = True,
    include_enrichment: bool = True,
) -> Dict[str, Any]:
    """POST a vulnerability payload. Returns delivery metadata for persistence."""
    payload = build_vulnerability_payload(
        vuln,
        include_description=include_description,
        include_evidence=include_evidence,
        include_remediation=include_remediation,
        include_references=include_references,
        include_enrichment=include_enrichment,
    )

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            integration.webhook_url,
            headers=_headers(integration),
            json=payload,
        )

    body_text = resp.text[:4000] if resp.text else None
    parsed: Any = None
    if body_text:
        try:
            parsed = resp.json()
        except Exception:
            parsed = None

    ids = _extract_identifiers(
        parsed, integration.webhook_url, integration.table_name or "incident"
    )

    if resp.status_code not in (200, 201, 202, 204):
        raise ValueError(
            f"ServiceNow webhook error {resp.status_code}: {(body_text or '')[:500]}"
        )

    return {
        "http_status": resp.status_code,
        "response_body": body_text,
        "snow_sys_id": ids["sys_id"],
        "snow_number": ids["number"],
        "snow_url": ids["url"],
        "snow_state": ids.get("state"),
        "snow_state_label": ids.get("state_label"),
        "payload": payload,
    }


def auto_push_sync(integration: ServiceNowIntegration, vuln: Vulnerability) -> None:
    """Synchronous wrapper for BackgroundTasks auto-push."""
    import asyncio

    from app.db.database import SessionLocal

    try:
        result = asyncio.run(push_vulnerability(integration, vuln))
        db = SessionLocal()
        try:
            delivery = ServiceNowDelivery(
                integration_id=integration.id,
                vulnerability_id=vuln.id,
                snow_sys_id=result.get("snow_sys_id"),
                snow_number=result.get("snow_number"),
                snow_url=result.get("snow_url"),
                snow_state=result.get("snow_state"),
                snow_state_label=result.get("snow_state_label"),
                http_status=result.get("http_status"),
                response_body=result.get("response_body"),
            )
            db.add(delivery)
            row = (
                db.query(ServiceNowIntegration)
                .filter(ServiceNowIntegration.id == integration.id)
                .first()
            )
            if row:
                row.last_delivery_at = datetime.utcnow()
                row.last_error = None
            db.commit()
            logger.info(
                "Auto-pushed vuln %s to ServiceNow (HTTP %s)",
                vuln.id,
                result.get("http_status"),
            )
        finally:
            db.close()
    except Exception as exc:
        logger.exception("Auto-push ServiceNow failed for vuln %s", vuln.id)
        try:
            db = SessionLocal()
            try:
                row = (
                    db.query(ServiceNowIntegration)
                    .filter(ServiceNowIntegration.id == integration.id)
                    .first()
                )
                if row:
                    row.last_error = str(exc)[:1000]
                    db.commit()
            finally:
                db.close()
        except Exception:
            logger.exception("Failed to persist ServiceNow auto-push error")


# ── ASM → ServiceNow status sync ─────────────────────────────────────────────

async def sync_delivery_for_status_change(
    integration: ServiceNowIntegration,
    delivery: ServiceNowDelivery,
    old_status: str,
    new_status: str,
    changed_by: str,
) -> Dict[str, Any]:
    """Push ASM status changes to the linked ServiceNow record."""
    result: Dict[str, Any] = {
        "ok": True,
        "message": "",
        "state_updated": False,
        "work_note_added": False,
        "validation_queued": False,
        "asm_status_updated": False,
        "snow_state": delivery.snow_state,
        "snow_state_label": delivery.snow_state_label,
    }

    if not integration.sync_enabled:
        result["message"] = "ServiceNow sync is disabled."
        return result

    if not delivery.snow_sys_id:
        result["ok"] = False
        result["message"] = (
            "No ServiceNow sys_id on this delivery — cannot sync. "
            "Have the Scripted REST handler return sys_id, or associate an existing record."
        )
        return result

    is_closing = new_status in CLOSING_STATUSES
    is_reopening = new_status in REOPENING_STATUSES and old_status in CLOSING_STATUSES
    if not is_closing and not is_reopening:
        result["message"] = "No ServiceNow sync needed for this status combination."
        return result

    if is_closing:
        target_state = integration.close_state or "6"
        reason_map = {
            "resolved": "Remediated",
            "accepted": "Risk Accepted",
            "false_positive": "False Positive",
            "mitigated": "Mitigated",
        }
        reason = reason_map.get(new_status, new_status.replace("_", " ").title())
        note = (
            f"[Judah Security ASM] Vulnerability marked as {reason} by {changed_by}. "
            f"Incident state updated automatically."
        )
    else:
        target_state = integration.reopen_state or "2"
        note = (
            f"[Judah Security ASM] Vulnerability reopened by {changed_by}. "
            f"New status: {new_status.replace('_', ' ').title()}."
        )

    update = await update_record_state(
        integration, delivery.snow_sys_id, target_state, work_notes=note
    )
    result["state_updated"] = True
    result["work_note_added"] = update.get("work_note_added", False)
    result["snow_state"] = update.get("state")
    result["snow_state_label"] = update.get("state_label")
    result["message"] = f"ServiceNow state set to {result['snow_state_label'] or target_state}."
    return result


def sync_delivery_for_status_change_sync(
    integration: ServiceNowIntegration,
    delivery: ServiceNowDelivery,
    old_status: str,
    new_status: str,
    changed_by: str,
) -> None:
    """Background wrapper that also persists refreshed state on the delivery."""
    import asyncio

    from app.db.database import SessionLocal

    try:
        result = asyncio.run(
            sync_delivery_for_status_change(
                integration, delivery, old_status, new_status, changed_by
            )
        )
        if result.get("state_updated"):
            db = SessionLocal()
            try:
                row = db.query(ServiceNowDelivery).filter(ServiceNowDelivery.id == delivery.id).first()
                if row:
                    row.snow_state = result.get("snow_state")
                    row.snow_state_label = result.get("snow_state_label")
                    row.last_synced_at = datetime.utcnow()
                    db.commit()
            finally:
                db.close()
    except Exception:
        logger.exception(
            "Background ServiceNow sync failed for delivery %s", delivery.id
        )


# ── ServiceNow → ASM pull + close validation ─────────────────────────────────

def _queue_close_validation(db, vuln: Vulnerability, org_id: int, delivery: ServiceNowDelivery) -> Optional[int]:
    """Queue a Vanguard validation triggered by a ServiceNow close claim."""
    from app.models.finding_validation import FindingValidation, ValidationStatus
    from app.api.routes.vulnerabilities import send_validation_to_sqs

    in_flight = (
        db.query(FindingValidation)
        .filter(
            FindingValidation.vulnerability_id == vuln.id,
            FindingValidation.status.in_([ValidationStatus.QUEUED, ValidationStatus.RUNNING]),
        )
        .first()
    )
    if in_flight:
        delivery.pending_close_validation = True
        delivery.pending_close_validation_id = in_flight.id
        return in_flight.id

    validation = FindingValidation(
        vulnerability_id=vuln.id,
        organization_id=org_id,
        status=ValidationStatus.QUEUED,
        requested_by_user_id=None,
        raw_output={"triggered_by": "servicenow_close", "delivery_id": delivery.id},
    )
    db.add(validation)
    vuln.validation_status = "queued"
    db.flush()
    delivery.pending_close_validation = True
    delivery.pending_close_validation_id = validation.id
    db.commit()
    db.refresh(validation)
    send_validation_to_sqs(validation)
    return validation.id


async def refresh_delivery(
    db,
    integration: ServiceNowIntegration,
    delivery: ServiceNowDelivery,
    *,
    apply_remote_close: bool = True,
) -> Dict[str, Any]:
    """Pull current ServiceNow state and optionally act on remote close."""
    result: Dict[str, Any] = {
        "ok": True,
        "message": "",
        "state_updated": False,
        "work_note_added": False,
        "validation_queued": False,
        "asm_status_updated": False,
        "snow_state": delivery.snow_state,
        "snow_state_label": delivery.snow_state_label,
    }

    if not delivery.snow_sys_id and not delivery.snow_number:
        result["ok"] = False
        result["message"] = "Delivery has no sys_id or number to refresh."
        return result

    detail = await get_record(
        integration,
        sys_id=delivery.snow_sys_id,
        number=None if delivery.snow_sys_id else delivery.snow_number,
    )
    delivery.snow_sys_id = delivery.snow_sys_id or detail.get("sys_id")
    delivery.snow_number = delivery.snow_number or detail.get("number")
    delivery.snow_url = delivery.snow_url or detail.get("url")
    delivery.snow_state = detail.get("state")
    delivery.snow_state_label = detail.get("state_label")
    delivery.last_synced_at = datetime.utcnow()
    result["snow_state"] = delivery.snow_state
    result["snow_state_label"] = delivery.snow_state_label
    result["state_updated"] = True

    if not apply_remote_close or not integration.sync_enabled:
        result["message"] = f"Refreshed — ServiceNow state is {delivery.snow_state_label or delivery.snow_state}."
        db.commit()
        return result

    closed = str(delivery.snow_state or "") in _closed_states(integration)
    if not closed:
        # Remote reopened while we had a pending close validation
        if delivery.pending_close_validation:
            delivery.pending_close_validation = False
        result["message"] = f"Refreshed — ServiceNow state is {delivery.snow_state_label or delivery.snow_state}."
        db.commit()
        return result

    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == delivery.vulnerability_id)
        .first()
    )
    if not vuln:
        result["message"] = "Linked vulnerability not found."
        db.commit()
        return result

    asm_status = vuln.status.value if vuln.status else "open"
    if asm_status in CLOSING_STATUSES:
        result["message"] = (
            f"ServiceNow is {delivery.snow_state_label}; ASM finding already {asm_status}."
        )
        db.commit()
        return result

    if integration.validate_on_remote_close:
        if delivery.pending_close_validation:
            result["message"] = (
                "ServiceNow reports closed — close-claim validation already in progress."
            )
            result["validation_queued"] = True
            db.commit()
            return result

        org_id = integration.organization_id
        vid = _queue_close_validation(db, vuln, org_id, delivery)
        result["validation_queued"] = True
        result["message"] = (
            f"ServiceNow reports closed — queued validation #{vid} before accepting close."
        )
        if delivery.snow_sys_id:
            try:
                await add_work_note(
                    integration,
                    delivery.snow_sys_id,
                    "[Judah Security ASM] Close claimed in ServiceNow. "
                    "Re-testing the finding before accepting remediation.",
                )
                result["work_note_added"] = True
            except Exception:
                logger.exception("Failed to add close-validation work note")
        return result

    # No validation — accept close immediately
    accept_as = integration.accept_close_as or "resolved"
    try:
        vuln.status = VulnerabilityStatus(accept_as)
    except ValueError:
        vuln.status = VulnerabilityStatus.RESOLVED
    if vuln.status == VulnerabilityStatus.RESOLVED:
        vuln.resolved_at = datetime.utcnow()
    result["asm_status_updated"] = True
    result["message"] = f"ServiceNow closed — ASM status set to {vuln.status.value}."
    db.commit()
    return result


def handle_close_validation_result(db, validation) -> None:
    """Called when a Vanguard validation completes (from scanner worker).

    If this validation was triggered by a ServiceNow close claim:
      - CONFIRMED → reject close (finding still open); reopen SNOW / work note
      - otherwise → accept close as configured (typically resolved / false_positive)
    """
    from app.models.finding_validation import ValidationVerdict

    raw = validation.raw_output if isinstance(validation.raw_output, dict) else {}

    # Prefer explicit link from when we queued the close-claim validation.
    delivery = (
        db.query(ServiceNowDelivery)
        .filter(ServiceNowDelivery.pending_close_validation_id == validation.id)
        .first()
    )
    if not delivery and raw.get("triggered_by") == "servicenow_close":
        delivery_id = raw.get("delivery_id")
        if delivery_id:
            delivery = db.query(ServiceNowDelivery).filter(ServiceNowDelivery.id == delivery_id).first()
    if not delivery:
        delivery = (
            db.query(ServiceNowDelivery)
            .filter(
                ServiceNowDelivery.vulnerability_id == validation.vulnerability_id,
                ServiceNowDelivery.pending_close_validation.is_(True),
                ServiceNowDelivery.disconnected_at.is_(None),
            )
            .order_by(ServiceNowDelivery.created_at.desc())
            .first()
        )
    if not delivery:
        return
    # Only apply the close-claim loop for deliveries waiting on validation
    if not delivery.pending_close_validation and raw.get("triggered_by") != "servicenow_close":
        return

    integration = (
        db.query(ServiceNowIntegration)
        .filter(ServiceNowIntegration.id == delivery.integration_id)
        .first()
    )
    vuln = (
        db.query(Vulnerability)
        .filter(Vulnerability.id == validation.vulnerability_id)
        .first()
    )
    if not integration or not vuln:
        return

    verdict = validation.verdict
    verdict_value = verdict.value if verdict else None
    delivery.pending_close_validation = False
    delivery.last_close_validation_verdict = verdict_value

    if verdict == ValidationVerdict.CONFIRMED:
        # Still vulnerable — reject the ServiceNow close claim
        note = (
            "[Judah Security ASM] Close claim REJECTED. "
            "Validator confirming the finding is still present on the target. "
            f"Reasoning: {(validation.reasoning or 'n/a')[:500]}"
        )
        if delivery.snow_sys_id and integration.sync_enabled:
            try:
                update_record_state_sync(
                    integration,
                    delivery.snow_sys_id,
                    integration.reopen_state or "2",
                    work_notes=note,
                )
                delivery.snow_state = integration.reopen_state or "2"
                delivery.snow_state_label = DEFAULT_STATE_LABELS.get(
                    delivery.snow_state, delivery.snow_state
                )
                delivery.last_synced_at = datetime.utcnow()
            except Exception:
                logger.exception("Failed to reopen ServiceNow after rejected close")
                try:
                    add_work_note_sync(integration, delivery.snow_sys_id, note)
                except Exception:
                    pass
        # Keep ASM finding open
        if vuln.status and vuln.status.value in CLOSING_STATUSES:
            vuln.status = VulnerabilityStatus.OPEN
        db.commit()
        logger.info(
            "ServiceNow close rejected for vuln %s (validation %s confirmed still open)",
            vuln.id,
            validation.id,
        )
        return

    if verdict == ValidationVerdict.NEEDS_MORE_EVIDENCE:
        note = (
            "[Judah Security ASM] Close claim not accepted yet — validator needs more evidence. "
            f"Reasoning: {(validation.reasoning or 'n/a')[:500]}"
        )
        if delivery.snow_sys_id:
            try:
                add_work_note_sync(integration, delivery.snow_sys_id, note)
            except Exception:
                logger.exception("Failed to add needs-more-evidence work note")
        db.commit()
        return

    # FALSE_POSITIVE or other non-confirmed → accept close
    accept_as = integration.accept_close_as or "resolved"
    # If validator said false_positive, prefer that over generic resolved
    if verdict == ValidationVerdict.FALSE_POSITIVE:
        accept_as = "false_positive"
    try:
        vuln.status = VulnerabilityStatus(accept_as)
    except ValueError:
        vuln.status = VulnerabilityStatus.RESOLVED
    if vuln.status == VulnerabilityStatus.RESOLVED:
        vuln.resolved_at = datetime.utcnow()

    note = (
        f"[Judah Security ASM] Close claim ACCEPTED after validation "
        f"({verdict_value}). ASM status set to {vuln.status.value}. "
        f"Reasoning: {(validation.reasoning or 'n/a')[:400]}"
    )
    if delivery.snow_sys_id and integration.sync_enabled:
        try:
            update_record_state_sync(
                integration,
                delivery.snow_sys_id,
                integration.close_state or "6",
                work_notes=note,
            )
            delivery.snow_state = integration.close_state or "6"
            delivery.snow_state_label = DEFAULT_STATE_LABELS.get(
                delivery.snow_state, delivery.snow_state
            )
            delivery.last_synced_at = datetime.utcnow()
        except Exception:
            logger.exception("Failed to confirm ServiceNow close after validation")

    db.commit()
    logger.info(
        "ServiceNow close accepted for vuln %s → %s (verdict=%s)",
        vuln.id,
        vuln.status.value,
        verdict_value,
    )


def to_response_dict(integration: ServiceNowIntegration) -> Dict[str, Any]:
    """Serialize integration for API responses (never expose password)."""
    return {
        "id": integration.id,
        "organization_id": integration.organization_id,
        "webhook_url": integration.webhook_url,
        "username": integration.username,
        "has_password": bool(integration.password_encrypted),
        "auto_create_enabled": integration.auto_create_enabled,
        "auto_create_min_severity": integration.auto_create_min_severity,
        "sync_enabled": bool(integration.sync_enabled),
        "table_name": integration.table_name or "incident",
        "close_state": integration.close_state or "6",
        "reopen_state": integration.reopen_state or "2",
        "remote_closed_states": list(integration.remote_closed_states or ["6", "7"]),
        "validate_on_remote_close": bool(
            True if integration.validate_on_remote_close is None else integration.validate_on_remote_close
        ),
        "accept_close_as": integration.accept_close_as or "resolved",
        "is_active": integration.is_active,
        "last_tested_at": integration.last_tested_at,
        "last_test_ok": integration.last_test_ok,
        "last_delivery_at": integration.last_delivery_at,
        "last_pull_at": getattr(integration, "last_pull_at", None),
        "last_error": integration.last_error,
        "created_at": integration.created_at,
        "updated_at": integration.updated_at,
    }
