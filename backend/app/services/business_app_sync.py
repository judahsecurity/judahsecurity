"""
Sync the organization's business applications from ServiceNow.

Reads the CMDB Business Application table (``cmdb_ci_business_app``) through
the Table API using the organization's existing ServiceNow integration
(instance URL + service account), and upserts ``business_applications`` rows
keyed by ServiceNow ``sys_id``. Analysts then link findings — or whole assets
— to an application by its unique id (``number``, e.g. APM0001234), and the
severity evaluation takes Business Impact from the application's
``business_criticality``.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.models.business_application import BusinessApplication
from app.models.servicenow_integration import ServiceNowIntegration
from app.services.servicenow_service import _headers, _instance_base

logger = logging.getLogger(__name__)

TABLE = "cmdb_ci_business_app"
FIELDS = (
    "sys_id,number,name,short_description,business_criticality,operational_status,"
    "life_cycle_stage,owned_by,it_application_owner,url,data_classification,application_type,user_base"
)
PAGE_SIZE = 500
MAX_RECORDS = 50_000


def criticality_level(raw: Optional[str]) -> Optional[int]:
    """ServiceNow business_criticality ("1 - most critical" … "4 - not
    critical", or the bare value) → 1–4."""
    match = re.match(r"\s*([1-4])\b", str(raw or ""))
    return int(match.group(1)) if match else None


def _text(value: Any) -> str:
    # sysparm_display_value=all returns {"value": ..., "display_value": ...}
    if isinstance(value, dict):
        return str(value.get("display_value") or value.get("value") or "")
    return str(value or "")


def _value(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("value") or "")
    return str(value or "")


def upsert_record(db: Session, organization_id: int, record: Dict[str, Any], instance: str) -> BusinessApplication:
    sys_id = _value(record.get("sys_id"))
    app = (
        db.query(BusinessApplication)
        .filter(
            BusinessApplication.organization_id == organization_id,
            BusinessApplication.source == "servicenow",
            BusinessApplication.external_id == sys_id,
        )
        .first()
    )
    if app is None:
        app = BusinessApplication(organization_id=organization_id, source="servicenow", external_id=sys_id)
        db.add(app)
    crit_raw = _text(record.get("business_criticality"))
    app.app_id = _text(record.get("number")) or None
    app.name = _text(record.get("name")) or app.app_id or sys_id
    app.description = _text(record.get("short_description")) or None
    app.business_criticality = crit_raw or None
    app.criticality_level = criticality_level(_value(record.get("business_criticality")) or crit_raw)
    app.operational_status = _text(record.get("operational_status")) or None
    app.lifecycle_stage = _text(record.get("life_cycle_stage")) or None
    app.owner = _text(record.get("owned_by")) or None
    app.it_owner = _text(record.get("it_application_owner")) or None
    app.url = _text(record.get("url")) or None
    app.external_url = f"{instance}/nav_to.do?uri={TABLE}.do?sys_id={sys_id}" if instance else None
    app.raw = record
    app.synced_at = datetime.utcnow()
    return app


async def sync_business_apps(
    db: Session,
    organization_id: int,
    *,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Pull every business application for the org. The caller commits."""
    integration = (
        db.query(ServiceNowIntegration).filter(ServiceNowIntegration.organization_id == organization_id).first()
    )
    if integration is None:
        raise ValueError("ServiceNow is not configured for this organization")
    instance = _instance_base(integration.webhook_url)
    if not instance:
        raise ValueError("Could not derive the ServiceNow instance URL from the integration")

    url = f"{instance}/api/now/table/{TABLE}"
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=60)
    seen = 0
    try:
        offset = 0
        while offset < MAX_RECORDS:
            resp = await client.get(
                url,
                headers=_headers(integration),
                params={
                    "sysparm_fields": FIELDS,
                    "sysparm_display_value": "all",
                    "sysparm_exclude_reference_link": "true",
                    "sysparm_limit": str(PAGE_SIZE),
                    "sysparm_offset": str(offset),
                    "sysparm_query": "ORDERBYsys_id",
                },
            )
            if resp.status_code == 403:
                raise PermissionError(
                    f"ServiceNow account cannot read {TABLE}; grant it read access to Business Applications"
                )
            resp.raise_for_status()
            records = (resp.json() or {}).get("result") or []
            for record in records:
                if _value(record.get("sys_id")):
                    upsert_record(db, organization_id, record, instance)
                    seen += 1
            if len(records) < PAGE_SIZE:
                break
            offset += PAGE_SIZE
    finally:
        if own_client:
            await client.aclose()
    logger.info("ServiceNow business apps: synced %d for org %s", seen, organization_id)
    return {"synced": seen, "table": TABLE}
