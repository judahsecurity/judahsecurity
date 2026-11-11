"""
Sync what runs each business application from the ServiceNow CMDB, and
attribute our assets (and through them, findings) to it.

One sync pulls, through the Table API and the org's existing ServiceNow
integration:

1. Business applications (``cmdb_ci_business_app``) — ``business_app_sync``.
2. Application services (``cmdb_ci_service_auto`` and its child classes:
   discovered, tag-based, calculated, query-based services).
3. What runs them — configuration items with a hostname or IP:
   - entry points (``sa_m2m_service_entry_point`` → ``cmdb_ci_endpoint_http``):
     the URLs a service is reached on; the strongest match for an
     internet-facing asset;
   - Service Mapping membership (``svc_ci_assoc``);
   - CMDB relationships (``cmdb_rel_ci``) from business applications and
     services to their CIs — this is also where a business application's
     "Consumes" link to its application services comes from.

Then ``attribute_assets`` matches each asset's hostname or IP to those CIs and
records the application service, business application and how the link was
made. Analysts' manual links are never overwritten.

Tables other than business applications are optional: when the integration
account cannot read one, the sync keeps going and reports a warning.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from sqlalchemy.orm import Session

from app.models.application_service import ApplicationService, CmdbCiLink
from app.models.asset import Asset
from app.models.business_application import BusinessApplication
from app.services.business_app_sync import (
    _text,
    _value,
    criticality_level,
    resolve_integration,
    sync_business_apps,
)
from app.services.servicenow_service import _headers

logger = logging.getLogger(__name__)

SERVICE_TABLE = "cmdb_ci_service_auto"
SERVICE_FIELDS = (
    "sys_id,number,name,short_description,sys_class_name,"
    # Service tables spell it "busines_criticality"; ask for both spellings.
    "busines_criticality,business_criticality,environment,operational_status,"
    "owned_by,managed_by,support_group,change_control,business_unit,department,company"
)
CI_FIELDS = ("name", "sys_class_name", "ip_address", "fqdn")
PAGE_SIZE = 500
MAX_RECORDS = 100_000

# Lower is stronger evidence that the asset is part of the service.
RELATION_PRIORITY = {"entry_point": 0, "service_map": 1, "relationship": 2}
RELATION_LABEL = {
    "entry_point": "ServiceNow entry point",
    "service_map": "ServiceNow service map",
    "relationship": "ServiceNow CMDB relationship",
}
AUTO_SOURCES = set(RELATION_PRIORITY)
MANUAL = "manual"

_HOST_RE = re.compile(r"^(?:\*\.)?[a-z0-9_](?:[a-z0-9_-]{0,62})(?:\.[a-z0-9_-]{1,63})+$")


# ── Normalization ────────────────────────────────────────────────────────────

def normalize_ip(raw: Any) -> Optional[str]:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return None


def normalize_host(raw: Any) -> Optional[str]:
    """A bare lowercase hostname from a hostname, host:port or URL; None for
    IPs and anything that is not a dotted hostname."""
    text = str(raw or "").strip().lower()
    if not text:
        return None
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return None
    else:
        text = text.split("/", 1)[0]
        if text.count(":") == 1:
            text = text.split(":", 1)[0]
    text = text.rstrip(".")
    if not text or normalize_ip(text):
        return None
    return text if _HOST_RE.match(text) else None


def asset_keys(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """(hostname, ip) to match an asset value against CMDB CIs."""
    text = str(value or "").strip()
    ip = normalize_ip(text)
    if ip:
        return None, ip
    host = normalize_host(text)
    if host:
        return host, None
    # host:port / URL with an IP host
    if "://" in text:
        try:
            return None, normalize_ip(urlsplit(text).hostname)
        except ValueError:
            return None, None
    if text.count(":") == 1:
        return None, normalize_ip(text.split(":", 1)[0])
    return None, None


# ── Table API ────────────────────────────────────────────────────────────────

class TableUnavailable(Exception):
    pass


async def fetch_table(
    client: httpx.AsyncClient,
    integration: Any,
    instance: str,
    table: str,
    fields: str,
    query: str = "",
) -> List[Dict[str, Any]]:
    url = f"{instance}/api/now/table/{table}"
    order = "ORDERBYsys_id"
    out: List[Dict[str, Any]] = []
    offset = 0
    while offset < MAX_RECORDS:
        resp = await client.get(
            url,
            headers=_headers(integration),
            params={
                "sysparm_fields": fields,
                "sysparm_display_value": "all",
                "sysparm_exclude_reference_link": "true",
                "sysparm_limit": str(PAGE_SIZE),
                "sysparm_offset": str(offset),
                "sysparm_query": f"{query}^{order}" if query else order,
            },
        )
        if resp.status_code in (400, 403, 404):
            raise TableUnavailable(f"{table}: HTTP {resp.status_code}")
        resp.raise_for_status()
        records = (resp.json() or {}).get("result") or []
        out.extend(records)
        if len(records) < PAGE_SIZE:
            break
        offset += PAGE_SIZE
    return out


# ── Application services ─────────────────────────────────────────────────────

def upsert_service(db: Session, organization_id: int, record: Dict[str, Any], instance: str) -> ApplicationService:
    sys_id = _value(record.get("sys_id"))
    svc = (
        db.query(ApplicationService)
        .filter(
            ApplicationService.organization_id == organization_id,
            ApplicationService.source == "servicenow",
            ApplicationService.external_id == sys_id,
        )
        .first()
    )
    if svc is None:
        svc = ApplicationService(organization_id=organization_id, source="servicenow", external_id=sys_id)
        db.add(svc)
    crit_field = record.get("busines_criticality") or record.get("business_criticality")
    crit_raw = _text(crit_field)
    svc_class = _value(record.get("sys_class_name")) or SERVICE_TABLE
    svc.number = _text(record.get("number")) or None
    svc.name = _text(record.get("name")) or svc.number or sys_id
    svc.description = _text(record.get("short_description")) or None
    svc.service_class = svc_class
    svc.business_criticality = crit_raw or None
    svc.criticality_level = criticality_level(_value(crit_field) or crit_raw)
    svc.environment = _text(record.get("environment")) or None
    svc.operational_status = _text(record.get("operational_status")) or None
    svc.owner = _text(record.get("owned_by")) or None
    svc.managed_by = _text(record.get("managed_by")) or None
    svc.support_group = _text(record.get("support_group")) or None
    svc.change_group = _text(record.get("change_control")) or None
    svc.business_unit = _text(record.get("business_unit")) or None
    svc.department = _text(record.get("department")) or None
    svc.company = _text(record.get("company")) or None
    svc.external_url = f"{instance}/nav_to.do?uri={svc_class}.do?sys_id={sys_id}" if instance else None
    svc.raw = record
    svc.synced_at = datetime.utcnow()
    return svc


def _ci_link(organization_id: int, relation: str, record: Dict[str, Any], prefix: str, **owner: Any) -> Optional[CmdbCiLink]:
    """A CI link from dot-walked ``<prefix>.name`` etc.; None when the CI has
    nothing to match an asset on."""
    name = _text(record.get(f"{prefix}.name"))
    ip = normalize_ip(_value(record.get(f"{prefix}.ip_address")))
    fqdn = normalize_host(_value(record.get(f"{prefix}.fqdn"))) or normalize_host(name)
    if not (fqdn or ip):
        return None
    return CmdbCiLink(
        organization_id=organization_id,
        relation=relation,
        ci_sys_id=_value(record.get(prefix)) or None,
        ci_name=name[:255] or None,
        ci_class=_value(record.get(f"{prefix}.sys_class_name")) or None,
        fqdn=fqdn,
        ip_address=ip,
        **owner,
    )


def _dotted(prefix: str, *extra: str) -> str:
    return ",".join([*extra, prefix, *(f"{prefix}.{f}" for f in CI_FIELDS)])


async def sync_cmdb(
    db: Session,
    organization_id: int,
    *,
    client: Optional[httpx.AsyncClient] = None,
) -> Dict[str, Any]:
    """Business apps, application services, the CIs that run them, then
    asset attribution. The caller commits."""
    integration, instance = resolve_integration(db, organization_id)
    own_client = client is None
    client = client or httpx.AsyncClient(timeout=60)
    warnings: List[str] = []
    result: Dict[str, Any] = {}

    async def optional(table: str, fields: str, query: str = "") -> Optional[List[Dict[str, Any]]]:
        try:
            return await fetch_table(client, integration, instance, table, fields, query)
        except TableUnavailable as exc:
            warnings.append(f"Could not read {exc}; grant the integration account read access to {table}")
            return None

    try:
        apps_result = await sync_business_apps(db, organization_id, client=client)
        result["business_apps"] = apps_result["synced"]
        db.flush()
        apps = {
            a.external_id: a
            for a in db.query(BusinessApplication).filter(
                BusinessApplication.organization_id == organization_id,
                BusinessApplication.source == "servicenow",
            )
        }

        # Application services
        services: Dict[str, ApplicationService] = {
            s.external_id: s
            for s in db.query(ApplicationService).filter(
                ApplicationService.organization_id == organization_id,
                ApplicationService.source == "servicenow",
            )
        }
        records = await optional(SERVICE_TABLE, SERVICE_FIELDS)
        if records is not None:
            seen = set()
            for record in records:
                sys_id = _value(record.get("sys_id"))
                if sys_id:
                    services[sys_id] = upsert_service(db, organization_id, record, instance)
                    seen.add(sys_id)
            for sys_id in [s for s in services if s not in seen]:
                stale = services.pop(sys_id)
                db.query(Asset).filter(Asset.app_service_id == stale.id).update(
                    {Asset.app_service_id: None}, synchronize_session=False
                )
                db.query(CmdbCiLink).filter(CmdbCiLink.app_service_id == stale.id).delete(synchronize_session=False)
                db.delete(stale)
        result["application_services"] = len(services)
        db.flush()

        links: Dict[str, List[CmdbCiLink]] = {}

        # Business application → service ("Consumes") and → CIs it runs on directly.
        rels = await optional(
            "cmdb_rel_ci",
            _dotted("child", "parent", "type"),
            "parent.sys_class_name=cmdb_ci_business_app",
        )
        if rels is not None:
            consumed: Dict[str, int] = {}
            rel_links = []
            for rel in rels:
                app = apps.get(_value(rel.get("parent")))
                child = _value(rel.get("child"))
                if app is None or not child:
                    continue
                if child in services:
                    consumed.setdefault(child, app.id)
                    continue
                link = _ci_link(organization_id, "relationship", rel, "child", business_app_id=app.id)
                if link:
                    rel_links.append(link)
            for sys_id, svc in services.items():
                if svc.business_app_id != consumed.get(sys_id):
                    svc.business_app_id = consumed.get(sys_id)
            links["relationship"] = rel_links

        # Service → CIs it depends on.
        classes = sorted({s.service_class or SERVICE_TABLE for s in services.values()})
        if classes and "relationship" in links:
            svc_rels = await optional(
                "cmdb_rel_ci",
                _dotted("child", "parent", "type"),
                "parent.sys_class_nameIN" + ",".join(classes),
            )
            if svc_rels is None:
                links.pop("relationship")
            else:
                for rel in svc_rels:
                    svc = services.get(_value(rel.get("parent")))
                    if svc is None or _value(rel.get("child")) in services:
                        continue
                    link = _ci_link(organization_id, "relationship", rel, "child", app_service_id=svc.id)
                    if link:
                        links["relationship"].append(link)

        # Service Mapping membership.
        if services:
            assoc = await optional("svc_ci_assoc", _dotted("ci_id", "service_id"))
            if assoc is not None:
                links["service_map"] = [
                    link
                    for row in assoc
                    if (svc := services.get(_value(row.get("service_id"))))
                    and (link := _ci_link(organization_id, "service_map", row, "ci_id", app_service_id=svc.id))
                ]

        # Entry points (the URLs a service is reached on).
        if services:
            eps = await optional(
                "sa_m2m_service_entry_point",
                "cmdb_ci_service,entry_point,entry_point.name,entry_point.sys_class_name",
            )
            if eps is not None:
                http = await optional("cmdb_ci_endpoint_http", "sys_id,name,url,host")
                by_id = {_value(r.get("sys_id")): r for r in (http or [])}
                ep_links = []
                for row in eps:
                    svc = services.get(_value(row.get("cmdb_ci_service")))
                    ep_id = _value(row.get("entry_point"))
                    if svc is None or not ep_id:
                        continue
                    ep = by_id.get(ep_id, {})
                    url = _value(ep.get("url")) or _text(row.get("entry_point.name"))
                    candidates = (_value(ep.get("host")), url, _text(ep.get("name")))
                    host = next((h for h in map(normalize_host, candidates) if h), None)
                    ip = next((i for i in (asset_keys(c)[1] for c in candidates) if i), None)
                    if not (host or ip):
                        continue
                    ep_links.append(CmdbCiLink(
                        organization_id=organization_id,
                        app_service_id=svc.id,
                        relation="entry_point",
                        ci_sys_id=ep_id,
                        ci_name=(_text(ep.get("name")) or _text(row.get("entry_point.name")))[:255] or None,
                        ci_class=_value(row.get("entry_point.sys_class_name")) or "cmdb_ci_endpoint_http",
                        fqdn=host,
                        ip_address=ip,
                        url=(url or "")[:500] or None,
                    ))
                links["entry_point"] = ep_links

        # Replace the links of each relation we could read.
        for relation, rows in links.items():
            db.query(CmdbCiLink).filter(
                CmdbCiLink.organization_id == organization_id, CmdbCiLink.relation == relation
            ).delete(synchronize_session=False)
            unique = {}
            for link in rows:
                unique.setdefault((link.app_service_id, link.business_app_id, link.fqdn, link.ip_address), link)
            db.add_all(unique.values())
            result[f"{relation}_links"] = len(unique)
        db.flush()
    finally:
        if own_client:
            await client.aclose()

    result["attribution"] = attribute_assets(db, organization_id)
    result["warnings"] = warnings
    logger.info("ServiceNow CMDB sync for org %s: %s", organization_id, result)
    return result


# ── Attribution ──────────────────────────────────────────────────────────────

def _assign(asset: Asset, **values: Any) -> bool:
    changed = False
    for key, value in values.items():
        if getattr(asset, key) != value:
            setattr(asset, key, value)
            changed = True
    return changed


def _detail(link: CmdbCiLink, others: int) -> str:
    what = link.url or link.ci_name or link.fqdn or link.ip_address or "CI"
    cls = f" ({link.ci_class})" if link.ci_class and link.relation != "entry_point" else ""
    more = f"; also matches {others} other application(s)" if others else ""
    return f"{RELATION_LABEL[link.relation]}: {what}{cls}{more}"[:500]


def is_manual(asset: Asset) -> bool:
    # A business app link made before automatic attribution existed is manual too.
    return asset.app_link_source == MANUAL or (asset.app_link_source is None and asset.business_app_id is not None)


def attribute_assets(db: Session, organization_id: int, assets: Optional[Iterable[Asset]] = None) -> Dict[str, Any]:
    """Match assets to the CIs that run an application service or business
    application. Updates assets whose link was made automatically or never
    made; leaves manual links alone. The caller commits."""
    services = {
        s.id: s for s in db.query(ApplicationService).filter(ApplicationService.organization_id == organization_id)
    }
    by_host: Dict[str, List[CmdbCiLink]] = {}
    by_ip: Dict[str, List[CmdbCiLink]] = {}
    for link in db.query(CmdbCiLink).filter(CmdbCiLink.organization_id == organization_id):
        if link.fqdn:
            by_host.setdefault(link.fqdn, []).append(link)
        if link.ip_address:
            by_ip.setdefault(link.ip_address, []).append(link)

    if assets is None:
        assets = db.query(Asset).filter(Asset.organization_id == organization_id).all()

    stats = {"linked": 0, "unlinked": 0, "unchanged": 0, "manual": 0, "by_source": {}}
    for asset in assets:
        if is_manual(asset):
            stats["manual"] += 1
            continue
        host, ip = asset_keys(asset.value)
        candidates = (by_host.get(host, []) if host else []) + (by_ip.get(ip, []) if ip else [])
        if not candidates:
            if asset.app_link_source in AUTO_SOURCES and _assign(
                asset, app_service_id=None, business_app_id=None, app_link_source=None, app_link_detail=None
            ):
                stats["unlinked"] += 1
            continue
        candidates.sort(key=lambda l: (RELATION_PRIORITY[l.relation], l.id or 0))
        best = candidates[0]
        svc = services.get(best.app_service_id) if best.app_service_id else None
        app_id = best.business_app_id or (svc.business_app_id if svc else None)
        targets = {(l.app_service_id, l.business_app_id) for l in candidates}
        changed = _assign(
            asset,
            app_service_id=svc.id if svc else None,
            business_app_id=app_id,
            app_link_source=best.relation,
            app_link_detail=_detail(best, len(targets) - 1),
        )
        stats["linked" if changed else "unchanged"] += 1
        stats["by_source"][best.relation] = stats["by_source"].get(best.relation, 0) + 1
    return stats
