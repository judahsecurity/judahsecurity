"""Deterministic CVE exploitation and detection timeline composition."""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from typing import Any, Iterable

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.custom_nuclei_template import CustomNucleiTemplate
from app.models.vulnerability import Vulnerability


_KIND_ORDER = {
    "cve_published": 10,
    "cve_modified": 20,
    "public_exploit_released": 30,
    "known_exploited_added": 40,
    "ransomware_activity_reported": 50,
    "detection_authored": 60,
    "detection_available": 70,
    "detection_enabled": 80,
    "first_asset_detected": 90,
    "remediation_due": 100,
}


def resolve_organization_id(current_user: Any, requested_id: int | None) -> int | None:
    """Resolve a request tenant without allowing cross-organization selection."""
    if getattr(current_user, "is_superuser", False):
        return requested_id
    user_org = getattr(current_user, "organization_id", None)
    if user_org is None:
        raise HTTPException(status_code=403, detail="Your account is not assigned to an organization")
    if requested_id is not None and requested_id != user_org:
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    return user_org


def normalize_timestamp(value: Any) -> str | None:
    """Return an RFC3339 UTC timestamp, or None when the source has no date."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime(value.year, value.month, value.day)
    else:
        raw = str(value).strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y/%m/%d", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event(
    *,
    cve_id: str,
    kind: str,
    category: str,
    timestamp: Any,
    title: str,
    source_id: str,
    source_label: str,
    description: str | None = None,
    source_url: str | None = None,
    deadline: bool = False,
    scope: str = "global",
    metadata: dict[str, Any] | None = None,
    identity: str = "",
) -> dict[str, Any] | None:
    normalized = normalize_timestamp(timestamp)
    if not normalized:
        return None
    safe_metadata = {k: v for k, v in (metadata or {}).items() if v not in (None, "", [])}
    stable = json.dumps(
        [cve_id.upper(), kind, source_id, normalized, identity, scope],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    source = {"id": source_id, "label": source_label}
    if source_url:
        source["url"] = source_url
    return {
        "id": f"intel_{hashlib.sha256(stable.encode()).hexdigest()[:20]}",
        "kind": kind,
        "category": category,
        "timestamp": normalized,
        "title": title,
        "description": description,
        "source": source,
        "deadline": deadline,
        "scope": scope,
        "metadata": safe_metadata,
    }


def _append(events: list[dict[str, Any]], event: dict[str, Any] | None) -> None:
    if event:
        events.append(event)


def external_intel_events(
    cve_id: str,
    catalog: dict[str, Any] | None,
    exploitation: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Map trustworthy upstream dates to typed events; undated claims are omitted."""
    cve = cve_id.upper()
    catalog = catalog or {}
    exploitation = exploitation or {}
    events: list[dict[str, Any]] = []

    nvd = catalog.get("nvd") or {}
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve}"
    _append(events, _event(cve_id=cve, kind="cve_published", category="publication",
        timestamp=nvd.get("published"), title="CVE published", source_id="nvd",
        source_label="NVD", source_url=nvd_url))
    _append(events, _event(cve_id=cve, kind="cve_modified", category="modification",
        timestamp=nvd.get("last_modified"), title="CVE record modified", source_id="nvd",
        source_label="NVD", source_url=nvd_url))

    cisa = exploitation.get("cisa") or {}
    cisa_added = cisa.get("dateAdded") or cisa.get("date_added")
    ransomware = str(cisa.get("knownRansomwareCampaignUse") or cisa.get("known_ransomware_use") or "")
    cisa_description = "Added to the CISA Known Exploited Vulnerabilities catalog."
    if ransomware.lower() in {"known", "yes"}:
        cisa_description += " CISA associates this CVE with known ransomware campaigns."
    _append(events, _event(cve_id=cve, kind="known_exploited_added", category="exploitation",
        timestamp=cisa_added, title="CISA confirmed known exploitation", description=cisa_description,
        source_id="cisa_kev", source_label="CISA KEV",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        metadata={"known_ransomware_use": ransomware or None}))
    _append(events, _event(cve_id=cve, kind="remediation_due", category="deadline",
        timestamp=cisa.get("dueDate") or cisa.get("due_date"), title="CISA remediation deadline",
        description=cisa.get("requiredAction") or cisa.get("required_action"),
        source_id="cisa_kev", source_label="CISA KEV",
        source_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", deadline=True))

    vulncheck = exploitation.get("vulncheck") or {}
    _append(events, _event(cve_id=cve, kind="known_exploited_added", category="exploitation",
        timestamp=vulncheck.get("date_added") or vulncheck.get("_timestamp"),
        title="VulnCheck reported exploitation", source_id="vulncheck_kev",
        source_label="VulnCheck KEV", source_url="https://vulncheck.com/advisories"))

    exploit_sources = catalog.get("exploit_sources") or {}
    source_specs = (
        ("poc_github", "PoC-in-GitHub", "pocs"),
        ("trickest", "trickest/cve", "pocs"),
        ("github_repos", "GitHub", "repos"),
    )
    for source_id, source_label, row_key in source_specs:
        for row in (exploit_sources.get(source_id) or {}).get(row_key) or []:
            if not isinstance(row, dict):
                continue
            reference = row.get("url")
            _append(events, _event(cve_id=cve, kind="public_exploit_released", category="exploitation",
                timestamp=row.get("created_at") or row.get("published_at"),
                title=f"Public exploit published via {source_label}",
                description=row.get("description"), source_id=source_id, source_label=source_label,
                source_url=reference, identity=str(row.get("full_name") or row.get("name") or reference or ""),
                metadata={"reference": reference, "provider": source_label}))
    return events


def _template_digest(template: CustomNucleiTemplate) -> str:
    return template.content_digest or hashlib.sha256((template.template_yaml or "").encode()).hexdigest()


def first_party_detection_events(
    db: Session,
    cve_id: str,
    organization_id: int | None,
) -> list[dict[str, Any]]:
    """Return only detection milestones visible to the selected organization."""
    if organization_id is None:
        return []
    cve = cve_id.upper()
    events: list[dict[str, Any]] = []
    templates = db.query(CustomNucleiTemplate).filter(
        CustomNucleiTemplate.organization_id == organization_id
    ).all()
    for template in templates:
        if cve not in {str(item).upper() for item in (template.cve_ids or [])}:
            continue
        digest = _template_digest(template)
        metadata = {
            "template_id": template.template_id,
            "template_name": template.name,
            "cve_id": cve,
            "version": digest[:12],
            "content_digest": f"sha256:{digest}",
            "provider": "Judah Nuclei",
            "reference": f"/nuclei-templates/{template.id}",
        }
        common = dict(cve_id=cve, source_id="judah_nuclei", source_label="Judah Nuclei",
                      scope="organization", metadata=metadata, identity=f"{organization_id}:{template.id}")
        _append(events, _event(kind="detection_authored", category="detection_authored",
            timestamp=template.created_at, title="Nuclei detection authored", **common))
        _append(events, _event(kind="detection_available", category="detection_available",
            timestamp=template.released_at, title="Nuclei detection released", **common))
        _append(events, _event(kind="detection_enabled", category="detection_enabled",
            timestamp=template.enabled_at, title="Nuclei detection enabled for organization", **common))

    first = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            func.upper(Vulnerability.cve_id) == cve,
            func.lower(func.coalesce(Vulnerability.detected_by, "")).like("%nuclei%"),
        )
        .order_by(Vulnerability.first_detected.asc(), Vulnerability.id.asc())
        .first()
    )
    if first:
        template_id = first.template_id or ""
        _append(events, _event(
            cve_id=cve, kind="first_asset_detected", category="asset_detected",
            timestamp=first.first_detected, title="First affected asset detected by Nuclei",
            description="First Nuclei finding for this CVE in the organization.",
            source_id="judah_nuclei", source_label="Judah Nuclei", scope="organization",
            identity=f"{organization_id}:{first.id}",
            metadata={"template_id": template_id or None, "cve_id": cve,
                      "provider": "Judah Nuclei"},
        ))
    return events


def order_and_dedupe(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    unique = {event["id"]: event for event in events if event and event.get("timestamp")}

    def key(event: dict[str, Any]) -> tuple[Any, ...]:
        return (event["timestamp"], _KIND_ORDER.get(event["kind"], 999),
                event["source"]["id"], event["id"])

    chronological = sorted(unique.values(), key=key)
    newest = sorted(unique.values(), key=lambda event: (
        -datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")).timestamp(),
        _KIND_ORDER.get(event["kind"], 999), event["source"]["id"], event["id"],
    ))
    return {"intel_updates": newest, "exploitation_timeline": chronological}


def build_cve_timeline(
    cve_id: str,
    catalog: dict[str, Any] | None,
    exploitation: dict[str, Any] | None,
    detection_events: Iterable[dict[str, Any]] = (),
) -> dict[str, list[dict[str, Any]]]:
    return order_and_dedupe([
        *external_intel_events(cve_id, catalog, exploitation),
        *detection_events,
    ])
