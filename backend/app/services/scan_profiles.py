"""Reusable scan-profile helpers."""

from sqlalchemy import or_
from sqlalchemy.orm import Query, Session

from app.models.scan_profile import ScanProfile


def profile_config(profile: ScanProfile) -> dict:
    config = {
        "profile_id": profile.id,
        "profile_name": profile.name,
        "severity": list(profile.nuclei_severity or []),
        "tags": list(profile.nuclei_tags or []),
        "exclude_tags": list(profile.nuclei_exclude_tags or []),
        "templates": list(profile.nuclei_templates or []),
        "rate_limit": profile.nuclei_rate_limit,
        "bulk_size": profile.nuclei_bulk_size,
        "concurrency": profile.nuclei_concurrency,
        "timeout": profile.nuclei_timeout,
        "top_ports": profile.port_scan_top,
        "ports": ",".join(str(port) for port in (profile.port_scan_custom or [])),
        "max_concurrent_hosts": profile.max_concurrent_hosts,
        "requests_per_second": profile.requests_per_second,
        "enable_subdomain_enum": profile.enable_subdomain_enum,
        "enable_port_scan": profile.enable_port_scan,
        "enable_http_probe": profile.enable_http_probe,
        "enable_technology_detection": profile.enable_technology_detection,
        "enable_vulnerability_scan": profile.enable_vulnerability_scan,
    }
    return {key: value for key, value in config.items() if value not in (None, [], "")}


def profiles_visible_to_organization(query: Query, organization_id: int) -> Query:
    """Limit a profile query to built-ins plus profiles owned by one tenant."""
    return query.filter(
        or_(
            ScanProfile.organization_id.is_(None),
            ScanProfile.organization_id == organization_id,
        )
    )


def get_visible_scan_profile(
    db: Session,
    profile_id: int,
    organization_id: int,
    *,
    active_only: bool = True,
) -> ScanProfile | None:
    """Resolve a profile without ever crossing an organization boundary."""
    query = profiles_visible_to_organization(
        db.query(ScanProfile).filter(ScanProfile.id == profile_id),
        organization_id,
    )
    if active_only:
        query = query.filter(ScanProfile.is_active.is_(True))
    return query.first()
