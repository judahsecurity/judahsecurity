"""Build observed hostname/IP links for an asset list without guessing origins."""

import ipaddress
from collections import defaultdict

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType


def _valid_ip(value: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(value or ""))
    except (ValueError, TypeError):
        return None


def _hostname(asset: Asset) -> str:
    value = (asset.value or "").strip().lower().rstrip(".")
    if asset.asset_type == AssetType.URL:
        from urllib.parse import urlsplit

        return (urlsplit(value if "://" in value else f"https://{value}").hostname or "").rstrip(".")
    return value


def _ip_role(ip_asset: Asset | None) -> str:
    if ip_asset and (
        (ip_asset.hosting_type or "").lower() == "cdn"
        or (ip_asset.hosting_provider or "").lower() in {"cloudflare", "akamai"}
    ):
        return "cdn_edge"
    return "observed"


def standalone_asset_filter():
    """Keep owned/direct IP assets, but collapse non-owned DNS children and CDN edges."""
    related_ip = and_(
        Asset.asset_type == AssetType.IP_ADDRESS,
        Asset.is_owned.isnot(True),
        or_(
            and_(Asset.resolved_from.isnot(None), Asset.resolved_from != ""),
            func.lower(func.coalesce(Asset.hosting_type, "")) == "cdn",
            func.lower(func.coalesce(Asset.hosting_provider, "")).in_(("cloudflare", "akamai")),
        ),
    )
    return ~related_ip


def batch_ip_relationships(db: Session, assets: list[Asset]) -> dict[int, list[dict]]:
    """Use stored DNS answers and discovery links; never infer an origin IP."""
    if not assets:
        return {}

    host_assets = [
        asset for asset in assets
        if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL)
    ]
    host_ids = {asset.id for asset in host_assets}
    host_org_by_id = {asset.id: asset.organization_id for asset in host_assets}
    host_keys: dict[tuple[int, str], set[int]] = defaultdict(set)
    for asset in host_assets:
        host_keys[(asset.organization_id, _hostname(asset))].add(asset.id)
    stored_ips = {
        ip
        for asset in host_assets
        for raw in [*(asset.ip_addresses or []), asset.ip_address]
        if (ip := _valid_ip(raw))
    }
    org_ids = {asset.organization_id for asset in assets}
    clauses = []
    if host_ids:
        clauses.append(Asset.parent_id.in_(host_ids))
    if host_keys:
        clauses.append(Asset.resolved_from.in_([key[1] for key in host_keys]))
    if stored_ips:
        clauses.append(Asset.value.in_(stored_ips))

    ip_assets = (
        db.query(Asset)
        .filter(
            Asset.organization_id.in_(org_ids),
            Asset.asset_type == AssetType.IP_ADDRESS,
            or_(*clauses),
        )
        .all()
        if clauses else []
    )
    by_ip = {(asset.organization_id, _valid_ip(asset.value)): asset for asset in ip_assets}
    linked: dict[int, set[str]] = defaultdict(set)
    for ip_asset in ip_assets:
        ip = _valid_ip(ip_asset.value)
        if not ip:
            continue
        if ip_asset.parent_id in host_ids and host_org_by_id[ip_asset.parent_id] == ip_asset.organization_id:
            linked[ip_asset.parent_id].add(ip)
        for host_id in host_keys.get((ip_asset.organization_id, (ip_asset.resolved_from or "").lower().rstrip(".")), ()):
            linked[host_id].add(ip)

    result: dict[int, list[dict]] = {}
    for asset in assets:
        if asset.asset_type == AssetType.IP_ADDRESS:
            ips = {_valid_ip(asset.value)}
        else:
            ips = {
                _valid_ip(raw)
                for raw in [*(asset.ip_addresses or []), asset.ip_address]
            } | linked[asset.id]
        relationships = []
        for ip in sorted(ip for ip in ips if ip):
            ip_asset = by_ip.get((asset.organization_id, ip))
            relationships.append({
                "ip": ip,
                "role": _ip_role(ip_asset),
                "provider": ip_asset.hosting_provider if ip_asset else None,
                "source": "dns_or_discovery" if asset.asset_type != AssetType.IP_ADDRESS else "ip_asset",
            })
        result[asset.id] = relationships
    return result
