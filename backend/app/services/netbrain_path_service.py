"""On-demand NetBrain calculated path evidence for exact asset pairs."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.netbrain_integration import NetBrainIntegration
from app.models.netbrain_path import NetBrainPath
from app.services.netbrain_service import _asset_candidates, _client_for
from app.services.graph_ip_identity import graph_ip_identity


class PathSelectionError(ValueError):
    def __init__(self, message: str, *, status_code: int = 422,
                 options: list[dict] | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.options = options


def _asset_ip(db: Session, org_id: int, asset_id: int, requested: str | None) -> tuple[Asset, str]:
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.organization_id == org_id).first()
    if asset is None:
        raise PathSelectionError(f"Asset {asset_id} was not found in this organization.", status_code=404)
    ips, _ = _asset_candidates(asset)
    ipv4 = sorted({ip for ip in ips if ipaddress.ip_address(ip).version == 4})
    if requested:
        try:
            chosen = str(ipaddress.ip_address(requested.strip()))
        except ValueError as exc:
            raise PathSelectionError("Select a valid IPv4 address.") from exc
        if chosen not in ipv4:
            raise PathSelectionError("Selected IPv4 address is not recorded on that asset.")
    elif len(ipv4) == 1:
        chosen = ipv4[0]
    elif not ipv4:
        raise PathSelectionError("The asset has no recorded IPv4 address.")
    else:
        raise PathSelectionError("The asset has multiple IPv4 addresses; select one.", status_code=409,
                                 options=[{"ip": ip} for ip in ipv4[:50]])
    return asset, chosen


def _gateway(gateways: list[dict[str, Any]], requested: dict[str, Any]) -> tuple[str, str, str]:
    valid: set[tuple[str, str, str]] = set()
    for item in gateways:
        try:
            ip = str(ipaddress.ip_address(str(item.get("ip") or "")))
        except ValueError:
            continue
        device = str(item.get("devName") or "").strip()
        interface = str(item.get("intfName") or "").strip()
        if ipaddress.ip_address(ip).version == 4 and device and interface:
            valid.add((ip, device, interface))
    if requested.get("gateway_ip"):
        try:
            selected_ip = str(ipaddress.ip_address(str(requested["gateway_ip"]).strip()))
        except ValueError as exc:
            raise PathSelectionError("Select a valid gateway IPv4 address.") from exc
        choice = (selected_ip, str(requested["gateway_device"]).strip(),
                  str(requested["gateway_interface"]).strip())
        if choice not in valid:
            raise PathSelectionError("Selected gateway is not in NetBrain's gateway list.", status_code=409,
                                     options=[{"ip": ip, "device": dev, "interface": intf}
                                              for ip, dev, intf in sorted(valid)[:50]])
        return choice
    if len(valid) != 1:
        raise PathSelectionError("Choose a source gateway from NetBrain's gateway list.", status_code=409,
                                 options=[{"ip": ip, "device": dev, "interface": intf}
                                          for ip, dev, intf in sorted(valid)[:50]])
    return next(iter(valid))


async def start_calculation(db: Session, integration: NetBrainIntegration,
                            values: dict[str, Any]) -> NetBrainPath:
    org_id = integration.organization_id
    if values["source_asset_id"] == values["target_asset_id"]:
        raise PathSelectionError("Choose two distinct assets.")
    source, source_ip = _asset_ip(db, org_id, values["source_asset_id"], values.get("source_ip"))
    target, target_ip = _asset_ip(db, org_id, values["target_asset_id"], values.get("target_ip"))
    if source_ip == target_ip:
        raise PathSelectionError(
            "NetBrain cannot distinguish the requested assets by this shared IPv4 address; "
            "select distinct recorded addresses.", status_code=409
        )
    async with _client_for(integration) as client:
        gateway_ip, gateway_device, gateway_interface = _gateway(
            await client.get_path_gateways(source_ip), values
        )
        task_id = await client.start_path_calculation({
            "sourceIP": source_ip,
            "sourcePort": 0,
            "sourceGwIP": gateway_ip,
            "sourceGwDev": gateway_device,
            "sourceGwIntf": gateway_interface,
            "destIP": target_ip,
            "destPort": values["destination_port"],
            "pathAnalysisSet": 1,
            "protocol": values["protocol"],
            "isLive": 1 if values["is_live"] else 0,
        })
    path = NetBrainPath(
        organization_id=org_id, integration_id=integration.id,
        source_integration_id=integration.id, task_id=task_id,
        source_asset_id=source.id, target_asset_id=target.id,
        source_ip=source_ip, target_ip=target_ip,
        source_scope_id=graph_ip_identity(source_ip, org_id, source).scope_id,
        target_scope_id=graph_ip_identity(target_ip, org_id, target).scope_id,
        tenant_id=integration.tenant_id, domain_id=integration.domain_id,
        gateway_ip=gateway_ip, gateway_device=gateway_device,
        gateway_interface=gateway_interface, protocol=values["protocol"],
        destination_port=values["destination_port"], is_live=values["is_live"],
        status="pending", hop_list=[],
    )
    db.add(path)
    db.commit()
    db.refresh(path)
    return path


def _clean_hops(raw_hops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hops = []
    ids = set()
    for item in raw_hops:
        hop_id = str(item.get("hopId") or "").strip()[:128]
        if not hop_id or hop_id in ids:
            continue
        ids.add(hop_id)
        next_ids = item.get("nextHopIdList")
        hops.append({
            "hop_id": hop_id,
            "source_device": str(item.get("srcDeviceName") or "")[:255],
            "target_device": str(item.get("dstDeviceName") or "")[:255],
            "inbound_interface": str(item.get("inboundInterface") or "")[:255],
            "outbound_interface": str(item.get("outboundInterface") or "")[:255],
            "next_hop_ids": [str(value)[:128] for value in next_ids[:100]]
                if isinstance(next_ids, list) else [],
        })
    return hops


async def refresh_calculation(db: Session, integration: NetBrainIntegration,
                              path: NetBrainPath) -> NetBrainPath:
    if path.status in ("succeeded", "failed", "canceled", "inconclusive"):
        return path
    async with _client_for(integration) as client:
        code = await client.get_path_status(path.task_id)
        hops = _clean_hops(await client.get_path_hops(path.task_id)) if code == 2 else []
    if code == 2:
        path.status = "succeeded" if hops else "inconclusive"
        path.hop_list = hops
        path.completed_at = datetime.utcnow()
    elif code in (3, 4):
        path.status = "failed" if code == 3 else "canceled"
        path.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(path)
    return path
