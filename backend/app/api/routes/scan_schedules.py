"""Scan Schedule API routes for continuous monitoring."""

from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.scan_schedule import ScanSchedule, ScheduleFrequency, CONTINUOUS_SCAN_TYPES, CRITICAL_PORTS, ALL_CRITICAL_PORTS, ICS_OT_PORTS, ALL_ICS_OT_PORTS
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType
from app.models.label import Label
from app.models.user import User
from app.models.netblock import Netblock
from app.schemas.scan_schedule import (
    ScanScheduleCreate,
    ScanScheduleUpdate,
    ScanScheduleResponse,
    ScanScheduleSummary,
    ManualTriggerRequest,
)
from app.api.deps import get_current_active_user, require_analyst
import ipaddress
import re

router = APIRouter(prefix="/scan-schedules", tags=["Scan Schedules"])

# Scan types that require IPv4 only (don't support IPv6)
IPV4_ONLY_SCAN_TYPES = [
    "port_scan", "masscan", "critical_ports", 
    "http_probe", "screenshot", "login_portal",
    "nuclei", "nuclei_critical", "nuclei_high", "nuclei_critical_high",
    "nuclei_medium", "nuclei_low_info", "nuclei_ics", "vulnerability", "technology",
    "katana", "paramspider", "waybackurls",
    # ICS/OT scan types
    "ics_ot_ports", "ics_plc_scan", "ics_scada_scan", 
    "ics_building_automation", "ics_full_discovery",
]


def filter_ipv6_targets(targets: List[str], scan_type: str) -> tuple:
    """
    Filter out IPv6 targets for scan types that don't support them.
    
    Returns: (filtered_targets, ipv6_skipped_count)
    """
    if scan_type not in IPV4_ONLY_SCAN_TYPES:
        return targets, 0
    
    filtered = []
    ipv6_count = 0
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
        
        # Quick check for IPv6 (contains colon but isn't a URL port)
        if ':' in target:
            # IPv6 addresses have multiple colons or are in brackets
            if target.count(':') > 1 or target.startswith('['):
                ipv6_count += 1
                continue
        
        # For CIDRs, check if IPv6
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.version == 6:
                    ipv6_count += 1
                    continue
            except ValueError:
                pass  # Not a valid CIDR
        
        filtered.append(target)
    
    return filtered, ipv6_count


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True


def calculate_target_stats(targets: List[str]) -> dict:
    """
    Calculate statistics for targets including total IPs from CIDR blocks.
    
    Returns:
        {
            "targets_original": number of target entries,
            "targets_expanded": total number of IPs/hosts,
            "cidr_count": number of CIDR ranges,
            "host_count": number of individual hosts/domains
        }
    """
    total_ips = 0
    cidr_count = 0
    host_count = 0
    
    cidr_pattern = re.compile(r'^[\d.:a-fA-F]+/\d+$')
    
    for target in targets:
        target = target.strip()
        if not target:
            continue
            
        # Check if it's a CIDR notation
        if cidr_pattern.match(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
                total_ips += network.num_addresses
                cidr_count += 1
            except ValueError:
                # Invalid CIDR, count as 1
                total_ips += 1
                host_count += 1
        else:
            # It's a domain, subdomain, or single IP
            total_ips += 1
            host_count += 1
    
    return {
        "targets_original": len(targets),
        "targets_expanded": total_ips,
        "cidr_count": cidr_count,
        "host_count": host_count
    }


def check_org_access_complete(user: User, org_id: int) -> bool:
    """Check if user has access to organization (complete version)."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.get("/scan-types")
def get_available_scan_types():
    """Get available scan types for continuous monitoring."""
    return CONTINUOUS_SCAN_TYPES


@router.get("/critical-ports")
def get_critical_ports():
    """Get the list of critical ports monitored by the system."""
    return {
        "categories": CRITICAL_PORTS,
        "all_ports": ALL_CRITICAL_PORTS,
        "total_count": len(ALL_CRITICAL_PORTS),
        "description": "These ports are monitored for exposure and generate security findings when found open."
    }


@router.get("/ics-ot-ports")
def get_ics_ot_ports():
    """
    Get the list of ICS/OT/SCADA ports monitored by the system.
    
    These are industrial control system ports that should NEVER be exposed
    to untrusted networks. Exposure indicates critical infrastructure risk.
    """
    return {
        "categories": ICS_OT_PORTS,
        "all_ports": ALL_ICS_OT_PORTS,
        "total_count": len(ALL_ICS_OT_PORTS),
        "description": "Industrial Control System and Operational Technology ports. Exposure is a CRITICAL finding.",
        "compliance_frameworks": [
            "NERC CIP (Power Grid)",
            "IEC 62443 (Industrial Automation)",
            "NIST SP 800-82 (ICS Security)",
            "TSA Security Directive (Pipelines)",
        ],
        "port_details": {
            "102": "Siemens S7comm (Stuxnet targeted)",
            "502": "Modbus/TCP (No authentication)",
            "20000": "DNP3 (SCADA/Utilities)",
            "44818": "EtherNet/IP (Rockwell/Allen-Bradley)",
            "47808": "BACnet (Building Automation)",
            "2404": "IEC 60870-5-104 (Power Grid)",
            "4840": "OPC UA (Industrial Data)",
            "9600": "OMRON FINS",
            "5007": "Mitsubishi MELSEC",
        }
    }


@router.get("/", response_model=List[ScanScheduleResponse])
def list_scan_schedules(
    organization_id: Optional[int] = None,
    scan_type: Optional[str] = None,
    is_enabled: Optional[bool] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List scan schedules with filtering options."""
    query = db.query(ScanSchedule)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(ScanSchedule.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return []
        query = query.filter(ScanSchedule.organization_id == current_user.organization_id)
    
    if scan_type:
        query = query.filter(ScanSchedule.scan_type == scan_type)
    if is_enabled is not None:
        query = query.filter(ScanSchedule.is_enabled == is_enabled)
    
    schedules = query.order_by(ScanSchedule.created_at.desc()).offset(skip).limit(limit).all()
    return schedules


@router.get("/summary", response_model=ScanScheduleSummary)
def get_schedules_summary(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get summary statistics for scan schedules."""
    query = db.query(ScanSchedule)
    
    if organization_id:
        if not check_org_access(current_user, organization_id):
            raise HTTPException(status_code=403, detail="Access denied")
        query = query.filter(ScanSchedule.organization_id == organization_id)
    elif current_user.organization_id:
        query = query.filter(ScanSchedule.organization_id == current_user.organization_id)
    
    schedules = query.all()
    
    enabled = [s for s in schedules if s.is_enabled]
    
    # Group by type
    by_type = {}
    for s in schedules:
        by_type[s.scan_type] = by_type.get(s.scan_type, 0) + 1
    
    # Group by frequency
    by_freq = {}
    for s in schedules:
        by_freq[s.frequency.value] = by_freq.get(s.frequency.value, 0) + 1
    
    # Get upcoming scans (next 24 hours)
    now = datetime.now(timezone.utc)
    upcoming = []
    for s in enabled:
        if s.next_run_at and s.next_run_at > now:
            upcoming.append({
                "id": s.id,
                "name": s.name,
                "scan_type": s.scan_type,
                "next_run_at": s.next_run_at.isoformat(),
            })
    
    upcoming.sort(key=lambda x: x["next_run_at"])
    
    return {
        "total_schedules": len(schedules),
        "enabled_schedules": len(enabled),
        "disabled_schedules": len(schedules) - len(enabled),
        "schedules_by_type": by_type,
        "schedules_by_frequency": by_freq,
        "upcoming_scans": upcoming[:10],
    }


@router.post("/", response_model=ScanScheduleResponse, status_code=status.HTTP_201_CREATED)
def create_scan_schedule(
    schedule_data: ScanScheduleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new scan schedule for continuous monitoring."""
    if not check_org_access(current_user, schedule_data.organization_id):
        raise HTTPException(status_code=403, detail="Access denied to this organization")
    
    # Validate scan type
    if schedule_data.scan_type not in CONTINUOUS_SCAN_TYPES:
        valid_types = list(CONTINUOUS_SCAN_TYPES.keys())
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan type. Valid types: {valid_types}"
        )
    
    schedule = ScanSchedule(
        name=schedule_data.name,
        description=schedule_data.description,
        organization_id=schedule_data.organization_id,
        scan_type=schedule_data.scan_type,
        targets=schedule_data.targets,
        label_ids=schedule_data.label_ids,
        match_all_labels=schedule_data.match_all_labels,
        config=schedule_data.config or CONTINUOUS_SCAN_TYPES[schedule_data.scan_type].get("default_config", {}),
        frequency=schedule_data.frequency,
        run_at_hour=schedule_data.run_at_hour,
        run_on_day=schedule_data.run_on_day,
        cron_expression=schedule_data.cron_expression,
        timezone=schedule_data.timezone,
        is_enabled=schedule_data.is_enabled,
        notify_on_completion=schedule_data.notify_on_completion,
        notify_on_findings=schedule_data.notify_on_findings,
        notification_emails=schedule_data.notification_emails,
        created_by=current_user.username,
    )
    
    # Calculate next run time
    schedule.next_run_at = schedule.calculate_next_run()
    
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    
    return schedule


@router.get("/{schedule_id}", response_model=ScanScheduleResponse)
def get_scan_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a single scan schedule by ID."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    return schedule


@router.put("/{schedule_id}", response_model=ScanScheduleResponse)
def update_scan_schedule(
    schedule_id: int,
    schedule_data: ScanScheduleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update a scan schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Update fields
    update_data = schedule_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(schedule, field, value)
    
    # Recalculate next run if frequency changed
    if any(f in update_data for f in ['frequency', 'run_at_hour', 'run_on_day']):
        schedule.next_run_at = schedule.calculate_next_run()
    
    db.commit()
    db.refresh(schedule)
    
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a scan schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db.delete(schedule)
    db.commit()


@router.post("/{schedule_id}/toggle", response_model=ScanScheduleResponse)
def toggle_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Enable or disable a scan schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    schedule.is_enabled = not schedule.is_enabled
    
    if schedule.is_enabled:
        schedule.next_run_at = schedule.calculate_next_run()
        schedule.consecutive_failures = 0
        schedule.last_error = None
    
    db.commit()
    db.refresh(schedule)
    
    return schedule


@router.post("/{schedule_id}/trigger", response_model=dict)
def trigger_scheduled_scan(
    schedule_id: int,
    request: Optional[ManualTriggerRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Manually trigger a scheduled scan immediately."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build targets from various sources
    targets = []
    
    # 1. Check for override targets from manual trigger
    if request and request.override_targets:
        targets = request.override_targets
    
    # 2. Check for explicit targets on the schedule
    elif schedule.targets:
        targets = schedule.targets
    
    # 3. Check for label-based targeting
    elif schedule.label_ids:
        query = db.query(Asset).filter(
            Asset.organization_id == schedule.organization_id,
            Asset.in_scope == True
        )
        
        if schedule.match_all_labels:
            for label_id in schedule.label_ids:
                query = query.filter(Asset.labels.any(Label.id == label_id))
        else:
            query = query.filter(Asset.labels.any(Label.id.in_(schedule.label_ids)))
        
        assets = query.distinct().all()
        targets = [a.value for a in assets]
    
    # 4. If no explicit targets, use ALL in-scope assets and netblocks for the organization
    else:
        # Domain-oriented scans (subdomain enumeration, domain discovery) only
        # make sense against domain assets — skip IPs / netblocks.
        domain_scoped = schedule.scan_type in ("subdomain_enum", "discovery", "full_discovery")
        if domain_scoped:
            asset_type_filter = [AssetType.DOMAIN, AssetType.SUBDOMAIN]
        else:
            asset_type_filter = [
                AssetType.DOMAIN,
                AssetType.SUBDOMAIN,
                AssetType.IP_ADDRESS,
                AssetType.IP_RANGE,
            ]

        assets = db.query(Asset).filter(
            Asset.organization_id == schedule.organization_id,
            Asset.in_scope == True,
            Asset.asset_type.in_(asset_type_filter)
        ).all()

        # Get all in-scope netblocks (CIDR ranges from WhoisXML, etc.) — not for
        # domain-oriented scans.
        netblocks = [] if domain_scoped else db.query(Netblock).filter(
            Netblock.organization_id == schedule.organization_id,
            Netblock.in_scope == True
        ).all()
        
        # Collect targets
        asset_targets = [a.value for a in assets]
        
        # Add CIDR notations from netblocks
        netblock_targets = []
        for nb in netblocks:
            if nb.cidr_notation:
                # Handle multiple CIDRs (semicolon or comma-separated)
                for sep in [';', ',']:
                    if sep in nb.cidr_notation:
                        cidrs = [c.strip() for c in nb.cidr_notation.split(sep) if c.strip()]
                        netblock_targets.extend(cidrs)
                        break
                else:
                    netblock_targets.append(nb.cidr_notation.strip())
        
        # Combine and deduplicate
        targets = list(set(asset_targets + netblock_targets))
    
    # Filter out IPv6 targets for scan types that don't support them
    original_count = len(targets)
    targets, ipv6_skipped = filter_ipv6_targets(targets, schedule.scan_type)
    
    if not targets:
        if ipv6_skipped > 0:
            raise HTTPException(
                status_code=400,
                detail=f"No valid targets after filtering {ipv6_skipped} IPv6 addresses (IPv6 not supported for {schedule.scan_type})"
            )
        raise HTTPException(
            status_code=400,
            detail="No targets found for this schedule. Run discovery first to populate assets and netblocks."
        )
    
    # Map schedule scan_type to ScanType enum
    scan_type_map = {
        "nuclei": ScanType.VULNERABILITY,
        "nuclei_critical": ScanType.VULNERABILITY,
        "nuclei_high": ScanType.VULNERABILITY,
        "nuclei_critical_high": ScanType.VULNERABILITY,
        "nuclei_medium": ScanType.VULNERABILITY,
        "nuclei_low_info": ScanType.VULNERABILITY,
        "nuclei_ics": ScanType.VULNERABILITY,
        "port_scan": ScanType.PORT_SCAN,
        "masscan": ScanType.PORT_SCAN,
        "critical_ports": ScanType.PORT_SCAN,
        "ics_ot_ports": ScanType.PORT_SCAN,
        "ics_plc_scan": ScanType.PORT_SCAN,
        "ics_scada_scan": ScanType.PORT_SCAN,
        "ics_building_automation": ScanType.PORT_SCAN,
        "ics_full_discovery": ScanType.PORT_SCAN,
        "discovery": ScanType.DISCOVERY,
        "full_discovery": ScanType.DISCOVERY,
        "screenshot": ScanType.SCREENSHOT,
        "technology": ScanType.TECHNOLOGY,
        "whatweb": ScanType.WHATWEB,
        "http_probe": ScanType.HTTP_PROBE,
        "dns_resolution": ScanType.DNS_RESOLUTION,
        "subdomain_enum": ScanType.SUBDOMAIN_ENUM,
        "login_portal": ScanType.LOGIN_PORTAL,
        "paramspider": ScanType.PARAMSPIDER,
        "waybackurls": ScanType.WAYBACKURLS,
        "katana": ScanType.KATANA,
        "cleanup": ScanType.CLEANUP,
    }
    
    if schedule.scan_type not in scan_type_map:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown schedule scan_type '{schedule.scan_type}'",
        )
    scan_type = scan_type_map[schedule.scan_type]
    
    # Build config — merge profile defaults so ICS NSE/ports survive thin configs
    profile_defaults = CONTINUOUS_SCAN_TYPES.get(schedule.scan_type, {}).get("default_config", {})
    config = {
        **profile_defaults,
        **(schedule.config or {}),
        **(request.override_config if request and request.override_config else {}),
        "triggered_by_schedule": schedule.id,
        "schedule_name": schedule.name,
        "schedule_scan_type": schedule.scan_type,
    }
    
    # For critical_ports scans, use masscan for speed on CIDR blocks
    if schedule.scan_type == "critical_ports":
        config["ports"] = ",".join(str(p) for p in ALL_CRITICAL_PORTS)
        config["generate_findings"] = True
        config["scanner"] = config.get("scanner", "masscan")  # Masscan is faster for CIDR blocks
        config["rate"] = config.get("rate", 10000)  # 10k packets/sec default

    ics_port_types = {
        "ics_ot_ports", "ics_plc_scan", "ics_scada_scan",
        "ics_building_automation", "ics_full_discovery",
    }
    if schedule.scan_type in ics_port_types:
        config["generate_findings"] = True
        if schedule.scan_type in ("ics_ot_ports", "ics_full_discovery"):
            config["ports"] = config.get("ports") or ",".join(str(p) for p in ALL_ICS_OT_PORTS)
        if schedule.scan_type == "ics_ot_ports":
            config["scanner"] = config.get("scanner", "masscan")
            config["rate"] = config.get("rate", 5000)
        elif schedule.scan_type == "ics_full_discovery":
            config["scanner"] = config.get("scanner", "nmap")
            config["rate"] = config.get("rate", 500)
            config["run_nuclei"] = config.get("run_nuclei", True)
            if not config.get("nuclei_tags") and not config.get("tags"):
                config["nuclei_tags"] = ["ics", "scada"]
    
    # Calculate target statistics (total IPs from CIDRs, etc.)
    target_stats = calculate_target_stats(targets)
    target_stats["ipv6_skipped"] = ipv6_skipped
    config["target_stats"] = target_stats
    
    scan = Scan(
        name=f"{schedule.name} - Manual Trigger",
        scan_type=scan_type,
        organization_id=schedule.organization_id,
        targets=targets,
        config=config,
        started_by=current_user.username,
        status=ScanStatus.PENDING,
        # Pre-populate results with target stats for immediate display
        results={
            "targets_original": target_stats["targets_original"],
            "targets_expanded": target_stats["targets_expanded"],
            "cidr_count": target_stats["cidr_count"],
            "host_count": target_stats["host_count"],
            "ipv6_skipped": ipv6_skipped,
        }
    )
    
    db.add(scan)
    
    # Update schedule
    schedule.last_run_at = datetime.now(timezone.utc)
    schedule.run_count += 1
    
    db.commit()
    db.refresh(scan)
    
    # Build message with IPv6 info if any were skipped
    message = f"Scan '{scan.name}' created with {target_stats['targets_expanded']:,} IPs from {target_stats['targets_original']} targets"
    if ipv6_skipped > 0:
        message += f" ({ipv6_skipped} IPv6 targets skipped)"
    
    return {
        "success": True,
        "scan_id": scan.id,
        "targets_count": target_stats["targets_original"],
        "total_ips": target_stats["targets_expanded"],
        "cidr_count": target_stats["cidr_count"],
        "host_count": target_stats["host_count"],
        "ipv6_skipped": ipv6_skipped,
        "message": message,
    }


@router.get("/{schedule_id}/history")
def get_schedule_history(
    schedule_id: int,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get scan history for a schedule."""
    schedule = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    
    if not check_org_access(current_user, schedule.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get scans triggered by this schedule
    # Use PostgreSQL JSONB ->> operator for text extraction
    from sqlalchemy import cast, String
    scans = db.query(Scan).filter(
        Scan.organization_id == schedule.organization_id,
        cast(Scan.config["triggered_by_schedule"], String) == str(schedule_id)
    ).order_by(Scan.created_at.desc()).limit(limit).all()
    
    return {
        "schedule_id": schedule_id,
        "schedule_name": schedule.name,
        "total_runs": schedule.run_count,
        "scans": [
            {
                "id": s.id,
                "name": s.name,
                "status": s.status.value,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "assets_discovered": s.assets_discovered,
                "vulnerabilities_found": s.vulnerabilities_found,
            }
            for s in scans
        ]
    }




