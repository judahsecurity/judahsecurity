"""Scan routes for ASM scan management."""

import os
import json
import logging
from typing import List, Optional, Dict
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session, defer

from app.db.database import get_db
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType
from app.models.label import Label
from app.models.user import User
from app.models.netblock import Netblock
from app.models.scan_schedule import CONTINUOUS_SCAN_TYPES, ALL_CRITICAL_PORTS, ALL_ICS_OT_PORTS
from app.schemas.scan import ScanCreate, ScanUpdate, ScanResponse, ScanByLabelRequest, BulkDomainScanRequest, AdhocScanRequest
from app.api.deps import get_current_active_user, require_analyst
from app.services.nuclei_service import count_cidr_targets

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])

# Keys safe to return on the scans list (polled frequently). Heavy arrays like
# host_results / ports_data / full targets blow up the UI after large OT scans.
_LIST_RESULT_SUMMARY_KEYS = (
    "ports_found",
    "ports_imported",
    "ports_updated",
    "live_hosts",
    "targets_scanned",
    "targets_original",
    "targets_expanded",
    "cidr_count",
    "host_count",
    "scanner",
    "duration_seconds",
    "findings_summary",
)
_DETAIL_TARGET_CAP = 200
_DETAIL_HOST_RESULTS_CAP = 500


def _slim_results_for_list(results: Optional[dict]) -> dict:
    """Keep only summary fields from scan.results for list responses."""
    if not results:
        return {}
    slim = {k: results[k] for k in _LIST_RESULT_SUMMARY_KEYS if k in results}
    errors = results.get("errors")
    if errors:
        if isinstance(errors, list):
            slim["error_count"] = len(errors)
            slim["errors"] = [str(e)[:300] for e in errors[:2]]
        else:
            slim["error_count"] = 1
            slim["errors"] = [str(errors)[:300]]
    # Count only — do not ship or walk host_results in list responses
    host_results = results.get("host_results")
    if isinstance(host_results, list):
        slim["host_results_count"] = len(host_results)
    return slim


def _scan_list_item(scan: Scan) -> dict:
    """Build a lightweight scan dict for GET /scans/ (no full targets/config)."""
    results = scan.results or {}
    slim_results = _slim_results_for_list(results)

    # Prefer stored expanded counts — never expand CIDRs across 10k+ target rows
    targets_count = (
        slim_results.get("targets_expanded")
        or slim_results.get("targets_original")
        or results.get("targets_expanded")
        or results.get("targets_original")
        or 0
    )

    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        # Empty on purpose — list UI uses targets_count / results.targets_expanded
        "targets": [],
        "config": {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": scan.assets_discovered,
        "technologies_found": scan.technologies_found,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "targets_count": targets_count,
        "findings_count": scan.vulnerabilities_found,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": (scan.error_message or "")[:500] or None,
        "results": slim_results,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


def _cap_scan_detail(scan: Scan) -> dict:
    """Cap huge arrays on GET /scans/{id} so the detail page can render."""
    targets = scan.targets or []
    results = dict(scan.results or {})
    host_results = results.get("host_results")
    if isinstance(host_results, list) and len(host_results) > _DETAIL_HOST_RESULTS_CAP:
        results["host_results_truncated"] = True
        results["host_results_total"] = len(host_results)
        results["host_results"] = host_results[:_DETAIL_HOST_RESULTS_CAP]
    if isinstance(results.get("ports_data"), list) and len(results["ports_data"]) > _DETAIL_HOST_RESULTS_CAP:
        results["ports_data_truncated"] = True
        results["ports_data_total"] = len(results["ports_data"])
        results["ports_data"] = results["ports_data"][:_DETAIL_HOST_RESULTS_CAP]

    targets_total = len(targets)
    targets_out = targets
    if targets_total > _DETAIL_TARGET_CAP:
        targets_out = targets[:_DETAIL_TARGET_CAP]

    targets_count = (
        results.get("targets_expanded")
        or results.get("targets_original")
        or targets_total
    )
    # Only expand when the list is small enough to be cheap
    if targets_total and targets_total <= 200 and not results.get("targets_expanded"):
        targets_count = count_cidr_targets(targets)

    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        "targets": targets_out,
        "config": scan.config or {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": scan.assets_discovered,
        "technologies_found": scan.technologies_found,
        "vulnerabilities_found": scan.vulnerabilities_found,
        "targets_count": targets_count,
        "findings_count": scan.vulnerabilities_found,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "results": {
            **results,
            "targets_total": targets_total,
            "targets_truncated": targets_total > _DETAIL_TARGET_CAP,
        },
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }

# SQS Configuration
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Initialize SQS client lazily
_sqs_client = None

def get_sqs_client():
    """Get or create SQS client."""
    global _sqs_client
    if _sqs_client is None and SQS_QUEUE_URL:
        try:
            import boto3
            _sqs_client = boto3.client('sqs', region_name=AWS_REGION)
            logger.info(f"SQS client initialized for queue: {SQS_QUEUE_URL}")
        except Exception as e:
            logger.error(f"Failed to initialize SQS client: {e}")
    return _sqs_client


def send_scan_to_sqs(scan: Scan) -> bool:
    """
    Send a scan job to SQS queue for processing.
    
    Returns True if message was sent successfully, False otherwise.
    """
    if not SQS_QUEUE_URL:
        logger.debug("SQS_QUEUE_URL not configured, skipping SQS notification")
        return False
    
    sqs = get_sqs_client()
    if not sqs:
        return False
    
    # Build job message - map ScanType to worker job_type
    # IMPORTANT: Keep this in sync with scanner_worker.py job_type_map
    job_type_map = {
        ScanType.VULNERABILITY: 'NUCLEI_SCAN',
        ScanType.PORT_SCAN: 'PORT_SCAN',
        ScanType.PORT_VERIFY: 'PORT_VERIFY',
        ScanType.SERVICE_DETECT: 'SERVICE_DETECT',
        ScanType.DISCOVERY: 'DISCOVERY',
        ScanType.FULL: 'DISCOVERY',
        ScanType.SUBDOMAIN_ENUM: 'SUBDOMAIN_ENUM',
        ScanType.DNS_RESOLUTION: 'DNS_RESOLUTION',
        ScanType.HTTP_PROBE: 'HTTP_PROBE',
        ScanType.DNS_ENUM: 'DNS_RESOLUTION',
        ScanType.LOGIN_PORTAL: 'LOGIN_PORTAL',
        ScanType.SCREENSHOT: 'SCREENSHOT',
        ScanType.TECHNOLOGY: 'TECHNOLOGY_SCAN',
        ScanType.WHATWEB: 'WHATWEB_SCAN',
        ScanType.PARAMSPIDER: 'PARAMSPIDER',
        ScanType.WAYBACKURLS: 'WAYBACKURLS',
        ScanType.KATANA: 'KATANA',
        ScanType.TLDFINDER: 'TLDFINDER',
        ScanType.CLEANUP: 'CLEANUP',
        ScanType.LLM_RED_TEAM: 'LLM_RED_TEAM',
        ScanType.ATLAS_DISCOVERY: 'ATLAS_DISCOVERY',
        ScanType.ARGUS_SECRETS: 'ARGUS_SECRETS',
        ScanType.HERMES_SECRETS: 'HERMES_SECRETS',
        ScanType.JANUS_DAST: 'JANUS_DAST',
        ScanType.THEMIS_CSPM: 'THEMIS_CSPM',
        ScanType.SUBDOMAIN_TAKEOVER: 'SUBDOMAIN_TAKEOVER',
        ScanType.GRAPHQL_SCAN: 'GRAPHQL_SCAN',
        ScanType.JS_RECON: 'JS_RECON',
        ScanType.JSLUICE_SCAN: 'JSLUICE_SCAN',
        ScanType.TRUFFLEHOG_SCAN: 'TRUFFLEHOG_SCAN',
    }
    
    job_type = job_type_map.get(scan.scan_type, 'NUCLEI_SCAN')
    config = scan.config or {}
    
    message_body = {
        'job_type': job_type,
        'scan_id': scan.id,
        'organization_id': scan.organization_id,
        'targets': scan.targets or [],
        'config': config,
        'scanner': config.get('scanner', 'naabu'),
        'ports': config.get('ports'),
        'severity': config.get('severity'),
    }
    
    try:
        response = sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(message_body),
            MessageAttributes={
                'job_type': {
                    'StringValue': job_type,
                    'DataType': 'String'
                },
                'scan_id': {
                    'StringValue': str(scan.id),
                    'DataType': 'Number'
                }
            }
        )
        logger.info(f"Sent scan {scan.id} to SQS, MessageId: {response.get('MessageId')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send scan {scan.id} to SQS: {e}")
        return False


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    organization_id: Optional[int] = None,
    scan_type: Optional[ScanType] = None,
    status: Optional[ScanStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List scans with filtering options."""
    query = db.query(Scan)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Scan.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return []
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    # Apply filters
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)
    if status:
        query = query.filter(Scan.status == status)
    
    # Defer full targets/config — OT scans store 10k+ targets and hang the UI
    # when every list poll serializes them. Summary counts come from results.
    scans = (
        query.options(defer(Scan.targets), defer(Scan.config))
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [_scan_list_item(scan) for scan in scans]


@router.get("/queue/status")
def get_queue_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get scan queue status including pending, running, and capacity info.
    
    Useful for understanding if ad-hoc scans can run immediately.
    """
    import os
    max_concurrent = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
    
    # Count scans by status
    pending_count = db.query(Scan).filter(Scan.status == ScanStatus.PENDING).count()
    running_count = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
    
    # Get running scans details
    running_scans = db.query(Scan).filter(
        Scan.status == ScanStatus.RUNNING
    ).order_by(Scan.started_at.asc()).all()
    
    running_details = []
    for scan in running_scans:
        is_scheduled = (scan.config or {}).get('triggered_by_schedule') is not None
        running_details.append({
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type.value if scan.scan_type else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "current_step": scan.current_step,
            "is_scheduled": is_scheduled,
        })
    
    # Get next pending scans
    pending_scans = db.query(Scan).filter(
        Scan.status == ScanStatus.PENDING
    ).order_by(Scan.created_at.asc()).limit(5).all()
    
    pending_details = []
    for scan in pending_scans:
        is_scheduled = (scan.config or {}).get('triggered_by_schedule') is not None
        pending_details.append({
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type.value if scan.scan_type else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "is_scheduled": is_scheduled,
        })
    
    available_slots = max(0, max_concurrent - running_count)
    
    return {
        "max_concurrent": max_concurrent,
        "running": running_count,
        "pending": pending_count,
        "available_slots": available_slots,
        "can_start_immediately": available_slots > 0,
        "running_scans": running_details,
        "next_pending": pending_details,
    }


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new scan."""
    # Check organization access
    if not check_org_access(current_user, scan_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # If label_ids are provided, get assets with those labels
    scan_dict = scan_data.model_dump()
    label_ids = scan_dict.pop('label_ids', [])
    match_all_labels = scan_dict.pop('match_all_labels', False)
    
    if label_ids:
        # Get assets with the specified labels
        query = db.query(Asset).filter(Asset.organization_id == scan_data.organization_id)
        
        if match_all_labels:
            # Assets must have ALL labels
            for label_id in label_ids:
                query = query.filter(Asset.labels.any(Label.id == label_id))
        else:
            # Assets must have ANY of the labels
            query = query.filter(Asset.labels.any(Label.id.in_(label_ids)))
        
        assets = query.distinct().all()
        
        # Add asset values to targets
        asset_values = [a.value for a in assets]
        scan_dict['targets'] = list(set(scan_dict.get('targets', []) + asset_values))
        
        # Store label info in config for reference
        scan_dict['config'] = scan_dict.get('config', {})
        scan_dict['config']['source_labels'] = label_ids
        scan_dict['config']['match_all_labels'] = match_all_labels
        scan_dict['config']['assets_from_labels'] = len(assets)
    
    # -- Rules of Engagement guardrail ---------------------------------------
    # If the org has RoE enabled, reject the whole scan when any target or the
    # scan type itself violates the accepted document. This is the hard gate
    # that prevents the platform (or the agent) from ever touching out-of-scope
    # hosts.
    try:
        from app.services import roe_service
        scan_type_value = (
            scan_dict.get('scan_type').value
            if hasattr(scan_dict.get('scan_type'), 'value')
            else scan_dict.get('scan_type')
        )
        ok, reason, rejected = roe_service.check_targets(
            db,
            scan_data.organization_id,
            scan_dict.get('targets') or [],
            scan_type=scan_type_value,
        )
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "Rules of Engagement violation",
                    "reason": reason,
                    "rejected_targets": rejected,
                },
            )
    except HTTPException:
        raise
    except Exception as exc:  # don't block if RoE module itself is misconfigured
        logger.warning(f"RoE check skipped due to error: {exc}")

    new_scan = Scan(
        **scan_dict,
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    return new_scan


@router.get("/scan-types")
def get_available_scan_types():
    """
    Get all available scan types for adhoc scans.
    
    Returns all scan types from CONTINUOUS_SCAN_TYPES that can be used
    for both scheduled and adhoc scans.
    """
    return CONTINUOUS_SCAN_TYPES


@router.post("/adhoc", status_code=status.HTTP_201_CREATED)
def create_adhoc_scan(
    request: AdhocScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create an adhoc scan using any scan type (including scheduled scan types).
    
    This endpoint supports all scan types from CONTINUOUS_SCAN_TYPES like:
    - nuclei, nuclei_critical, nuclei_high, nuclei_critical_high
    - critical_ports, masscan, port_scan
    - discovery, full_discovery, subdomain_enum
    - http_probe, dns_resolution, technology
    - screenshot, login_portal, paramspider, waybackurls, katana, cleanup
    
    Targets can be specified via:
    - Explicit list in `targets`
    - Assets with specific labels via `label_ids`
    - All in-scope assets via `use_all_in_scope=true`
    """
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Validate scan type
    if request.scan_type not in CONTINUOUS_SCAN_TYPES:
        valid_types = list(CONTINUOUS_SCAN_TYPES.keys())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan type '{request.scan_type}'. Valid types: {valid_types}"
        )
    
    # Build targets
    targets = list(request.targets) if request.targets else []
    
    # Add targets from labels
    if request.label_ids:
        query = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.in_scope == True
        )
        
        if request.match_all_labels:
            for label_id in request.label_ids:
                query = query.filter(Asset.labels.any(Label.id == label_id))
        else:
            query = query.filter(Asset.labels.any(Label.id.in_(request.label_ids)))
        
        assets = query.distinct().all()
        targets.extend([a.value for a in assets])
    
    # Use all in-scope assets if requested and no other targets
    if request.use_all_in_scope and not targets:
        assets = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.in_scope == True,
            Asset.asset_type.in_([
                AssetType.DOMAIN,
                AssetType.SUBDOMAIN,
                AssetType.IP_ADDRESS,
                AssetType.IP_RANGE,
            ])
        ).all()
        targets.extend([a.value for a in assets])
        
        # Add netblocks if requested
        if request.include_netblocks:
            netblocks = db.query(Netblock).filter(
                Netblock.organization_id == request.organization_id,
                Netblock.in_scope == True
            ).all()
            
            for nb in netblocks:
                if nb.cidr_notation:
                    for sep in [';', ',']:
                        if sep in nb.cidr_notation:
                            cidrs = [c.strip() for c in nb.cidr_notation.split(sep) if c.strip()]
                            targets.extend(cidrs)
                            break
                    else:
                        targets.append(nb.cidr_notation.strip())
    
    # Deduplicate targets
    targets = list(set(targets))
    
    if not targets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No targets specified. Provide targets, label_ids, or set use_all_in_scope=true"
        )
    
    # Map scan type string to ScanType enum
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
        "full": ScanType.FULL,  # Full scan (discovery + all scans)
        "web_scan": ScanType.VULNERABILITY,  # Web scan uses Nuclei vulnerability scanner
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
        "geo_enrich": ScanType.GEO_ENRICH,
        "tldfinder": ScanType.TLDFINDER,
    }
    
    scan_type_enum = scan_type_map.get(request.scan_type, ScanType.VULNERABILITY)
    
    # Build config with defaults from CONTINUOUS_SCAN_TYPES
    default_config = CONTINUOUS_SCAN_TYPES[request.scan_type].get("default_config", {})
    config = {
        **default_config,
        **request.config,
        "adhoc_scan_type": request.scan_type,
    }
    
    # Special handling for critical_ports
    if request.scan_type == "critical_ports":
        config["ports"] = config.get("ports", ",".join(str(p) for p in ALL_CRITICAL_PORTS))
        config["generate_findings"] = True
        config["scanner"] = config.get("scanner", "masscan")
        config["rate"] = config.get("rate", 10000)
    
    # Special handling for ICS/OT scans
    if request.scan_type in [
        "ics_ot_ports", "ics_plc_scan", "ics_scada_scan",
        "ics_building_automation", "ics_full_discovery",
    ]:
        config["generate_findings"] = True
        config["finding_category"] = config.get("finding_category") or "ics_ot"
        if request.scan_type in ["ics_ot_ports", "ics_full_discovery"]:
            config["ports"] = config.get("ports") or ",".join(str(p) for p in ALL_ICS_OT_PORTS)
        if request.scan_type == "ics_full_discovery":
            config["scanner"] = config.get("scanner", "nmap")
            config["run_nuclei"] = config.get("run_nuclei", True)
            if not config.get("nuclei_tags") and not config.get("tags"):
                config["nuclei_tags"] = ["ics", "scada"]
    
    # Create the scan
    new_scan = Scan(
        name=request.name,
        scan_type=scan_type_enum,
        organization_id=request.organization_id,
        targets=targets,
        config=config,
        started_by=current_user.username,
        status=ScanStatus.PENDING,
    )
    
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    scan_type_info = CONTINUOUS_SCAN_TYPES[request.scan_type]
    
    return {
        "id": new_scan.id,
        "name": new_scan.name,
        "scan_type": request.scan_type,
        "scan_type_name": scan_type_info.get("name"),
        "scan_type_description": scan_type_info.get("description"),
        "organization_id": new_scan.organization_id,
        "targets_count": len(targets),
        "status": new_scan.status.value,
        "config": config,
        "created_at": new_scan.created_at.isoformat() if new_scan.created_at else None,
        "message": f"Adhoc {scan_type_info.get('name')} scan created with {len(targets)} targets"
    }


@router.post("/by-label", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan_by_label(
    request: ScanByLabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a scan targeting assets with specific labels."""
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Verify labels exist and belong to the organization
    labels = db.query(Label).filter(
        Label.id.in_(request.label_ids),
        Label.organization_id == request.organization_id
    ).all()
    
    if len(labels) != len(request.label_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more labels not found or do not belong to this organization"
        )
    
    # Get assets with the specified labels
    query = db.query(Asset).filter(
        Asset.organization_id == request.organization_id,
        Asset.in_scope == True
    )
    
    if request.match_all_labels:
        for label_id in request.label_ids:
            query = query.filter(Asset.labels.any(Label.id == label_id))
    else:
        query = query.filter(Asset.labels.any(Label.id.in_(request.label_ids)))
    
    assets = query.distinct().all()
    
    if not assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No in-scope assets found with the specified labels"
        )
    
    # Create targets from asset values
    targets = [a.value for a in assets]
    
    # Create the scan
    new_scan = Scan(
        name=request.name,
        scan_type=request.scan_type,
        organization_id=request.organization_id,
        targets=targets,
        config={
            **request.config,
            "source_labels": request.label_ids,
            "label_names": [l.name for l in labels],
            "match_all_labels": request.match_all_labels,
            "assets_count": len(assets),
        },
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    return new_scan


@router.post("/bulk-domain-scan")
def bulk_domain_port_scan(
    request: BulkDomainScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a port scan targeting multiple domains at once.
    
    Accepts domains as either:
    - A list in the `domains` field
    - Raw text with one domain per line in `domains_text`
    
    Features:
    - Optionally pre-resolves domains to IPs before scanning
    - Creates domain assets if they don't exist
    - Supports Naabu, Nmap, or Masscan
    """
    from app.models.asset import AssetType
    import re
    import socket
    
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Parse domains from either list or text
    domains = list(request.domains) if request.domains else []
    
    if request.domains_text:
        # Parse text input - one domain per line
        for line in request.domains_text.strip().split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                # Remove protocol prefix if present
                line = re.sub(r'^https?://', '', line)
                # Remove trailing path/slash
                line = line.split('/')[0]
                # Remove port if present
                line = line.split(':')[0]
                if line and '.' in line:
                    domains.append(line)
    
    # Deduplicate and validate domains
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$')
    valid_domains = []
    seen = set()
    
    for domain in domains:
        domain = domain.lower().strip()
        if domain and domain not in seen:
            if domain_pattern.match(domain):
                valid_domains.append(domain)
                seen.add(domain)
    
    if not valid_domains:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid domains provided. Domains should be in format: example.com, sub.example.com"
        )
    
    # Optionally resolve domains to IPs
    resolved_ips = None
    targets = valid_domains.copy()
    
    if request.resolve_first:
        resolved_ips = []
        resolved_targets = []
        
        for domain in valid_domains:
            try:
                ip = socket.gethostbyname(domain)
                resolved_ips.append(ip)
                resolved_targets.append(ip)
                logger.info(f"Resolved {domain} -> {ip}")
            except socket.gaierror:
                # Keep domain in list even if resolution fails (scanner may have better luck)
                resolved_targets.append(domain)
                logger.warning(f"Could not resolve {domain}, keeping as target")
        
        targets = list(set(resolved_targets))  # Dedupe IPs
    
    # Create domain assets if requested
    assets_created = 0
    if request.create_assets:
        for domain in valid_domains:
            # Check if asset already exists
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain
            ).first()
            
            if not existing:
                # Determine asset type (subdomain vs root domain)
                parts = domain.split('.')
                if len(parts) > 2:
                    asset_type = AssetType.SUBDOMAIN
                else:
                    asset_type = AssetType.DOMAIN
                
                new_asset = Asset(
                    organization_id=request.organization_id,
                    name=domain,
                    value=domain,
                    asset_type=asset_type,
                    in_scope=True,
                    is_monitored=True,
                    association_reason="bulk_domain_scan",
                )
                db.add(new_asset)
                assets_created += 1
        
        if assets_created > 0:
            db.commit()
            logger.info(f"Created {assets_created} new domain assets")
    
    # Generate scan name if not provided
    scan_name = request.name or f"Bulk Domain Scan - {len(valid_domains)} domains"
    
    # Build config
    config = {
        "scanner": request.scanner,
        "rate": request.rate,
        "top_ports": request.top_ports,
        "service_detection": request.service_detection,
        "source": "bulk_domain_scan",
        "original_domains": valid_domains,
        "domains_count": len(valid_domains),
    }
    
    if request.ports:
        config["ports"] = request.ports
    
    if resolved_ips:
        config["resolved_ips"] = resolved_ips
    
    # Create the port scan
    new_scan = Scan(
        name=scan_name,
        scan_type=ScanType.PORT_SCAN,
        organization_id=request.organization_id,
        targets=targets,
        config=config,
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    logger.info(f"Created bulk domain port scan {new_scan.id} with {len(valid_domains)} domains, {len(targets)} targets")
    
    return {
        "scan_id": new_scan.id,
        "scan_name": scan_name,
        "domains_count": len(valid_domains),
        "resolved_ips": resolved_ips,
        "assets_created": assets_created,
        "message": f"Port scan created for {len(valid_domains)} domains. Scan ID: {new_scan.id}"
    }


@router.get("/labels/preview")
def preview_scan_by_labels(
    label_ids: List[int] = Query(...),
    organization_id: int = Query(...),
    match_all: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Preview which assets would be included in a label-based scan."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope == True
    )
    
    if match_all:
        for label_id in label_ids:
            query = query.filter(Asset.labels.any(Label.id == label_id))
    else:
        query = query.filter(Asset.labels.any(Label.id.in_(label_ids)))
    
    assets = query.distinct().all()
    
    # Get label names for display
    labels = db.query(Label).filter(Label.id.in_(label_ids)).all()
    
    return {
        "label_ids": label_ids,
        "label_names": [l.name for l in labels],
        "match_all": match_all,
        "asset_count": len(assets),
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "value": a.value,
                "asset_type": a.asset_type.value,
                "labels": [{"id": l.id, "name": l.name, "color": l.color} for l in a.labels],
            }
            for a in assets[:100]  # Limit preview to 100 assets
        ],
        "truncated": len(assets) > 100,
    }


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return _cap_scan_detail(scan)


@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(
    scan_id: int,
    scan_data: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = scan_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)
    
    db.commit()
    db.refresh(scan)
    
    return scan


@router.post("/{scan_id}/start", response_model=ScanResponse)
def start_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Start a pending scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start scan with status {scan.status.value}"
        )
    
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    scan.started_by = current_user.username
    
    db.commit()
    db.refresh(scan)
    
    # Note: In production, this would trigger an async scan job
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Cancel a running or pending scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status {scan.status.value}"
        )
    
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    
    db.commit()
    db.refresh(scan)
    
    return scan


@router.post("/{scan_id}/retry", response_model=ScanResponse)
def retry_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Retry a stuck or failed scan by resetting it to PENDING status.
    
    This is useful for scans that got stuck in RUNNING status due to
    worker crashes or other issues. Unlike rescan, this does not create
    a new scan - it resets the existing one.
    
    Can only be called on scans with status: RUNNING, FAILED, or CANCELLED.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Only allow retry for stuck/failed scans, not pending or completed
    if scan.status not in [ScanStatus.RUNNING, ScanStatus.FAILED, ScanStatus.CANCELLED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot retry scan with status {scan.status.value}. Only RUNNING, FAILED, or CANCELLED scans can be retried."
        )
    
    # Reset scan to pending
    scan.status = ScanStatus.PENDING
    scan.started_at = None
    scan.completed_at = None
    scan.error_message = None
    scan.current_step = None
    scan.progress = 0
    
    # Track manual retry in config
    config = scan.config or {}
    manual_retries = config.get('_manual_retries', 0) + 1
    config['_manual_retries'] = manual_retries
    config['_last_manual_retry'] = datetime.utcnow().isoformat()
    config['_retried_by'] = current_user.username
    scan.config = config
    
    db.commit()
    db.refresh(scan)
    
    # Optionally send to SQS for faster pickup
    send_scan_to_sqs(scan)
    
    logger.info(f"Scan {scan_id} manually retried by {current_user.username}")
    
    return scan


@router.post("/{scan_id}/rescan", response_model=ScanResponse)
def rescan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a new scan based on an existing scan's configuration.
    
    This clones the original scan's targets, type, and config, then queues it for execution.
    Useful for re-running completed or failed scans.
    """
    original_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not original_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Original scan not found"
        )
    
    if not check_org_access(current_user, original_scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Clone the scan configuration
    new_scan = Scan(
        name=f"{original_scan.name} (Rescan)",
        scan_type=original_scan.scan_type,
        organization_id=original_scan.organization_id,
        targets=original_scan.targets,
        config={
            **(original_scan.config or {}),
            "rescan_of": original_scan.id,
            "original_scan_name": original_scan.name,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    return new_scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scan"
        )
    
    db.delete(scan)
    db.commit()
    
    return None


# =============================================================================
# Quick Action Scan Endpoints
# =============================================================================

@router.post("/quick/dns-resolution", response_model=ScanResponse)
def quick_dns_resolution_scan(
    organization_id: int = Query(..., description="Organization ID"),
    include_geo: bool = Query(True, description="Include geo-enrichment"),
    limit: int = Query(500, ge=1, le=2000, description="Max assets to process"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Quick action: Create a DNS resolution scan to resolve all domains to IPs.
    
    This scan will:
    1. Find all domain/subdomain assets without IP addresses
    2. Resolve them using dnsx
    3. Update assets with resolved IPs
    4. Optionally geo-enrich with lat/lon for the world map
    
    Use this to populate IP addresses and geolocation for the asset map.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Count unresolved assets
    from app.models.asset import AssetType
    unresolved_count = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        (Asset.ip_address.is_(None) | (Asset.ip_address == ''))
    ).count()
    
    if unresolved_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No assets need DNS resolution. All domains already have IP addresses."
        )
    
    # Create scan
    scan = Scan(
        name=f"DNS Resolution - {min(unresolved_count, limit)} assets",
        scan_type=ScanType.DNS_RESOLUTION,
        organization_id=organization_id,
        targets=[],  # Will resolve all unresolved assets
        config={
            "include_geo": include_geo,
            "limit": limit,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(scan)
    
    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        "targets": scan.targets or [],
        "config": scan.config or {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": 0,
        "technologies_found": 0,
        "vulnerabilities_found": 0,
        "targets_count": min(unresolved_count, limit),
        "findings_count": 0,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "results": {"pending_assets": min(unresolved_count, limit)},
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


@router.post("/quick/http-probe", response_model=ScanResponse)
def quick_http_probe_scan(
    organization_id: int = Query(..., description="Organization ID"),
    limit: int = Query(500, ge=1, le=2000, description="Max assets to probe"),
    timeout: int = Query(30, ge=5, le=120, description="Timeout per target"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Quick action: Create an HTTP probe scan to find live web assets.
    
    This scan will:
    1. Probe all domain/subdomain assets for HTTP/HTTPS
    2. Update assets with live status, HTTP status code, and page title
    3. Store the final URL (after redirects)
    4. Update IP addresses if discovered
    
    Use this to identify which assets have live web services.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Count assets to probe
    from app.models.asset import AssetType
    asset_count = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN])
    ).count()
    
    if asset_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No domain/subdomain assets found to probe."
        )
    
    # Create scan
    scan = Scan(
        name=f"HTTP Probe - {min(asset_count, limit)} assets",
        scan_type=ScanType.HTTP_PROBE,
        organization_id=organization_id,
        targets=[],  # Will probe all assets
        config={
            "limit": limit,
            "timeout": timeout,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(scan)
    
    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        "targets": scan.targets or [],
        "config": scan.config or {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": 0,
        "technologies_found": 0,
        "vulnerabilities_found": 0,
        "targets_count": min(asset_count, limit),
        "findings_count": 0,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "results": {"pending_assets": min(asset_count, limit)},
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


# =============================================================================
# Unified Export Endpoints
# =============================================================================

@router.get("/{scan_id}/export/unified", response_model=dict)
def export_scan_unified(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export scan results in unified ASM format.
    
    This standardized format is compatible with H-ISAC and ASM Recon outputs,
    making it easy to share, integrate, or import into other security tools.
    """
    from app.schemas.unified_results import (
        UnifiedFinding, UnifiedScanResult, ASMExportFormat,
        ResultType, Severity
    )
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Build unified scan result
    unified_result = UnifiedScanResult(
        scan_id=scan.id,
        scan_type=scan.scan_type.value if scan.scan_type else "unknown",
        scanner=scan.config.get("scanner", "unknown") if scan.config else "unknown",
        success=scan.status == ScanStatus.COMPLETED,
        status=scan.status.value if scan.status else "unknown",
        targets_original=scan.targets or [],
        targets_scanned=count_cidr_targets(scan.targets) if scan.targets else 0,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=(scan.completed_at - scan.started_at).total_seconds() if scan.started_at and scan.completed_at else 0,
        organization_id=scan.organization_id,
        started_by=scan.started_by,
        errors=[scan.error_message] if scan.error_message else [],
    )
    
    # Add vulnerability findings
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    for vuln in vulns:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        finding = UnifiedFinding(
            type=ResultType.VULNERABILITY,
            source=vuln.detected_by or "nuclei",
            target=vuln.asset.value if vuln.asset else "",
            host=vuln.asset.value if vuln.asset else "",
            ip=vuln.ip_address,
            url=vuln.url,
            title=vuln.title,
            description=vuln.description,
            severity=severity_map.get(vuln.severity.value if vuln.severity else "info", Severity.INFO),
            template_id=vuln.template_id,
            cve_id=vuln.cve_id,
            cvss_score=vuln.cvss_score,
            tags=vuln.tags or [],
            references=vuln.references or [],
            timestamp=vuln.first_detected_at or vuln.created_at,
            first_seen=vuln.first_detected_at,
            last_seen=vuln.last_detected_at,
            organization_id=scan.organization_id,
            asset_id=vuln.asset_id,
            scan_id=scan.id,
        )
        unified_result.add_finding(finding)
    
    # Add port findings (for port scans)
    if scan.scan_type == ScanType.PORT_SCAN:
        # Get assets scanned in this job
        for target in scan.targets or []:
            asset = db.query(Asset).filter(
                Asset.organization_id == scan.organization_id,
                Asset.value == target
            ).first()
            if asset:
                ports = db.query(PortService).filter(PortService.asset_id == asset.id).all()
                for port in ports:
                    finding = UnifiedFinding(
                        type=ResultType.PORT,
                        source=port.discovered_by or "naabu",
                        target=target,
                        host=asset.value,
                        ip=asset.ip_address,
                        port=port.port,
                        protocol=port.protocol.value if port.protocol else "tcp",
                        title=f"Port {port.port}/{port.protocol.value if port.protocol else 'tcp'} Open",
                        service_name=port.service_name,
                        service_product=port.service_product,
                        service_version=port.service_version,
                        banner=port.banner,
                        state=port.state.value if port.state else "open",
                        is_risky=port.is_risky or False,
                        risk_reason=port.risk_reason,
                        severity=Severity.MEDIUM if port.is_risky else Severity.INFO,
                        timestamp=port.first_seen or port.created_at,
                        first_seen=port.first_seen,
                        last_seen=port.last_seen,
                        organization_id=scan.organization_id,
                        asset_id=asset.id,
                        scan_id=scan.id,
                    )
                    unified_result.add_finding(finding)
    
    # Build export format
    org_name = scan.organization.name if scan.organization else None
    export = ASMExportFormat.from_scan_result(unified_result, org_name)
    
    return export.model_dump(mode="json")


@router.get("/export/all", response_model=dict)
def export_all_findings(
    organization_id: Optional[int] = None,
    finding_type: Optional[str] = Query(None, description="Filter by type: vulnerability, port, subdomain, etc."),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    source: Optional[str] = Query(None, description="Filter by source tool: nuclei, naabu, subfinder, etc."),
    since: Optional[datetime] = Query(None, description="Filter findings after this date"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum findings to export"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export all findings in unified ASM format across all scans.
    
    This endpoint provides a consolidated view of all findings for:
    - Threat intel sharing (H-ISAC compatible)
    - SIEM integration
    - Security reporting
    - Cross-tool analysis
    """
    from app.schemas.unified_results import (
        UnifiedFinding, ASMExportFormat,
        ResultType, Severity
    )
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    from app.models.organization import Organization
    
    # Determine organization scope
    if current_user.is_superuser:
        org_id = organization_id
    else:
        org_id = current_user.organization_id
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID required"
        )
    
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    findings = []
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    
    # Get vulnerabilities
    if not finding_type or finding_type == "vulnerability":
        vuln_query = db.query(Vulnerability).filter(Vulnerability.organization_id == org_id)
        if severity:
            vuln_query = vuln_query.filter(Vulnerability.severity == severity)
        if source:
            vuln_query = vuln_query.filter(Vulnerability.detected_by == source)
        if since:
            vuln_query = vuln_query.filter(Vulnerability.created_at >= since)
        
        for vuln in vuln_query.limit(limit).all():
            finding = UnifiedFinding(
                type=ResultType.VULNERABILITY,
                source=vuln.detected_by or "nuclei",
                target=vuln.asset.value if vuln.asset else "",
                host=vuln.asset.value if vuln.asset else "",
                ip=vuln.ip_address,
                url=vuln.url,
                title=vuln.title,
                description=vuln.description,
                severity=severity_map.get(vuln.severity.value if vuln.severity else "info", Severity.INFO),
                template_id=vuln.template_id,
                cve_id=vuln.cve_id,
                cvss_score=vuln.cvss_score,
                tags=vuln.tags or [],
                references=vuln.references or [],
                timestamp=vuln.first_detected_at or vuln.created_at,
                first_seen=vuln.first_detected_at,
                last_seen=vuln.last_detected_at,
                organization_id=org_id,
                asset_id=vuln.asset_id,
                scan_id=vuln.scan_id,
            )
            findings.append(finding)
    
    # Get port findings
    if not finding_type or finding_type == "port":
        # Get assets for this org
        asset_ids = [a.id for a in db.query(Asset).filter(Asset.organization_id == org_id).all()]
        
        port_query = db.query(PortService).filter(PortService.asset_id.in_(asset_ids))
        if source:
            port_query = port_query.filter(PortService.discovered_by == source)
        if since:
            port_query = port_query.filter(PortService.created_at >= since)
        
        remaining = limit - len(findings)
        for port in port_query.limit(remaining).all():
            asset = port.asset
            finding = UnifiedFinding(
                type=ResultType.PORT,
                source=port.discovered_by or "naabu",
                target=asset.value if asset else "",
                host=asset.value if asset else "",
                ip=asset.ip_address if asset else None,
                port=port.port,
                protocol=port.protocol.value if port.protocol else "tcp",
                title=f"Port {port.port}/{port.protocol.value if port.protocol else 'tcp'} Open",
                service_name=port.service_name,
                service_product=port.service_product,
                service_version=port.service_version,
                banner=port.banner,
                state=port.state.value if port.state else "open",
                is_risky=port.is_risky or False,
                risk_reason=port.risk_reason,
                severity=Severity.MEDIUM if port.is_risky else Severity.INFO,
                timestamp=port.first_seen or port.created_at,
                first_seen=port.first_seen,
                last_seen=port.last_seen,
                organization_id=org_id,
                asset_id=port.asset_id,
            )
            
            # Apply severity filter
            if severity and finding.severity.value != severity:
                continue
            
            findings.append(finding)
    
    # Build export format
    severity_breakdown = {s.value: 0 for s in Severity}
    type_breakdown = {}
    source_breakdown = {}
    
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1
        type_breakdown[f.type.value] = type_breakdown.get(f.type.value, 0) + 1
        source_breakdown[f.source] = source_breakdown.get(f.source, 0) + 1
    
    export = ASMExportFormat(
        organization=org.name if org else None,
        organization_id=org_id,
        findings=findings,
        total_count=len(findings),
        severity_breakdown=severity_breakdown,
        type_breakdown=type_breakdown,
        source_breakdown=source_breakdown,
    )
    
    return export.model_dump(mode="json")


# =============================================================================
# H-ISAC Format Export Endpoints
# =============================================================================

@router.get("/{scan_id}/export/hisac", response_model=List[Dict])
def export_scan_hisac(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export scan results in H-ISAC format.
    
    Returns JSON Lines compatible output matching the H-ISAC reconnaissance
    scripts format:
    
    {"ip_or_fqdn": "...", "port": 443, "protocol": "tcp", "data": [...]}
    
    This format is compatible with:
    - get_masscan
    - get_massdns
    - get_whoxy
    - Other H-ISAC recon scripts
    """
    from app.schemas.hisac_format import HISACResult
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    results = []
    
    # Export vulnerability findings
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    for vuln in vulns:
        result = HISACResult(
            ip_or_fqdn=vuln.asset.value if vuln.asset else vuln.ip_address or "",
            port=0,
            protocol="vuln",
            data=[{
                "template_id": vuln.template_id,
                "severity": vuln.severity.value if vuln.severity else "info",
                "title": vuln.title,
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "matched_at": vuln.url,
            }],
            source="nuclei",
        )
        results.append(result.model_dump(mode="json", exclude_none=True))
    
    # Export port findings (for port scans)
    if scan.scan_type == ScanType.PORT_SCAN:
        for target in scan.targets or []:
            asset = db.query(Asset).filter(
                Asset.organization_id == scan.organization_id,
                Asset.value == target
            ).first()
            if asset:
                ports = db.query(PortService).filter(PortService.asset_id == asset.id).all()
                for port in ports:
                    result = HISACResult(
                        ip_or_fqdn=asset.ip_address or asset.value,
                        port=port.port,
                        protocol=port.protocol.value if port.protocol else "tcp",
                        data=[{
                            "status": port.state.value if port.state else "open",
                            "service": port.service_name,
                            "product": port.service_product,
                            "version": port.service_version,
                            "banner": port.banner,
                        }],
                        source=port.discovered_by or "naabu",
                    )
                    # Clean up None values in data
                    result.data = [{k: v for k, v in d.items() if v is not None} for d in result.data]
                    results.append(result.model_dump(mode="json", exclude_none=True))
    
    return results


@router.get("/export/hisac", response_model=List[Dict])
def export_all_hisac(
    organization_id: Optional[int] = None,
    protocol: Optional[str] = Query(None, description="Filter by protocol: tcp, dns, whois, vuln, etc."),
    since: Optional[datetime] = Query(None, description="Filter findings after this date"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum results"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export all findings in H-ISAC format.
    
    Returns JSON Lines compatible output that can be piped to other H-ISAC tools
    or used for integration with external systems.
    """
    from app.schemas.hisac_format import HISACResult
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
    # Determine organization scope
    if current_user.is_superuser:
        org_id = organization_id
    else:
        org_id = current_user.organization_id
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID required"
        )
    
    results = []
    
    # Get vulnerabilities (protocol = "vuln")
    if not protocol or protocol == "vuln":
        vuln_query = db.query(Vulnerability).filter(Vulnerability.organization_id == org_id)
        if since:
            vuln_query = vuln_query.filter(Vulnerability.created_at >= since)
        
        for vuln in vuln_query.limit(limit).all():
            result = HISACResult(
                ip_or_fqdn=vuln.asset.value if vuln.asset else vuln.ip_address or "",
                port=0,
                protocol="vuln",
                data=[{
                    "template_id": vuln.template_id,
                    "severity": vuln.severity.value if vuln.severity else "info",
                    "title": vuln.title,
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "matched_at": vuln.url,
                }],
                source="nuclei",
            )
            results.append(result.model_dump(mode="json", exclude_none=True))
    
    # Get ports (protocol = "tcp" or "udp")
    if not protocol or protocol in ["tcp", "udp"]:
        asset_ids = [a.id for a in db.query(Asset).filter(Asset.organization_id == org_id).all()]
        
        port_query = db.query(PortService).filter(PortService.asset_id.in_(asset_ids))
        if protocol:
            from app.models.port_service import Protocol as PortProtocol
            port_query = port_query.filter(PortService.protocol == PortProtocol(protocol))
        if since:
            port_query = port_query.filter(PortService.created_at >= since)
        
        remaining = limit - len(results)
        for port in port_query.limit(remaining).all():
            asset = port.asset
            result = HISACResult(
                ip_or_fqdn=asset.ip_address or asset.value if asset else "",
                port=port.port,
                protocol=port.protocol.value if port.protocol else "tcp",
                data=[{
                    "status": port.state.value if port.state else "open",
                    "service": port.service_name,
                    "product": port.service_product,
                    "version": port.service_version,
                    "banner": port.banner,
                }],
                source=port.discovered_by or "naabu",
            )
            result.data = [{k: v for k, v in d.items() if v is not None} for d in result.data]
            results.append(result.model_dump(mode="json", exclude_none=True))
    
    return results


@router.post("/import/hisac", response_model=Dict)
def import_hisac_results(
    organization_id: int,
    results: List[Dict],
    source: Optional[str] = Query(None, description="Source tool name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import H-ISAC format results into the ASM database.
    
    Accepts JSON array of H-ISAC format objects:
    [{"ip_or_fqdn": "...", "port": 443, "protocol": "tcp", "data": [...]}]
    
    This allows importing results from:
    - H-ISAC reconnaissance scripts
    - Other ASM tools using the same format
    - Manual data entry in H-ISAC format
    """
    from app.schemas.hisac_format import HISACResult, hisac_to_asm
    from app.schemas.data_sources import FindingCategory
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    imported = 0
    errors = []
    
    for i, raw_result in enumerate(results):
        try:
            # Parse H-ISAC result
            hisac = HISACResult(**raw_result)
            hisac.organization_id = organization_id
            
            # Convert to ASM model
            asm_finding = hisac_to_asm(hisac, source_hint=source)
            
            # Import based on category
            if asm_finding.category == FindingCategory.PORT:
                # Create or update port service
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == asm_finding.hostname or asm_finding.ip_address
                ).first()
                
                if not asset:
                    # Create asset
                    asset = Asset(
                        organization_id=organization_id,
                        asset_type="ip" if asm_finding.ip_address else "domain",
                        value=asm_finding.ip_address or asm_finding.hostname,
                        ip_address=asm_finding.ip_address,
                        is_active=True,
                    )
                    db.add(asset)
                    db.flush()
                
                # Create port service
                from app.models.port_service import PortService, Protocol as PortProtocol, PortState as PSState
                existing_port = db.query(PortService).filter(
                    PortService.asset_id == asset.id,
                    PortService.port == asm_finding.port,
                    PortService.protocol == asm_finding.protocol
                ).first()
                
                if not existing_port:
                    port_service = PortService(
                        asset_id=asset.id,
                        port=asm_finding.port,
                        protocol=asm_finding.protocol,
                        service_name=asm_finding.service_name,
                        service_product=asm_finding.service_product,
                        service_version=asm_finding.service_version,
                        banner=asm_finding.banner,
                        state=asm_finding.port_state or PSState.OPEN,
                        discovered_by=source or "hisac_import",
                    )
                    db.add(port_service)
                    imported += 1
            
            # Add more category handlers as needed
            
        except Exception as e:
            errors.append({"index": i, "error": str(e)})
    
    db.commit()
    
    return {
        "success": True,
        "imported": imported,
        "total": len(results),
        "errors": errors,
    }


# ==================== PORT VERIFICATION SCANS ====================

@router.post("/port-verify/{organization_id}")
def create_port_verification_scan(
    organization_id: int,
    max_ports: int = Query(500, ge=1, le=2000, description="Maximum ports to verify"),
    verify_filtered: bool = Query(False, description="Also re-verify filtered ports"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a port verification scan to validate all unverified open ports with nmap.
    
    This runs nmap on ports discovered by masscan/naabu to determine:
    - If they're truly open or filtered by a firewall
    - Service version information
    
    Use this after running a fast port scan to get accurate results.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Count unverified ports
    from app.models.port_service import PortService, PortState
    unverified_count = db.query(PortService).join(Asset).filter(
        Asset.organization_id == organization_id,
        PortService.verified == False,
        PortService.state == PortState.OPEN
    ).count()
    
    if unverified_count == 0:
        return {
            "message": "No unverified ports to verify",
            "unverified_count": 0
        }
    
    # Create the scan
    scan = Scan(
        name=f"Port Verification ({min(unverified_count, max_ports)} ports)",
        scan_type=ScanType.PORT_VERIFY,
        organization_id=organization_id,
        targets=[],
        config={
            "max_ports": max_ports,
            "verify_filtered": verify_filtered
        },
        status=ScanStatus.PENDING,
        started_by=current_user.email
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Queue for processing
    send_scan_to_sqs(scan)
    
    return {
        "scan_id": scan.id,
        "message": f"Port verification scan queued for up to {max_ports} ports",
        "unverified_count": unverified_count,
        "ports_to_verify": min(unverified_count, max_ports)
    }


@router.post("/service-detect/{organization_id}")
def create_service_detection_scan(
    organization_id: int,
    max_ports: int = Query(200, ge=1, le=500, description="Maximum ports to scan"),
    intensity: int = Query(7, ge=1, le=9, description="Nmap version detection intensity"),
    include_scripts: bool = Query(True, description="Run NSE scripts"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a service detection scan for ports with unknown services.
    
    This runs deep nmap version detection (-sV) on ports where the service
    is currently "unknown" or empty to identify what's actually running.
    
    Intensity levels:
    - 1-3: Quick (faster but less accurate)
    - 4-6: Default
    - 7-9: Thorough (slower but more accurate)
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Count unknown services
    from app.models.port_service import PortService, PortState
    from sqlalchemy import or_
    
    unknown_count = db.query(PortService).join(Asset).filter(
        Asset.organization_id == organization_id,
        PortService.state == PortState.OPEN,
        or_(
            PortService.service_name.is_(None),
            PortService.service_name == '',
            PortService.service_name == 'unknown',
            PortService.service_name == 'tcpwrapped'
        )
    ).count()
    
    if unknown_count == 0:
        return {
            "message": "No unknown services to identify",
            "unknown_count": 0
        }
    
    # Create the scan
    scan = Scan(
        name=f"Service Detection ({min(unknown_count, max_ports)} ports)",
        scan_type=ScanType.SERVICE_DETECT,
        organization_id=organization_id,
        targets=[],
        config={
            "max_ports": max_ports,
            "intensity": intensity,
            "include_scripts": include_scripts
        },
        status=ScanStatus.PENDING,
        started_by=current_user.email
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Queue for processing
    send_scan_to_sqs(scan)
    
    return {
        "scan_id": scan.id,
        "message": f"Service detection scan queued for up to {max_ports} ports",
        "unknown_count": unknown_count,
        "ports_to_scan": min(unknown_count, max_ports)
    }









