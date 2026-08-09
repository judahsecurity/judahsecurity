"""
ASM Platform - Scanner Worker

This worker polls SQS for scan jobs and executes them using the appropriate
scanning tools (Nuclei, Nmap, etc.)

Runs as a separate container in AWS ECS with full network access for scanning.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.netblock import Netblock
from app.models.vulnerability import Vulnerability
# Must import FindingValidation so SQLAlchemy can resolve
# Vulnerability.validations (order_by=FindingValidation.created_at.desc()).
# Also required by poll_database_for_validations().
from app.models.finding_validation import (
    FindingValidation,
    ValidationStatus,
    ValidationVerdict,
)
from app.models.project_settings import ProjectSettings, MODULE_SCAN_TOGGLES, MODULE_SECURITY_CHECKS
from app.models.port_service import PortService, PortState, Protocol
from app.services.nuclei_service import NucleiService
from app.services.nuclei_findings_service import NucleiFindingsService
from app.services.port_scanner_service import PortScannerService, ScannerType
from app.services.port_findings_service import PortFindingsService
from app.services.discovery_service import DiscoveryService
from app.services.dns_resolution_service import DNSResolutionService
from app.services.geolocation_service import get_geolocation_service
import ipaddress
import re


def trigger_graph_sync(organization_id: int) -> None:
    """
    Trigger a background graph sync after scan completion.
    This is non-blocking and failures are logged but not raised.
    """
    try:
        from app.services.graph_service import sync_organization_background
        result = sync_organization_background(organization_id)
        if result.get("error"):
            logger.debug(f"Graph sync skipped: {result['error']}")
        elif result.get("synced", 0) > 0:
            logger.info(f"Graph sync completed: {result['synced']} assets synced to Neo4j")
    except Exception as e:
        logger.debug(f"Graph sync not available: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "20"))
VISIBILITY_TIMEOUT = int(os.getenv("VISIBILITY_TIMEOUT", "3600"))

# Multi-scan configuration
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))  # Max parallel scans
PRIORITY_AD_HOC = True  # Prioritize ad-hoc scans over scheduled

# Performance tuning from environment
DEFAULT_PORT_SCAN_RATE = int(os.getenv("PORT_SCAN_RATE", "500"))  # Packets per second
DEFAULT_NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))  # Requests per second

# Global shutdown flag
shutdown_requested = False

# Active scans tracking
active_scans = set()
scan_semaphore = None  # Initialized in worker


def _calculate_targets_expanded(targets: list) -> int:
    """
    Calculate total number of IPs from a list of targets (CIDRs, domains, IPs).
    """
    if not targets:
        return 0
    
    total = 0
    cidr_pattern = re.compile(r'^[\d.:a-fA-F]+/\d+$')
    
    for target in targets:
        if not target:
            continue
        target = str(target).strip()
        
        if cidr_pattern.match(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
                total += network.num_addresses
            except ValueError:
                total += 1
        else:
            total += 1
    
    return total


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


class ScannerWorker:
    """
    Scanner worker that processes scan jobs from SQS or database.
    
    Features:
    - Concurrent scan execution (configurable via MAX_CONCURRENT_SCANS)
    - Priority handling (ad-hoc scans run before scheduled scans)
    - Graceful shutdown with active scan tracking
    
    Job Types:
    - NUCLEI_SCAN: Run Nuclei vulnerability scan
    - PORT_SCAN: Run port scan (naabu/nmap/masscan)
    - DISCOVERY: Full asset discovery
    - SUBDOMAIN_ENUM: Subdomain enumeration
    - And more...
    """
    
    def __init__(self):
        """Initialize the scanner worker."""
        global scan_semaphore
        
        # Database connection
        if DATABASE_URL:
            self.engine = create_engine(
                DATABASE_URL,
                pool_pre_ping=True,  # Verify connections before use
                pool_reset_on_return='rollback'  # Ensure clean state on connection return
            )
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        else:
            logger.warning("DATABASE_URL not set, running in test mode")
            self.engine = None
            self.SessionLocal = None
        
        # SQS client
        if SQS_QUEUE_URL:
            self.sqs = boto3.client('sqs', region_name=AWS_REGION)
            self.queue_url = SQS_QUEUE_URL
        else:
            logger.warning("SQS_QUEUE_URL not set, running in test mode")
            self.sqs = None
            self.queue_url = None
        
        # Initialize services (lazy init for discovery which needs db)
        from app.core.config import settings
        from pathlib import Path
        _custom_templates: Optional[str] = None
        if settings.NUCLEI_CUSTOM_TEMPLATES_PATH:
            _p = Path(__file__).parent.parent.parent / settings.NUCLEI_CUSTOM_TEMPLATES_PATH
            if _p.exists():
                _custom_templates = str(_p)
                logger.info(f"Custom Nuclei templates loaded from: {_custom_templates}")
            else:
                logger.warning(f"Custom Nuclei templates path not found: {_p}")
        self.nuclei_service = NucleiService(templates_path=_custom_templates)
        self.port_scanner_service = PortScannerService()
        self._discovery_service = None  # Lazy initialized with db session
        
        # Initialize semaphore for concurrent scan limiting
        scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.scan_semaphore = scan_semaphore
        
        logger.info(f"Scanner worker initialized (max_concurrent={MAX_CONCURRENT_SCANS})")
    
    def get_discovery_service(self, db):
        """Get or create discovery service with db session."""
        return DiscoveryService(db)
    
    def get_db_session(self):
        """Get a fresh database session with clean transaction state."""
        if self.SessionLocal:
            session = self.SessionLocal()
            # Ensure we start with a clean transaction state
            try:
                session.rollback()
            except Exception:
                pass  # Ignore if no transaction to rollback
            return session
        return None
    
    async def poll_for_jobs(self):
        """Poll for scan jobs from SQS and database (hybrid approach).
        
        This ensures scans are processed whether they were queued to SQS or not.
        SQS messages are processed first, then database PENDING scans are checked.
        """
        messages = []
        
        # If SQS is configured, poll it first
        if self.sqs and self.queue_url:
            try:
                response = self.sqs.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=5,  # Shorter wait for hybrid polling
                    VisibilityTimeout=VISIBILITY_TIMEOUT,
                    MessageAttributeNames=['All']
                )
                messages = response.get('Messages', [])
            except ClientError as e:
                logger.error(f"Error polling SQS: {e}")
        
        # Also check database for any PENDING scans not in SQS
        # This catches scheduled scans that failed to queue, or scans created when SQS was down
        if not messages:
            db_messages = await self.poll_database_for_jobs()
            if db_messages:
                messages.extend(db_messages)
        
        # Check for queued on-demand finding validations (DB-backed queue).
        # These are lightweight/low-volume and run regardless of SQS config.
        if not messages:
            validation_messages = self.poll_database_for_validations()
            if validation_messages:
                messages.extend(validation_messages)

        # Pending workflow runs (Trickest-style DAG executor)
        if not messages:
            workflow_messages = self.poll_database_for_workflow_runs()
            if workflow_messages:
                messages.extend(workflow_messages)
        
        # If no messages from either source, wait before next poll
        if not messages:
            await asyncio.sleep(POLL_INTERVAL)
        
        return messages
    
    def poll_database_for_validations(self):
        """Claim queued finding validations and return them as job messages.
        
        Validations are claimed atomically (status queued -> running) at poll
        time so the same request is never processed twice, mirroring how scans
        are marked RUNNING on pickup.
        """
        db = self.get_db_session()
        if not db:
            return []
        try:
            queued = db.query(FindingValidation).filter(
                FindingValidation.status == ValidationStatus.QUEUED
            ).order_by(FindingValidation.created_at.asc()).limit(3).all()
            
            messages = []
            for validation in queued:
                validation.status = ValidationStatus.RUNNING
                validation.started_at = datetime.utcnow()
                db.commit()
                
                job_data = {
                    'job_type': 'VALIDATE_FINDING',
                    'validation_id': validation.id,
                    'vulnerability_id': validation.vulnerability_id,
                    'organization_id': validation.organization_id,
                }
                messages.append({
                    'MessageId': f'db-val-{validation.id}',
                    'ReceiptHandle': f'db-val-{validation.id}',
                    'Body': json.dumps(job_data),
                })
                logger.info(f"Claimed finding validation {validation.id} for vuln {validation.vulnerability_id}")
            
            return messages
        except Exception as e:
            logger.error(f"Error polling validations: {e}")
            db.rollback()
            return []
        finally:
            db.close()

    def poll_database_for_workflow_runs(self):
        """Claim pending workflow runs and return WORKFLOW_RUN job messages."""
        from app.models.workflow import WorkflowRun, WorkflowRunStatus

        db = self.get_db_session()
        if not db:
            return []
        try:
            pending = (
                db.query(WorkflowRun)
                .filter(WorkflowRun.status == WorkflowRunStatus.PENDING)
                .order_by(WorkflowRun.created_at.asc())
                .limit(2)
                .all()
            )
            messages = []
            for run in pending:
                # Claim immediately to avoid double pickup
                run.status = WorkflowRunStatus.RUNNING
                run.started_at = datetime.utcnow()
                run.current_step = "claimed"
                db.commit()
                job_data = {
                    "job_type": "WORKFLOW_RUN",
                    "workflow_run_id": run.id,
                    "organization_id": run.organization_id,
                    "workflow_id": run.workflow_id,
                    "version_id": run.version_id,
                }
                messages.append(
                    {
                        "MessageId": f"db-wf-{run.id}",
                        "ReceiptHandle": f"db-wf-{run.id}",
                        "Body": json.dumps(job_data),
                    }
                )
                logger.info("Claimed workflow run %s", run.id)
            return messages
        except Exception as e:
            logger.error("Error polling workflow runs: %s", e)
            try:
                db.rollback()
            except Exception:
                pass
            return []
        finally:
            db.close()

    async def handle_workflow_run(self, job_data: dict):
        """Execute a Trickest-style workflow DAG run."""
        from app.models.workflow import WorkflowRun, WorkflowRunStatus
        from app.services.workflow.executor import WorkflowExecutor

        run_id = job_data.get("workflow_run_id")
        if not run_id:
            logger.error("WORKFLOW_RUN missing workflow_run_id")
            return

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for workflow run %s", run_id)
            return
        try:
            run = db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
            if not run:
                logger.error("WorkflowRun %s not found", run_id)
                return
            if run.status in (
                WorkflowRunStatus.COMPLETED,
                WorkflowRunStatus.FAILED,
                WorkflowRunStatus.CANCELLED,
            ):
                logger.info("WorkflowRun %s already %s; skipping", run_id, run.status.value)
                return
            # Avoid double-execution if another worker already progressed this run
            if (
                run.status == WorkflowRunStatus.RUNNING
                and run.current_step
                and run.current_step not in ("claimed", "pending")
                and (run.progress or 0) > 0
            ):
                logger.info("WorkflowRun %s already in progress; skipping", run_id)
                return
            if run.status == WorkflowRunStatus.PENDING:
                run.status = WorkflowRunStatus.RUNNING
                run.started_at = datetime.utcnow()
                run.current_step = "claimed"
                db.commit()

            executor = WorkflowExecutor(db, self)
            await executor.execute(run_id)
        except Exception as e:
            logger.exception("Workflow run %s failed: %s", run_id, e)
            try:
                run = db.query(WorkflowRun).filter(WorkflowRun.id == run_id).first()
                if run and run.status not in (
                    WorkflowRunStatus.COMPLETED,
                    WorkflowRunStatus.CANCELLED,
                ):
                    run.status = WorkflowRunStatus.FAILED
                    run.error_message = str(e)[:2000]
                    run.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()
        finally:
            db.close()
    
    async def poll_database_for_jobs(self):
        """
        Poll database for pending scans.
        
        Supports concurrent execution by fetching multiple scans.
        Prioritizes ad-hoc scans (not triggered by scheduler) over scheduled scans.
        """
        db = self.get_db_session()
        if not db:
            return []
        
        try:
            # Calculate how many more scans we can run
            available_slots = MAX_CONCURRENT_SCANS - len(active_scans)
            if available_slots <= 0:
                await asyncio.sleep(5)  # Brief wait when at capacity
                return []
            
            # Find pending scans, prioritizing ad-hoc over scheduled
            # Ad-hoc scans don't have 'triggered_by_schedule' in config
            # Note: We order by created_at to process oldest first (FIFO)
            # The is_scheduled flag is determined after fetching, not in the query
            pending_scans = db.query(Scan).filter(
                Scan.status == ScanStatus.PENDING,
                ~Scan.id.in_(active_scans)  # Exclude already active
            ).order_by(
                Scan.created_at.asc()  # Process oldest scans first (FIFO)
            ).limit(available_slots).all()
            
            if not pending_scans:
                await asyncio.sleep(POLL_INTERVAL)
                return []
            
            # Convert to message format
            job_type_map = {
                ScanType.VULNERABILITY: 'NUCLEI_SCAN',
                ScanType.PORT_SCAN: 'PORT_SCAN',
                ScanType.PORT_VERIFY: 'PORT_VERIFY',
                ScanType.SERVICE_DETECT: 'SERVICE_DETECT',
                ScanType.DISCOVERY: 'DISCOVERY',
                ScanType.FULL: 'RECON_PIPELINE',  # FULL = recon workflow (discovery → port → http → resource_enum → vuln)
                ScanType.SUBDOMAIN_ENUM: 'SUBDOMAIN_ENUM',
                ScanType.DNS_RESOLUTION: 'DNS_RESOLUTION',
                ScanType.HTTP_PROBE: 'HTTP_PROBE',
                ScanType.DNS_ENUM: 'DNS_RESOLUTION',  # Alias
                ScanType.LOGIN_PORTAL: 'LOGIN_PORTAL',
                ScanType.SCREENSHOT: 'SCREENSHOT',
                ScanType.PARAMSPIDER: 'PARAMSPIDER',
                ScanType.WAYBACKURLS: 'WAYBACKURLS',
                ScanType.KATANA: 'KATANA',
                ScanType.CLEANUP: 'CLEANUP',
                ScanType.TECHNOLOGY: 'TECHNOLOGY_SCAN',
                ScanType.WHATWEB: 'WHATWEB_SCAN',
                ScanType.GEO_ENRICH: 'GEO_ENRICH',
                ScanType.TLDFINDER: 'TLDFINDER',
                ScanType.COMMONCRAWL_ENUM: 'COMMONCRAWL_ENUM',
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
                ScanType.EMAIL_BREACH: 'EMAIL_BREACH',
                ScanType.DNS_THREAT: 'DNS_THREAT',
                ScanType.URLHAUS_LOOKUP: 'URLHAUS_LOOKUP',
                ScanType.BGP_LOOKUP: 'BGP_LOOKUP',
            }
            
            messages = []
            for pending_scan in pending_scans:
                job_type = job_type_map.get(pending_scan.scan_type, 'NUCLEI_SCAN')
                config = pending_scan.config or {}
                is_scheduled = config.get('triggered_by_schedule') is not None
                
                # Build job data with config values extracted
                job_data = {
                    'job_type': job_type,
                    'scan_id': pending_scan.id,
                    'organization_id': pending_scan.organization_id,
                    'targets': pending_scan.targets or [],
                    'config': config,
                    'is_scheduled': is_scheduled,
                    # Extract common config fields for easier access
                    'scanner': config.get('scanner', 'naabu'),
                    'ports': config.get('ports'),
                    'severity': config.get('severity'),
                    'tags': config.get('tags'),
                    'exclude_tags': config.get('exclude_tags'),
                    'service_detection': config.get('service_detection', True),
                    'domain': pending_scan.targets[0] if pending_scan.targets else None,
                }
                
                message = {
                    'MessageId': f'db-{pending_scan.id}',
                    'ReceiptHandle': f'db-{pending_scan.id}',
                    'Body': json.dumps(job_data)
                }
                messages.append(message)
                
                scan_type_str = 'scheduled' if is_scheduled else 'ad-hoc'
                logger.info(f"Found {scan_type_str} scan {pending_scan.id} ({pending_scan.scan_type.value})")
            
            return messages
            
        except Exception as e:
            logger.error(f"Error polling database: {e}")
            return []
        finally:
            db.close()
    
    def _mark_scan_running(self, scan_id: int) -> bool:
        """Mark a scan as RUNNING immediately. Returns True if successful."""
        db = self.get_db_session()
        if not db:
            logger.error(f"Scan {scan_id}: No database connection to mark RUNNING")
            return False
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status == ScanStatus.PENDING:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan {scan_id} marked as RUNNING")
                return True
            elif scan:
                logger.warning(f"Scan {scan_id} already has status {scan.status.value}, skipping")
                return False
            else:
                logger.error(f"Scan {scan_id} not found in database")
                return False
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as RUNNING: {e}")
            db.rollback()
            return False
        finally:
            db.close()
    
    def _mark_scan_failed(self, scan_id: int, error_message: str):
        """Mark a scan as FAILED."""
        db = self.get_db_session()
        if not db:
            logger.error(f"Scan {scan_id}: No database connection to mark FAILED")
            return
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status != ScanStatus.COMPLETED:
                scan.status = ScanStatus.FAILED
                scan.error_message = error_message[:500] if error_message else "Unknown error"
                scan.completed_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan {scan_id} marked as FAILED: {error_message[:100]}")
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as FAILED: {e}")
            db.rollback()
        finally:
            db.close()

    def _recover_stuck_scan_if_needed(self, scan_id: int):
        """
        If scan is RUNNING and has been for a while (e.g. worker crashed), reset to PENDING
        so the next poll can retry it. Uses a 10-minute threshold to avoid resetting active scans.
        """
        from datetime import timedelta
        STUCK_THRESHOLD_MINUTES = 10
        db = self.get_db_session()
        if not db:
            return
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan or scan.status != ScanStatus.RUNNING:
                return
            threshold = datetime.utcnow() - timedelta(minutes=STUCK_THRESHOLD_MINUTES)
            if scan.started_at and scan.started_at < threshold:
                old_started = scan.started_at
                scan.status = ScanStatus.PENDING
                scan.started_at = None
                scan.error_message = ((scan.error_message or "")[:200] + " [Reset: was RUNNING >10m]")[:500]
                db.commit()
                logger.info(f"Scan {scan_id} reset to PENDING (was RUNNING since {old_started})")
        except Exception as e:
            logger.debug(f"Could not recover stuck scan {scan_id}: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def recover_stale_scans(self) -> int:
        """
        Detect and recover scans that are stuck in RUNNING status.
        
        Scans are considered stale if they:
        - Have been RUNNING for more than STALE_SCAN_THRESHOLD_MINUTES
        - Are not currently being processed by this worker (not in active_scans)
        
        Stale scans are reset to PENDING to be retried.
        
        Returns the count of recovered scans.
        """
        # Must be above NUCLEI_MAX_RUNTIME_CAP_SECONDS (default 2700s / 45m)
        # so legitimate scaled nuclei jobs can finish.
        STALE_SCAN_THRESHOLD_MINUTES = 55
        
        db = self.get_db_session()
        if not db:
            return 0
        
        try:
            from datetime import timedelta
            threshold = datetime.utcnow() - timedelta(minutes=STALE_SCAN_THRESHOLD_MINUTES)
            
            # Find scans RUNNING longer than the threshold. Include ones still in
            # active_scans — previously we skipped those, so a hung nuclei
            # subprocess held a worker slot forever and the queue wedged.
            stale_scans = db.query(Scan).filter(
                Scan.status == ScanStatus.RUNNING,
                Scan.started_at < threshold,
            ).all()
            
            recovered_count = 0
            for scan in stale_scans:
                # Reset to PENDING so it will be retried
                old_error = scan.error_message or ""
                scan.status = ScanStatus.PENDING
                scan.started_at = None
                scan.error_message = f"Recovered from stale RUNNING state after {STALE_SCAN_THRESHOLD_MINUTES}+ minutes. Previous error: {old_error[:200]}"
                
                # Track retry count in config
                config = scan.config or {}
                retry_count = config.get('_retry_count', 0) + 1
                config['_retry_count'] = retry_count
                config['_last_recovery'] = datetime.utcnow().isoformat()
                scan.config = config
                
                # If too many retries, mark as failed instead
                if retry_count >= 3:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = f"Failed after {retry_count} automatic recovery attempts. Manual investigation required."
                    scan.completed_at = datetime.utcnow()
                    logger.warning(f"Scan {scan.id} failed after {retry_count} recovery attempts")
                else:
                    logger.info(f"Recovered stale scan {scan.id} (attempt {retry_count})")
                    recovered_count += 1
            
            if stale_scans:
                db.commit()
                logger.info(f"Recovered {recovered_count} stale scans, {len(stale_scans) - recovered_count} marked as failed")
            
            return recovered_count
            
        except Exception as e:
            logger.error(f"Error recovering stale scans: {e}")
            db.rollback()
            return 0
        finally:
            db.close()

    def _delete_sqs_message_safe(self, message_id: str, receipt_handle: str, is_db_message: bool, scan_id: int = None):
        """Safely delete an SQS message with comprehensive logging."""
        if is_db_message:
            logger.debug(f"Skipping SQS delete for database message {message_id}")
            return
        
        if not self.sqs:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: SQS client not initialized")
            return
            
        if not self.queue_url:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: Queue URL not configured")
            return
            
        if not receipt_handle:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: No receipt handle")
            return
        
        try:
            self.sqs.delete_message(
                QueueUrl=self.queue_url,
                ReceiptHandle=receipt_handle
            )
            logger.info(f"Deleted SQS message {message_id} for scan {scan_id}")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"AWS error deleting SQS message for scan {scan_id}: {error_code} - {e}")
        except Exception as e:
            logger.error(f"Failed to delete SQS message for scan {scan_id}: {type(e).__name__}: {e}")

    async def _auto_close_stale_findings(
        self,
        db,
        organization_id: int,
        scanned_hosts: set,
        current_findings: list,
        scan_id: int
    ) -> int:
        """
        Auto-close findings that were not detected in the current scan.
        
        This compares previous open findings against what was found in this scan.
        If a finding existed before but wasn't re-detected on the same host+template,
        it's marked as resolved (auto-closed).
        
        Returns the count of auto-resolved findings.
        """
        from app.models.vulnerability import Vulnerability, VulnerabilityStatus
        from urllib.parse import urlparse
        
        # Normalize scanned hosts (remove protocol/port)
        normalized_hosts = set()
        for host in scanned_hosts:
            if host.startswith(("http://", "https://")):
                normalized = urlparse(host).netloc.split(":")[0]
            else:
                normalized = host.split(":")[0]
            if normalized:
                normalized_hosts.add(normalized.lower())
        
        if not normalized_hosts:
            return 0
        
        # Build a set of (host, template_id) tuples from current findings
        current_finding_keys = set()
        for finding in current_findings:
            if finding.host and finding.template_id:
                host = finding.host
                if host.startswith(("http://", "https://")):
                    host = urlparse(host).netloc.split(":")[0]
                else:
                    host = host.split(":")[0]
                if host:
                    current_finding_keys.add((host.lower(), finding.template_id))
        
        # Get assets that were scanned
        from app.models.asset import Asset
        scanned_assets = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value.in_(list(normalized_hosts))
        ).all()
        
        if not scanned_assets:
            return 0
        
        scanned_asset_ids = [a.id for a in scanned_assets]
        scanned_asset_values = {a.id: a.value.lower() for a in scanned_assets}
        
        # Find all open findings for scanned assets
        open_findings = db.query(Vulnerability).filter(
            Vulnerability.asset_id.in_(scanned_asset_ids),
            Vulnerability.status == VulnerabilityStatus.OPEN
        ).all()
        
        auto_resolved_count = 0
        for finding in open_findings:
            if not finding.template_id:
                continue  # Skip findings without template_id
            
            asset_value = scanned_asset_values.get(finding.asset_id, "").lower()
            if not asset_value:
                continue
            
            # Check if this finding was re-detected
            finding_key = (asset_value, finding.template_id)
            if finding_key not in current_finding_keys:
                # Finding was not re-detected - auto-close it
                finding.status = VulnerabilityStatus.RESOLVED
                finding.resolved_at = datetime.utcnow()
                if finding.metadata_ is None:
                    finding.metadata_ = {}
                finding.metadata_['auto_resolved'] = True
                finding.metadata_['auto_resolved_scan_id'] = scan_id
                finding.metadata_['auto_resolved_reason'] = 'Not detected in rescan'
                auto_resolved_count += 1
        
        if auto_resolved_count > 0:
            db.commit()
        
        return auto_resolved_count

    async def process_message(self, message: dict):
        """Process a single scan job message."""
        message_id = message.get('MessageId')
        receipt_handle = message.get('ReceiptHandle')
        is_db_message = message_id.startswith('db-') if message_id else False
        
        try:
            body = json.loads(message.get('Body', '{}'))
            job_type = body.get('job_type')
            scan_id = body.get('scan_id')
            
            logger.info(f"Processing job {message_id}: type={job_type}, scan_id={scan_id}")
            
            # CRITICAL: Mark scan as RUNNING immediately to prevent re-polling
            if scan_id and not self._mark_scan_running(scan_id):
                logger.warning(f"Scan {scan_id} could not be marked RUNNING, skipping")
                # If scan is stuck RUNNING (e.g. worker crashed), reset to PENDING so it can be retried
                self._recover_stuck_scan_if_needed(scan_id)
                # IMPORTANT: Delete the SQS message even when skipping to prevent infinite reprocessing
                self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                return
            
            try:
                # Route to appropriate handler
                if job_type == 'NUCLEI_SCAN':
                    await self.handle_nuclei_scan(body)
                elif job_type == 'PORT_SCAN':
                    await self.handle_port_scan(body)
                elif job_type == 'PORT_VERIFY':
                    await self.handle_port_verify(body)
                elif job_type == 'SERVICE_DETECT':
                    await self.handle_service_detect(body)
                elif job_type == 'DISCOVERY':
                    await self.handle_discovery(body)
                elif job_type == 'SUBDOMAIN_ENUM':
                    await self.handle_subdomain_enum(body)
                elif job_type == 'DNS_RESOLUTION':
                    await self.handle_dns_resolution(body)
                elif job_type == 'HTTP_PROBE':
                    await self.handle_http_probe(body)
                elif job_type == 'LOGIN_PORTAL':
                    await self.handle_login_portal_scan(body)
                elif job_type == 'SCREENSHOT':
                    await self.handle_screenshot_scan(body)
                elif job_type == 'PARAMSPIDER':
                    await self.handle_paramspider_scan(body)
                elif job_type == 'WAYBACKURLS':
                    await self.handle_waybackurls_scan(body)
                elif job_type == 'KATANA':
                    await self.handle_katana_scan(body)
                elif job_type == 'CLEANUP':
                    await self.handle_cleanup(body)
                elif job_type == 'TECHNOLOGY_SCAN':
                    await self.handle_technology_scan(body)
                elif job_type == 'WHATWEB_SCAN':
                    # WhatWeb enrichment: same as technology scan with source=whatweb
                    whatweb_body = {**body, "config": {**(body.get("config") or {}), "source": "whatweb"}}
                    await self.handle_technology_scan(whatweb_body)
                elif job_type == 'GEO_ENRICH':
                    await self.handle_geo_enrichment(body)
                elif job_type == 'TLDFINDER':
                    await self.handle_tldfinder_scan(body)
                elif job_type == 'COMMONCRAWL_ENUM':
                    await self.handle_commoncrawl_enum_scan(body)
                elif job_type == 'RECON_PIPELINE':
                    await self.handle_recon_pipeline(body)
                elif job_type == 'LLM_RED_TEAM':
                    await self.handle_llm_red_team(body)
                elif job_type == 'ATLAS_DISCOVERY':
                    await self.handle_atlas_discovery(body)
                elif job_type == 'ARGUS_SECRETS':
                    await self.handle_argus_secrets(body)
                elif job_type == 'HERMES_SECRETS':
                    await self.handle_hermes_secrets(body)
                elif job_type == 'JANUS_DAST':
                    await self.handle_janus_dast(body)
                elif job_type == 'THEMIS_CSPM':
                    await self.handle_themis_cspm(body)
                elif job_type == 'SUBDOMAIN_TAKEOVER':
                    await self.handle_subdomain_takeover(body)
                elif job_type == 'GRAPHQL_SCAN':
                    await self.handle_graphql_scan(body)
                elif job_type == 'JS_RECON':
                    await self.handle_js_recon(body)
                elif job_type == 'JSLUICE_SCAN':
                    await self.handle_jsluice_scan(body)
                elif job_type == 'TRUFFLEHOG_SCAN':
                    await self.handle_trufflehog_scan(body)
                elif job_type == 'EMAIL_BREACH':
                    await self.handle_email_breach(body)
                elif job_type == 'DNS_THREAT':
                    await self.handle_dns_threat(body)
                elif job_type == 'URLHAUS_LOOKUP':
                    await self.handle_urlhaus_lookup(body)
                elif job_type == 'BGP_LOOKUP':
                    await self.handle_bgp_lookup(body)
                elif job_type == 'VALIDATE_FINDING':
                    await self.handle_validate_finding(body)
                elif job_type == 'WORKFLOW_RUN':
                    await self.handle_workflow_run(body)
                else:
                    logger.warning(f"Unknown job type: {job_type}")
                    if scan_id:
                        self._mark_scan_failed(scan_id, f"Unknown job type: {job_type}")
                    # Delete message for unknown job types to prevent infinite reprocessing
                    self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                    return
            except Exception as handler_error:
                logger.error(f"Scan {scan_id} handler failed: {handler_error}", exc_info=True)
                if scan_id:
                    self._mark_scan_failed(scan_id, str(handler_error))
                # Delete message even on failure to prevent infinite reprocessing
                self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                raise
            
            # Delete message from SQS queue after successful processing
            self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
            
            logger.info(f"Job {message_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error processing message {message_id}: {e}", exc_info=True)
            # Message will return to queue after visibility timeout (SQS)
            # For DB messages, the scan status will be set to FAILED by handlers
    
    async def handle_validate_finding(self, job_data: dict):
        """Validate a single finding by invoking the Aegis Vanguard validator agent.

        Invokes aegis-vanguard/validate_finding.py (via `docker run` of the
        Aegis Vanguard image by default, or a local subprocess when
        AEGIS_VALIDATOR_MODE=subprocess). The agent actively re-tests the
        live target and returns a structured JSON verdict, which is written back
        to the FindingValidation row and denormalized onto the Vulnerability.
        A false positive attributed to the template's own logic also records a
        DetectionFeedback entry with a generated upstream bug report.
        """
        import subprocess
        from pathlib import Path
        from urllib.parse import urlparse

        try:
            from app.models.finding_validation import (
                FindingValidation,
                ValidationStatus,
                ValidationVerdict,
            )
        except ModuleNotFoundError:
            logger.error(
                "VALIDATE_FINDING: app.models.finding_validation is not installed "
                "in this image — skipping validation job"
            )
            return

        JSON_START = "===VALIDATION_JSON_START==="
        JSON_END = "===VALIDATION_JSON_END==="

        validation_id = job_data.get('validation_id')
        vulnerability_id = job_data.get('vulnerability_id')

        db = self.get_db_session()
        if not db:
            logger.error("VALIDATE_FINDING: no database connection")
            return
        validation = None
        try:
            validation = db.query(FindingValidation).filter(
                FindingValidation.id == validation_id
            ).first() if validation_id else None
            if not validation:
                logger.error(f"VALIDATE_FINDING: validation {validation_id} not found")
                return

            # Idempotency: with the SQS + DB-poll hybrid, a validation could be
            # delivered twice. Skip anything already finished.
            if validation.status == ValidationStatus.COMPLETED:
                logger.info(f"VALIDATE_FINDING: validation {validation.id} already completed, skipping")
                return

            vuln = db.query(Vulnerability).filter(
                Vulnerability.id == validation.vulnerability_id
            ).first()
            if not vuln:
                validation.status = ValidationStatus.FAILED
                validation.error = "vulnerability_not_found"
                validation.completed_at = datetime.utcnow()
                db.commit()
                return

            # Ensure claimed (SQS path may not have gone through the DB poller).
            if validation.status != ValidationStatus.RUNNING:
                validation.status = ValidationStatus.RUNNING
                if not validation.started_at:
                    validation.started_at = datetime.utcnow()
                db.commit()

            # Resolve a target for the validator to re-test. Findings come from many
            # sources (nuclei, port_scanner, js_recon, trufflehog, manual, ...), each
            # storing the affected location differently — probe common keys, then fall
            # back to the asset value (and host:port for network findings).
            meta = vuln.metadata_ or {}
            asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
            asset_value = asset.value if asset else None
            target = None
            for key in (
                "nuclei_matched_at", "nuclei_host", "matched_at", "url", "endpoint",
                "location", "request_url", "target", "host",
            ):
                if meta.get(key):
                    target = meta[key]
                    break
            if not target and meta.get("port"):
                base_host = meta.get("scanned_ip") or asset_value
                if base_host:
                    target = f"{base_host}:{meta['port']}"
            if not target and vuln.affected_component:
                target = vuln.affected_component
            if not target:
                target = asset_value
            severity = vuln.severity.value if vuln.severity else "medium"

            # Classify the source so the validator can pick the right re-test strategy.
            detected_by = (vuln.detected_by or "").lower()
            if vuln.is_manual:
                source_kind = "manual"
            elif detected_by in ("port_scanner",):
                source_kind = "network_service"
            elif detected_by in ("trufflehog", "github_secret_scanner"):
                source_kind = "secret"
            elif detected_by in (
                "nuclei", "graphql_scanner", "takeover_scanner", "js_recon",
                "jsluice", "agent", "llm_red_team", "auto_discovery",
            ):
                source_kind = "web"
            else:
                source_kind = "generic"

            # Resolve the matched template's YAML so the validator can reason about
            # WHY the template fired (true positive vs. template-logic mis-detection).
            template_yaml = None
            if vuln.template_id:
                try:
                    from app.services.custom_template_ai import lookup_template_yaml
                    template_yaml = lookup_template_yaml(db, validation.organization_id, vuln.template_id)
                except Exception as e:
                    logger.debug(f"VALIDATE_FINDING: could not load template YAML: {e}")

            # Trim metadata to keep the payload bounded but source-aware.
            trimmed_meta = {}
            if isinstance(meta, dict):
                for k, v in meta.items():
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        trimmed_meta[k] = v
                    else:
                        trimmed_meta[k] = str(v)[:500]

            finding_payload = {
                "id": vuln.id,
                "title": vuln.title,
                "description": vuln.description,
                "severity": severity,
                "status": vuln.status.value if vuln.status else None,
                "target": target,
                "asset": asset_value,
                "source_kind": source_kind,
                "detected_by": vuln.detected_by,
                "template_id": vuln.template_id,
                "template_yaml": template_yaml,
                "matcher_name": vuln.matcher_name,
                "cve_id": vuln.cve_id,
                "cwe_id": vuln.cwe_id,
                "detection_confidence": vuln.detection_confidence,
                "references": vuln.references or [],
                "tags": vuln.tags or [],
                "evidence": vuln.evidence,
                # Manual / pentest context (present for manual and some agent findings).
                "is_manual": bool(vuln.is_manual),
                "impact": vuln.impact,
                "affected_component": vuln.affected_component,
                "steps_to_reproduce": vuln.steps_to_reproduce,
                "proof_of_concept": vuln.proof_of_concept,
                # Full (trimmed) source metadata so the agent can read source-specific fields.
                "metadata": trimmed_meta,
            }
            finding_json = json.dumps(finding_payload, default=str)

            scope = ""
            if target:
                host = urlparse(target if "://" in str(target) else f"//{target}").hostname or str(target)
                scope = host

            # Build the validator invocation.
            mode = os.getenv("AEGIS_VALIDATOR_MODE", "docker").lower()
            max_turns = os.getenv("AEGIS_VALIDATE_MAX_TURNS", "20")
            timeout_sec = int(os.getenv("AEGIS_VALIDATE_TIMEOUT", "900"))
            cwd = None
            if mode == "subprocess":
                vanguard_path = os.getenv("AEGIS_VANGUARD_PATH") or str(
                    Path(__file__).resolve().parents[3] / "aegis-vanguard"
                )
                cmd = [
                    "python3", os.path.join(vanguard_path, "validate_finding.py"),
                    "--finding-json", "-", "--max-turns", str(max_turns),
                ]
                cwd = vanguard_path
            else:
                image = os.getenv("AEGIS_VANGUARD_IMAGE", "aegis-vanguard:latest")
                cmd = [
                    "docker", "run", "--rm", "-i",
                    "-e", "ANTHROPIC_API_KEY", "-e", "AEGIS_MODEL",
                    image,
                    "python3", "/agent/validate_finding.py",
                    "--finding-json", "-", "--max-turns", str(max_turns),
                ]
            if scope:
                cmd += ["--scope", scope]

            logger.info(
                f"VALIDATE_FINDING: validating vuln {vuln.id} (source={source_kind}, "
                f"detected_by={vuln.detected_by}, template={vuln.template_id}) "
                f"on {target} via {mode}"
            )

            def _run():
                return subprocess.run(
                    cmd,
                    input=finding_json,
                    capture_output=True,
                    text=True,
                    timeout=timeout_sec,
                    cwd=cwd,
                    env=os.environ.copy(),
                )

            verdict_data = None
            run_error = None
            try:
                proc = await asyncio.to_thread(_run)
                stdout = proc.stdout or ""
                if JSON_START in stdout and JSON_END in stdout:
                    chunk = stdout.split(JSON_START, 1)[1].split(JSON_END, 1)[0].strip()
                    try:
                        verdict_data = json.loads(chunk)
                    except json.JSONDecodeError as e:
                        run_error = f"unparseable_verdict: {e}"
                else:
                    run_error = "no_verdict_in_output"
                    logger.warning(
                        f"VALIDATE_FINDING: no verdict sentinels in output. "
                        f"stderr tail: {(proc.stderr or '')[-500:]}"
                    )
            except subprocess.TimeoutExpired:
                run_error = "validator_timeout"
            except FileNotFoundError as e:
                run_error = f"invocation_failed: {e}"
            except Exception as e:
                run_error = f"validator_error: {e}"

            now = datetime.utcnow()
            if verdict_data is None:
                validation.status = ValidationStatus.FAILED
                validation.error = (run_error or "unknown_error")[:255]
                validation.completed_at = now
                vuln.validation_status = "failed"
                vuln.last_validated_at = now
                db.commit()
                logger.warning(f"VALIDATE_FINDING: validation {validation.id} failed: {run_error}")
                return

            verdict_str = str(verdict_data.get("verdict", "needs_more_evidence")).lower()
            verdict_map = {
                "confirmed": ValidationVerdict.CONFIRMED,
                "false_positive": ValidationVerdict.FALSE_POSITIVE,
                "needs_more_evidence": ValidationVerdict.NEEDS_MORE_EVIDENCE,
            }
            verdict_enum = verdict_map.get(verdict_str, ValidationVerdict.NEEDS_MORE_EVIDENCE)
            template_logic_issue = verdict_data.get("template_logic_issue")

            validation.status = ValidationStatus.COMPLETED
            validation.verdict = verdict_enum
            validation.confidence = str(verdict_data.get("confidence") or "")[:20] or None
            validation.recommended_severity = str(verdict_data.get("recommended_severity") or "")[:20] or None
            validation.reasoning = verdict_data.get("reasoning")
            validation.evidence = verdict_data.get("evidence")
            validation.template_logic_issue = template_logic_issue
            validation.error = verdict_data.get("error")
            validation.raw_output = verdict_data
            validation.completed_at = now

            vuln.validation_status = "completed"
            vuln.last_validation_verdict = verdict_enum.value
            vuln.last_validated_at = now
            db.commit()

            # Log a template-logic issue when the FP is attributed to the template.
            if verdict_enum == ValidationVerdict.FALSE_POSITIVE and vuln.template_id and template_logic_issue:
                try:
                    from app.services.detection_feedback_service import record_detection_feedback
                    record_detection_feedback(
                        db,
                        organization_id=validation.organization_id,
                        template_id=vuln.template_id,
                        logic_issue=str(template_logic_issue),
                        detected_by=vuln.detected_by or "nuclei",
                        verdict="false_positive",
                        severity=severity,
                        target=str(target) if target else None,
                        evidence=verdict_data.get("evidence"),
                        reasoning=verdict_data.get("reasoning"),
                        example_vulnerability_id=vuln.id,
                        finding_validation_id=validation.id,
                        source="validator_agent",
                    )
                    logger.info(
                        f"VALIDATE_FINDING: recorded detection feedback for template {vuln.template_id}"
                    )
                except Exception as e:
                    logger.error(f"VALIDATE_FINDING: failed to record detection feedback: {e}")

            # Close the loop: when a template-logic false positive is confirmed and
            # auto-refine is enabled, generate a tightened template and re-check it
            # against the known false-positive target.
            auto_refine = os.getenv("NUCLEI_AUTO_REFINE_ON_FP", "false").lower() in ("1", "true", "yes")
            if (
                auto_refine
                and verdict_enum == ValidationVerdict.FALSE_POSITIVE
                and vuln.template_id
                and template_logic_issue
                and template_yaml
            ):
                try:
                    from app.services import custom_template_ai as ai
                    refined = await ai.refine_template(
                        db,
                        organization_id=validation.organization_id,
                        template_logic_issue=str(template_logic_issue),
                        original_yaml=template_yaml,
                        template_id=vuln.template_id,
                        target=str(target) if target else None,
                        evidence=verdict_data.get("evidence"),
                        reasoning=verdict_data.get("reasoning"),
                        cve_ids=[vuln.cve_id] if vuln.cve_id else None,
                        created_by_user_id=validation.requested_by_user_id,
                        example_vulnerability_id=vuln.id,
                    )
                    recheck = None
                    if target:
                        recheck = await ai.recheck_template_against_target(
                            refined.template_yaml, str(target)
                        )
                    # Record the produced refinement on the validation for the UI.
                    ro = dict(validation.raw_output or {})
                    ro["refined_template_id"] = refined.id
                    ro["refined_template_key"] = refined.template_id
                    ro["refined_recheck"] = recheck
                    validation.raw_output = ro
                    db.commit()
                    logger.info(
                        f"VALIDATE_FINDING: auto-refined template {vuln.template_id} -> "
                        f"draft custom template {refined.template_id} (recheck={recheck})"
                    )
                except Exception as e:
                    logger.error(f"VALIDATE_FINDING: auto-refine failed: {e}", exc_info=True)

            # Re-evaluate the false-positive pattern for this template. A pattern
            # spanning enough hosts raises a suppression recommendation (it never
            # auto-suppresses without analyst approval).
            if verdict_enum == ValidationVerdict.FALSE_POSITIVE and vuln.template_id:
                try:
                    from app.services.detection_pattern_service import evaluate_template
                    evaluate_template(
                        db,
                        organization_id=validation.organization_id,
                        template_id=vuln.template_id,
                        detected_by=vuln.detected_by or "nuclei",
                    )
                except Exception as e:
                    logger.error(f"VALIDATE_FINDING: pattern evaluation failed: {e}")

            logger.info(
                f"VALIDATE_FINDING: validation {validation.id} completed -> {verdict_enum.value}"
            )
        except Exception as e:
            logger.error(f"VALIDATE_FINDING handler error: {e}", exc_info=True)
            try:
                if validation:
                    validation.status = ValidationStatus.FAILED
                    validation.error = str(e)[:255]
                    validation.completed_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()
        finally:
            db.close()

    def _queue_nuclei_follow_ups(self, db, parent_scan, remaining_targets, config, chunk_size):
        """Queue the *next* follow-up NUCLEI scan only (chain, don't flood).

        Previously we enqueued every remaining chunk at once (part 2..N), which
        filled the worker with dozens of PENDING/RUNNING nuclei jobs and starved
        ad-hoc scans. Now we enqueue a single follow-up that carries ALL remaining
        hosts; when that job starts it re-applies the cap and queues the next
        link in the chain.
        """
        if not remaining_targets:
            return 0
        try:
            parent_name = parent_scan.name if (parent_scan and parent_scan.name) else "nuclei"
            # Strip prior "(part N)" so names stay "foo (part 3)" not "foo (part 2) (part 3)"
            import re
            base_name = re.sub(r"\s*\(part \d+\)\s*$", "", parent_name).strip() or "nuclei"
            part_num = int((config or {}).get("follow_up_part", 1)) + 1
            org_id = parent_scan.organization_id if parent_scan else config.get("organization_id")
            started_by = parent_scan.started_by if parent_scan else "system"
            follow_config = {
                **(config or {}),
                # Skip expensive asset pre-create; still allow re-split/cap.
                "skip_asset_precreate": True,
                "max_targets": chunk_size,
                "follow_up_part": part_num,
            }
            # Drop obsolete flag if present
            follow_config.pop("presplit", None)
            db.add(Scan(
                name=f"{base_name} (part {part_num})",
                scan_type=ScanType.VULNERABILITY,
                organization_id=org_id,
                targets=list(remaining_targets),
                config=follow_config,
                started_by=started_by,
                status=ScanStatus.PENDING,
            ))
            db.commit()
            logger.info(
                f"Queued Nuclei follow-up '{base_name} (part {part_num})' "
                f"with {len(remaining_targets)} remaining hosts"
            )
            return 1
        except Exception as e:
            logger.error(f"Failed to queue Nuclei follow-up scan: {e}")
            try:
                db.rollback()
            except Exception:
                pass
            return 0

    async def handle_nuclei_scan(self, job_data: dict):
        """Handle Nuclei vulnerability scan job."""
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        # Default to all severities to catch all findings (including info for asset discovery)
        severity = job_data.get('severity') or ['critical', 'high', 'medium', 'low', 'info']
        tags = job_data.get('tags') or []
        exclude_tags = job_data.get('exclude_tags') or []
        # Follow-up scans: skip asset pre-create, but still apply the host cap
        # and chain the next part (one at a time) so the queue isn't flooded.
        _cfg_early = job_data.get('config') or {}
        skip_asset_precreate = bool(
            _cfg_early.get('skip_asset_precreate') or _cfg_early.get('presplit')
        )
        
        # Drop CIDR/netblock ranges — expanding them into 100k+ hosts is what
        # wedged the worker (scans never finished, slots never freed).
        from app.services.nuclei_service import filter_nuclei_targets
        targets, skipped_cidrs = filter_nuclei_targets(targets)
        if skipped_cidrs:
            logger.warning(
                f"Nuclei scan {scan_id}: skipped {skipped_cidrs} CIDR/netblock "
                f"target(s); Nuclei will run against hostnames/IPs/URLs only"
            )

        # Normalize targets - ensure URLs have protocol
        normalized_targets = []
        for target in targets:
            target = target.strip()
            if not target:
                continue
            # If it's a domain without protocol, add https://
            if not target.startswith(('http://', 'https://')) and '/' not in target:
                # It's a bare domain - try https first
                normalized_targets.append(f"https://{target}")
            else:
                normalized_targets.append(target)
        
        if normalized_targets:
            targets = normalized_targets
            logger.info(f"Normalized {len(targets)} targets for Nuclei scan")

        if not targets:
            logger.error(f"Nuclei scan {scan_id}: no eligible targets after CIDR filter")
            self._mark_scan_failed(scan_id, "No eligible Nuclei targets (CIDR ranges are skipped)")
            return
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for Nuclei scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            # Status is already set to RUNNING in process_message
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            # IMPORTANT: Create assets for ALL targets BEFORE scanning
            # This ensures assets appear in the assets table even if no vulnerabilities are found
            from urllib.parse import urlparse
            assets_created = 0
            assets_updated = 0
            
            if scan:
                scan.current_step = "Creating assets for scan targets"
                db.commit()

            # Cap asset pre-creation — looping 10k targets with per-row queries
            # was delaying nuclei start by minutes and holding a worker slot.
            asset_targets = [] if skip_asset_precreate else targets[:500]
            
            for target in asset_targets:
                try:
                    # Extract hostname from URL
                    target_str = target.strip()
                    if target_str.startswith(('http://', 'https://')):
                        parsed = urlparse(target_str)
                        hostname = parsed.hostname or parsed.netloc
                        if hostname and ':' in hostname:
                            hostname = hostname.split(':')[0]
                    else:
                        hostname = target_str.split(':')[0] if ':' in target_str else target_str
                    
                    if not hostname:
                        continue
                    
                    hostname = hostname.lower().strip()
                    
                    # Check if asset already exists
                    existing_asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == hostname
                    ).first()
                    
                    if existing_asset:
                        # Update last seen
                        existing_asset.last_seen = datetime.utcnow()
                        assets_updated += 1
                    else:
                        # Determine asset type based on hostname pattern
                        import re
                        is_ip = bool(re.match(r'^[\d.]+$', hostname) or ':' in hostname)  # IPv4 or IPv6
                        
                        # Determine if it's a subdomain or root domain
                        parts = hostname.split('.')
                        if is_ip:
                            asset_type = AssetType.IP_ADDRESS
                        elif len(parts) > 2:
                            asset_type = AssetType.SUBDOMAIN
                        else:
                            asset_type = AssetType.DOMAIN
                        
                        # Extract root domain for subdomain assets
                        root_domain = None
                        if asset_type == AssetType.SUBDOMAIN and len(parts) >= 2:
                            # Get last two parts (e.g., rockwell.com from sub.domain.rockwell.com)
                            root_domain = '.'.join(parts[-2:])
                        
                        # Create the asset
                        new_asset = Asset(
                            organization_id=organization_id,
                            name=hostname,
                            value=hostname,
                            asset_type=asset_type,
                            root_domain=root_domain,
                            discovery_source="nuclei_scan",
                            association_reason=f"Added as target for vulnerability scan {scan_id}",
                            status=AssetStatus.DISCOVERED,
                            in_scope=True,
                            # For IP assets, also populate ip_address fields
                            ip_address=hostname if is_ip else None,
                            ip_addresses=[hostname] if is_ip else [],
                        )
                        db.add(new_asset)
                        assets_created += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to create asset for target {target}: {e}")
                    continue
            
            # Commit assets before running scan
            if assets_created > 0 or assets_updated > 0:
                db.commit()
                logger.info(f"Pre-scan asset creation: {assets_created} created, {assets_updated} updated")
            
            if scan:
                scan.current_step = "Running Nuclei vulnerability scan"
                db.commit()
            
            # Run Nuclei scan
            logger.info(f"Starting Nuclei scan on {len(targets)} targets with severity: {severity}")
            logger.debug(f"Nuclei targets: {targets[:5]}{'...' if len(targets) > 5 else ''}")
            
            # Get rate limit from config or use environment default
            config = job_data.get('config', {})
            rate_limit = config.get('rate_limit', DEFAULT_NUCLEI_RATE_LIMIT)

            # Cap hosts per job so one scan can't monopolize a worker slot.
            # CIDRs were already filtered out above — slice the host list only.
            # Queue at most ONE follow-up with the remainder (chained); that job
            # will re-cap and enqueue the next link when it runs.
            targets_to_scan = targets
            # Env wins over baked-in follow-up config (older parts had max_targets=500
            # which cannot finish under the runtime budget and returns 0 findings).
            try:
                max_targets = int(
                    os.getenv('NUCLEI_MAX_TARGETS_PER_SCAN')
                    or config.get('max_targets')
                    or 75
                )
            except (TypeError, ValueError):
                max_targets = 75
            if max_targets > 0 and len(targets) > max_targets:
                targets_to_scan = targets[:max_targets]
                remaining = targets[max_targets:]
                queued = self._queue_nuclei_follow_ups(
                    db,
                    scan,
                    remaining,
                    {**config, 'severity': severity, 'tags': tags, 'exclude_tags': exclude_tags},
                    max_targets,
                )
                logger.warning(
                    f"Nuclei scan {scan_id}: {len(targets)} hosts exceed cap "
                    f"{max_targets}; scanning first {len(targets_to_scan)} and queued "
                    f"{queued} follow-up scan(s) for {len(remaining)} remaining hosts."
                )

            # Materialize this org's active custom (analyst/AI-generated) templates
            # from the DB to disk so Nuclei can actually run them alongside the
            # shipped/official templates.
            extra_templates = None
            try:
                from app.services.custom_template_store import materialize_org_templates
                custom_dir = materialize_org_templates(db, organization_id)
                if custom_dir:
                    extra_templates = [custom_dir]
                    logger.info(f"Including custom templates from {custom_dir} in Nuclei scan")
            except Exception as e:
                logger.warning(f"Failed to materialize custom Nuclei templates: {e}")

            result = await self.nuclei_service.scan_targets(
                targets=targets_to_scan,
                severity=severity,
                tags=tags if tags else None,
                exclude_tags=exclude_tags if exclude_tags else None,
                templates=extra_templates,
                rate_limit=rate_limit
            )
            
            # Log Nuclei results
            logger.info(
                f"Nuclei scan returned: {len(result.findings)} findings, "
                f"success={result.success}, errors={len(result.errors)}, "
                f"duration={result.duration_seconds:.2f}s, timed_out={result.timed_out}"
            )
            
            if result.errors:
                logger.warning(f"Nuclei scan errors: {result.errors}")
            
            if result.timed_out and not result.findings:
                logger.warning(
                    f"Nuclei scan {scan_id} timed out with 0 findings on "
                    f"{len(targets_to_scan)} targets — chunk was likely too large "
                    f"for the runtime budget. Lower NUCLEI_MAX_TARGETS_PER_SCAN."
                )
            elif not result.findings:
                logger.info(
                    f"Nuclei found no vulnerabilities for targets. This could mean: "
                    f"1) The site is secure, 2) WAF is blocking scans, or "
                    f"3) Templates don't match the target technologies."
                )
            
            # Import findings
            findings_service = NucleiFindingsService(db)
            import_summary = findings_service.import_scan_results(
                scan_result=result,
                organization_id=organization_id,
                scan_id=scan_id,
                create_assets=True,
                create_labels=True
            )
            
            # Mark scanned assets as live (we got a response from Nuclei)
            live_assets_count = 0
            for finding in result.findings:
                if finding.host:
                    hostname = finding.host
                    # Strip protocol/port if present
                    if hostname.startswith(("http://", "https://")):
                        from urllib.parse import urlparse
                        hostname = urlparse(hostname).netloc.split(":")[0]
                    else:
                        hostname = hostname.split(":")[0]
                    
                    # Update asset to mark as live
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == hostname
                    ).first()
                    
                    if asset and not asset.is_live:
                        asset.is_live = True
                        live_assets_count += 1
            
            if live_assets_count > 0:
                db.commit()
                logger.info(f"Marked {live_assets_count} assets as live from Nuclei scan")
            
            # Calculate unique hosts that responded
            unique_hosts = set()
            for finding in result.findings:
                if finding.host:
                    unique_hosts.add(finding.host)
            
            # Auto-close findings not found in rescan
            # Only do this if we scanned specific assets and got results
            auto_resolved_count = 0
            if unique_hosts and organization_id:
                try:
                    auto_resolved_count = await self._auto_close_stale_findings(
                        db=db,
                        organization_id=organization_id,
                        scanned_hosts=unique_hosts,
                        current_findings=result.findings,
                        scan_id=scan_id
                    )
                    if auto_resolved_count > 0:
                        logger.info(f"Auto-resolved {auto_resolved_count} findings not found in rescan")
                except Exception as e:
                    logger.warning(f"Failed to auto-close stale findings: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                # Count created + updated so rescans that refresh existing
                # findings don't show "0 Vulnerabilities" in the UI.
                findings_touched = (
                    int(import_summary.get('findings_created') or 0)
                    + int(import_summary.get('findings_updated') or 0)
                    + int(import_summary.get('findings_reactivated') or 0)
                )
                scan.vulnerabilities_found = findings_touched
                scan.assets_discovered = assets_created  # Record assets created from targets
                if result.timed_out:
                    msg = (
                        f"Nuclei timed out after {result.duration_seconds:.0f}s on "
                        f"{len(targets_to_scan)} targets "
                        f"({findings_touched} findings from partial results)"
                    )
                    scan.error_message = msg[:500]
                    if scan.current_step:
                        scan.current_step = "Completed (timed out — partial results)"
                scan.results = {
                    'summary': result.summary,
                    'import_summary': import_summary,
                    'targets_original': result.targets_original,
                    'targets_expanded': result.targets_expanded,
                    'targets_scanned': result.targets_scanned,
                    'live_hosts': len(unique_hosts),
                    'findings_count': findings_touched,
                    'auto_resolved_count': auto_resolved_count,
                    'assets_created_from_targets': assets_created,
                    'assets_updated': assets_updated,
                    'timed_out': result.timed_out,
                    'duration_seconds': result.duration_seconds,
                }
                db.commit()
            
            logger.info(
                f"Nuclei scan complete: {import_summary['findings_created']} created, "
                f"{import_summary.get('findings_updated', 0)} updated, "
                f"{len(import_summary.get('cves_found', []))} CVEs, {len(unique_hosts)} live hosts"
            )
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_port_scan(self, job_data: dict):
        """Handle port scan job."""
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        scanner = job_data.get('scanner', 'naabu')
        ports = job_data.get('ports')
        service_detection = job_data.get('service_detection', True)
        
        # Get advanced config options with sensible defaults for reliability
        config = job_data.get('config', {})
        rate = config.get('rate', DEFAULT_PORT_SCAN_RATE)  # Use env var for default rate
        timeout = config.get('timeout', 30)  # Longer timeout
        retries = config.get('retries', 2)  # Retry on failure
        chunk_size = config.get('chunk_size', 64)  # Chunk large scans
        
        # Naabu-specific options
        top_ports = config.get('top_ports', 100)  # Top N ports if no ports specified
        exclude_cdn = config.get('exclude_cdn', True)  # Exclude CDN IPs
        exclude_ports = config.get('exclude_ports')  # Ports to exclude (e.g., "22,23")
        scan_type = config.get('scan_type', 'c')  # 'c' = CONNECT (no root), 's' = SYN
        host_discovery = config.get('host_discovery', False)  # Enable host discovery
        
        # Masscan-specific options
        banner_grab = config.get('banner_grab', True)  # Grab banners for service ID
        one_port_at_a_time = config.get('one_port_at_a_time', False)  # ASM Recon mode
        
        # Filter out IPv6 targets (not supported for port scanning)
        from app.services.port_scanner_service import PortScannerService
        scanner_svc = PortScannerService()
        original_count = len(targets)
        targets, ipv6_skipped = scanner_svc.filter_ipv4_only(targets)
        if ipv6_skipped > 0:
            logger.info(f"Filtered out {ipv6_skipped} IPv6 targets (not supported for port scanning)")
        
        if not targets:
            logger.warning(f"No valid IPv4 targets after filtering (skipped {ipv6_skipped} IPv6)")
            # Mark scan as completed with no results instead of leaving it pending
            db = self.get_db_session()
            if db:
                try:
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()
                        scan.results = {"error": "No valid IPv4 targets", "ipv6_skipped": ipv6_skipped}
                        db.commit()
                        logger.info(f"Scan {scan_id} marked completed (no valid targets)")
                finally:
                    db.close()
            return
        
        # IMPORTANT: Set default ports if not specified (don't scan all 65535!)
        # This prevents accidental 33+ minute scans
        if not ports or ports == "-":
            # Default to top 100 common ports for reasonable scan time
            ports = config.get('ports') or "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,8080,8443"
            logger.info(f"No ports specified, defaulting to top common ports")
        
        # Log scan estimate
        num_ports = scanner_svc._count_ports(ports) if hasattr(scanner_svc, '_count_ports') else 0
        num_hosts = scanner_svc._estimate_hosts(targets) if hasattr(scanner_svc, '_estimate_hosts') else len(targets)
        logger.info(f"Port scan: {num_hosts} hosts × {num_ports} ports = ~{num_hosts * num_ports:,} probes")
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for port scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            # Status is already set to RUNNING in process_message
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            # Map scanner type
            scanner_type_map = {
                'naabu': ScannerType.NAABU,
                'masscan': ScannerType.MASSCAN,
                'nmap': ScannerType.NMAP
            }
            selected_scanner = scanner_type_map.get(scanner, ScannerType.NAABU)
            
            # Run port scan with scanner-specific options
            # Base kwargs that all scanners accept
            scan_kwargs = {
                "targets": targets, 
                "ports": ports,
            }
            
            # Add scanner-specific options
            if selected_scanner == ScannerType.NAABU:
                scan_kwargs["rate"] = rate
                scan_kwargs["timeout"] = timeout
                scan_kwargs["retries"] = retries
                scan_kwargs["chunk_size"] = chunk_size
                scan_kwargs["top_ports"] = top_ports
                scan_kwargs["exclude_cdn"] = exclude_cdn
            elif selected_scanner == ScannerType.MASSCAN:
                scan_kwargs["rate"] = rate
                scan_kwargs["timeout"] = timeout
                scan_kwargs["banner_grab"] = banner_grab
                scan_kwargs["one_port_at_a_time"] = one_port_at_a_time
            elif selected_scanner == ScannerType.NMAP:
                # Nmap doesn't use rate/timeout in the same way
                scan_kwargs["service_detection"] = service_detection
                # Pass NSE scripts for ICS/OT protocol detection
                nse_scripts = config.get('nse_scripts', [])
                if nse_scripts:
                    scan_kwargs["scripts"] = nse_scripts
                    logger.info(f"Using NSE scripts for ICS detection: {nse_scripts}")
            
            logger.info(f"Starting port scan with rate={rate}, timeout={timeout}, retries={retries}")
            
            result = await self.port_scanner_service.scan(
                scanner=selected_scanner,
                **scan_kwargs
            )
            
            logger.info(f"Scan {scan_id}: masscan/naabu completed with {len(result.ports_found)} ports found")
            
            # Import results with error handling.
            # create_all_hosts=False: only create IP assets for hosts with at
            # least one open port.  CIDR blocks are updated separately via the
            # post-scan CIDR update loop below, so we don't need to flood the
            # asset DB with hundreds of empty IPs per /24 CIDR target.
            try:
                import_summary = self.port_scanner_service.import_results_to_assets(
                    db=db,
                    scan_result=result,
                    organization_id=organization_id,
                    create_assets=True,
                    create_all_hosts=False,
                )
                logger.info(f"Scan {scan_id}: imported {import_summary.get('ports_imported', 0)} ports")
            except Exception as import_error:
                logger.error(f"Scan {scan_id}: import_results_to_assets failed: {import_error}", exc_info=True)
                # CRITICAL: Rollback the failed transaction to allow subsequent queries
                try:
                    db.rollback()
                except Exception:
                    pass
                import_summary = {"ports_imported": 0, "ports_updated": 0, "errors": [str(import_error)]}
            
            # Generate findings from port scan results
            try:
                findings_service = PortFindingsService()
                findings_summary = findings_service.create_findings_from_scan(
                    db=db,
                    organization_id=organization_id,
                    scan_id=scan_id
                )
                logger.info(f"Scan {scan_id}: created {findings_summary.get('findings_created', 0)} findings")
            except Exception as findings_error:
                logger.error(f"Scan {scan_id}: create_findings_from_scan failed: {findings_error}", exc_info=True)
                # CRITICAL: Rollback the failed transaction to allow subsequent queries
                try:
                    db.rollback()
                except Exception:
                    pass
                findings_summary = {"findings_created": 0, "by_severity": {}}
            
            # Calculate unique live hosts (assets discovered)
            unique_hosts = set()
            for p in result.ports_found:
                unique_hosts.add(p.ip or p.host)
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.assets_discovered = len(unique_hosts)  # Live hosts with open ports
                scan.vulnerabilities_found = findings_summary.get('findings_created', 0)
                
                # Convert PortResult objects to dicts for JSON serialization
                ports_data = [
                    {"host": p.host, "ip": p.ip, "port": p.port, "protocol": p.protocol, "state": p.state}
                    for p in result.ports_found
                ]
                
                # Build host_results for frontend display
                # Group ports by host
                host_ports = {}
                for p in result.ports_found:
                    host_key = p.ip or p.host
                    if host_key not in host_ports:
                        host_ports[host_key] = []
                    host_ports[host_key].append(p.port)
                
                # Also get host results from import_summary if available
                host_results = import_summary.get('host_results', [])
                if not host_results:
                    # Build from our port data
                    host_results = []
                    for host, ports in host_ports.items():
                        host_results.append({
                            'host': host,
                            'ip': host,
                            'is_live': len(ports) > 0,
                            'open_ports': sorted(set(ports)),
                            'port_count': len(set(ports)),
                        })
                
                # Get pre-calculated targets stats from config (set during schedule trigger)
                # or calculate from targets
                config_target_stats = scan.config.get('target_stats', {}) if scan.config else {}
                existing_results = scan.results or {}
                
                # Prefer pre-calculated value, then existing, then fallback
                targets_expanded = (
                    config_target_stats.get('targets_expanded') or 
                    existing_results.get('targets_expanded') or
                    _calculate_targets_expanded(scan.targets)
                )
                targets_original = (
                    config_target_stats.get('targets_original') or 
                    existing_results.get('targets_original') or
                    len(scan.targets) if scan.targets else 0
                )
                cidr_count = config_target_stats.get('cidr_count', 0)
                host_count = config_target_stats.get('host_count', 0)
                
                scan.results = {
                    # Frontend expects ports_found as a NUMBER, not array
                    'ports_found': len(result.ports_found),
                    'ports_data': ports_data,  # Keep array data under different key
                    'ports_imported': import_summary.get('ports_imported', 0),
                    'ports_updated': import_summary.get('ports_updated', 0),
                    'live_hosts': len(unique_hosts),
                    'host_results': host_results,  # Array for frontend table display
                    'targets_scanned': result.targets_scanned,
                    'targets_original': targets_original,
                    'targets_expanded': targets_expanded,
                    'cidr_count': cidr_count,
                    'host_count': host_count,
                    'scanner': result.scanner.value,
                    'duration_seconds': result.duration_seconds,
                    'errors': result.errors,
                    'import_summary': import_summary,
                    'findings_summary': findings_summary
                }
                # If there were scanner errors but scan "succeeded", note it
                if result.errors:
                    scan.error_message = "; ".join(result.errors[:3])  # First 3 errors
                
                # Update netblocks that were scanned
                # Check if any scanned targets match netblock CIDR ranges
                scanned_netblocks = 0
                for target in targets:
                    # Check if target is a CIDR range
                    if '/' in target:
                        try:
                            # Find matching netblock by CIDR notation
                            netblock = db.query(Netblock).filter(
                                Netblock.organization_id == organization_id,
                                Netblock.cidr_notation.contains(target)
                            ).first()
                            
                            if netblock:
                                netblock.last_scanned = datetime.utcnow()
                                netblock.scan_count = (netblock.scan_count or 0) + 1
                                scanned_netblocks += 1
                        except Exception as e:
                            logger.warning(f"Failed to update netblock for {target}: {e}")
                    else:
                        # Single IP - try to find containing netblock
                        try:
                            ip_obj = ipaddress.ip_address(target)
                            # Find netblocks where this IP falls within the range
                            org_netblocks = db.query(Netblock).filter(
                                Netblock.organization_id == organization_id
                            ).all()
                            
                            for netblock in org_netblocks:
                                if netblock.cidr_notation:
                                    for cidr in netblock.cidr_notation.split(';'):
                                        cidr = cidr.strip()
                                        if cidr:
                                            try:
                                                network = ipaddress.ip_network(cidr, strict=False)
                                                if ip_obj in network:
                                                    netblock.last_scanned = datetime.utcnow()
                                                    netblock.scan_count = (netblock.scan_count or 0) + 1
                                                    scanned_netblocks += 1
                                                    break
                                            except ValueError:
                                                pass
                        except ValueError:
                            pass  # Not an IP address
                
                if scanned_netblocks > 0:
                    logger.info(f"Updated {scanned_netblocks} netblocks as scanned")
                
                # -------------------------------------------------------
                # Update CIDR block ASSETS with aggregate scan results.
                #
                # Naabu pre-expands CIDRs to individual IPs so the original
                # CIDR notation never appears in result.hosts_scanned.
                # import_results_to_assets handles CIDRs that ARE in
                # hosts_scanned (masscan path), but for naabu we need this
                # additional pass over the original targets list.
                # -------------------------------------------------------
                cidr_assets_updated = 0
                for target in targets:
                    if '/' not in target:
                        continue
                    try:
                        network = ipaddress.ip_network(target, strict=False)
                    except ValueError:
                        continue
                    
                    # Find live IPs within this CIDR from scan results
                    live_ips: set[str] = set()
                    for p in result.ports_found:
                        try:
                            ip_obj = ipaddress.ip_address(p.ip or p.host)
                            if ip_obj in network:
                                live_ips.add(str(ip_obj))
                        except ValueError:
                            pass
                    
                    usable = network.num_addresses - 2 if network.prefixlen < 31 else network.num_addresses
                    
                    # Find the CIDR block asset in the DB
                    cidr_asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == target
                    ).first()
                    
                    if cidr_asset:
                        meta = dict(cidr_asset.metadata_ or {})
                        meta["last_port_scan"] = datetime.utcnow().isoformat()
                        meta["live_hosts_found"] = len(live_ips)
                        meta["live_ips"] = sorted(live_ips)
                        meta["usable_hosts"] = usable
                        meta["scan_id"] = scan_id
                        cidr_asset.metadata_ = meta
                        cidr_asset.last_seen = datetime.utcnow()
                        if live_ips:
                            cidr_asset.is_live = True
                        cidr_assets_updated += 1
                    
                    # Also update the host_results entry for this CIDR so the
                    # frontend table shows accurate aggregate info.
                    for hr in scan.results.get("host_results", []):
                        if hr.get("host") == target or hr.get("ip") == target:
                            hr["live_hosts_in_cidr"] = len(live_ips)
                            hr["usable_hosts"] = usable
                            hr["is_live"] = len(live_ips) > 0
                            hr["is_cidr"] = True
                            break
                    else:
                        # CIDR was pre-expanded (naabu path) — it's not in
                        # host_results yet.  Add a summary row.
                        if cidr_asset:
                            scan.results["host_results"].append({
                                "host": target,
                                "ip": target,
                                "is_live": len(live_ips) > 0,
                                "is_cidr": True,
                                "live_hosts_in_cidr": len(live_ips),
                                "usable_hosts": usable,
                                "open_ports": [],
                                "port_count": 0,
                                "asset_id": cidr_asset.id,
                                "asset_created": False,
                            })
                
                if cidr_assets_updated > 0:
                    logger.info(f"Updated {cidr_assets_updated} CIDR block assets with port-scan summary")
            
            # Commit the scan results BEFORE any additional processing
            try:
                db.commit()
                logger.info(
                    f"Port scan {scan_id} complete: {len(result.ports_found)} ports, "
                    f"{findings_summary.get('findings_created', 0)} findings"
                )
                
                # Trigger graph sync after port scan (updates port relationships)
                if organization_id and len(result.ports_found) > 0:
                    trigger_graph_sync(organization_id)
                
            except Exception as commit_error:
                logger.error(f"Scan {scan_id}: Failed to commit results: {commit_error}", exc_info=True)
                db.rollback()
                raise
            
        except Exception as e:
            logger.error(f"Port scan {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_port_verify(self, job_data: dict):
        """
        Handle port verification job - runs nmap on all unverified open ports.
        
        This is the background scan that verifies masscan-discovered ports using
        nmap to determine if they're truly open or filtered.
        """
        import subprocess
        import re as regex_module
        from app.models.port_service import PortService, PortState, Protocol
        
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config', {})
        
        # Config options
        max_ports = config.get('max_ports', 500)  # Max ports to verify per scan
        port_ids = config.get('port_ids')  # Specific port IDs to verify (from bulk verify)
        verify_filtered = config.get('verify_filtered', False)  # Also re-verify filtered ports
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for port verification")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.current_step = "Gathering unverified ports"
                db.commit()
            
            # Get ports to verify
            if port_ids:
                # Specific ports requested (from bulk verify)
                ports_query = db.query(PortService).filter(PortService.id.in_(port_ids))
            else:
                # Get all unverified open ports for the organization
                ports_query = db.query(PortService).join(Asset).filter(
                    Asset.organization_id == organization_id,
                    PortService.verified == False,
                    PortService.state == PortState.OPEN
                )
                
                if verify_filtered:
                    # Also include filtered ports that haven't been verified
                    ports_query = db.query(PortService).join(Asset).filter(
                        Asset.organization_id == organization_id,
                        PortService.verified == False,
                        PortService.state.in_([PortState.OPEN, PortState.FILTERED])
                    )
            
            ports_to_verify = ports_query.limit(max_ports).all()
            
            if not ports_to_verify:
                logger.info(f"Scan {scan_id}: No unverified ports found")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {"message": "No unverified ports to verify", "ports_verified": 0}
                    db.commit()
                return
            
            logger.info(f"Scan {scan_id}: Verifying {len(ports_to_verify)} ports with nmap")
            
            verified_count = 0
            open_count = 0
            filtered_count = 0
            closed_count = 0
            errors = []
            
            # Process ports - group by IP for efficiency
            ip_ports = {}
            for port_record in ports_to_verify:
                # Get IP address for this port
                ip = port_record.scanned_ip
                if not ip and port_record.asset:
                    if port_record.asset.ip_addresses:
                        ip = port_record.asset.ip_addresses[0]
                    elif port_record.asset.value and regex_module.match(r'^[\d.]+$', port_record.asset.value):
                        ip = port_record.asset.value
                
                if ip:
                    if ip not in ip_ports:
                        ip_ports[ip] = []
                    ip_ports[ip].append(port_record)
            
            total_ips = len(ip_ports)
            processed_ips = 0
            
            for ip, port_records in ip_ports.items():
                processed_ips += 1
                
                # Update progress
                if scan:
                    progress = int((processed_ips / total_ips) * 100)
                    scan.progress = progress
                    scan.current_step = f"Verifying {ip} ({processed_ips}/{total_ips})"
                    db.commit()
                
                # Build port list for this IP
                port_list = ",".join([str(p.port) for p in port_records])
                
                # Run nmap for this IP (batch all ports together)
                cmd = [
                    "nmap", "-Pn", "-sT", "-sV", "--version-light",
                    "-p", port_list, ip,
                    "--max-retries", "2",
                    "-T4",
                    "-oG", "-"  # Greppable output for easier parsing
                ]
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=120  # 2 minute timeout per IP
                    )
                    
                    output = result.stdout
                    
                    # Parse greppable output for each port
                    # Format: "Host: 1.2.3.4 (hostname)  Ports: 80/open/tcp//http//, 443/open/tcp//https//"
                    for port_record in port_records:
                        port_num = port_record.port
                        protocol = port_record.protocol.value
                        
                        # Look for port in output
                        # Pattern: "PORT/STATE/PROTOCOL//SERVICE//"
                        port_pattern = rf'{port_num}/(\w+)/{protocol}//([^/]*)//'
                        match = regex_module.search(port_pattern, output)
                        
                        if match:
                            state = match.group(1)  # open, closed, filtered
                            service = match.group(2).strip() if match.group(2) else None
                        else:
                            # Try standard output format
                            std_pattern = rf'{port_num}/{protocol}\s+(\w+)\s+(\S+)'
                            std_match = regex_module.search(std_pattern, output)
                            if std_match:
                                state = std_match.group(1)
                                service = std_match.group(2) if std_match.group(2) != "unknown" else None
                            else:
                                state = "unknown"
                                service = None
                        
                        # Update port record
                        port_record.verified = True
                        port_record.verified_at = datetime.utcnow()
                        port_record.verified_state = state
                        port_record.verification_scanner = "nmap"
                        
                        # Update service if detected
                        if service and service not in ["unknown", ""]:
                            port_record.service_name = service
                        
                        # Update port state based on nmap result
                        if state == "open":
                            port_record.state = PortState.OPEN
                            open_count += 1
                        elif state == "filtered":
                            port_record.state = PortState.FILTERED
                            filtered_count += 1
                        elif state == "closed":
                            port_record.state = PortState.CLOSED
                            closed_count += 1
                        
                        verified_count += 1
                    
                    db.commit()
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"Nmap timeout for {ip}")
                    errors.append(f"Timeout scanning {ip}")
                except Exception as e:
                    logger.error(f"Error verifying {ip}: {e}")
                    errors.append(f"Error scanning {ip}: {str(e)[:100]}")
                    db.rollback()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.results = {
                    "ports_verified": verified_count,
                    "open_confirmed": open_count,
                    "filtered_detected": filtered_count,
                    "closed_detected": closed_count,
                    "ips_scanned": total_ips,
                    "errors": errors[:10] if errors else []
                }
                if errors:
                    scan.error_message = f"{len(errors)} errors during verification"
                db.commit()
            
            logger.info(
                f"Port verification {scan_id} complete: {verified_count} ports verified "
                f"(open={open_count}, filtered={filtered_count}, closed={closed_count})"
            )
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Port verification {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_service_detect(self, job_data: dict):
        """
        Handle service detection job - runs deep nmap scans on unknown services.
        
        This scans ports where service_name is 'unknown' or NULL to identify
        what service is actually running using nmap's version detection.
        """
        import subprocess
        import re as regex_module
        from app.models.port_service import PortService, PortState, Protocol
        
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config', {})
        
        # Config options
        max_ports = config.get('max_ports', 200)  # Max ports to scan (deep scan is slower)
        intensity = config.get('intensity', 7)  # Version detection intensity (1-9)
        include_scripts = config.get('include_scripts', True)  # Run default NSE scripts
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for service detection")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.current_step = "Finding ports with unknown services"
                db.commit()
            
            # Get ports with unknown services
            from sqlalchemy import or_
            ports_to_scan = db.query(PortService).join(Asset).filter(
                Asset.organization_id == organization_id,
                PortService.state == PortState.OPEN,
                or_(
                    PortService.service_name.is_(None),
                    PortService.service_name == '',
                    PortService.service_name == 'unknown',
                    PortService.service_name == 'tcpwrapped'
                )
            ).limit(max_ports).all()
            
            if not ports_to_scan:
                logger.info(f"Scan {scan_id}: No unknown services found")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {"message": "No unknown services to identify", "services_detected": 0}
                    db.commit()
                return
            
            logger.info(f"Scan {scan_id}: Deep scanning {len(ports_to_scan)} unknown services")
            
            detected_count = 0
            errors = []
            service_results = []
            
            # Group by IP
            ip_ports = {}
            for port_record in ports_to_scan:
                ip = port_record.scanned_ip
                if not ip and port_record.asset:
                    if port_record.asset.ip_addresses:
                        ip = port_record.asset.ip_addresses[0]
                    elif port_record.asset.value and regex_module.match(r'^[\d.]+$', port_record.asset.value):
                        ip = port_record.asset.value
                
                if ip:
                    if ip not in ip_ports:
                        ip_ports[ip] = []
                    ip_ports[ip].append(port_record)
            
            total_ips = len(ip_ports)
            processed_ips = 0
            
            for ip, port_records in ip_ports.items():
                processed_ips += 1
                
                # Update progress
                if scan:
                    progress = int((processed_ips / total_ips) * 100)
                    scan.progress = progress
                    scan.current_step = f"Deep scanning {ip} ({processed_ips}/{total_ips})"
                    db.commit()
                
                port_list = ",".join([str(p.port) for p in port_records])
                
                # Run deep nmap scan with version detection
                cmd = [
                    "nmap", "-Pn", "-sT", "-sV",
                    f"--version-intensity", str(intensity),
                    "-p", port_list, ip,
                    "-T4"
                ]
                
                # Add NSE scripts for service identification
                if include_scripts:
                    cmd.extend(["-sC"])  # Default scripts
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout for deep scans
                    )
                    
                    output = result.stdout
                    
                    # Parse output for each port
                    for port_record in port_records:
                        port_num = port_record.port
                        protocol = port_record.protocol.value
                        
                        # Look for detailed service info
                        # Format: "443/tcp open  https   nginx 1.18.0"
                        # Or: "443/tcp open  ssl/http nginx 1.18.0"
                        pattern = rf'{port_num}/{protocol}\s+\w+\s+([^\s]+)\s*(.*)?$'
                        
                        for line in output.split('\n'):
                            match = regex_module.search(pattern, line)
                            if match:
                                service = match.group(1).strip()
                                extra = match.group(2).strip() if match.group(2) else ""
                                
                                # Clean up service name
                                if service and service not in ["unknown", ""]:
                                    # Handle ssl/http style services
                                    if '/' in service:
                                        parts = service.split('/')
                                        port_record.is_ssl = 'ssl' in parts
                                        service = parts[-1]  # Get the actual service
                                    
                                    port_record.service_name = service
                                    
                                    # Parse product and version from extra
                                    if extra:
                                        # Try to extract product and version
                                        version_match = regex_module.match(r'([^\d\s]+)\s*([\d.]+.*)?', extra)
                                        if version_match:
                                            port_record.service_product = version_match.group(1).strip()
                                            if version_match.group(2):
                                                port_record.service_version = version_match.group(2).strip()
                                        else:
                                            port_record.service_extra_info = extra
                                    
                                    detected_count += 1
                                    service_results.append({
                                        "ip": ip,
                                        "port": port_num,
                                        "service": service,
                                        "product": port_record.service_product,
                                        "version": port_record.service_version
                                    })
                                break
                    
                    db.commit()
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"Deep scan timeout for {ip}")
                    errors.append(f"Timeout scanning {ip}")
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
                    errors.append(f"Error scanning {ip}: {str(e)[:100]}")
                    db.rollback()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.results = {
                    "services_detected": detected_count,
                    "ports_scanned": len(ports_to_scan),
                    "ips_scanned": total_ips,
                    "detected_services": service_results[:50],  # First 50 for display
                    "errors": errors[:10] if errors else []
                }
                if errors:
                    scan.error_message = f"{len(errors)} errors during detection"
                db.commit()
            
            logger.info(
                f"Service detection {scan_id} complete: {detected_count} services identified "
                f"from {len(ports_to_scan)} unknown ports"
            )
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Service detection {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_discovery(self, job_data: dict):
        """Handle full asset discovery job."""
        import re
        import ipaddress
        
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        domain = job_data.get('domain')
        organization_id = job_data.get('organization_id')
        
        # Filter targets to only include valid domains (not IPs or CIDRs)
        valid_domains = []
        
        # If single domain provided, use it
        if domain and not self._is_ip_or_cidr(domain):
            valid_domains.append(domain)
        
        # If targets list provided, filter for domains only
        for target in targets:
            if target and not self._is_ip_or_cidr(target):
                # Looks like a domain
                valid_domains.append(target)
        
        # Deduplicate
        valid_domains = list(set(valid_domains))
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
            
            if not valid_domains:
                logger.warning(f"No valid domains found for discovery scan {scan_id}. Targets were: {targets[:5]}...")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {
                        'message': 'No valid domains to discover (IPs/CIDRs are not valid for domain discovery)',
                        'targets_received': len(targets),
                        'valid_domains': 0
                    }
                    db.commit()
                return
            
            logger.info(f"Running discovery for {len(valid_domains)} domains: {valid_domains[:3]}...")
            
            # Run discovery for each domain
            discovery_service = self.get_discovery_service(db)
            total_assets = 0
            total_subdomains = 0
            total_technologies = 0
            
            config = job_data.get('config', {})
            use_tldfinder = config.get('use_tldfinder', False)
            for domain_target in valid_domains:
                try:
                    result = await discovery_service.full_discovery(
                        domain=domain_target,
                        organization_id=organization_id,
                        enable_subdomain_enum=True,
                        enable_dns_enum=True,
                        enable_http_probe=True,
                        enable_tech_detection=True,
                        use_tldfinder=use_tldfinder,
                    )
                    total_assets += result.get('assets_created', 0)
                    total_subdomains += result.get('subdomains_found', 0)
                    total_technologies += result.get('technologies_detected', 0)
                    logger.info(f"Discovery for {domain_target}: {result.get('assets_created', 0)} assets")
                except Exception as domain_error:
                    logger.error(f"Discovery failed for {domain_target}: {domain_error}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'assets_created': total_assets,
                    'subdomains_found': total_subdomains,
                    'technologies_detected': total_technologies,
                    'domains_processed': len(valid_domains)
                }
                db.commit()
            
            logger.info(f"Discovery complete: {total_assets} assets from {len(valid_domains)} domains")
            
            # Trigger graph sync after discovery completes
            if organization_id and total_assets > 0:
                trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_recon_pipeline(self, job_data: dict):
        """
        Run the recon workflow in order: domain_discovery → port_scan → http_probe
        → resource_enum (Katana, Wayback, ParamSpider) → vuln_scan.
        Uses project_settings scan_toggles to enable/disable each phase.
        See docs/RECON_WORKFLOW.md.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', []) or []
        domain = job_data.get('domain') or (targets[0] if targets else None)
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for recon pipeline")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            toggles = ProjectSettings.get_config(db, organization_id, MODULE_SCAN_TOGGLES)
            domain_discovery = toggles.get('domain_discovery', True)
            port_scan = toggles.get('port_scan', True)
            http_probe = toggles.get('http_probe', True)
            resource_enum = toggles.get('resource_enum', True)
            js_analysis = toggles.get('js_analysis', True)
            vuln_scan = toggles.get('vuln_scan', True)
        except Exception as e:
            logger.warning(f"Could not load scan_toggles, using defaults: {e}")
            domain_discovery = port_scan = http_probe = resource_enum = js_analysis = vuln_scan = True
        finally:
            db.close()
        
        def _set_pipeline_step(step_name: str):
            d = self.get_db_session()
            if not d:
                return
            try:
                scan = d.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.RUNNING
                    scan.current_step = step_name
                    d.commit()
            except Exception as e:
                logger.debug(f"Could not set pipeline step: {e}")
            finally:
                if d:
                    d.close()
        
        try:
            if domain_discovery and (domain or targets):
                _set_pipeline_step("Domain discovery")
                await self.handle_discovery({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'domain': domain,
                    'targets': targets,
                    'config': config,
                })
            else:
                logger.info(f"Recon pipeline: domain_discovery skipped (toggle or no targets)")
            
            if port_scan:
                _set_pipeline_step("Port scan")
                port_targets = []
                d = self.get_db_session()
                try:
                    if d:
                        port_targets = [a.value for a in d.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
                            Asset.value.isnot(None),
                            Asset.value != "",
                        ).limit(500).all()]
                except Exception as e:
                    logger.warning(f"Could not get targets for port scan: {e}")
                    port_targets = list(targets) if targets else ([domain] if domain else [])
                finally:
                    if d:
                        d.close()
                if port_targets:
                    await self.handle_port_scan({
                        'scan_id': scan_id,
                        'organization_id': organization_id,
                        'targets': port_targets,
                        'config': config,
                    })
                else:
                    logger.info("Recon pipeline: no assets for port scan, skipping")
            
            if http_probe:
                _set_pipeline_step("HTTP probe")
                await self.handle_http_probe({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'targets': [],  # probe all org assets
                    'config': config,
                })
            
            # Optional asm_scanner_core CLI checks (nerva/titus/gitleaks) → platform ingest
            await self._run_asm_core_security_checks({
                'scan_id': scan_id,
                'organization_id': organization_id,
                'domain': domain,
                'targets': targets,
                'config': config,
            })
            
            if resource_enum:
                _set_pipeline_step("Resource enumeration (Katana)")
                await self.handle_katana_scan({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'targets': [],
                    'config': config,
                })
                _set_pipeline_step("Resource enumeration (Wayback)")
                await self.handle_waybackurls_scan({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'targets': [],
                    'config': config,
                })
                _set_pipeline_step("Resource enumeration (ParamSpider)")
                await self.handle_paramspider_scan({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'targets': [],
                    'config': config,
                })

            if js_analysis:
                _set_pipeline_step("JS analysis (jsluice)")
                # Prefer Katana-discovered js_files stored on assets; fall back
                # to running discovery against the original targets.
                pipeline_js_urls: list[str] = []
                d = self.get_db_session()
                try:
                    if d:
                        for a in d.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.js_files.isnot(None),
                        ).all():
                            files = getattr(a, 'js_files', None) or []
                            if isinstance(files, list):
                                pipeline_js_urls.extend(files)
                except Exception as e:
                    logger.warning(f"Recon pipeline: could not read js_files for jsluice: {e}")
                finally:
                    if d:
                        d.close()

                await self.handle_jsluice_scan({
                    'scan_id': scan_id,
                    'organization_id': organization_id,
                    'targets': targets or ([domain] if domain else []),
                    'config': {
                        'js_urls': list(dict.fromkeys(pipeline_js_urls))[:1000],
                        **config,
                    },
                })

            if vuln_scan:
                _set_pipeline_step("Vulnerability scan")
                vuln_targets = []
                d = self.get_db_session()
                try:
                    if d:
                        assets = d.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL]),
                            Asset.value.isnot(None),
                            Asset.value != "",
                        ).limit(200).all()
                        for a in assets:
                            url = getattr(a, 'live_url', None) or None
                            if not url and a.value:
                                url = f"https://{a.value}" if not a.value.startswith(('http://', 'https://')) else a.value
                            if url:
                                vuln_targets.append(url)
                except Exception as e:
                    logger.warning(f"Could not get targets for vuln scan: {e}")
                    vuln_targets = [f"https://{t}" for t in (targets or [domain] or []) if t and not t.startswith(('http://', 'https://'))]
                finally:
                    if d:
                        d.close()
                if vuln_targets:
                    await self.handle_nuclei_scan({
                        'scan_id': scan_id,
                        'organization_id': organization_id,
                        'targets': vuln_targets,
                        'config': config,
                        'severity': config.get('severity'),
                        'tags': config.get('tags'),
                        'exclude_tags': config.get('exclude_tags'),
                    })
            
            if organization_id:
                trigger_graph_sync(organization_id)
            
            # Explicitly mark scan COMPLETED (don't rely on last sub-handler)
            d = self.get_db_session()
            if d:
                try:
                    scan = d.query(Scan).filter(Scan.id == scan_id).first()
                    if scan and scan.status != ScanStatus.COMPLETED:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()
                        scan.current_step = "Pipeline completed"
                        d.commit()
                        logger.info(f"Scan {scan_id} marked COMPLETED (recon pipeline)")
                except Exception as e:
                    logger.warning(f"Could not mark scan {scan_id} COMPLETED: {e}")
                    d.rollback()
                finally:
                    d.close()
            logger.info(f"Recon pipeline {scan_id} completed")
        
        except Exception as e:
            logger.error(f"Recon pipeline failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
            raise
    
    async def _run_asm_core_security_checks(self, job_data: dict):
        """
        Run optional checks from the asm_scanner_core package (shared with OpenClaw workers).

        Controlled by project_settings.security_checks: asm_core_checks + asm_core_nerva /
        asm_core_argus / asm_core_atlas / asm_core_gitleaks. Findings use the same ingestion
        path as agents.
        """
        scan_id = job_data.get("scan_id")
        organization_id = job_data.get("organization_id")
        domain = job_data.get("domain")
        seed_targets = job_data.get("targets") or []

        try:
            from asm_scanner_core.checks.context import SecurityCheckContext
            from asm_scanner_core.checks.runner import run_security_checks
        except ImportError:
            logger.debug("asm_scanner_core not installed; skipping asm core checks")
            return

        from app.models.port_service import PortService
        from app.services.asm_core_adapter import ingest_core_findings

        db = self.get_db_session()
        if not db:
            return
        try:
            sec_cfg = ProjectSettings.get_config(db, organization_id, MODULE_SECURITY_CHECKS)
        finally:
            db.close()

        if not sec_cfg.get("asm_core_checks", True):
            logger.info("asm_core_checks disabled for org %s", organization_id)
            return
        if not any(sec_cfg.get(k) for k in (
            "asm_core_nerva", "asm_core_argus", "asm_core_atlas",
            "asm_core_hermes", "asm_core_janus", "asm_core_gitleaks",
        )):
            logger.debug("No asm_core_* tool toggles enabled; skipping")
            return

        db = self.get_db_session()
        port_targets = []
        try:
            rows = (
                db.query(PortService, Asset)
                .join(Asset, PortService.asset_id == Asset.id)
                .filter(Asset.organization_id == organization_id)
                .limit(400)
                .all()
            )
            for ps, asset in rows:
                if not asset.value or not ps.port:
                    continue
                pv = getattr(ps.protocol, "value", None) or str(ps.protocol)
                if pv and str(pv).lower() != "tcp":
                    continue
                port_targets.append(f"{asset.value}:{ps.port}")
        except Exception as e:
            logger.warning("Could not load port targets for asm core checks: %s", e)
        finally:
            db.close()

        if not port_targets and seed_targets:
            for t in seed_targets[:50]:
                if isinstance(t, str) and t.strip():
                    port_targets.append(t.strip())

        ctx = SecurityCheckContext(
            organization_id=organization_id,
            scan_id=scan_id,
            domain=domain,
            targets=port_targets,
            extra=dict(job_data.get("config") or {}),
        )

        findings = await asyncio.to_thread(run_security_checks, sec_cfg, ctx)
        if not findings:
            return

        db = self.get_db_session()
        if not db:
            return
        try:
            summary = ingest_core_findings(db, organization_id, findings, scan_id=scan_id)
            if summary:
                logger.info("asm_scanner_core ingest summary: %s", summary)
        except Exception as e:
            logger.warning("asm_scanner_core ingest failed: %s", e, exc_info=True)
            db.rollback()
        finally:
            db.close()
    
    def _is_ip_or_cidr(self, value: str) -> bool:
        """Check if a value is an IP address or CIDR block."""
        import ipaddress
        try:
            # Try to parse as IP address
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        
        try:
            # Try to parse as network/CIDR
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            pass
        
        return False

    def _filter_scannable_domains(self, targets: list) -> tuple:
        """Filter a raw target list to ParamSpider-scannable domains.

        Delegates to the shared implementation in paramspider_service so the
        scheduler (batch rotation) and worker apply identical rules.
        """
        from app.services.paramspider_service import filter_scannable_domains
        return filter_scannable_domains(targets)
    
    async def handle_subdomain_enum(self, job_data: dict):
        """Handle subdomain enumeration job."""
        scan_id = job_data.get('scan_id')
        # Support both 'domain' and 'targets' for flexibility
        domain = job_data.get('domain')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        
        # If no domain specified, use first target
        if not domain and targets:
            domain = targets[0] if isinstance(targets, list) else targets
        
        if not domain:
            logger.error(f"Scan {scan_id}: No domain specified for subdomain enumeration")
            return
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
            
            # Run subdomain enumeration
            from app.services.subdomain_service import SubdomainService
            subdomain_service = SubdomainService()
            
            # enumerate_subdomains returns list[SubdomainResult]
            results = await subdomain_service.enumerate_subdomains(domain)
            
            # Create assets for discovered subdomains
            from app.models.asset import AssetType
            assets_created = 0
            sources_used = set()
            all_subdomains = []
            
            # Results is a list of SubdomainResult objects
            for result in results:
                subdomain = result.subdomain if hasattr(result, 'subdomain') else str(result)
                source = result.source if hasattr(result, 'source') else 'unknown'
                
                all_subdomains.append(subdomain)
                sources_used.add(source)
                
                existing = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == subdomain
                ).first()
                
                if not existing:
                    asset = Asset(
                        organization_id=organization_id,
                        name=subdomain,
                        value=subdomain,
                        asset_type=AssetType.SUBDOMAIN,
                        discovery_source=source
                    )
                    db.add(asset)
                    assets_created += 1
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'subdomains_found': len(all_subdomains),
                    'assets_created': assets_created,
                    'sources': list(sources_used)
                }
                db.commit()
            
            logger.info(f"Subdomain enum complete: {len(all_subdomains)} found, {assets_created} created")
            if organization_id:
                trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Subdomain enum failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    db.rollback()
            raise
        finally:
            if db:
                db.close()
    
    async def handle_dns_resolution(self, job_data: dict):
        """
        Handle DNS resolution scan job.
        
        Resolves domains/subdomains to IP addresses using dnsx and optionally
        geo-enriches the resolved IPs. This is useful for:
        - Populating IP addresses for newly discovered assets
        - Getting geolocation data for the world map
        - Understanding the infrastructure behind domains
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        include_geo = config.get('include_geo', True)
        limit = config.get('limit', 1000)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Resolving domains to IPs"
                db.commit()
            
            dns_service = DNSResolutionService(db)
            
            # If specific targets provided, resolve just those
            if targets:
                logger.info(f"Resolving {len(targets)} specified targets")
                dns_results = await dns_service.resolve_domains(targets)
                
                resolved_count = 0
                geo_enriched = 0
                
                # Update assets with resolved IPs
                for target in targets:
                    dns_result = dns_results.get(target)
                    if not dns_result or not dns_result.ip_addresses:
                        continue
                    
                    # Find the asset
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == target
                    ).first()
                    
                    if asset:
                        # Update all IPs using the helper method
                        asset.update_ip_addresses(dns_result.ip_addresses)
                        
                        # Store DNS records
                        if not asset.metadata_:
                            asset.metadata_ = {}
                        asset.metadata_['dns_records'] = {
                            'a': dns_result.a_records,
                            'aaaa': dns_result.aaaa_records,
                            'cname': dns_result.cname,
                        }
                        asset.last_seen = datetime.utcnow()
                        resolved_count += 1
                        
                        # Geo-enrich if enabled
                        if include_geo and dns_result.ip_addresses:
                            geo_service = get_geolocation_service()
                            geo_data = await geo_service.lookup_ip(dns_result.ip_addresses[0])
                            if geo_data:
                                asset.latitude = geo_data.get('latitude')
                                asset.longitude = geo_data.get('longitude')
                                asset.city = geo_data.get('city')
                                asset.country = geo_data.get('country')
                                asset.country_code = geo_data.get('country_code')
                                asset.isp = geo_data.get('isp')
                                asset.asn = geo_data.get('asn')
                                geo_enriched += 1
                
                db.commit()
                
                result_summary = {
                    'targets': len(targets),
                    'resolved': resolved_count,
                    'geo_enriched': geo_enriched
                }
            else:
                # Resolve all unresolved assets in the organization
                logger.info(f"Resolving unresolved assets for org {organization_id}")
                
                if scan:
                    scan.current_step = "Resolving all unresolved domains"
                    db.commit()
                
                result_summary = await dns_service.resolve_and_update_assets(
                    organization_id=organization_id,
                    limit=limit,
                    include_geo=include_geo
                )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = result_summary
                scan.assets_discovered = result_summary.get('resolved', 0)
                db.commit()
            
            logger.info(f"DNS resolution complete: {result_summary}")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_http_probe(self, job_data: dict):
        """
        Handle HTTP probing scan job.
        
        Probes domains/subdomains to check if they have live web services.
        Updates assets with:
        - is_live status
        - HTTP status code
        - Page title
        - Live URL (final URL after redirects)
        - IP address (if discovered)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        limit = config.get('limit', 1000)
        timeout = config.get('timeout', 30)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Probing HTTP services"
                db.commit()
            
            dns_service = DNSResolutionService(db)
            
            # If specific targets provided, probe just those
            if targets:
                logger.info(f"Probing {len(targets)} specified targets")
                probe_results = await dns_service.probe_http(targets, timeout=timeout)
                
                live_count = 0
                
                # Update assets
                for target in targets:
                    result = probe_results.get(target)
                    
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == target
                    ).first()
                    
                    if asset and result and result.is_live:
                        asset.is_live = True
                        asset.http_status = result.status_code
                        asset.http_title = result.title
                        asset.live_url = result.url
                        if result.ip_address:
                            asset.add_ip_address(result.ip_address)
                        asset.last_seen = datetime.utcnow()
                        live_count += 1
                
                db.commit()
                
                result_summary = {
                    'targets': len(targets),
                    'live': live_count,
                    'not_live': len(targets) - live_count
                }
            else:
                # Probe all assets in the organization
                logger.info(f"Probing all assets for org {organization_id}")
                
                if scan:
                    scan.current_step = "Probing all web assets"
                    db.commit()
                
                result_summary = await dns_service.probe_and_update_assets(
                    organization_id=organization_id,
                    limit=limit
                )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = result_summary
                scan.assets_discovered = result_summary.get('live', 0)
                db.commit()
            
            logger.info(f"HTTP probe complete: {result_summary}")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"HTTP probe failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_login_portal_scan(self, job_data: dict):
        """
        Handle login portal detection scan job.
        
        Detects login pages, admin panels, and authentication endpoints.
        Uses subfinder, httpx, waybackurls, and pattern matching.
        
        Flags parent domain/subdomain assets with has_login_portal=True.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        include_subdomains = config.get('include_subdomains', True)
        use_wayback = config.get('use_wayback', True)
        # Per-domain timeout (seconds). Prevents scan from running >60min and being marked stale.
        timeout_seconds = config.get('timeout_seconds', 600)  # 10 min per domain default
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Detecting login portals"
                db.commit()
            
            from app.services.login_portal_service import LoginPortalService
            from urllib.parse import urlparse
            portal_service = LoginPortalService()
            
            total_portals = 0
            all_portals = []
            assets_flagged = 0
            
            # Process each target domain
            for target in targets:
                if self._is_ip_or_cidr(target):
                    continue  # Skip IPs/CIDRs
                
                logger.info(f"Scanning {target} for login portals")
                try:
                    result = await asyncio.wait_for(
                        portal_service.detect_login_portals(
                            domain=target,
                            include_subdomains=include_subdomains,
                            use_wayback=use_wayback,
                            timeout=timeout_seconds,
                        ),
                        timeout=timeout_seconds + 30,  # Slightly over so service can return timeout error
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"Login portal scan timed out for {target} after {timeout_seconds}s")
                    result = {"portals": [], "error": f"Timed out after {timeout_seconds} seconds"}
                
                portals = result.get("portals", [])
                total_portals += len(portals)
                all_portals.extend(portals)
                
                # Group portals by their host (domain/subdomain)
                portals_by_host = {}
                for portal in portals:
                    url = portal.get("url", "")
                    try:
                        parsed = urlparse(url)
                        host = parsed.netloc.split(":")[0]  # Remove port
                        if host:
                            if host not in portals_by_host:
                                portals_by_host[host] = []
                            portals_by_host[host].append({
                                "url": url,
                                "type": portal.get("portal_type"),
                                "status": portal.get("status_code"),
                                "title": portal.get("title"),
                                "verified": portal.get("verified", False)
                            })
                    except Exception:
                        pass
                
                # Attach portals to host (subdomain/domain) asset only; create host asset if missing
                for host, host_portals in portals_by_host.items():
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == host
                    ).first()
                    
                    if asset:
                        asset.has_login_portal = True
                        existing_portals = asset.login_portals or []
                        existing_urls = {p.get("url") for p in existing_portals}
                        for p in host_portals:
                            if p["url"] not in existing_urls:
                                existing_portals.append(p)
                        asset.login_portals = existing_portals
                        asset.last_seen = datetime.utcnow()
                        assets_flagged += 1
                        logger.info(f"Flagged {host} with {len(host_portals)} login portals")
                    else:
                        # Create host asset so one record per subdomain with endpoints in Application Map.
                        # Skip if a previous record for this host was marked out of scope.
                        existing_host = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == host,
                        ).first()
                        if existing_host is not None:
                            if not existing_host.in_scope:
                                logger.debug(
                                    f"Login portal: skipping '{host}' — out of scope"
                                )
                            continue
                        root = target if host != target else None
                        new_asset = Asset(
                            organization_id=organization_id,
                            name=host,
                            value=host,
                            asset_type=AssetType.SUBDOMAIN if host != target else AssetType.DOMAIN,
                            root_domain=root,
                            is_live=any(p.get("verified") for p in host_portals),
                            has_login_portal=True,
                            login_portals=host_portals,
                            discovery_source="login_portal_scan",
                        )
                        db.add(new_asset)
                        assets_flagged += 1
                        logger.info(f"Created host asset {host} with {len(host_portals)} login portals")
                
                # Do not create per-URL assets; endpoints are listed on the host asset's Application Map (login_portals).
                
                db.commit()
                logger.info(f"Found {len(portals)} login portals for {target}, flagged {assets_flagged} assets")
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_portals
                scan.results = {
                    'portals_found': total_portals,
                    'assets_flagged': assets_flagged,
                    'domains_scanned': len(targets),
                    'portals': all_portals[:100]  # Limit stored results
                }
                db.commit()
            
            logger.info(f"Login portal scan complete: {total_portals} portals found, {assets_flagged} assets flagged")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Login portal scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_screenshot_scan(self, job_data: dict):
        """
        Handle screenshot capture scan job.
        
        Captures screenshots of web assets using EyeWitness.
        Screenshots are stored and linked to assets for visual monitoring.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Capturing screenshots"
                db.commit()
            
            from app.services.screenshot_service import _capture_screenshots_async
            
            # If no specific targets, get live assets from the organization (include non-live if no live assets)
            # Use live_url when available for better screenshot accuracy
            # Include domains, subdomains, AND IP addresses
            if not targets:
                # Prefer live assets; if none, include all web assets so we still have targets
                live_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.is_live == True,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS])
                ).limit(config.get('max_hosts', 200)).all()
                if not live_assets:
                    live_assets = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS])
                    ).limit(config.get('max_hosts', 200)).all()
                
                # Prefer live_url (the actual responding URL) over just the domain/IP
                # This ensures we screenshot the actual endpoint (e.g., /global-protect/login.esp)
                targets = []
                for a in live_assets:
                    if getattr(a, 'live_url', None):
                        targets.append(a.live_url)
                    else:
                        targets.append(f"https://{a.value}")
            
            logger.info(f"Starting screenshot capture for {len(targets)} targets")
            
            # Use the async capture function
            result = await _capture_screenshots_async(
                db,
                organization_id=organization_id,
                hosts=targets,
                max_hosts=config.get('max_hosts', 200),
                timeout=config.get('timeout', 30)
            )
            
            screenshots_captured = result.get('screenshots_captured', 0)
            screenshots_failed = result.get('screenshots_failed', 0)
            capture_error = result.get('error')
            
            # Update scan record (include error/hint so UI can show why capture failed)
            if scan:
                scan.status = ScanStatus.COMPLETED if not capture_error else ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = screenshots_captured
                scan.results = {
                    'screenshots_captured': screenshots_captured,
                    'screenshots_failed': screenshots_failed,
                    'targets_processed': len(targets),
                    'assets_updated': result.get('assets_updated', 0),
                }
                if capture_error:
                    scan.results['error'] = capture_error
                    scan.results['hint'] = (
                        'Install EyeWitness and Chromium in the scanner container, or enable xvfb for headless screenshots.'
                        if 'not installed' in capture_error.lower() or 'not found' in capture_error.lower()
                        else 'Check scanner logs for details.'
                    )
                db.commit()
            
            logger.info(f"Screenshot scan complete: {screenshots_captured} captured, {screenshots_failed} failed")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Screenshot scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_paramspider_scan(self, job_data: dict):
        """
        Handle ParamSpider parameter discovery scan.
        
        Discovers URL parameters from web archives for vulnerability testing.
        Updates assets with discovered parameters, endpoints, and JS files.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Discovering URL parameters"
                db.commit()
            
            from app.services.paramspider_service import ParamSpiderService
            paramspider = ParamSpiderService()
            
            # If no specific targets, get domains from the organization
            if not targets:
                domain_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                    Asset.is_live == True
                ).all()
                targets = [a.value for a in domain_assets]
            
            # Filter to domains ParamSpider can actually mine (drop IPs, CIDRs,
            # wildcards, malformed entries) and dedupe. This avoids wasting scan
            # slots on targets that can never return archive data.
            raw_target_count = len(targets)
            targets, filter_stats = self._filter_scannable_domains(targets)
            logger.info(
                f"ParamSpider target filtering: {raw_target_count} raw -> "
                f"{filter_stats['scannable_domains']} scannable domains "
                f"(skipped {filter_stats['skipped_ip_cidr']} IP/CIDR, "
                f"{filter_stats['skipped_invalid']} invalid, "
                f"{filter_stats['deduped']} duplicates)"
            )
            
            # Cap the number of domains to keep runtime bounded. Applies to valid
            # domains only now, so the cap reflects real coverage.
            max_targets = config.get('max_domains', 500)
            capped = False
            if len(targets) > max_targets:
                logger.info(f"Limiting ParamSpider scan from {len(targets)} to {max_targets} scannable domains")
                targets = targets[:max_targets]
                capped = True
            
            logger.info(f"Running ParamSpider on {len(targets)} domains (parallel)")
            
            total_urls = 0
            total_params = 0
            total_endpoints = 0
            total_js_files = 0
            assets_updated = 0
            
            # Update progress tracking
            if scan:
                scan.current_step = f"Discovering params from {len(targets)} domains (parallel)"
                db.commit()
            
            # Use parallel processing for faster completion. Archive mining is
            # I/O bound (HTTP to web.archive.org), so higher concurrency is the
            # main runtime lever.
            results = await paramspider.scan_multiple_domains(
                domains=targets,
                max_concurrent=config.get('max_concurrent', 15),
                level=config.get('level', 'high'),
                timeout=config.get('timeout', 120),  # Reduced from 300 to 120 seconds per target
            )
            
            for result in results:
                try:
                    if result.success:
                        total_urls += len(result.urls)
                        total_params += len(result.parameters)
                        total_endpoints += len(result.endpoints)
                        total_js_files += len(result.js_files)
                        
                        # Update the asset with discovered data
                        asset = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == result.domain
                        ).first()
                        
                        if asset:
                            # Merge with existing data
                            existing_endpoints = asset.endpoints or []
                            existing_params = asset.parameters or []
                            existing_js = asset.js_files or []
                            
                            asset.endpoints = list(set(existing_endpoints + result.endpoints[:500]))
                            asset.parameters = list(set(existing_params + result.parameters))
                            asset.js_files = list(set(existing_js + result.js_files[:100]))
                            asset.last_seen = datetime.utcnow()
                            assets_updated += 1
                        
                        logger.info(f"ParamSpider for {result.domain}: {len(result.parameters)} params, {len(result.endpoints)} endpoints")
                    else:
                        logger.warning(f"ParamSpider failed for {result.domain}: {result.error}")
                        
                except Exception as e:
                    logger.warning(f"ParamSpider result processing error: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_params
                scan.results = {
                    'domains_scanned': len(targets),
                    'total_urls': total_urls,
                    'total_parameters': total_params,
                    'total_endpoints': total_endpoints,
                    'total_js_files': total_js_files,
                    'assets_updated': assets_updated,
                    'input_targets': filter_stats['input_targets'],
                    'skipped_ip_cidr': filter_stats['skipped_ip_cidr'],
                    'skipped_invalid': filter_stats['skipped_invalid'],
                    'duplicates_removed': filter_stats['deduped'],
                    'capped': capped,
                    'max_domains': max_targets,
                }
                if total_params == 0 and total_endpoints == 0 and len(targets) > 0:
                    scan.results['error'] = 'No parameters or endpoints discovered from web archives for any domain.'
                    scan.results['hint'] = (
                        'ParamSpider uses Wayback Machine and Common Crawl. Domains with little or no archive history will return nothing. '
                        'Try running a Katana (live crawl) scan instead for active discovery, or run WaybackURLs first to populate historical URLs.'
                    )
                db.commit()
            
            logger.info(f"ParamSpider scan complete: {total_params} params, {total_endpoints} endpoints from {len(targets)} domains")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"ParamSpider scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_waybackurls_scan(self, job_data: dict):
        """
        Handle WaybackURLs historical URL discovery scan.
        
        Fetches historical URLs from Wayback Machine to find:
        - Forgotten endpoints
        - Old config files
        - Sensitive files
        - API endpoints
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Fetching historical URLs"
                db.commit()
            
            from app.services.waybackurls_service import WaybackURLsService
            wayback = WaybackURLsService(db)
            
            # If no specific targets, get domains from the organization
            if not targets:
                domain_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN])
                ).limit(config.get('max_domains', 100)).all()
                targets = [a.value for a in domain_assets]
            
            logger.info(f"Running WaybackURLs on {len(targets)} targets")
            
            # Use the batch fetch
            results = await wayback.fetch_urls_batch(
                domains=targets,
                no_subs=not config.get('include_subdomains', True),
                timeout=config.get('timeout_per_domain', 120),
                max_concurrent=config.get('max_concurrent', 3)
            )
            
            total_urls = 0
            total_interesting = 0
            assets_updated = 0
            
            for result in results:
                if result.success:
                    total_urls += len(result.urls)
                    total_interesting += len(result.interesting_urls)
                    
                    # Update the asset with discovered data
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == result.domain
                    ).first()
                    
                    if asset:
                        # Store in metadata
                        if not asset.metadata_:
                            asset.metadata_ = {}
                        
                        asset.metadata_['wayback_urls_count'] = len(result.urls)
                        asset.metadata_['wayback_interesting_count'] = len(result.interesting_urls)
                        asset.metadata_['wayback_extensions'] = result.file_extensions
                        asset.metadata_['wayback_last_scan'] = datetime.utcnow().isoformat()
                        
                        # Store unique paths as endpoints
                        existing_endpoints = asset.endpoints or []
                        asset.endpoints = list(set(existing_endpoints + result.unique_paths[:500]))
                        
                        asset.last_seen = datetime.utcnow()
                        assets_updated += 1
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_interesting
                scan.results = {
                    'domains_scanned': len(targets),
                    'total_urls': total_urls,
                    'interesting_urls': total_interesting,
                    'assets_updated': assets_updated,
                }
                db.commit()
            
            logger.info(f"WaybackURLs scan complete: {total_urls} URLs, {total_interesting} interesting from {len(targets)} domains")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"WaybackURLs scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_katana_scan(self, job_data: dict):
        """
        Handle Katana deep web crawling scan.
        
        Actively crawls websites to discover:
        - All reachable URLs and endpoints
        - JavaScript files (for secret scanning)
        - URL parameters (for injection testing)
        - Form actions
        - API endpoints
        
        Results are stored directly on each asset.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Deep crawling with Katana"
                db.commit()
            
            from app.services.katana_service import KatanaService
            katana = KatanaService()
            
            if not katana.is_available():
                raise Exception("Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            
            # If no specific targets, get crawlable domains from the organization.
            # Prefer live/probed assets; if none, use any domain/subdomain so JS scan can run.
            if not targets:
                limit = config.get('max_targets', 50)
                # 1) Prefer assets that are known live (HTTP-probed) or have a live_url
                live_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                    Asset.is_live == True
                ).limit(limit).all()
                if live_assets:
                    targets = [getattr(a, 'live_url', None) or f"https://{a.value}" for a in live_assets]
                else:
                    # 2) No live assets: use any domain/subdomain so Katana has something to crawl
                    any_assets = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                        Asset.value.isnot(None),
                        Asset.value != ""
                    ).limit(limit).all()
                    targets = [getattr(a, 'live_url', None) or f"https://{a.value}" for a in any_assets]
                if not targets:
                    logger.warning(
                        "Katana: no targets and no domain/subdomain assets for org %s. "
                        "Run discovery or add domains to an organization.",
                        organization_id,
                    )
                    if scan:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()
                        scan.current_step = None
                        scan.assets_discovered = 0
                        scan.results = {
                            "error": "No crawlable targets. Add domain/subdomain assets (run Discovery) or set explicit targets on the schedule.",
                            "targets_crawled": 0,
                        }
                        db.commit()
                    return

            # Normalize to URLs (Katana expects http(s) URLs)
            normalized = []
            for t in targets:
                t = (t or "").strip()
                if not t:
                    continue
                if not t.startswith(("http://", "https://")):
                    t = f"https://{t}"
                normalized.append(t)
            targets = normalized

            # Limit targets to prevent excessively long scans
            max_targets = config.get('max_targets', 20)  # Reduced from 50
            if len(targets) > max_targets:
                logger.info(f"Limiting Katana scan from {len(targets)} to {max_targets} targets")
                targets = targets[:max_targets]

            # Persist resolved targets to scan record so UI shows what was crawled
            if scan and targets:
                scan.targets = targets
                db.commit()

            total_urls = 0
            total_endpoints = 0
            total_params = 0
            total_js = 0
            assets_updated = 0
            
            # One Katana process with -list <urls.txt> when multiple targets (matches: katana -list live_sites.txt -d 5 -jc -fx -ef ...).
            per_target_timeout = config.get('timeout', 300)  # Per-target when not using batch
            max_concurrent = config.get('max_concurrent', 3)
            num_targets = len(targets)
            use_batch_stdin = config.get('batch_stdin', num_targets > 1)  # Default True for multi-target
            batch_total_timeout = min(3600, max(600, 90 * num_targets)) if use_batch_stdin else per_target_timeout

            logger.info(
                f"Running Katana on {num_targets} targets with depth={config.get('depth', 5)} "
                f"({'batch -list file (one process)' if use_batch_stdin else 'parallel per target'}, "
                f"timeout={batch_total_timeout if use_batch_stdin else per_target_timeout}s)"
            )
            
            # Update progress tracking
            if scan:
                scan.current_step = (
                    f"Deep crawling {num_targets} targets (batch)" if use_batch_stdin
                    else f"Deep crawling {num_targets} targets (parallel)"
                )
                db.commit()
            
            depth = config.get('depth', 5)
            headless = config.get('headless', False)
            user_agent = config.get('user_agent')
            if use_batch_stdin:
                batch_result = await katana.crawl_batch_stdin(
                    targets=targets,
                    depth=depth,
                    js_crawl=config.get('js_crawl', True),
                    form_extraction=config.get('form_extraction', True),
                    known_files=config.get('known_files', False),
                    extension_filter_preset=config.get('extension_filter_preset', 'pipeline'),
                    extension_filter_custom=config.get('extension_filter'),
                    timeout=batch_total_timeout,
                    rate_limit=config.get('rate_limit', DEFAULT_NUCLEI_RATE_LIMIT),
                    concurrency=config.get('concurrency', 10),
                    headless=headless,
                    user_agent=user_agent,
                )
                results = [batch_result] if batch_result.target == "stdin_batch" else []
                # For batch we'll handle the single result below and set js_files_for_review
            else:
                results = await katana.crawl_multiple(
                    targets=targets,
                    max_concurrent=max_concurrent,
                    depth=depth,
                    js_crawl=config.get('js_crawl', True),
                    form_extraction=config.get('form_extraction', True),
                    known_files=config.get('known_files', False),
                    extension_filter_preset=config.get('extension_filter_preset', 'pipeline'),
                    extension_filter_custom=config.get('extension_filter'),
                    timeout=per_target_timeout,
                    rate_limit=config.get('rate_limit', DEFAULT_NUCLEI_RATE_LIMIT),
                    concurrency=config.get('concurrency', 10),
                    headless=headless,
                    user_agent=user_agent,
                )
            
            # Collect first error for scan results if all fail
            first_error = None
            all_js_for_review = []  # Collect all JS URLs for AI/sensitive-data assessment
            # Process results and update assets
            from urllib.parse import urlparse
            for result in results:
                try:
                    if result.success:
                        total_urls += len(result.urls)
                        total_endpoints += len(result.endpoints)
                        total_params += len(result.parameters)
                        total_js += len(result.js_files)
                        all_js_for_review.extend(result.js_files)
                        # Batch stdin: one result; attribute all URLs/endpoints/params/js to assets by hostname
                        if result.target == "stdin_batch":
                            from collections import defaultdict
                            from urllib.parse import parse_qs
                            by_host = defaultdict(lambda: {"urls": set(), "endpoints": set(), "params": set(), "js": set(), "api": set()})
                            for u in result.urls:
                                try:
                                    parsed = urlparse(u)
                                    host = parsed.netloc.split(":")[0]
                                    if not host:
                                        continue
                                    by_host[host]["urls"].add(u)
                                    path = parsed.path.rstrip("/")
                                    if path and path != "/":
                                        by_host[host]["endpoints"].add(path)
                                    if parsed.query:
                                        by_host[host]["params"].update(parse_qs(parsed.query).keys())
                                    _JS_EXTS = ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx')
                                    _JS_PATHS = ('/js/', '/scripts/', '/_next/static/', '/static/js/', '/assets/', '/bundles/', '/dist/')
                                    if path.endswith(_JS_EXTS) or any(p in path for p in _JS_PATHS):
                                        by_host[host]["js"].add(u)
                                    if any(re.search(p, u.lower()) for p in ["/api/", r"/v\d+/", "/graphql", "/rest/"]):
                                        by_host[host]["api"].add(u)
                                except Exception:
                                    pass
                            for host, data in by_host.items():
                                try:
                                    asset = db.query(Asset).filter(
                                        Asset.organization_id == organization_id,
                                        Asset.value == host
                                    ).first()
                                    if not asset:
                                        continue
                                    existing_endpoints = set(asset.endpoints or [])
                                    existing_params = set(asset.parameters or [])
                                    existing_js = set(asset.js_files or [])
                                    existing_endpoints.update(data["endpoints"])
                                    existing_params.update(data["params"])
                                    existing_js.update(data["js"])
                                    asset.endpoints = sorted(existing_endpoints)[:1000]
                                    asset.parameters = sorted(existing_params)[:500]
                                    asset.js_files = sorted(existing_js)[:500]
                                    if not asset.metadata_:
                                        asset.metadata_ = {}
                                    asset.metadata_["katana_last_scan"] = datetime.utcnow().isoformat()
                                    asset.metadata_["katana_urls_found"] = len(data["urls"])
                                    asset.metadata_["katana_api_endpoints"] = sorted(data["api"])[:50]
                                    asset.last_seen = datetime.utcnow()
                                    assets_updated += 1
                                except Exception as e:
                                    logger.warning(f"Batch attribution for {host}: {e}")
                            continue
                        # Per-target result: attribute to single asset
                        target = result.target
                        if target.startswith(('http://', 'https://')):
                            netloc = urlparse(target).netloc
                            target = netloc.split(':')[0] if netloc else target
                        else:
                            target = target.split(':')[0]
                        
                        asset = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == target
                        ).first()
                        
                        if asset and (result.endpoints or result.urls or result.parameters or result.js_files):
                            # Only update when we actually discovered something
                            existing_endpoints = set(asset.endpoints or [])
                            existing_params = set(asset.parameters or [])
                            existing_js = set(asset.js_files or [])
                            
                            existing_endpoints.update(result.endpoints)
                            existing_params.update(result.parameters)
                            existing_js.update(result.js_files)
                            
                            asset.endpoints = sorted(list(existing_endpoints))[:1000]
                            asset.parameters = sorted(list(existing_params))[:500]
                            asset.js_files = sorted(list(existing_js))[:500]
                            
                            if not asset.metadata_:
                                asset.metadata_ = {}
                            asset.metadata_['katana_last_scan'] = datetime.utcnow().isoformat()
                            asset.metadata_['katana_urls_found'] = len(result.urls)
                            asset.metadata_['katana_api_endpoints'] = result.api_endpoints[:50]
                            
                            asset.last_seen = datetime.utcnow()
                            assets_updated += 1
                        
                        logger.info(
                            f"Katana crawl of {result.target}: {len(result.endpoints)} endpoints, "
                            f"{len(result.parameters)} params, {len(result.js_files)} JS files"
                        )
                    else:
                        if not first_error and result.error:
                            first_error = result.error
                        logger.warning(f"Katana failed for {result.target}: {result.error}")
                except Exception as e:
                    logger.warning(f"Katana result processing error: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            db.commit()
            
            # Optional: AI-powered sensitive data scan on discovered JS files
            ai_secrets_findings = []
            if config.get('ai_secrets_scan') and all_js_for_review:
                try:
                    from app.services.js_secrets_scan_service import (
                        is_ai_secrets_scan_available,
                        scan_urls_for_sensitive_data,
                        MAX_URLS_PER_SCAN,
                    )
                    if is_ai_secrets_scan_available():
                        if scan:
                            scan.current_step = "Analyzing JS files for sensitive data (AI)"
                            db.commit()
                        urls_to_scan = sorted(set(all_js_for_review))[:MAX_URLS_PER_SCAN]
                        results_ai = await scan_urls_for_sensitive_data(urls_to_scan)
                        for r in results_ai:
                            if r.findings:
                                ai_secrets_findings.append({
                                    "url": r.url,
                                    "findings": [
                                        {"type": f.type, "snippet": f.snippet, "severity": f.severity, "line_hint": f.line_hint}
                                        for f in r.findings
                                    ],
                                })
                        logger.info(f"AI secrets scan: {len(ai_secrets_findings)} URLs with findings from {len(results_ai)} analyzed")
                except Exception as e:
                    logger.warning("AI secrets scan failed: %s", e)
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_endpoints
                scan.results = {
                    'targets_crawled': len(targets),
                    'total_urls': total_urls,
                    'total_endpoints': total_endpoints,
                    'total_parameters': total_params,
                    'total_js_files': total_js,
                    'assets_updated': assets_updated,
                }
                if all_js_for_review:
                    scan.results['js_files_for_review'] = sorted(set(all_js_for_review))
                if ai_secrets_findings:
                    scan.results['ai_secrets_findings'] = ai_secrets_findings
                    scan.results['ai_secrets_urls_with_findings'] = len(ai_secrets_findings)
                if total_endpoints == 0 and total_urls == 0 and len(targets) > 0:
                    scan.results['error'] = first_error or 'No URLs or endpoints discovered on any target.'
                    scan.results['hint'] = (
                        'Sites may block automated crawlers (e.g. Cloudflare, bot detection), require login, '
                        'or return no crawlable links. Re-run this scan with headless crawl enabled (scan config: headless=true) '
                        'for bot-protected or JS-heavy sites; or set a browser-like user_agent in config. '
                        'Ensure an HTTP probe has run first so targets are known live.'
                    )
                db.commit()
            
            logger.info(
                f"Katana scan complete: {total_endpoints} endpoints, "
                f"{total_params} params, {total_js} JS files from {len(targets)} targets"
            )
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Katana scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_cleanup(self, job_data: dict):
        """
        Handle system cleanup and maintenance task.
        
        Cleans up:
        - Old scan result files
        - Temporary files from scanning tools
        - Old/orphaned screenshots
        - Failed scan records
        """
        scan_id = job_data.get('scan_id')
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running system cleanup"
                db.commit()
            
            from app.services.cleanup_service import CleanupService
            
            cleanup = CleanupService(db)
            
            # Build retention config
            retention_days = {
                'screenshots': config.get('screenshots_retention_days', 90),
                'scan_results': config.get('scan_files_retention_days', 30),
                'temp_files': config.get('temp_files_retention_days', 1),
                'failed_scans': config.get('failed_scans_retention_days', 14),
            }
            
            dry_run = config.get('dry_run', False)
            
            logger.info(f"Running cleanup with retention: {retention_days}, dry_run={dry_run}")
            
            # Run full cleanup
            stats = await cleanup.run_full_cleanup(
                retention_days=retention_days,
                dry_run=dry_run
            )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = {
                    'files_deleted': stats.get('files_deleted', 0),
                    'bytes_freed': stats.get('bytes_freed', 0),
                    'mb_freed': round(stats.get('bytes_freed', 0) / 1024 / 1024, 2),
                    'records_cleaned': stats.get('records_cleaned', 0),
                    'errors': stats.get('errors', [])[:10],  # Limit errors in results
                    'dry_run': dry_run,
                }
                db.commit()
            
            logger.info(
                f"Cleanup complete: {stats.get('files_deleted', 0)} files deleted, "
                f"{stats.get('bytes_freed', 0) / 1024 / 1024:.2f} MB freed"
            )
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_technology_scan(self, job_data: dict):
        """
        Handle technology detection scan job.
        
        Detects web technologies on domains/subdomains using:
        - Wappalyzer (local fingerprinting - fast, 150+ technologies)
        - WhatRuns API (comprehensive - CMS, JS libs, fonts, analytics, security)
        
        Results are stored:
        - In the technologies table
        - Associated with assets via asset_technologies
        - As tech:xxx labels for filtering
        
        Config options:
        - source: "wappalyzer", "whatruns", or "both" (default: "both")
        - max_hosts: Maximum hosts to scan (default: 500)
        - only_live: Only scan assets marked as is_live (default: false)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        source = config.get('source', 'both')  # wappalyzer, whatruns, or both
        max_hosts = config.get('max_hosts', 500)
        only_live = config.get('only_live', False)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = f"Detecting technologies using {source}"
                db.commit()
            
            from app.models.project_settings import ProjectSettings, MODULE_WAPPALYZER
            
            wappalyzer_config = ProjectSettings.get_config(db, organization_id, MODULE_WAPPALYZER)
            if not wappalyzer_config.get("enabled", True):
                logger.info(f"Technology (Wappalyzer) scan disabled for org {organization_id}; skipping")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {"message": "Technology scan disabled in project settings"}
                    db.commit()
                return
            
            # If no specific targets, get domains/subdomains/IPs from the organization
            # Include IP addresses that have live_url (detected via HTTP probe)
            if not targets:
                query = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS])
                )
                
                if only_live:
                    query = query.filter(Asset.is_live == True)
                else:
                    # For IP addresses, only include if they have a live_url (HTTP responds)
                    # This prevents scanning IPs that don't have web services
                    from sqlalchemy import or_
                    query = query.filter(
                        or_(
                            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                            Asset.live_url.isnot(None)  # IP assets must have live_url
                        )
                    )
                
                assets = query.limit(max_hosts).all()
                targets = [a.value for a in assets]
            
            if not targets:
                logger.warning(f"No targets found for technology scan {scan_id}")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {
                        'message': 'No domains/subdomains/IPs to scan',
                        'targets': 0
                    }
                    db.commit()
                return
            
            logger.info(f"Starting technology scan for {len(targets)} targets with source={source}")
            
            # Close db before running the scan (it creates its own session)
            db.close()
            db = None
            
            # Run technology scan directly via the async helper — calling the
            # synchronous run_technology_scan_for_hosts wrapper would invoke
            # asyncio.run() inside an already-running event loop (RuntimeError).
            from app.services.technology_scan_service import _scan_hosts_async
            from app.db.database import SessionLocal as _SessionLocal

            _db = _SessionLocal()
            try:
                result = await _scan_hosts_async(
                    _db,
                    organization_id=organization_id,
                    hosts=targets,
                    max_hosts=max_hosts,
                    source=source,
                    wappalyzer_config=wappalyzer_config,
                )
            finally:
                _db.close()
            
            # Reopen db for final update
            db = self.get_db_session()
            
            # Update scan record
            if db:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.current_step = None
                    scan.technologies_found = result.get('technologies_found', 0)
                    scan.assets_discovered = result.get('hosts_scanned', 0)
                    scan.results = {
                        'total_hosts': result.get('total_hosts', 0),
                        'hosts_scanned': result.get('hosts_scanned', 0),
                        'technologies_found': result.get('technologies_found', 0),
                        'chatbots_found': result.get('chatbots_found', 0),
                        'skipped_no_asset': result.get('skipped_no_asset', 0),
                        'errors': result.get('errors', 0),
                        'source': source,
                    }
                    db.commit()
            
            logger.info(
                f"Technology scan complete: {result.get('technologies_found', 0)} technologies "
                f"on {result.get('hosts_scanned', 0)}/{result.get('total_hosts', 0)} hosts"
            )
            
            # Trigger graph sync after technology scan (updates technology relationships)
            if organization_id and result.get('technologies_found', 0) > 0:
                trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Technology scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_geo_enrichment(self, job_data: dict):
        """
        Handle geo-location enrichment scan job.
        
        Enriches all assets with country/geo data using:
        1. Netblock country data (fast, no API calls) - for assets in known CIDR ranges
        2. IP geolocation API lookup for remaining assets
        
        Config options:
        - max_assets: Maximum assets to enrich via API (default: 10000)
        - force: Re-enrich assets that already have geo data (default: False)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config', {})
        
        max_assets = config.get('max_assets', 10000)
        force = config.get('force', False)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Enriching assets with geolocation data"
                db.commit()
            
            from app.services.http_probe_service import run_full_geo_enrichment
            
            logger.info(f"Starting geo enrichment for organization {organization_id}")
            
            def progress_callback(pct, step):
                """Update scan progress."""
                try:
                    progress_db = self.get_db_session()
                    if progress_db:
                        progress_scan = progress_db.query(Scan).filter(Scan.id == scan_id).first()
                        if progress_scan:
                            progress_scan.progress = pct
                            progress_scan.current_step = step
                            progress_db.commit()
                        progress_db.close()
                except Exception as e:
                    logger.debug(f"Progress callback error: {e}")
            
            # Run geo enrichment
            result = await run_full_geo_enrichment(
                db,
                organization_id=organization_id,
                max_assets=max_assets,
                force=force,
                progress_callback=progress_callback,
            )
            
            # Update scan record
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                total_enriched = result.get('from_netblocks', 0) + result.get('from_ip_lookup', 0)
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.progress = 100
                scan.assets_discovered = total_enriched
                scan.results = {
                    'total_assets': result.get('total_assets', 0),
                    'from_netblocks': result.get('from_netblocks', 0),
                    'from_ip_lookup': result.get('from_ip_lookup', 0),
                    'failed_lookup': result.get('failed_lookup', 0),
                    'countries': result.get('countries', {}),
                    'regions': result.get('regions', {}),
                }
                db.commit()
            
            logger.info(
                f"Geo enrichment complete: {result.get('from_netblocks', 0)} from netblocks, "
                f"{result.get('from_ip_lookup', 0)} from IP lookup"
            )
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"Geo enrichment failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_tldfinder_scan(self, job_data: dict):
        """
        Handle TLD/domain discovery scan using ProjectDiscovery tldfinder.
        
        Runs tldfinder for better coverage of subdomains/domains (e.g. for
        keywords like "Rockwell Automation" use org root domain or targets).
        Creates/updates assets for discovered domains.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            from app.services.tldfinder_service import TLDFinderService, TLDFINDER_AVAILABLE
            from app.models.organization import Organization
            
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running tldfinder for TLD/domain discovery"
                db.commit()
            
            if not TLDFINDER_AVAILABLE:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "tldfinder binary not found. Install: go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return
            
            # Resolve targets: use job targets or org domain + root domains from assets
            if not targets:
                org = db.query(Organization).filter(Organization.id == organization_id).first()
                if org and org.domain:
                    targets = [org.domain.strip()]
                if not targets:
                    # Fallback: root domains from existing assets
                    from sqlalchemy import func, distinct
                    rows = db.query(distinct(Asset.root_domain)).filter(
                        Asset.organization_id == organization_id,
                        Asset.root_domain.isnot(None),
                        Asset.root_domain != '',
                    ).limit(20).all()
                    targets = [r[0] for r in rows if r[0]]
                if not targets:
                    if scan:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()
                        scan.results = {'message': 'No domains to run tldfinder against'}
                        db.commit()
                    return
            
            discovery_mode = config.get('discovery_mode', 'domain')
            max_time = config.get('max_time_minutes', 10)
            tldfinder = TLDFinderService(timeout=max(60, max_time * 60 + 30))
            result = await tldfinder.run(
                domains=targets[:10],
                discovery_mode=discovery_mode,
                max_time_minutes=max_time,
            )
            
            if not result.success and result.error:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = (result.error or '')[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return
            
            # Create/update assets for discovered domains
            created = 0
            for domain in result.domains:
                domain = (domain or '').strip().lower()
                if not domain or not self._is_valid_domain(domain):
                    continue
                existing = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == domain,
                ).first()
                if existing is not None:
                    if not existing.in_scope:
                        logger.debug(
                            f"TLDFinder: skipping '{domain}' — out of scope"
                        )
                    continue
                root = self._extract_root_domain(domain)
                parent = None
                if root and root != domain:
                    parent = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == root,
                    ).first()
                asset_type = AssetType.SUBDOMAIN if (root and root != domain) else AssetType.DOMAIN
                new_asset = Asset(
                    organization_id=organization_id,
                    name=domain,
                    value=domain,
                    asset_type=asset_type,
                    root_domain=root or domain,
                    parent_id=parent.id if parent else None,
                    discovery_source='tldfinder',
                )
                db.add(new_asset)
                created += 1
            
            db.commit()
            
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = created
                scan.results = {
                    'targets': targets,
                    'domains_found': len(result.domains),
                    'assets_created': created,
                    'elapsed_seconds': result.elapsed_seconds,
                }
                db.commit()
            
            logger.info(f"TLDFinder scan complete: {len(result.domains)} domains, {created} new assets")
            trigger_graph_sync(organization_id)
            
        except Exception as e:
            logger.error(f"TLDFinder scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_commoncrawl_enum_scan(self, job_data: dict):
        """
        CommonCrawl CDX subdomain enumeration (CCrawlDNS-style).

        Queries the live CommonCrawl CDX API to discover subdomains that have
        been crawled by CommonCrawl over the selected years/datasets.  Results
        are stored as SUBDOMAIN (or DOMAIN) Asset records identical to every
        other discovery source.

        Config keys (all optional):
            years          – "last2" (default), "last3", "lastN", "all",
                             "2025", or "2025,2024" (comma-separated years)
            max_per_year   – datasets per year, default 1 (most efficient)
            timeout        – per-release request timeout seconds, default 120
            triggered_by   – informational tag set by the caller
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})

        db = self.get_db_session()
        if not db:
            logger.error("handle_commoncrawl_enum_scan: no database connection")
            return

        scan = None
        try:
            from app.services.commoncrawl_live_service import CommonCrawlLiveService
            from app.models.organization import Organization

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Querying CommonCrawl CDX API for subdomains"
                db.commit()

            # ----------------------------------------------------------------
            # Resolve targets: build the full set of root domains to query.
            #
            # Priority:
            #   1. DOMAIN-type assets in the org's inventory (covers every root
            #      domain that TLDFINDER / other discovery has found, e.g.
            #      rockwellautomation.com, ab.com, factorytalk.com …)
            #   2. Any explicit targets passed in the job (e.g. on first run
            #      before discovery has populated the inventory)
            #   3. The org's primary domain as a final fallback
            # ----------------------------------------------------------------
            domain_assets: list[str] = []
            domain_asset_rows = db.query(Asset.value).filter(
                Asset.organization_id == organization_id,
                Asset.asset_type == AssetType.DOMAIN,
                Asset.value.isnot(None),
                Asset.value != '',
            ).all()
            domain_assets = [r[0].strip().lower() for r in domain_asset_rows if r[0]]

            # Merge explicit targets (e.g. primary domain at org creation) with
            # inventory domains, then deduplicate while preserving order.
            seed_targets = [t.strip().lower() for t in (targets or []) if t.strip()]
            seen: set[str] = set()
            combined: list[str] = []
            for d in seed_targets + domain_assets:
                if d and d not in seen:
                    seen.add(d)
                    combined.append(d)
            targets = combined

            # Last resort: org primary domain
            if not targets:
                org = db.query(Organization).filter(
                    Organization.id == organization_id
                ).first()
                if org and org.domain:
                    targets = [org.domain.strip().lower()]

            if not targets:
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {'message': 'No domains to query CommonCrawl for'}
                    db.commit()
                return

            logger.info(
                f"CommonCrawl enum: querying {len(targets)} domain(s) for org {organization_id}: "
                + ", ".join(targets[:10]) + ("…" if len(targets) > 10 else "")
            )

            # ----------------------------------------------------------------
            # Build service + shared config
            # ----------------------------------------------------------------
            years = config.get('years', 'last1')
            max_per_year = int(config.get('max_per_year', 1))
            timeout = float(config.get('timeout', 120.0))
            max_results = int(config.get('max_results_per_release', 100_000))
            use_keyword_search = bool(config.get('use_keyword_search', True))

            service = CommonCrawlLiveService(
                years=years,
                max_per_year=max_per_year,
                timeout=timeout,
                max_results_per_release=max_results,
            )

            releases_used: list[str] = []

            # ----------------------------------------------------------------
            # MODE 1 — Subdomain enumeration (*.domain per known root domain)
            # ----------------------------------------------------------------
            if scan:
                scan.current_step = "Mode 1: CommonCrawl subdomain enumeration"
                db.commit()

            total_subdomains: set[str] = set()

            for domain in targets[:20]:  # cap to 20 root domains per scan
                domain = domain.strip().lower()
                if not domain:
                    continue
                if scan:
                    scan.current_step = f"CC subdomain enum: {domain}"
                    db.commit()

                sub_result = await service.search_domain(domain)
                if sub_result.error:
                    logger.warning(f"CC subdomain error for {domain}: {sub_result.error}")
                    continue
                total_subdomains.update(sub_result.subdomains)
                for r in sub_result.releases_queried:
                    if r not in releases_used:
                        releases_used.append(r)

            # ----------------------------------------------------------------
            # MODE 2 — Brand / keyword discovery
            #
            # Sources (in order):
            #   1. org.commoncrawl_org_name  (e.g. "Rockwell Automation")
            #   2. org.commoncrawl_keywords  (e.g. ["factorytalk", "ab.com"])
            #
            # Strips spaces and lowercases before querying.  Hostnames whose
            # root domain is already in the org's inventory are counted as
            # subdomains; entirely new roots are flagged for review.
            # ----------------------------------------------------------------
            keyword_hostnames: set[str] = set()
            keywords_used: list[str] = []

            if use_keyword_search:
                if scan:
                    scan.current_step = "Mode 2: CommonCrawl brand keyword sweep"
                    db.commit()

                org = db.query(Organization).filter(
                    Organization.id == organization_id
                ).first()

                raw_keywords: list[str] = []
                if org:
                    if org.commoncrawl_org_name:
                        raw_keywords.append(org.commoncrawl_org_name)
                    if org.commoncrawl_keywords:
                        raw_keywords.extend(org.commoncrawl_keywords)

                # Normalise: strip spaces, lowercase, deduplicate, drop blanks
                seen_kw: set[str] = set()
                keywords_norm: list[str] = []
                for kw in raw_keywords:
                    kw_norm = kw.strip().lower().replace(" ", "")
                    if kw_norm and kw_norm not in seen_kw:
                        seen_kw.add(kw_norm)
                        keywords_norm.append(kw_norm)
                        keywords_used.append(kw.strip())

                if keywords_norm:
                    logger.info(
                        f"CC keyword sweep for org {organization_id}: {keywords_norm}"
                    )
                    kw_result = await service.search_keywords(
                        keywords=keywords_norm,
                        known_root_domains=targets,
                    )
                    if kw_result.error:
                        logger.warning(f"CC keyword sweep error: {kw_result.error}")
                    else:
                        keyword_hostnames.update(kw_result.hostnames)
                        for r in kw_result.releases_queried:
                            if r not in releases_used:
                                releases_used.append(r)
                        logger.info(
                            f"CC keyword sweep: {len(keyword_hostnames)} hostnames "
                            f"from {len(keywords_norm)} keyword(s)"
                        )
                else:
                    logger.info(
                        f"CC keyword sweep skipped: no commoncrawl_org_name or "
                        f"commoncrawl_keywords set for org {organization_id}"
                    )

            # ----------------------------------------------------------------
            # Persist discovered assets
            # ----------------------------------------------------------------
            if scan:
                scan.current_step = "Persisting CommonCrawl discoveries"
                db.commit()

            # Build a set of known root domains for classification
            known_roots: set[str] = {t.strip().lower() for t in targets if t.strip()}

            def _persist_hostname(hostname: str, source_tag: str) -> bool:
                """
                Insert a newly discovered hostname as an Asset if it is not
                already in the inventory.

                Rules:
                  - Asset already exists + in_scope=False → skip silently.
                    CommonCrawl never re-enables out-of-scope assets.
                  - Asset already exists + in_scope=True  → skip (already known).
                  - Asset does not exist → create it.  in_scope is intentionally
                    NOT set here so the model default (True) applies; we do not
                    override any value an analyst may have set previously.

                Returns True only when a new asset row is inserted.
                """
                hostname = hostname.strip().lower()
                if not hostname or not self._is_valid_domain(hostname):
                    return False

                existing = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == hostname,
                ).first()

                if existing is not None:
                    if not existing.in_scope:
                        logger.debug(
                            f"CC discovery: skipping '{hostname}' — "
                            f"already in inventory and marked out of scope"
                        )
                    return False

                root = self._extract_root_domain(hostname)
                parent = None
                if root and root != hostname:
                    parent = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == root,
                    ).first()

                asset_type = AssetType.SUBDOMAIN if (root and root != hostname) else AssetType.DOMAIN

                db.add(Asset(
                    organization_id=organization_id,
                    name=hostname,
                    value=hostname,
                    asset_type=asset_type,
                    root_domain=root or hostname,
                    parent_id=parent.id if parent else None,
                    discovery_source=source_tag,
                    # in_scope is deliberately omitted — the column default (True)
                    # applies to genuinely new assets; we never touch existing rows.
                ))
                return True

            created = 0
            for hostname in sorted(total_subdomains):
                if _persist_hostname(hostname, 'commoncrawl'):
                    created += 1

            # Keyword hits: subdomains of known roots → 'commoncrawl'
            #               unknown roots              → 'commoncrawl-keyword'
            kw_created = 0
            for hostname in sorted(keyword_hostnames):
                if hostname in total_subdomains:
                    continue  # already persisted above
                root = self._extract_root_domain(hostname)
                tag = 'commoncrawl' if (root in known_roots) else 'commoncrawl-keyword'
                if _persist_hostname(hostname, tag):
                    kw_created += 1

            db.commit()

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = created + kw_created
                scan.results = {
                    'targets': targets,
                    'releases_queried': releases_used,
                    'mode1_subdomains_found': len(total_subdomains),
                    'mode1_assets_created': created,
                    'mode2_keyword_hostnames_found': len(keyword_hostnames),
                    'mode2_assets_created': kw_created,
                    'keywords_used': keywords_used,
                    'years': years,
                    'max_per_year': max_per_year,
                }
                db.commit()

            logger.info(
                f"CommonCrawl enum complete — "
                f"Mode 1: {len(total_subdomains)} subdomains ({created} new) | "
                f"Mode 2: {len(keyword_hostnames)} keyword hits ({kw_created} new)"
            )
            trigger_graph_sync(organization_id)

        except Exception as exc:
            logger.error(f"CommonCrawl enum scan failed: {exc}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(exc)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    async def handle_atlas_discovery(self, job_data: dict):
        """
        Atlas - org-wide attack-surface mapping (wraps Praetorian pius).

        Config (from scan.config):
            org (required, falls back to organization.name/domain)
            domain (optional hint)
            asn (optional 'AS12345' hint)
            mode ('passive' default, 'active', 'all')
            plugins / disable (optional lists)
            concurrency (int, default 5)
            timeout (seconds, default 900)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return

        try:
            from app.models.organization import Organization
            from app.models.netblock import Netblock
            import ipaddress

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running Atlas attack-surface discovery"
                db.commit()

            org_row = db.query(Organization).filter(Organization.id == organization_id).first()
            org_name = config.get('org') or (org_row.name if org_row else None)
            domain_hint = config.get('domain') or (org_row.domain if org_row else None)

            if not org_name:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Atlas requires an organization name (config.org)"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            try:
                from asm_scanner_core.scanners.atlas import run_atlas
            except ImportError:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "asm_scanner_core not installed in worker image"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            plugins = config.get('plugins') if isinstance(config.get('plugins'), list) else None
            disable = config.get('disable') if isinstance(config.get('disable'), list) else None
            mode = config.get('mode', 'passive')
            asn = config.get('asn')
            concurrency = int(config.get('concurrency', 5))
            timeout = int(config.get('timeout', 900))

            result = await asyncio.to_thread(
                run_atlas,
                org=org_name,
                domain=domain_hint,
                asn=asn,
                mode=mode,
                plugins=plugins,
                disable=disable,
                concurrency=concurrency,
                timeout=timeout,
            )

            if result.errors and not result.findings:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "; ".join(result.errors)[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            domains_created = 0
            netblocks_created = 0
            for f in result.findings:
                value = (f.target or '').strip().lower().rstrip('.')
                if not value:
                    continue

                if f.type == 'ip_range':
                    try:
                        net = ipaddress.ip_network(value, strict=False)
                    except ValueError:
                        continue
                    cidr = str(net)
                    existing = db.query(Netblock).filter(
                        Netblock.organization_id == organization_id,
                        Netblock.cidr_notation == cidr,
                    ).first()
                    if existing:
                        existing.last_verified = datetime.utcnow()
                        continue
                    source_plugin = f.source.replace('atlas:', '') if f.source else 'atlas'
                    db.add(Netblock(
                        organization_id=organization_id,
                        inetnum=f"{net.network_address} - {net.broadcast_address}" if net.version == 4 else cidr,
                        start_ip=str(net.network_address),
                        end_ip=str(net.broadcast_address) if net.version == 4 else str(net[-1]),
                        cidr_notation=cidr,
                        ip_count=net.num_addresses,
                        ip_version=f"ipv{net.version}",
                        is_owned=True,
                        in_scope=True,
                        ownership_confidence=75 if 'needs-review' not in (f.tags or []) else 40,
                        discovery_source=f'atlas:{source_plugin}',
                        discovered_at=datetime.utcnow(),
                        tags=list(f.tags or []),
                        metadata_={'scan_id': scan_id, 'source_plugin': source_plugin},
                    ))
                    netblocks_created += 1
                elif f.type in ('domain', 'subdomain'):
                    if not self._is_valid_domain(value):
                        continue
                    existing = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == value,
                    ).first()
                    if existing is not None:
                        if not existing.in_scope:
                            logger.debug(
                                f"Atlas: skipping domain '{value}' — out of scope"
                            )
                        continue
                    root = self._extract_root_domain(value)
                    parent = None
                    if root and root != value:
                        parent = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == root,
                        ).first()
                    asset_type = AssetType.SUBDOMAIN if (root and root != value) else AssetType.DOMAIN
                    source_plugin = f.source.replace('atlas:', '') if f.source else 'atlas'
                    db.add(Asset(
                        organization_id=organization_id,
                        name=value,
                        value=value,
                        asset_type=asset_type,
                        root_domain=root or value,
                        parent_id=parent.id if parent else None,
                        discovery_source=f'atlas:{source_plugin}',
                    ))
                    domains_created += 1
                elif f.type == 'ip_address':
                    existing = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == value,
                    ).first()
                    if existing is not None:
                        if not existing.in_scope:
                            logger.debug(
                                f"Atlas: skipping IP '{value}' — out of scope"
                            )
                        continue
                    source_plugin = f.source.replace('atlas:', '') if f.source else 'atlas'
                    db.add(Asset(
                        organization_id=organization_id,
                        name=value,
                        value=value,
                        asset_type=AssetType.IP_ADDRESS,
                        discovery_source=f'atlas:{source_plugin}',
                    ))
                    domains_created += 1

            db.commit()

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = domains_created
                scan.results = {
                    'org': org_name,
                    'domain_hint': domain_hint,
                    'mode': mode,
                    'domains_found': len(result.domains) + len(result.subdomains),
                    'cidrs_found': len(result.cidrs),
                    'assets_created': domains_created,
                    'netblocks_created': netblocks_created,
                    'errors': result.errors,
                }
                db.commit()

            logger.info(
                "Atlas discovery complete: %s domains/subs, %s CIDRs (%s new assets, %s new netblocks)",
                len(result.domains) + len(result.subdomains),
                len(result.cidrs),
                domains_created,
                netblocks_created,
            )
            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"Atlas discovery failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    async def handle_argus_secrets(self, job_data: dict):
        """
        Argus - secrets scanning (wraps Praetorian titus).

        Config (from scan.config):
            path (required) - Absolute filesystem path (directory, file, or local git repo)
            validate (bool) - live credential validation (default False)
            timeout (seconds, default 900)
            extra_args (list) - additional CLI flags passed to the titus CLI
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running Argus secrets scan"
                db.commit()

            path = config.get('path') or config.get('argus_scan_path')
            if not path:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Argus scan requires config.path (filesystem path to scan)"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            try:
                from asm_scanner_core.scanners.argus import run_argus
            except ImportError:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "asm_scanner_core not installed in worker image"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            timeout = int(config.get('timeout', 900))
            validate = bool(config.get('validate', False))
            extra = config.get('extra_args') if isinstance(config.get('extra_args'), list) else None

            result = await asyncio.to_thread(
                run_argus,
                path,
                validate=validate,
                timeout=timeout,
                extra_args=extra,
            )

            if result.errors and not result.findings:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "; ".join(result.errors)[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            findings_ingested = 0
            if result.findings:
                from app.services.asm_core_adapter import ingest_core_findings
                summary = ingest_core_findings(
                    db,
                    organization_id,
                    result.findings,
                    scan_id=scan_id,
                    agent_id="asm-scanner-core:argus",
                )
                if summary:
                    findings_ingested = summary.get('processed') or len(result.findings)

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.vulnerabilities_found = len(result.findings)
                scan.results = {
                    'path': path,
                    'validate': validate,
                    'findings': len(result.findings),
                    'findings_ingested': findings_ingested,
                    'errors': result.errors,
                }
                db.commit()

            logger.info("Argus scan complete: %s findings ingested (%s total)", findings_ingested, len(result.findings))

        except Exception as e:
            logger.error(f"Argus secrets scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    async def handle_hermes_secrets(self, job_data: dict):
        """
        Hermes - remote secrets across GitHub/GitLab/S3/GCS/Docker/... (wraps TruffleHog v3).

        Config (from scan.config):
            source (required)   - one of git, github, gitlab, s3, gcs, azure,
                                  docker, postman, jenkins, filesystem, ...
            target (required)   - repo URL / org name / bucket / image / path
            only_verified (bool) - emit only live-validated secrets
            timeout (seconds, default 900)
            extra_args (list)   - additional CLI flags
            env (dict)          - auth env vars (GITHUB_TOKEN, AWS_*, etc.)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running Hermes remote-secrets scan"
                db.commit()

            source = config.get('source') or config.get('hermes_source')
            target = config.get('target') or config.get('hermes_target')
            if not source or not target:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Hermes requires config.source and config.target"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            try:
                from asm_scanner_core.scanners.hermes import run_hermes
            except ImportError:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "asm_scanner_core not installed in worker image"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            timeout = int(config.get('timeout', 900))
            only_verified = bool(config.get('only_verified', False))
            extra = config.get('extra_args') if isinstance(config.get('extra_args'), list) else None
            env = config.get('env') if isinstance(config.get('env'), dict) else None

            result = await asyncio.to_thread(
                run_hermes,
                source=source,
                target=target,
                only_verified=only_verified,
                timeout=timeout,
                extra_args=extra,
                env=env,
            )

            if result.errors and not result.findings:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "; ".join(result.errors)[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            findings_ingested = 0
            if result.findings:
                from app.services.asm_core_adapter import ingest_core_findings
                summary = ingest_core_findings(
                    db,
                    organization_id,
                    result.findings,
                    scan_id=scan_id,
                    agent_id="asm-scanner-core:hermes",
                )
                if summary:
                    findings_ingested = summary.get('processed') or len(result.findings)

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.vulnerabilities_found = len(result.findings)
                scan.results = {
                    'source': source,
                    'target': target,
                    'only_verified': only_verified,
                    'findings': len(result.findings),
                    'findings_ingested': findings_ingested,
                    'sources_scanned': result.sources_scanned,
                    'errors': result.errors,
                }
                db.commit()

            logger.info(
                "Hermes scan complete (%s/%s): %s findings ingested (%s total)",
                source, target, findings_ingested, len(result.findings),
            )

        except Exception as e:
            logger.error(f"Hermes scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    async def handle_janus_dast(self, job_data: dict):
        """
        Janus - OWASP ZAP DAST (baseline = passive; full = active).

        Config (from scan.config):
            target_url (required, else first entry in job_data['targets'])
            mode ('baseline' default, 'full')
            minutes (int, caps ZAP internal timers)
            ajax (bool, enable ajax-spider for SPAs)
            timeout (seconds, default 1800)
            context_file (path, optional ZAP .context for auth/scope)
            extra_args (list)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config') or {}
        targets = job_data.get('targets') or []

        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running Janus DAST scan"
                db.commit()

            target_url = config.get('target_url') or (targets[0] if targets else None)
            if not target_url:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Janus requires config.target_url or a target"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return
            if not str(target_url).startswith("http"):
                target_url = f"https://{target_url}"

            try:
                from asm_scanner_core.scanners.janus import run_janus
            except ImportError:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "asm_scanner_core not installed in worker image"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            mode = config.get('mode', 'baseline')
            minutes_raw = config.get('minutes')
            minutes = int(minutes_raw) if minutes_raw else None
            ajax = bool(config.get('ajax', False))
            timeout = int(config.get('timeout', 1800))
            extra = config.get('extra_args') if isinstance(config.get('extra_args'), list) else None
            context_file = config.get('context_file')

            result = await asyncio.to_thread(
                run_janus,
                target_url=target_url,
                mode=mode,
                minutes=minutes,
                ajax=ajax,
                timeout=timeout,
                context_file=context_file,
                extra_args=extra,
            )

            if result.errors and not result.findings:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "; ".join(result.errors)[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            findings_ingested = 0
            if result.findings:
                from app.services.asm_core_adapter import ingest_core_findings
                summary = ingest_core_findings(
                    db,
                    organization_id,
                    result.findings,
                    scan_id=scan_id,
                    agent_id="asm-scanner-core:janus",
                )
                if summary:
                    findings_ingested = summary.get('processed') or len(result.findings)

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.vulnerabilities_found = len(result.findings)
                scan.results = {
                    'target_url': target_url,
                    'mode': mode,
                    'findings': len(result.findings),
                    'findings_ingested': findings_ingested,
                    'report_path': result.report_path,
                    'errors': result.errors,
                }
                db.commit()

            logger.info(
                "Janus %s scan complete (%s): %s findings ingested (%s total)",
                mode, target_url, findings_ingested, len(result.findings),
            )
            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"Janus DAST scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    async def handle_themis_cspm(self, job_data: dict):
        """
        Themis - cloud CSPM via Prowler (AWS/Azure/GCP/Kubernetes).

        Config (from scan.config):
            provider (required)  - 'aws' | 'azure' | 'gcp' | 'kubernetes' | 'k8s'
            compliance (str)     - e.g. 'cis_1.5_aws', 'pci_3.2.1', 'soc2_cc'
            services (list)      - restrict to named services (iam, s3, ...)
            checks (list)        - restrict to specific Prowler check IDs
            severity_filter (list)- drop findings below a severity set
            profile (str)        - AWS named profile
            region (str)         - AWS / Azure region hint
            subscription (str)   - Azure subscription id
            project_id (str)     - GCP project id
            kubeconfig (str)     - path to kubeconfig for Kubernetes
            context (str)        - kubeconfig context
            timeout (seconds, default 1800)
            extra_args (list)
            env (dict)           - credential env vars passed to the subprocess
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running Themis cloud CSPM audit"
                db.commit()

            provider = config.get('provider') or config.get('themis_provider')
            if not provider:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "Themis requires config.provider (aws|azure|gcp|kubernetes)"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            try:
                from asm_scanner_core.scanners.themis import run_themis
            except ImportError:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "asm_scanner_core not installed in worker image"
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            timeout = int(config.get('timeout', 1800))
            compliance = config.get('compliance')
            services = config.get('services') if isinstance(config.get('services'), list) else None
            checks = config.get('checks') if isinstance(config.get('checks'), list) else None
            severity_filter = config.get('severity_filter') if isinstance(config.get('severity_filter'), list) else None
            extra = config.get('extra_args') if isinstance(config.get('extra_args'), list) else None
            env = config.get('env') if isinstance(config.get('env'), dict) else None

            result = await asyncio.to_thread(
                run_themis,
                provider=provider,
                compliance=compliance,
                services=services,
                checks=checks,
                severity_filter=severity_filter,
                profile=config.get('profile'),
                region=config.get('region'),
                subscription=config.get('subscription'),
                project_id=config.get('project_id'),
                kubeconfig=config.get('kubeconfig'),
                context=config.get('context'),
                timeout=timeout,
                extra_args=extra,
                env=env,
            )

            if result.errors and not result.findings:
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = "; ".join(result.errors)[:500]
                    scan.completed_at = datetime.utcnow()
                    db.commit()
                return

            findings_ingested = 0
            if result.findings:
                from app.services.asm_core_adapter import ingest_core_findings
                summary = ingest_core_findings(
                    db,
                    organization_id,
                    result.findings,
                    scan_id=scan_id,
                    agent_id="asm-scanner-core:themis",
                )
                if summary:
                    findings_ingested = summary.get('processed') or len(result.findings)

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.vulnerabilities_found = len(result.findings)
                scan.results = {
                    'provider': result.provider,
                    'compliance': compliance,
                    'findings': len(result.findings),
                    'findings_ingested': findings_ingested,
                    'checks_total': result.checks_total,
                    'passed': result.passed,
                    'failed': result.failed,
                    'report_path': result.report_path,
                    'errors': result.errors,
                }
                db.commit()

            logger.info(
                "Themis %s audit complete: %s findings ingested (%s total, %s failed)",
                result.provider, findings_ingested, len(result.findings), result.failed,
            )
            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"Themis CSPM scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception:
                    pass
            raise
        finally:
            if db:
                db.close()

    def _is_valid_domain(self, s: str) -> bool:
        """Basic domain validity."""
        if len(s) < 3 or len(s) > 253:
            return False
        if '..' in s or s.startswith('.') or s.endswith('.'):
            return False
        return True
    
    def _extract_root_domain(self, domain: str) -> str:
        """Extract root (e.g. example.com from sub.example.com)."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    async def _process_with_semaphore(self, message: dict):
        """Process a message with semaphore limiting."""
        scan_id = None
        try:
            body = json.loads(message.get('Body', '{}'))
            scan_id = body.get('scan_id')

            # Note: scan_id is already added to active_scans in the main loop
            # to prevent race conditions during polling

            async with self.scan_semaphore:
                await self.process_message(message)

        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {e}", exc_info=True)
        finally:
            # Remove from active scans when complete
            if scan_id:
                active_scans.discard(scan_id)
                logger.info(f"Scan {scan_id} removed from active scans")
    
    async def handle_llm_red_team(self, job_data: dict):
        """Handle LLM red team scan against chatbot/AI endpoints."""
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for LLM red team scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.llm_red_team.scanner import (
                run_scan, ScanConfig, ChatEndpoint, build_finding_data,
            )
            from app.models.vulnerability import Vulnerability, Severity

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running LLM red team assessment"
                db.commit()

            target_url = targets[0] if targets else config.get('target_url', '')
            if not target_url:
                self._mark_scan_failed(scan_id, "No target URL provided")
                return

            endpoints = []
            for ep_cfg in config.get('endpoints', []):
                endpoints.append(ChatEndpoint(
                    url=ep_cfg.get('url', ''),
                    method=ep_cfg.get('method', 'POST'),
                    message_field=ep_cfg.get('message_field', 'message'),
                    response_field=ep_cfg.get('response_field'),
                    headers=ep_cfg.get('headers', {}),
                    auth_token=ep_cfg.get('auth_token'),
                    extra_body=ep_cfg.get('extra_body', {}),
                    detected_by="scan_config",
                ))

            scan_config = ScanConfig(
                target_url=target_url,
                endpoints=endpoints,
                categories=config.get('categories'),
                auto_discover=config.get('auto_discover', True),
                use_llm_grading=config.get('use_llm_grading', True),
                rate_limit_delay=config.get('rate_limit_delay', 1.0),
                max_payloads=config.get('max_payloads'),
            )

            async def progress_cb(pct, step):
                try:
                    s = db.query(Scan).filter(Scan.id == scan_id).first()
                    if s:
                        s.progress = pct
                        s.current_step = step
                        db.commit()
                except Exception:
                    pass

            scan_result = await run_scan(scan_config, progress_callback=progress_cb)

            created = 0
            sev_map = {
                "critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
            }
            if scan_result.vulnerabilities_found > 0:
                from app.models.asset import Asset, AssetType, AssetStatus
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                hostname = parsed.netloc or parsed.path.split("/")[0]
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == hostname,
                ).first()
                if not asset:
                    asset = Asset(
                        value=hostname,
                        asset_type=AssetType.DOMAIN,
                        organization_id=organization_id,
                        status=AssetStatus.ACTIVE,
                    )
                    db.add(asset)
                    db.flush()

                for test_result in scan_result.results:
                    if test_result.get("verdict") != "fail":
                        continue
                    finding_data = build_finding_data(test_result, target_url)
                    vuln = Vulnerability(
                        title=finding_data["title"][:500],
                        description=finding_data.get("description", "")[:10000],
                        severity=sev_map.get(finding_data.get("severity", "medium"), Severity.MEDIUM),
                        asset_id=asset.id,
                        scan_id=scan_id,
                        detected_by="llm_red_team",
                        template_id=finding_data.get("template_id"),
                        evidence=finding_data.get("evidence", "")[:5000],
                        cwe_id=finding_data.get("cwe_id"),
                        remediation=finding_data.get("remediation", "")[:5000],
                        tags=finding_data.get("tags", []),
                        metadata_=finding_data.get("metadata", {}),
                    )
                    db.add(vuln)
                    created += 1

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = created
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = scan_result.summary
            db.commit()

            logger.info(
                f"LLM red team scan {scan_id} completed: "
                f"{scan_result.endpoints_tested} endpoints, "
                f"{scan_result.payloads_sent} payloads, "
                f"{created} findings"
            )
            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"LLM red team scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    async def handle_subdomain_takeover(self, job_data: dict):
        """
        Subdomain takeover scanner.

        Combines a pure-Python CNAME+HTTP fingerprint engine with optional
        Nuclei takeover templates and Subjack. Findings are persisted as
        Vulnerability rows (severity HIGH, deterministic template_id for dedup).

        Config (from scan.config):
            targets (list[str])          - hostnames to test (required if no scan.targets)
            engines (list[str])          - any of ["cname", "nuclei", "subjack"]; default ["cname","nuclei"]
            concurrency (int, default 20)
            timeout (seconds, default 900)
            dns_only (bool, default False)   - skip HTTP probe, CNAME-only detection
            nuclei_templates (list[str]) - override template paths for takeover
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets') or []
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for subdomain takeover scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.takeover_scanner_service import (
                scan_takeovers,
                persist_takeover_findings,
            )

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running subdomain takeover detection"
                scan.progress = 5
                db.commit()

            hostnames = list(targets) or list(config.get('targets') or [])
            hostnames = [h.strip() for h in hostnames if h and isinstance(h, str)]
            if not hostnames:
                self._mark_scan_failed(scan_id, "No targets provided for subdomain takeover scan")
                return

            engines = config.get('engines') or ["cname", "nuclei"]
            if isinstance(engines, str):
                engines = [engines]
            engines_set = {e.lower() for e in engines}

            result = await scan_takeovers(
                hostnames=hostnames,
                enable_cname="cname" in engines_set,
                enable_nuclei="nuclei" in engines_set,
                enable_subjack="subjack" in engines_set,
                concurrency=int(config.get('concurrency', 20)),
                http_timeout=float(config.get('timeout', 8)),
            )

            persist_summary = await asyncio.to_thread(
                persist_takeover_findings,
                db, organization_id, scan_id, result,
            )
            created = int(persist_summary.get("created", 0))

            by_provider: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            for f in result.findings:
                by_provider[f.provider] = by_provider.get(f.provider, 0) + 1
                sev = "high" if f.verdict == "confirmed" else ("low" if f.verdict == "manual_review" else "medium")
                by_severity[sev] = by_severity.get(sev, 0) + 1

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = created
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "hostnames_tested": len(hostnames),
                    "findings": len(result.findings),
                    "engines_used": result.engines_used,
                    "duration_seconds": result.duration_seconds,
                    "by_provider": by_provider,
                    "by_severity": by_severity,
                    "errors": result.errors,
                    "persist": persist_summary,
                }
            db.commit()

            logger.info(
                f"Takeover scan {scan_id} completed: {len(hostnames)} hosts, "
                f"{len(result.findings)} findings, {created} persisted"
            )
            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"Subdomain takeover scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    async def handle_graphql_scan(self, job_data: dict):
        """
        GraphQL security scan.

        Discovers GraphQL endpoints on provided targets, runs introspection
        probes, and records misconfigurations (introspection exposed,
        verbose errors, field suggestions, csrf-bypass, etc).

        Config:
            targets (list[str])          - URLs or hostnames
            paths (list[str])            - extra paths to probe (defaults to common list)
            timeout (seconds, default 120)
            use_graphql_cop (bool)       - also run graphql-cop if installed
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets') or []
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for GraphQL scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.graphql_scanner_service import (
                scan_graphql_endpoints,
                persist_graphql_findings,
            )

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Scanning GraphQL endpoints"
                scan.progress = 5
                db.commit()

            urls = list(targets) or list(config.get('targets') or [])
            urls = [u.strip() for u in urls if u and isinstance(u, str)]
            if not urls:
                self._mark_scan_failed(scan_id, "No targets provided for GraphQL scan")
                return

            async def progress_cb(pct: int, step: str):
                try:
                    s = db.query(Scan).filter(Scan.id == scan_id).first()
                    if s:
                        s.progress = pct
                        s.current_step = step
                        db.commit()
                except Exception:
                    pass

            result = await scan_graphql_endpoints(
                targets=urls,
                extra_paths=config.get('paths'),
                timeout=int(config.get('timeout', 120)),
                use_graphql_cop=bool(config.get('use_graphql_cop', True)),
                progress_callback=progress_cb,
            )

            created = await asyncio.to_thread(
                persist_graphql_findings,
                db, organization_id, scan_id, result.findings,
            )

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = created
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "endpoints_found": len(result.endpoints),
                    "findings": len(result.findings),
                    "endpoints": [e.__dict__ for e in result.endpoints][:200],
                }
            db.commit()

            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"GraphQL scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    async def handle_js_recon(self, job_data: dict):
        """
        JS reconnaissance scan.

        Fetches in-scope JavaScript bundles, analyses them for leaked secrets,
        API endpoints, dependency-confusion risks, exposed source maps and
        DOM-sink patterns.

        Config:
            targets (list[str])          - URLs or hostnames
            max_scripts (int, default 200)
            timeout (seconds, default 300)
            include_source_maps (bool, default True)
            verify_secrets (bool, default True)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets') or []
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for JS recon scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.js_recon_service import (
                run_js_recon,
                persist_js_findings,
            )

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running JS reconnaissance"
                scan.progress = 5
                db.commit()

            urls = list(targets) or list(config.get('targets') or [])
            urls = [u.strip() for u in urls if u and isinstance(u, str)]
            if not urls:
                self._mark_scan_failed(scan_id, "No targets provided for JS recon scan")
                return

            async def progress_cb(pct: int, step: str):
                try:
                    s = db.query(Scan).filter(Scan.id == scan_id).first()
                    if s:
                        s.progress = pct
                        s.current_step = step
                        db.commit()
                except Exception:
                    pass

            result = await run_js_recon(
                targets=urls,
                max_scripts=int(config.get('max_scripts', 200)),
                timeout=int(config.get('timeout', 300)),
                include_source_maps=bool(config.get('include_source_maps', True)),
                verify_secrets=bool(config.get('verify_secrets', True)),
                progress_callback=progress_cb,
            )

            created = await asyncio.to_thread(
                persist_js_findings,
                db, organization_id, scan_id, result.findings,
            )

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = created
                scan.progress = 100
                scan.current_step = "Completed"

                # Build comprehensive results so analysts can audit everything
                # that was analyzed, not just what raised a finding.
                _scripts = sorted({f.source_url for f in result.findings if f.source_url})
                _endpoints = sorted({
                    f.match for f in result.findings if f.kind in ("endpoint", "js_path")
                })
                _secrets = [
                    {
                        "kind": f.pattern_name,
                        "severity": f.severity,
                        "match": f.match[:80],   # truncate for safety
                        "source_url": f.source_url,
                        "verified": f.verified,
                    }
                    for f in result.findings if f.kind == "secret"
                ]
                _sourcemaps = [
                    {"url": f.match, "source_url": f.source_url, "severity": f.severity}
                    for f in result.findings if f.kind == "sourcemap"
                ]
                _dom_sinks = [
                    {"sink": f.match, "source_url": f.source_url, "context": f.evidence[:200]}
                    for f in result.findings if f.kind == "dom_sink"
                ]
                _dep_confusion = [
                    {"package": f.match, "verified": f.verified}
                    for f in result.findings if f.kind == "dep_confusion"
                ]
                _js_paths = [
                    {
                        "url": f.match,
                        "method": (f.extras or {}).get("method", "GET"),
                        "query_params": (f.extras or {}).get("query_params", []),
                        "body_params": (f.extras or {}).get("body_params", []),
                        "url_type": (f.extras or {}).get("type"),
                        "source_js": f.source_url,
                    }
                    for f in result.findings if f.kind == "js_path"
                ]

                scan.results = {
                    # Counts
                    "scripts_analyzed": result.scripts_analyzed,
                    "secrets_found": result.secrets_found,
                    "source_maps_found": result.source_maps_found,
                    "endpoints_extracted": result.endpoints_extracted,
                    "dep_confusion_candidates": result.dep_confusion_candidates,
                    "js_paths_found": result.js_paths_found,
                    "js_params_found": result.js_params_found,
                    "dom_sinks_found": result.dom_sinks,
                    "duration_seconds": round(result.duration_seconds, 1),
                    "errors": result.errors[:20],
                    # Full inventories (capped to keep JSON column manageable)
                    "scripts": _scripts[:500],
                    "endpoints": _endpoints[:1000],
                    "secrets": _secrets[:500],
                    "sourcemaps": _sourcemaps[:200],
                    "dom_sinks": _dom_sinks[:200],
                    "dep_confusion": _dep_confusion[:200],
                    "jsluice_paths": [p for p in _js_paths if p["query_params"] or p["body_params"]][:200],
                    "jsluice_all_paths": _js_paths[:500],
                }
            db.commit()

            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"JS recon scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    async def handle_jsluice_scan(self, job_data: dict):
        """
        jsluice standalone scan — extract URLs, paths, query/body params,
        and secrets from JavaScript files.

        Can be triggered:
          1. Directly as ScanType.JSLUICE_SCAN with targets or js_urls in config.
          2. From handle_recon_pipeline after Katana populates asset.js_files.

        Config:
            targets (list[str])          - URLs/hostnames to discover JS from
            js_urls (list[str])          - Pre-discovered JS file URLs (skips
                                           discovery; used by recon pipeline)
            max_js (int, default 500)    - Max JS files to analyse
            timeout (int, default 600)
            concurrency (int, default 20)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets') or []
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for jsluice scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.jsluice_service import (
                run_jsluice_scan,
                persist_jsluice_findings,
                build_results_summary,
            )

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running jsluice analysis"
                scan.progress = 5
                db.commit()

            js_urls = config.get('js_urls') or []
            clean_targets = [t.strip() for t in targets if t and isinstance(t, str)]

            if not js_urls and not clean_targets:
                self._mark_scan_failed(scan_id, "No targets or JS URLs provided for jsluice scan")
                return

            result = await run_jsluice_scan(
                js_urls=js_urls,
                targets=clean_targets,
                max_js=int(config.get('max_js', 500)),
                timeout=int(config.get('timeout', 600)),
                concurrency=int(config.get('concurrency', 20)),
            )

            if scan:
                scan.progress = 80
                scan.current_step = "Persisting findings"
                db.commit()

            created = await asyncio.to_thread(
                persist_jsluice_findings,
                db, organization_id, scan_id, result,
            )

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = created
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = build_results_summary(result)
            db.commit()

            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"jsluice scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    async def handle_trufflehog_scan(self, job_data: dict):
        """
        TruffleHog deep secret scan with active verification.

        Config:
            sources (list[{"type": ..., "name": ...}])
                Source types: "git" | "github" | "gitlab" | "s3" | "filesystem"
            only_verified (bool, default True)
            include_unverified (bool, default False)
            concurrency (int, default 4)
            timeout (seconds, default 900)
            since_commit (str, optional, git sources)
            branch (str, optional, git sources)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets') or []
        config = job_data.get('config') or {}

        db = self.get_db_session()
        if not db:
            logger.error("No database connection for TruffleHog scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return

        try:
            from app.services.trufflehog_service import (
                run_trufflehog,
                persist_trufflehog_findings,
            )

            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running TruffleHog secret scan"
                scan.progress = 5
                db.commit()

            sources = config.get('sources') or []
            if not sources and targets:
                # Infer: github slug if it looks like org/repo, else git URL.
                for t in targets:
                    if isinstance(t, str):
                        if t.startswith(("http://", "https://", "git@")):
                            sources.append({"type": "git", "name": t})
                        elif "/" in t:
                            sources.append({"type": "github", "name": t})
                        else:
                            sources.append({"type": "github", "name": t})

            if not sources:
                self._mark_scan_failed(scan_id, "No sources provided for TruffleHog scan")
                return

            async def progress_cb(pct: int, step: str):
                try:
                    s = db.query(Scan).filter(Scan.id == scan_id).first()
                    if s:
                        s.progress = pct
                        s.current_step = step
                        db.commit()
                except Exception:
                    pass

            total_findings = 0
            total_created = 0
            errors: list[str] = []
            per_source: list[dict] = []

            for idx, src in enumerate(sources):
                pct = 10 + int(80 * (idx / max(1, len(sources))))
                await progress_cb(pct, f"Scanning {src.get('name')}")
                result = await run_trufflehog(
                    source_type=src.get('type', 'git'),
                    source_name=src.get('name', ''),
                    only_verified=bool(config.get('only_verified', True)),
                    include_unverified=bool(config.get('include_unverified', False)),
                    since_commit=config.get('since_commit'),
                    branch=config.get('branch'),
                    concurrency=int(config.get('concurrency', 4)),
                    timeout=int(config.get('timeout', 900)),
                )
                total_findings += len(result.findings)
                errors.extend(result.errors)
                created = await asyncio.to_thread(
                    persist_trufflehog_findings,
                    db, organization_id, scan_id, result,
                )
                total_created += created
                per_source.append({
                    "source": src,
                    "findings": len(result.findings),
                    "duration_seconds": result.duration_seconds,
                    "binary_available": result.binary_available,
                    "errors": result.errors,
                })

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = total_created
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "sources_scanned": len(sources),
                    "findings": total_findings,
                    "persisted": total_created,
                    "errors": errors,
                    "per_source": per_source,
                }
            db.commit()

            trigger_graph_sync(organization_id)

        except Exception as e:
            logger.error(f"TruffleHog scan {scan_id} failed: {e}", exc_info=True)
            self._mark_scan_failed(scan_id, str(e))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # Email Breach handler
    # ------------------------------------------------------------------

    async def handle_email_breach(self, body: dict) -> None:
        """
        Check an org's domain against XposedOrNot for email breach exposure.

        config keys:
            domain  (str)  — org domain to check, e.g. "target.com"
            emails  (list) — optional explicit email list to check individually
        """
        from app.services.email_breach_service import get_email_breach_service

        scan_id = body.get("scan_id")
        organization_id = body.get("organization_id")
        config = body.get("config") or {}
        db = SessionLocal()

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.current_step = "Checking email breach exposure"
                db.commit()

            domain = config.get("domain") or (body.get("targets") or [""])[0]
            explicit_emails: list[str] = config.get("emails") or []

            service = get_email_breach_service()
            results: dict = {}

            # Domain-level check
            if domain:
                dom_result = await service.check_domain_breach_exposure(domain)
                results["domain"] = dom_result.to_dict()

            # Per-email checks (if provided or extracted from assets)
            if not explicit_emails and organization_id:
                # Pull discovered email-like assets from DB
                email_assets = (
                    db.query(Asset)
                    .filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type == AssetType.OTHER,
                        Asset.value.like("%@%"),
                    )
                    .limit(50)
                    .all()
                )
                explicit_emails = [a.value for a in email_assets if "@" in a.value]

            if explicit_emails:
                email_results = await service.batch_check_emails(explicit_emails[:50])
                results["emails"] = {
                    email: r.to_dict() for email, r in email_results.items()
                }

            breached_count = sum(
                1 for r in results.get("emails", {}).values() if r.get("breached")
            )

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "domain": domain,
                    "breached_emails": breached_count,
                    "emails_checked": len(explicit_emails),
                    "data": results,
                }
            db.commit()
            logger.info(
                "Email breach scan %s completed: %d/%d emails breached",
                scan_id, breached_count, len(explicit_emails),
            )

        except Exception as exc:
            logger.error("Email breach scan %s failed: %s", scan_id, exc, exc_info=True)
            self._mark_scan_failed(scan_id, str(exc))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # DNS Threat handler
    # ------------------------------------------------------------------

    async def handle_dns_threat(self, body: dict) -> None:
        """
        Run multi-DNSBL checks on all discovered IPs and domains for an org.

        config keys:
            targets  (list) — explicit targets; falls back to DB assets
            max_assets (int) — cap on DB-sourced assets (default 200)
        """
        from app.services.dns_threat_service import get_dns_threat_service

        scan_id = body.get("scan_id")
        organization_id = body.get("organization_id")
        config = body.get("config") or {}
        db = SessionLocal()

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.current_step = "Running DNS threat checks"
                db.commit()

            targets: list[str] = body.get("targets") or config.get("targets") or []
            if not targets and organization_id:
                max_assets = int(config.get("max_assets", 200))
                assets = (
                    db.query(Asset)
                    .filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type.in_([AssetType.IP, AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                        Asset.status != AssetStatus.INACTIVE,
                    )
                    .limit(max_assets)
                    .all()
                )
                targets = [a.value for a in assets if a.value]

            service = get_dns_threat_service()
            results = await service.check_bulk(targets, max_concurrent=15)

            listed_targets = [t for t, r in results.items() if r.is_listed]
            high_severity = [
                t for t, r in results.items() if r.severity in ("high", "critical")
            ]

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "targets_checked": len(targets),
                    "listed_count": len(listed_targets),
                    "high_severity_count": len(high_severity),
                    "listed_targets": listed_targets[:50],
                    "details": {t: r.to_dict() for t, r in results.items() if r.is_listed},
                }
            db.commit()
            logger.info(
                "DNS threat scan %s: %d/%d targets listed on DNSBLs",
                scan_id, len(listed_targets), len(targets),
            )

        except Exception as exc:
            logger.error("DNS threat scan %s failed: %s", scan_id, exc, exc_info=True)
            self._mark_scan_failed(scan_id, str(exc))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # URLhaus Lookup handler
    # ------------------------------------------------------------------

    async def handle_urlhaus_lookup(self, body: dict) -> None:
        """
        Query URLhaus for discovered URLs, domains, or IPs.

        config keys:
            targets (list) — URLs, domains, IPs, or hashes to query
        """
        from app.services.urlhaus_lookup_service import get_urlhaus_lookup_service

        scan_id = body.get("scan_id")
        organization_id = body.get("organization_id")
        config = body.get("config") or {}
        db = SessionLocal()

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.current_step = "Querying URLhaus"
                db.commit()

            targets: list[str] = body.get("targets") or config.get("targets") or []
            if not targets and organization_id:
                # Pull HTTP assets as default targets
                assets = (
                    db.query(Asset)
                    .filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type.in_([AssetType.URL, AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                        Asset.status != AssetStatus.INACTIVE,
                    )
                    .limit(100)
                    .all()
                )
                targets = [a.value for a in assets if a.value]

            service = get_urlhaus_lookup_service()

            # Run lookups with concurrency limit
            sem = asyncio.Semaphore(5)

            async def _lookup(target: str) -> tuple[str, dict]:
                async with sem:
                    await asyncio.sleep(0.3)
                    result = await service.lookup(target)
                    return target, result

            pairs = await asyncio.gather(*[_lookup(t) for t in targets[:100]])
            results = dict(pairs)

            malicious = {t: r for t, r in results.items() if r.get("is_malicious")}

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "targets_checked": len(targets),
                    "malicious_count": len(malicious),
                    "malicious_targets": list(malicious.keys()),
                    "details": malicious,
                }
            db.commit()
            logger.info(
                "URLhaus scan %s: %d/%d targets flagged",
                scan_id, len(malicious), len(targets),
            )

        except Exception as exc:
            logger.error("URLhaus scan %s failed: %s", scan_id, exc, exc_info=True)
            self._mark_scan_failed(scan_id, str(exc))
        finally:
            db.close()

    # ------------------------------------------------------------------
    # BGP Lookup handler
    # ------------------------------------------------------------------

    async def handle_bgp_lookup(self, body: dict) -> None:
        """
        Enrich discovered IPs with BGP/ASN context via RIPEstat.

        config keys:
            targets   (list) — IPs or ASNs to look up
            enrich_db (bool) — if true, update asset metadata with BGP info
        """
        from app.services.ripestat_service import get_ripestat_service

        scan_id = body.get("scan_id")
        organization_id = body.get("organization_id")
        config = body.get("config") or {}
        db = SessionLocal()

        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first() if scan_id else None
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.current_step = "Running BGP/ASN lookups"
                db.commit()

            targets: list[str] = body.get("targets") or config.get("targets") or []
            if not targets and organization_id:
                ip_assets = (
                    db.query(Asset)
                    .filter(
                        Asset.organization_id == organization_id,
                        Asset.asset_type == AssetType.IP,
                        Asset.status != AssetStatus.INACTIVE,
                    )
                    .limit(200)
                    .all()
                )
                targets = [a.value for a in ip_assets if a.value]

            service = get_ripestat_service()
            enrich_db = bool(config.get("enrich_db", True))

            sem = asyncio.Semaphore(10)

            async def _lookup(target: str):
                async with sem:
                    await asyncio.sleep(0.1)
                    return target, await service.lookup_ip(target)

            pairs = await asyncio.gather(*[_lookup(t) for t in targets[:200]])
            results = {t: r for t, r in pairs}

            # Optionally write BGP context back to asset metadata
            if enrich_db and organization_id:
                for target, result in results.items():
                    if not result.success:
                        continue
                    asset = (
                        db.query(Asset)
                        .filter(
                            Asset.organization_id == organization_id,
                            Asset.value == target,
                        )
                        .first()
                    )
                    if asset:
                        meta = asset.metadata or {}
                        meta["bgp"] = {
                            "asn": result.asn,
                            "asn_name": result.asn_name,
                            "prefix": result.covering_prefix,
                            "block_name": result.block_name,
                        }
                        asset.metadata = meta
                db.commit()

            asn_summary: dict[str, int] = {}
            for r in results.values():
                if r.asn:
                    asn_summary[r.asn] = asn_summary.get(r.asn, 0) + 1

            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.current_step = "Completed"
                scan.results = {
                    "targets_enriched": len([r for r in results.values() if r.success]),
                    "unique_asns": len(asn_summary),
                    "asn_distribution": asn_summary,
                    "details": {t: r.to_dict() for t, r in results.items() if r.success},
                }
            db.commit()
            trigger_graph_sync(organization_id)
            logger.info(
                "BGP lookup %s: %d IPs enriched across %d ASNs",
                scan_id, len(results), len(asn_summary),
            )

        except Exception as exc:
            logger.error("BGP lookup %s failed: %s", scan_id, exc, exc_info=True)
            self._mark_scan_failed(scan_id, str(exc))
        finally:
            db.close()

    async def run(self):
        """
        Main worker loop with concurrent scan processing.
        
        Features:
        - Runs up to MAX_CONCURRENT_SCANS in parallel
        - Prioritizes ad-hoc scans over scheduled scans
        - Graceful shutdown with active scan tracking
        - Periodic recovery of stale RUNNING scans
        """
        logger.info(f"Starting scanner worker (max_concurrent={MAX_CONCURRENT_SCANS})...")
        
        pending_tasks = set()
        last_stale_check = datetime.utcnow()
        STALE_CHECK_INTERVAL = 300  # Check for stale scans every 5 minutes
        
        # Initial stale scan recovery on startup
        try:
            recovered = await self.recover_stale_scans()
            if recovered > 0:
                logger.info(f"Startup: recovered {recovered} stale scans")
        except Exception as e:
            logger.error(f"Error during startup stale scan recovery: {e}")
        
        while not shutdown_requested:
            try:
                # Periodic stale scan recovery
                if (datetime.utcnow() - last_stale_check).total_seconds() > STALE_CHECK_INTERVAL:
                    try:
                        recovered = await self.recover_stale_scans()
                        if recovered > 0:
                            logger.info(f"Periodic recovery: recovered {recovered} stale scans")
                    except Exception as e:
                        logger.error(f"Error during periodic stale scan recovery: {e}")
                    last_stale_check = datetime.utcnow()
                
                messages = await self.poll_for_jobs()
                
                # Create tasks for each message
                for message in messages:
                    if shutdown_requested:
                        break
                    
                    # Add scan to active_scans BEFORE creating task to prevent race condition
                    try:
                        body = json.loads(message.get('Body', '{}'))
                        scan_id = body.get('scan_id')
                        if scan_id:
                            active_scans.add(scan_id)
                            logger.info(f"Starting processing for scan {scan_id}")
                    except Exception:
                        pass
                    
                    # Create task for concurrent processing
                    task = asyncio.create_task(self._process_with_semaphore(message))
                    pending_tasks.add(task)
                    task.add_done_callback(pending_tasks.discard)
                
                # Brief pause to let async tasks start processing
                if messages:
                    await asyncio.sleep(0.5)
                
                # Clean up completed tasks
                done_tasks = [t for t in pending_tasks if t.done()]
                for task in done_tasks:
                    pending_tasks.discard(task)
                    
            except Exception as e:
                logger.error(f"Error in worker loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Back off on error
        
        # Wait for active scans to complete on shutdown
        if pending_tasks:
            logger.info(f"Waiting for {len(pending_tasks)} active scans to complete...")
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        
        logger.info("Scanner worker shutting down...")


async def main():
    """Main entry point."""
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    worker = ScannerWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())













