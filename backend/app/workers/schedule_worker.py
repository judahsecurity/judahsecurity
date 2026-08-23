"""
ASM Platform - Schedule Worker

This worker runs in the background and triggers scheduled scans
at their configured times. It checks for due schedules and creates
scan jobs that are then processed by the scanner worker.
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.models.scan_schedule import (
    ScanSchedule,
    ScheduleFrequency,
    CONTINUOUS_SCAN_TYPES,
    ALL_CRITICAL_PORTS,
    ALL_ICS_OT_PORTS,
)
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType
from app.models.label import Label
from app.models.netblock import Netblock
from app.api.routes.scans import send_scan_to_sqs

# Scan types that require IPv4 only (don't support IPv6)
IPV4_ONLY_SCAN_TYPES = [
    "port_scan", "masscan", "critical_ports",
    "ics_ot_ports", "ics_plc_scan", "ics_scada_scan",
    "ics_building_automation", "ics_full_discovery",
    "http_probe", "screenshot", "login_portal",
    "nuclei", "nuclei_critical", "nuclei_high", "nuclei_critical_high",
    "nuclei_medium", "nuclei_low_info", "nuclei_ics", "vulnerability", "technology",
    "katana", "paramspider", "waybackurls",
]

# ICS/OT schedule types → port scan (nmap/masscan + NSE). Not Nuclei.
ICS_PORT_SCAN_TYPES = {
    "ics_ot_ports",
    "ics_plc_scan",
    "ics_scada_scan",
    "ics_building_automation",
    "ics_full_discovery",
}


def filter_ipv6_targets(targets: list, scan_type: str) -> tuple:
    """
    Filter out IPv6 targets for scan types that don't support them.
    
    Returns: (filtered_targets, ipv6_skipped_count)
    """
    import ipaddress
    
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
            # Check if it's actually an IPv6 address (not a URL with port like example.com:8080)
            # IPv6 addresses have multiple colons or are in brackets
            if target.count(':') > 1 or target.startswith('['):
                ipv6_count += 1
                continue
            # Single colon might be domain:port, let it through
        
        # For CIDRs, check if IPv6
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                if network.version == 6:
                    ipv6_count += 1
                    continue
            except ValueError:
                pass  # Not a valid CIDR, might be a domain path
        
        filtered.append(target)
    
    return filtered, ipv6_count

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
CHECK_INTERVAL = int(os.getenv("SCHEDULE_CHECK_INTERVAL", "60"))  # Check every minute

# Global shutdown flag
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


class ScheduleWorker:
    """
    Schedule worker that processes scan schedules and creates scan jobs.
    
    Responsibilities:
    - Check for schedules that are due
    - Create scan jobs for due schedules
    - Update schedule next_run_at times
    - Handle schedule errors
    """
    
    def __init__(self):
        """Initialize the schedule worker."""
        if DATABASE_URL:
            self.engine = create_engine(
                DATABASE_URL,
                pool_pre_ping=True,  # Verify connections before use
                pool_reset_on_return='rollback'  # Ensure clean state on connection return
            )
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        else:
            logger.warning("DATABASE_URL not set")
            self.engine = None
            self.SessionLocal = None
        
        logger.info("Schedule worker initialized")
    
    def get_db_session(self) -> Optional[Session]:
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
    
    async def check_and_run_schedules(self):
        """Check for due schedules and trigger them."""
        db = self.get_db_session()
        if not db:
            return
        
        try:
            now = datetime.now(timezone.utc)
            
            # Find schedules that are due
            due_schedules = db.query(ScanSchedule).filter(
                ScanSchedule.is_enabled == True,
                ScanSchedule.next_run_at <= now,
                ScanSchedule.consecutive_failures < 5  # Skip schedules with too many failures
            ).all()
            
            for schedule in due_schedules:
                try:
                    await self.run_schedule(db, schedule)
                except Exception as e:
                    logger.error(f"Error running schedule {schedule.id}: {e}")
                    schedule.consecutive_failures += 1
                    schedule.last_error = str(e)
                    db.commit()
            
        except Exception as e:
            logger.error(f"Error checking schedules: {e}")
        finally:
            db.close()
    
    async def run_schedule(self, db: Session, schedule: ScanSchedule):
        """Run a single schedule by creating a scan job."""
        logger.info(f"Running schedule: {schedule.name} (ID: {schedule.id})")
        
        # Get targets from various sources
        targets = []
        
        # 1. Check for explicit targets on the schedule
        if schedule.targets:
            targets = schedule.targets
        
        # 2. Check for label-based targeting
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
        
        # 3. If no explicit targets, use ALL in-scope assets and netblocks for the organization
        else:
            # Domain-oriented scans (subdomain enumeration, domain discovery) only
            # make sense against domain assets — pivot on apex domains + subdomains
            # and skip IPs / netblocks so a daily "enumerate all domains" schedule
            # stays fast and covers every domain in inventory (including new ones).
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

            # Domain-oriented scans don't use IP netblocks as targets.
            netblocks = []
            if not domain_scoped:
                # For port scans and critical_ports, only use IPv4 netblocks
                # IPv6 has a much larger address space and requires different scanning strategies
                netblock_query = db.query(Netblock).filter(
                    Netblock.organization_id == schedule.organization_id,
                    Netblock.in_scope == True
                )

                if schedule.scan_type in ["port_scan", "masscan", "critical_ports"]:
                    netblock_query = netblock_query.filter(Netblock.ip_version == "ipv4")
                    logger.info(f"Filtering netblocks to IPv4 only for {schedule.scan_type}")

                netblocks = netblock_query.all()
            
            # Collect targets
            asset_targets = [a.value for a in assets]
            
            # Add CIDR notations from netblocks
            netblock_targets = []
            for nb in netblocks:
                if nb.cidr_notation:
                    # Handle multiple CIDRs (semicolon or comma-separated)
                    # WhoisXML uses semicolon, but also support comma for flexibility
                    cidr_str = nb.cidr_notation
                    if ';' in cidr_str:
                        cidrs = [c.strip() for c in cidr_str.split(';') if c.strip()]
                    elif ',' in cidr_str:
                        cidrs = [c.strip() for c in cidr_str.split(',') if c.strip()]
                    else:
                        cidrs = [cidr_str.strip()] if cidr_str.strip() else []
                    netblock_targets.extend(cidrs)
            
            # Combine and deduplicate
            targets = list(set(asset_targets + netblock_targets))
            logger.info(f"Auto-targeting {len(asset_targets)} assets + {len(netblock_targets)} netblock CIDRs")
        
        # Filter out IPv6 targets for scan types that don't support them
        original_count = len(targets)
        targets, ipv6_skipped = filter_ipv6_targets(targets, schedule.scan_type)
        if ipv6_skipped > 0:
            logger.info(f"Filtered out {ipv6_skipped} IPv6 targets for {schedule.scan_type} scan (IPv6 not supported)")

        if schedule.scan_type == "tester_process":
            await self._run_tester_process_schedule(db, schedule, targets)
            return
        
        if not targets:
            # Check what's missing to give a better error message
            all_assets_count = db.query(Asset).filter(
                Asset.organization_id == schedule.organization_id
            ).count()
            
            all_netblocks_count = db.query(Netblock).filter(
                Netblock.organization_id == schedule.organization_id
            ).count()
            
            in_scope_netblocks = db.query(Netblock).filter(
                Netblock.organization_id == schedule.organization_id,
                Netblock.in_scope == True
            ).count()
            
            if all_assets_count == 0 and all_netblocks_count == 0:
                error_msg = "No assets or netblocks found - run External Discovery first"
            elif all_netblocks_count > 0 and in_scope_netblocks == 0:
                error_msg = f"Found {all_netblocks_count} netblocks but none are marked in-scope. Go to Netblocks page and mark them as in-scope."
            elif all_assets_count > 0:
                error_msg = f"Found {all_assets_count} assets but none are marked in-scope"
            else:
                error_msg = "No in-scope targets found - check asset/netblock scope settings"
            
            logger.warning(f"No targets for schedule {schedule.id}: {error_msg}")
            schedule.last_error = error_msg
            schedule.next_run_at = schedule.calculate_next_run()
            db.commit()
            return
        
        # Map schedule scan_type to ScanType enum.
        # ICS profiles are PORT_SCAN (nmap/masscan + NSE). Only nuclei_ics is Nuclei.
        # Unknown types must NOT default to VULNERABILITY — that misrouted ICS
        # full discovery into Nuclei sharding (timeouts, 0 findings).
        scan_type_map = {
            "nuclei": ScanType.VULNERABILITY,
            "nuclei_critical": ScanType.VULNERABILITY,
            "nuclei_high": ScanType.VULNERABILITY,
            "nuclei_critical_high": ScanType.VULNERABILITY,
            "nuclei_medium": ScanType.VULNERABILITY,
            "nuclei_low_info": ScanType.VULNERABILITY,
            "nuclei_ics": ScanType.VULNERABILITY,
            "vulnerability": ScanType.VULNERABILITY,
            "port_scan": ScanType.PORT_SCAN,
            "masscan": ScanType.PORT_SCAN,
            "critical_ports": ScanType.PORT_SCAN,
            "ics_ot_ports": ScanType.PORT_SCAN,
            "ics_plc_scan": ScanType.PORT_SCAN,
            "ics_scada_scan": ScanType.PORT_SCAN,
            "ics_building_automation": ScanType.PORT_SCAN,
            "ics_full_discovery": ScanType.PORT_SCAN,
            "discovery": ScanType.DISCOVERY,
            "full_discovery": ScanType.DISCOVERY,  # Alias for discovery
            "full": ScanType.FULL,
            "technology": ScanType.TECHNOLOGY,
            "http_probe": ScanType.HTTP_PROBE,
            "dns_resolution": ScanType.DNS_RESOLUTION,
            "subdomain_enum": ScanType.SUBDOMAIN_ENUM,
            "login_portal": ScanType.LOGIN_PORTAL,
            "screenshot": ScanType.SCREENSHOT,
            "paramspider": ScanType.PARAMSPIDER,
            "waybackurls": ScanType.WAYBACKURLS,
            "katana": ScanType.KATANA,
            "tldfinder": ScanType.TLDFINDER,
            "commoncrawl_enum": ScanType.COMMONCRAWL_ENUM,
            "cleanup": ScanType.CLEANUP,
        }

        if schedule.scan_type not in scan_type_map:
            logger.error(
                f"Unknown schedule scan_type '{schedule.scan_type}' for schedule "
                f"{schedule.id} ({schedule.name}); skipping (refusing Nuclei default)"
            )
            schedule.last_error = f"Unknown scan_type: {schedule.scan_type}"
            schedule.next_run_at = schedule.calculate_next_run()
            db.commit()
            return

        scan_type = scan_type_map[schedule.scan_type]
        
        # Build config — merge profile defaults so ICS NSE/ports survive thin schedule configs
        profile_defaults = CONTINUOUS_SCAN_TYPES.get(schedule.scan_type, {}).get("default_config", {})
        config = {
            **profile_defaults,
            **(schedule.config or {}),
            "triggered_by_schedule": schedule.id,
            "schedule_name": schedule.name,
            "schedule_scan_type": schedule.scan_type,
        }
        
        # ParamSpider batch rotation: archive mining can't cover thousands of
        # domains in a single run, so rotate through the attack surface in
        # batches across successive scheduled runs. State (offset) is persisted
        # on the schedule so each run picks up where the last left off, giving
        # full coverage over time without ever running one giant scan.
        if schedule.scan_type == "paramspider":
            from app.services.paramspider_service import filter_scannable_domains
            domains, ps_stats = filter_scannable_domains(targets)
            if domains:
                batch_size = max(1, int(config.get("max_domains", 500)))
                sched_cfg = dict(schedule.config or {})
                offset = int(sched_cfg.get("_paramspider_offset", 0) or 0)
                if offset >= len(domains):
                    offset = 0

                batch = domains[offset:offset + batch_size]
                # Wrap so a short final batch is topped up from the start
                if len(domains) > batch_size and len(batch) < batch_size:
                    batch += domains[:batch_size - len(batch)]

                if batch_size >= len(domains):
                    next_offset = 0  # whole surface covered in one run
                else:
                    next_offset = (offset + batch_size) % len(domains)

                sched_cfg["_paramspider_offset"] = next_offset
                schedule.config = sched_cfg  # reassign so SQLAlchemy persists it

                config = {
                    **config,
                    "_paramspider_offset": offset,
                    "batch_coverage": f"{offset}-{offset + len(batch)} of {len(domains)} domains",
                }
                targets = batch
                logger.info(
                    f"ParamSpider batch rotation for schedule {schedule.id}: "
                    f"{len(domains)} scannable domains, scanning {len(batch)} this "
                    f"run (offset {offset} -> {next_offset}, batch_size {batch_size})"
                )
        
        # Special handling for critical_ports - use masscan for speed on CIDR blocks
        if schedule.scan_type == "critical_ports":
            config["ports"] = ",".join(str(p) for p in ALL_CRITICAL_PORTS)
            config["generate_findings"] = True
            config["scanner"] = config.get("scanner", "masscan")  # Masscan is faster for CIDR blocks
            config["rate"] = config.get("rate", 10000)  # 10k packets/sec default

        # ICS/OT: ensure ports + findings; full discovery keeps nmap + NSE from profile
        if schedule.scan_type in ICS_PORT_SCAN_TYPES:
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
        
        # Create the scan
        scan = Scan(
            name=f"[Scheduled] {schedule.name}",
            scan_type=scan_type,
            organization_id=schedule.organization_id,
            targets=targets,
            config=config,
            started_by="scheduler",
            status=ScanStatus.PENDING,
        )
        
        db.add(scan)
        
        # Update schedule
        schedule.last_run_at = datetime.now(timezone.utc)
        schedule.last_scan_id = scan.id
        schedule.run_count += 1
        schedule.consecutive_failures = 0
        schedule.last_error = None
        schedule.next_run_at = schedule.calculate_next_run()
        
        db.commit()
        db.refresh(scan)
        
        # Send to SQS for processing (if SQS is configured)
        if send_scan_to_sqs(scan):
            logger.info(f"Created scan {scan.id} for schedule {schedule.name}, {len(targets)} targets (sent to SQS)")
        else:
            logger.info(f"Created scan {scan.id} for schedule {schedule.name}, {len(targets)} targets (database polling)")

    async def _run_tester_process_schedule(self, db: Session, schedule: ScanSchedule, targets: list):
        """Observe→assess→fireteam hunt, not a Nuclei Scan row."""
        from app.services.agent.scheduled_hunt import (
            notify_emails,
            run_tester_process_targets,
            web_targets,
        )

        cfg = schedule.config or {}
        limit = max(1, int(cfg.get("max_targets") or 3))
        urls = web_targets(targets, limit=limit)
        if not urls:
            schedule.last_error = "No web URLs for tester_process (need http(s) hosts)"
            schedule.next_run_at = schedule.calculate_next_run()
            schedule.consecutive_failures = (schedule.consecutive_failures or 0) + 1
            db.commit()
            return
        price = float(cfg.get("price_limit_usd") or 8.0)
        user_id = schedule.created_by or "scheduler"
        result = await run_tester_process_targets(
            organization_id=schedule.organization_id,
            user_id=str(user_id),
            targets=urls,
            price_limit_usd=price,
            schedule_name=schedule.name,
        )
        digest = result.get("digest") or ""
        failed = any(r.get("error") for r in (result.get("results") or []))
        schedule.last_run_at = datetime.now(timezone.utc)
        schedule.run_count = (schedule.run_count or 0) + 1
        schedule.next_run_at = schedule.calculate_next_run()
        schedule.last_error = None if not failed else digest[:2000]
        schedule.consecutive_failures = (schedule.consecutive_failures or 0) + 1 if failed else 0
        db.commit()
        if schedule.notify_on_completion or schedule.notify_on_findings:
            notify_emails(
                schedule.notification_emails or [],
                f"[Judah] tester-process: {schedule.name}",
                digest,
            )
        logger.info("tester_process schedule %s finished: %s", schedule.id, digest[:300])

    async def run_daily_commoncrawl_refresh(self):
        """
        Queue a CommonCrawl subdomain enumeration scan for every active organization
        that has the commoncrawl module enabled and whose primary domain is set.

        Runs once per day from the main loop. Skips orgs that already have a
        CommonCrawl scan queued or running, and respects each org's saved
        ProjectSettings (years, max_per_year, timeout).
        """
        from app.models.organization import Organization
        from app.models.project_settings import ProjectSettings, MODULE_COMMONCRAWL

        db = self.get_db_session()
        if not db:
            return

        try:
            orgs = db.query(Organization).filter(Organization.is_active == True).all()
            queued = 0

            for org in orgs:
                if not org.domain or not org.domain.strip():
                    continue

                # Read per-org CommonCrawl settings
                cc_cfg = ProjectSettings.get_config(db, org.id, MODULE_COMMONCRAWL)
                if not cc_cfg.get("enabled", True):
                    logger.debug(f"CommonCrawl disabled for org {org.id} ({org.name}), skipping")
                    continue

                # Skip if a CC scan is already queued or running for this org
                active = db.query(Scan).filter(
                    Scan.organization_id == org.id,
                    Scan.scan_type == ScanType.COMMONCRAWL_ENUM,
                    Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                ).first()
                if active:
                    logger.debug(
                        f"CommonCrawl scan already active for org {org.id} ({org.name}), skipping"
                    )
                    continue

                # Pass no explicit targets — the scanner handler will sweep
                # ALL DOMAIN-type assets in the inventory (rockwellautomation.com,
                # ab.com, factorytalk.com, etc.) before falling back to org.domain.
                scan = Scan(
                    name=f"[Daily] CommonCrawl subdomain refresh: {org.name}",
                    scan_type=ScanType.COMMONCRAWL_ENUM,
                    organization_id=org.id,
                    targets=[],
                    config={
                        "years": cc_cfg.get("years", "last1"),
                        "max_per_year": cc_cfg.get("max_per_year", 1),
                        "timeout": cc_cfg.get("timeout", 120),
                        "max_results_per_release": cc_cfg.get("max_results_per_release", 100_000),
                        "triggered_by": "daily_scheduler",
                    },
                    started_by="scheduler",
                    status=ScanStatus.PENDING,
                )
                db.add(scan)
                db.flush()
                db.refresh(scan)

                if send_scan_to_sqs(scan):
                    logger.info(
                        f"Queued daily CommonCrawl scan {scan.id} for org {org.id} ({org.name})"
                    )
                else:
                    logger.info(
                        f"Queued daily CommonCrawl scan {scan.id} for org {org.id} ({org.name}) "
                        f"(database polling)"
                    )
                queued += 1

            db.commit()
            logger.info(f"Daily CommonCrawl refresh complete: {queued}/{len(orgs)} org(s) queued")

        except Exception as exc:
            logger.error(f"Daily CommonCrawl refresh failed: {exc}", exc_info=True)
            try:
                db.rollback()
            except Exception:
                pass
        finally:
            db.close()

    async def run_censys_asm_syncs(self):
        """Run continuous Censys ASM syncs for connections whose interval is due.

        Each active connection with ``continuous_sync_enabled`` is re-synced once
        its ``sync_interval_minutes`` has elapsed since the last sync. Runs on
        every loop tick (once/minute); the due-check is what enforces the cadence.
        """
        from app.models.censys_integration import CensysAsmIntegration
        from app.services import censys_asm_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(CensysAsmIntegration).filter(
                CensysAsmIntegration.is_active == True,
                CensysAsmIntegration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"Censys ASM: {len(due)} connection(s) due for continuous sync")
            for integration in due:
                try:
                    result = await censys_asm_service.sync_integration(db, integration)
                    logger.info(
                        f"Censys ASM sync (org {integration.organization_id}, "
                        f"'{integration.workspace_name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"Censys ASM sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"Censys ASM continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run_hackerone_syncs(self):
        """Run continuous HackerOne syncs for connections whose interval is due."""
        from app.models.hackerone_integration import HackerOneIntegration
        from app.services import hackerone_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(HackerOneIntegration).filter(
                HackerOneIntegration.is_active == True,
                HackerOneIntegration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"HackerOne: {len(due)} connection(s) due for continuous sync")
            for integration in due:
                try:
                    result = await hackerone_service.sync_integration(db, integration)
                    logger.info(
                        f"HackerOne sync (org {integration.organization_id}, "
                        f"'{integration.connection_name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"HackerOne sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"HackerOne continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run_akamai_waf_syncs(self):
        """Run continuous Akamai WAF syncs for connections whose interval is due."""
        from app.models.akamai_integration import AkamaiWafIntegration
        from app.services import akamai_waf_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(AkamaiWafIntegration).filter(
                AkamaiWafIntegration.is_active == True,
                AkamaiWafIntegration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"Akamai WAF: {len(due)} connection(s) due for continuous sync")
            for integration in due:
                try:
                    result = await akamai_waf_service.sync_integration(db, integration)
                    logger.info(
                        f"Akamai WAF sync (org {integration.organization_id}, "
                        f"'{integration.connection_name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"Akamai WAF sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"Akamai WAF continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run_panorama_syncs(self):
        """Run continuous Panorama syncs for connections whose interval is due."""
        from app.models.panorama_integration import PanoramaIntegration
        from app.services import panorama_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(PanoramaIntegration).filter(
                PanoramaIntegration.is_active == True,
                PanoramaIntegration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"Panorama: {len(due)} connection(s) due for continuous sync")
            for integration in due:
                try:
                    result = await panorama_service.sync_integration(db, integration)
                    logger.info(
                        f"Panorama sync (org {integration.organization_id}, "
                        f"'{integration.name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"Panorama sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"Panorama continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run_f5_syncs(self):
        """Run continuous F5 VIP→member reachability syncs when due."""
        from app.models.f5_integration import F5Integration
        from app.services import f5_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(F5Integration).filter(
                F5Integration.is_active == True,
                F5Integration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"F5: {len(due)} connection(s) due for continuous sync")
            for integration in due:
                try:
                    result = await f5_service.sync_integration(db, integration)
                    logger.info(
                        f"F5 sync (org {integration.organization_id}, "
                        f"'{integration.name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"F5 sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"F5 continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run_cloudflare_waf_syncs(self):
        """Run continuous Cloudflare WAF whitelist syncs when due."""
        from app.models.cloudflare_integration import CloudflareWafIntegration
        from app.services import cloudflare_waf_service

        db = self.get_db_session()
        if not db:
            return

        try:
            now = datetime.utcnow()
            candidates = db.query(CloudflareWafIntegration).filter(
                CloudflareWafIntegration.is_active == True,
                CloudflareWafIntegration.continuous_sync_enabled == True,
            ).all()

            due = [c for c in candidates if c.is_sync_due(now)]
            if not due:
                return

            logger.info(f"Cloudflare WAF: {len(due)} connection(s) due for whitelist sync")
            for integration in due:
                try:
                    result = await cloudflare_waf_service.sync_integration(db, integration)
                    logger.info(
                        f"Cloudflare WAF sync (org {integration.organization_id}, "
                        f"'{integration.connection_name}'): {result.get('message')}"
                    )
                except Exception as exc:
                    logger.error(
                        f"Cloudflare WAF sync failed for connection {integration.id}: {exc}",
                        exc_info=True,
                    )
                    try:
                        db.rollback()
                    except Exception:
                        pass
        except Exception as exc:
            logger.error(f"Cloudflare WAF continuous sync check failed: {exc}", exc_info=True)
        finally:
            db.close()

    async def run(self):
        """Main worker loop."""
        logger.info("Starting schedule worker...")

        # Track when we last ran the daily CommonCrawl refresh so we fire it
        # once every 24 hours regardless of how often the loop ticks.
        last_daily_cc_run: Optional[datetime] = None

        while not shutdown_requested:
            try:
                await self.check_and_run_schedules()

                # Continuous Censys ASM syncs — due-check enforces per-connection cadence
                await self.run_censys_asm_syncs()

                # Continuous HackerOne bug bounty syncs
                await self.run_hackerone_syncs()

                # Continuous Akamai WAF syncs
                await self.run_akamai_waf_syncs()

                # Continuous Panorama syncs — address-object inventory import
                await self.run_panorama_syncs()

                # Continuous F5 syncs — VIP → pool-member reachability
                await self.run_f5_syncs()

                # Continuous Cloudflare WAF whitelist syncs
                await self.run_cloudflare_waf_syncs()

                # Daily CommonCrawl refresh — fire once per 24-hour window
                now = datetime.now(timezone.utc)
                if last_daily_cc_run is None or (now - last_daily_cc_run) >= timedelta(hours=24):
                    logger.info("Running daily CommonCrawl subdomain refresh…")
                    await self.run_daily_commoncrawl_refresh()
                    last_daily_cc_run = now

                await asyncio.sleep(CHECK_INTERVAL)
            except Exception as e:
                logger.error(f"Error in schedule worker loop: {e}")
                await asyncio.sleep(CHECK_INTERVAL)

        logger.info("Schedule worker shutting down...")


async def main():
    """Main entry point."""
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    worker = ScheduleWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())

