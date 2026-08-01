"""
API routes for external discovery services.

Provides endpoints to:
- Configure API keys for external services
- Run discovery using external intelligence sources
- View available services and their status
"""

import asyncio
import time
from datetime import datetime
from typing import List, Optional, Dict
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from sqlalchemy.orm import Session


def extract_root_domain(hostname: str) -> str:
    """
    Extract the root domain from a hostname or subdomain.
    
    Examples:
        - "www.rockwellautomation.com" -> "rockwellautomation.com"
        - "sic.rockwellautomation.com" -> "rockwellautomation.com"
        - "rockwellautomation.com" -> "rockwellautomation.com"
        - "foo.bar.co.uk" -> "bar.co.uk" (handles common TLDs)
    """
    hostname = hostname.lower().strip()
    
    # Handle URLs by extracting hostname
    if '://' in hostname:
        hostname = urlparse(hostname).netloc
    
    # Remove port if present
    hostname = hostname.split(':')[0]
    
    # Common multi-part TLDs
    multi_tlds = {'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'co.in', 'org.uk', 'gov.uk', 'ac.uk'}
    
    parts = hostname.split('.')
    
    # Check for multi-part TLD
    if len(parts) >= 3:
        potential_tld = '.'.join(parts[-2:])
        if potential_tld in multi_tlds:
            # Return domain + multi-part TLD
            return '.'.join(parts[-3:])
    
    # Standard case: return last two parts
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    
    return hostname

from app.api.deps import get_db, get_current_active_user, require_analyst, require_admin
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.api_config import APIConfig, ExternalService
from app.models.organization import Organization
from app.schemas.external_discovery import (
    APIConfigCreate,
    APIConfigUpdate,
    APIConfigResponse,
    APIConfigListResponse,
    ExternalDiscoveryRequest,
    ExternalDiscoveryResponse,
    SingleSourceRequest,
    SingleSourceResponse,
    ReverseDiscoveryRequest,
    ReverseDiscoveryResponse,
    SourceResult,
    AvailableServicesResponse,
    PAID_SERVICES_INFO,
    FREE_SERVICES_INFO,
)
from app.services.external_discovery_service import ExternalDiscoveryService
from app.services.technology_scan_service import run_technology_scan_for_hosts
from app.services.subdomain_service import SubdomainService
from app.services.screenshot_service import run_screenshots_for_hosts
from app.services.http_probe_service import (
    run_http_probe_for_hosts,
    run_dns_resolution_for_hosts,
    run_geo_enrichment_for_org,
    run_ip_assets_geo_enrichment,
)
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/external-discovery", tags=["external-discovery"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.role.value == "admin":
        return True
    return user.organization_id == org_id


def mask_api_key(key: str) -> str:
    """Mask API key for display."""
    if not key:
        return None
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


async def chain_enumerate_domains(
    db: Session,
    organization_id: int,
    domains: List[str],
    *,
    create_assets: bool = True,
    max_domains: int = 50,
    skip_existing: bool = True,
) -> Dict[str, int]:
    """Run subdomain enumeration on freshly-discovered domains and (optionally)
    persist the results as SUBDOMAIN assets.

    Shared by the reverse-pivot and single-source discovery endpoints so a
    newly-found domain immediately expands into its subdomains — matching the
    behavior of the main ``/run`` flow. Bounded concurrency keeps us from
    hammering upstream sources (crt.sh / subfinder).

    Returns a summary dict: ``{"domains_enumerated", "subdomains_found", "assets_created"}``.
    """
    summary = {"domains_enumerated": 0, "subdomains_found": 0, "assets_created": 0}
    unique_domains = [d for d in dict.fromkeys(domains) if d and "." in d]
    if not unique_domains:
        return summary

    targets = unique_domains[:max_domains]
    summary["domains_enumerated"] = len(targets)
    subdomain_service = SubdomainService(organization_id=organization_id)
    chain_semaphore = asyncio.Semaphore(5)

    async def _enumerate_one(domain_to_enum: str):
        async with chain_semaphore:
            try:
                return domain_to_enum, await subdomain_service.enumerate_subdomains(
                    domain=domain_to_enum,
                    use_crtsh=True,
                    wordlist=None,
                ), None
            except Exception as exc:  # noqa: BLE001 - report per-domain, keep going
                return domain_to_enum, [], exc

    results = await asyncio.gather(*[_enumerate_one(d) for d in targets])

    # Map each subdomain back to the domain that surfaced it (for attribution).
    parent_of: Dict[str, str] = {}
    for domain_to_enum, subdomains, err in results:
        if err is not None:
            logger.warning(f"Chained enumeration failed for {domain_to_enum}: {err}")
            continue
        for sub_result in subdomains:
            parent_of.setdefault(sub_result.subdomain, domain_to_enum)

    summary["subdomains_found"] = len(parent_of)
    if not (create_assets and parent_of):
        return summary

    assets_created = 0
    for subdomain, parent in parent_of.items():
        existing = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == subdomain,
        ).first()
        if existing:
            if skip_existing:
                continue
            if not existing.discovery_chain:
                existing.discovery_source = "chained_subdomain_enum"
                existing.association_reason = (
                    f"Found via chained subdomain enumeration from {parent}"
                )
                existing.association_confidence = 95
            continue

        asset = Asset(
            name=subdomain,
            asset_type=AssetType.SUBDOMAIN,
            value=subdomain,
            root_domain=extract_root_domain(subdomain),
            organization_id=organization_id,
            status=AssetStatus.DISCOVERED,
            discovery_source="chained_subdomain_enum",
            association_reason=f"Found via chained subdomain enumeration from {parent}",
            association_confidence=95,
            discovery_chain=[{
                "step": 1,
                "source": "chained_subdomain_enum",
                "query_domain": parent,
                "timestamp": datetime.utcnow().isoformat(),
                "confidence": 95,
            }],
            tags=["source:chained_subdomain_enum"],
        )
        db.add(asset)
        assets_created += 1

    if assets_created:
        db.commit()
    summary["assets_created"] = assets_created
    return summary


# =============================================================================
# API Configuration Management
# =============================================================================

@router.get("/services", response_model=AvailableServicesResponse)
def list_available_services(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all available external discovery services."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get configured services
    configs = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.is_active == True
    ).all()
    
    configured = [c.service_name for c in configs]
    
    return AvailableServicesResponse(
        paid_services=PAID_SERVICES_INFO,
        free_services=FREE_SERVICES_INFO,
        configured_services=configured
    )


@router.get("/reverse-pivots/{organization_id}")
async def get_reverse_pivots(
    organization_id: int,
    domain: Optional[str] = None,
    whois_preview: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """
    Read-only preview of what reverse-NS/MX/WHOIS discovery WOULD pivot on for
    this organization — before any run spends provider credits.

    - Nameserver/mailserver pivots are derived from config + free DNS + stored
      records, each annotated with how many in-scope assets they recur on and
      where they came from (config / primary_domain / sampled).
    - Reverse-WHOIS terms are previewed via WhoisXML's free preview mode, which
      reports the would-return domain count without spending purchase credits.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    service = ExternalDiscoveryService(db, organization_id)
    return await service.get_reverse_pivot_plan(domain=domain, whois_preview=whois_preview)


@router.get("/configs/{organization_id}", response_model=APIConfigListResponse)
def list_api_configs(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all API configurations for an organization."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    configs = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id
    ).all()
    
    # All available service names
    available = [s["name"] for s in PAID_SERVICES_INFO]
    
    responses = []
    for config in configs:
        resp = APIConfigResponse(
            id=config.id,
            organization_id=config.organization_id,
            service_name=config.service_name,
            api_user=config.api_user,
            config=config.config,
            is_active=config.is_active,
            is_valid=config.is_valid,
            last_used=config.last_used,
            usage_count=config.usage_count,
            daily_usage=config.daily_usage,
            last_error=config.last_error,
            created_at=config.created_at,
            updated_at=config.updated_at,
            api_key_masked=mask_api_key(config.get_api_key()) if config.api_key_encrypted else None
        )
        responses.append(resp)
    
    return APIConfigListResponse(
        configs=responses,
        available_services=available
    )


@router.post("/configs/{organization_id}", response_model=APIConfigResponse)
def create_api_config(
    organization_id: int,
    config: APIConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create or update an API configuration."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if config already exists for this service
    existing = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == config.service_name
    ).first()
    
    if existing:
        # Update existing
        # Only update API key if provided (allows config-only updates)
        if config.api_key:
            existing.set_api_key(config.api_key)
            existing.is_valid = True  # Reset validation on new key
            existing.last_error = None
        if config.api_user:
            existing.api_user = config.api_user
        if config.api_secret:
            existing.set_api_secret(config.api_secret)
        if config.config:
            # Merge config instead of replacing to preserve other settings
            existing.config = {**(existing.config or {}), **config.config}
        existing.is_active = True
        db.commit()
        db.refresh(existing)
        db_config = existing
    else:
        # Create new - require API key for new configs
        if not config.api_key:
            raise HTTPException(
                status_code=400, 
                detail="API key is required when creating a new configuration"
            )
        db_config = APIConfig(
            organization_id=organization_id,
            service_name=config.service_name,
            api_user=config.api_user,
            config=config.config or {}
        )
        db_config.set_api_key(config.api_key)
        if config.api_secret:
            db_config.set_api_secret(config.api_secret)
        
        db.add(db_config)
        db.commit()
        db.refresh(db_config)
    
    return APIConfigResponse(
        id=db_config.id,
        organization_id=db_config.organization_id,
        service_name=db_config.service_name,
        api_user=db_config.api_user,
        config=db_config.config,
        is_active=db_config.is_active,
        is_valid=db_config.is_valid,
        last_used=db_config.last_used,
        usage_count=db_config.usage_count,
        daily_usage=db_config.daily_usage,
        last_error=db_config.last_error,
        created_at=db_config.created_at,
        updated_at=db_config.updated_at,
        api_key_masked=mask_api_key(db_config.get_api_key())
    )


@router.put("/configs/{config_id}", response_model=APIConfigResponse)
def update_api_config(
    config_id: int,
    updates: APIConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update an API configuration."""
    config = db.query(APIConfig).filter(APIConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    
    if not check_org_access(current_user, config.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if updates.api_key:
        config.set_api_key(updates.api_key)
    if updates.api_user is not None:
        config.api_user = updates.api_user
    if updates.api_secret:
        config.set_api_secret(updates.api_secret)
    if updates.config is not None:
        config.config = updates.config
    if updates.is_active is not None:
        config.is_active = updates.is_active
    
    db.commit()
    db.refresh(config)
    
    return APIConfigResponse(
        id=config.id,
        organization_id=config.organization_id,
        service_name=config.service_name,
        api_user=config.api_user,
        config=config.config,
        is_active=config.is_active,
        is_valid=config.is_valid,
        last_used=config.last_used,
        usage_count=config.usage_count,
        daily_usage=config.daily_usage,
        last_error=config.last_error,
        created_at=config.created_at,
        updated_at=config.updated_at,
        api_key_masked=mask_api_key(config.get_api_key())
    )


@router.delete("/configs/{config_id}")
def delete_api_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete an API configuration."""
    config = db.query(APIConfig).filter(APIConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    
    if not check_org_access(current_user, config.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db.delete(config)
    db.commit()
    
    return {"message": "Config deleted successfully"}


# =============================================================================
# External Discovery
# =============================================================================

@router.post("/run", response_model=ExternalDiscoveryResponse)
async def run_external_discovery(
    request: ExternalDiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run external discovery for a domain using all available sources.
    
    This will query multiple external services to discover:
    - Subdomains (crt.sh, VirusTotal, OTX, Wayback, RapidDNS)
    - Related domains (M365 federation, Whoxy reverse WHOIS)
    - IP ranges (WhoisXML by organization name)
    
    Example domain: rockwellautomation.com
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    start_time = time.time()
    
    # Get organization for saved discovery settings
    org = db.query(Organization).filter(Organization.id == request.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Use provided keywords or fall back to saved organization settings
    commoncrawl_org_name = request.commoncrawl_org_name
    commoncrawl_keywords = request.commoncrawl_keywords
    sni_keywords = request.sni_keywords
    
    # Fall back to saved settings if not provided in request
    if not commoncrawl_org_name and org.commoncrawl_org_name:
        commoncrawl_org_name = org.commoncrawl_org_name
        logger.info(f"Using saved commoncrawl_org_name: {commoncrawl_org_name}")
    
    if not commoncrawl_keywords and org.commoncrawl_keywords:
        commoncrawl_keywords = org.commoncrawl_keywords
        logger.info(f"Using saved commoncrawl_keywords: {commoncrawl_keywords}")
    
    if not sni_keywords and org.sni_keywords:
        sni_keywords = org.sni_keywords
        logger.info(f"Using saved sni_keywords: {sni_keywords}")
    
    # Save keywords to organization if new ones were provided
    settings_updated = False
    if request.commoncrawl_org_name and request.commoncrawl_org_name != org.commoncrawl_org_name:
        org.commoncrawl_org_name = request.commoncrawl_org_name
        settings_updated = True
    if request.commoncrawl_keywords and request.commoncrawl_keywords != org.commoncrawl_keywords:
        org.commoncrawl_keywords = request.commoncrawl_keywords
        settings_updated = True
    if request.sni_keywords and request.sni_keywords != org.sni_keywords:
        org.sni_keywords = request.sni_keywords
        settings_updated = True
    
    if settings_updated:
        db.commit()
        logger.info(f"Saved discovery keywords for organization {org.id}")
    
    # Initialize discovery service
    service = ExternalDiscoveryService(db, request.organization_id)
    
    # Run full discovery
    results = await service.full_discovery(
        domain=request.domain,
        include_paid=request.include_paid_sources,
        include_free=request.include_free_sources,
        organization_names=request.organization_names,
        registration_emails=request.registration_emails,
        commoncrawl_org_name=commoncrawl_org_name,
        commoncrawl_keywords=commoncrawl_keywords,
        include_sni_discovery=request.include_sni_discovery,
        sni_keywords=sni_keywords
    )
    
    # Aggregate results
    aggregated = service.aggregate_results(results, request.domain)
    
    # Build source results
    source_results = []
    for source, result in results.items():
        source_results.append(SourceResult(
            source=result.source,
            success=result.success,
            domains_found=len(result.domains),
            subdomains_found=len(result.subdomains),
            ips_found=len(result.ip_addresses),
            cidrs_found=len(result.ip_ranges),
            elapsed_time=result.elapsed_time,
            error=result.error
        ))
    
    # ==========================================================================
    # CHAINED SUBDOMAIN ENUMERATION on discovered domains
    # Run subdomain enumeration on all domains discovered from Whoxy, M365, etc.
    # ==========================================================================
    if request.enumerate_discovered_domains and len(aggregated["domains"]) > 1:
        logger.info(f"Running chained subdomain enumeration on {len(aggregated['domains'])} discovered domains")
        subdomain_service = SubdomainService()

        discovered_domains = [d for d in aggregated["domains"] if d != request.domain]
        domains_to_enumerate = discovered_domains[:request.max_domains_to_enumerate]

        # Fan-out: enumerate every chained domain concurrently. Bounded
        # parallelism so we don't overload upstream APIs (subfinder/crt.sh).
        chain_semaphore = asyncio.Semaphore(5)

        async def _enumerate_one(domain_to_enum: str):
            async with chain_semaphore:
                try:
                    logger.info(f"Enumerating subdomains for discovered domain: {domain_to_enum}")
                    return domain_to_enum, await subdomain_service.enumerate_subdomains(
                        domain=domain_to_enum,
                        use_crtsh=True,
                        wordlist=None,
                    ), None
                except Exception as exc:
                    return domain_to_enum, [], exc

        chain_results = await asyncio.gather(
            *[_enumerate_one(d) for d in domains_to_enumerate]
        )

        chained_subdomains_total = 0
        for domain_to_enum, subdomains, err in chain_results:
            if err is not None:
                logger.warning(f"Failed to enumerate subdomains for {domain_to_enum}: {err}")
                continue
            for sub_result in subdomains:
                if sub_result.subdomain not in aggregated["subdomains"]:
                    aggregated["subdomains"].add(sub_result.subdomain)
                    chained_subdomains_total += 1
                    for ip in sub_result.ip_addresses:
                        aggregated["ip_addresses"].add(ip)

        if chained_subdomains_total > 0:
            logger.info(f"Chained subdomain enumeration found {chained_subdomains_total} additional subdomains")
            # Add a source result for chained enumeration
            source_results.append(SourceResult(
                source="chained_subdomain_enum",
                success=True,
                domains_found=0,
                subdomains_found=chained_subdomains_total,
                ips_found=0,
                cidrs_found=0,
                elapsed_time=0,
                error=None
            ))
    
    # Create assets if requested
    assets_created = 0
    assets_skipped = 0
    created_hosts: list[str] = []
    all_hosts: list[str] = []  # ALL discovered domains and subdomains for tech scanning
    
    # Build a mapping of asset -> discovery source(s) with DETAILED match criteria
    # This tracks exactly HOW and WHY each asset was discovered
    asset_sources: dict[str, list[dict]] = {}
    
    for source_name, result in results.items():
        # For Whoxy, extract the specific match criteria (email or company that matched)
        if result.source == "whoxy" and result.raw_data:
            domains_by_email = result.raw_data.get("domains_by_email", {})
            domains_by_company = result.raw_data.get("domains_by_company", {})
            
            # Track which email caused each domain to be discovered
            for email, domains_list in domains_by_email.items():
                for domain in domains_list:
                    if domain not in asset_sources:
                        asset_sources[domain] = []
                    asset_sources[domain].append({
                        "step": len(asset_sources[domain]) + 1,
                        "source": "whoxy",
                        "match_type": "email",
                        "match_value": email,
                        "query_domain": request.domain,
                        "timestamp": datetime.utcnow().isoformat(),
                        "confidence": 90 if "@" in email and "rockwell" in email.lower() else 70
                    })
            
            # Track which company caused each domain to be discovered
            for company, domains_list in domains_by_company.items():
                for domain in domains_list:
                    if domain not in asset_sources:
                        asset_sources[domain] = []
                    asset_sources[domain].append({
                        "step": len(asset_sources[domain]) + 1,
                        "source": "whoxy",
                        "match_type": "company",
                        "match_value": company,
                        "query_domain": request.domain,
                        "timestamp": datetime.utcnow().isoformat(),
                        "confidence": 85  # Company matches are generally reliable
                    })
        # For SecurityTrails, capture which reverse pivot matched each domain
        elif result.source == "securitytrails" and result.raw_data:
            pivot_map = [
                ("domains_by_email", "registrant email", 90),
                ("domains_by_registrar", "registrar", 75),
                ("domains_by_ns", "shared nameserver", 85),
                ("domains_by_mx", "shared mail server", 85),
            ]
            for raw_key, match_type, conf in pivot_map:
                for match_value, domains_list in (result.raw_data.get(raw_key, {}) or {}).items():
                    for domain in domains_list:
                        if domain not in asset_sources:
                            asset_sources[domain] = []
                        asset_sources[domain].append({
                            "step": len(asset_sources[domain]) + 1,
                            "source": "securitytrails",
                            "match_type": match_type,
                            "match_value": match_value,
                            "query_domain": request.domain,
                            "timestamp": datetime.utcnow().isoformat(),
                            "confidence": conf,
                        })
            for domain in (result.raw_data.get("domains_associated", []) or []):
                if domain not in asset_sources:
                    asset_sources[domain] = []
                asset_sources[domain].append({
                    "step": len(asset_sources[domain]) + 1,
                    "source": "securitytrails",
                    "match_type": "associated domain",
                    "match_value": request.domain,
                    "query_domain": request.domain,
                    "timestamp": datetime.utcnow().isoformat(),
                    "confidence": 70,
                })
        # For reverse-DNS, capture which owned NS/MX matched each domain
        elif result.source == "reverse_dns" and result.raw_data:
            for raw_key, match_type in (("domains_by_ns", "shared nameserver"),
                                        ("domains_by_mx", "shared mail server")):
                for match_value, domains_list in (result.raw_data.get(raw_key, {}) or {}).items():
                    for domain in domains_list:
                        if domain not in asset_sources:
                            asset_sources[domain] = []
                        asset_sources[domain].append({
                            "step": len(asset_sources[domain]) + 1,
                            "source": "reverse_dns",
                            "match_type": match_type,
                            "match_value": match_value,
                            "query_domain": request.domain,
                            "timestamp": datetime.utcnow().isoformat(),
                            # Owned infra is a strong ownership signal
                            "confidence": 90,
                        })
        else:
            # For other sources, just track the source
            for domain in result.domains:
                if domain not in asset_sources:
                    asset_sources[domain] = []
                asset_sources[domain].append({
                    "step": len(asset_sources[domain]) + 1,
                    "source": result.source,
                    "query_domain": request.domain,
                    "timestamp": datetime.utcnow().isoformat(),
                    "confidence": 80
                })
        
        for subdomain in result.subdomains:
            if subdomain not in asset_sources:
                asset_sources[subdomain] = []
            asset_sources[subdomain].append({
                "step": len(asset_sources[subdomain]) + 1,
                "source": result.source,
                "query_domain": request.domain,
                "timestamp": datetime.utcnow().isoformat(),
                "confidence": 95  # Subdomains from DNS/certs are very reliable
            })
    
    if request.create_assets:
        # Create domain assets
        for domain in aggregated["domains"]:
            all_hosts.append(domain)  # Track all hosts for tech scanning
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain,
                Asset.asset_type == AssetType.DOMAIN
            ).first()
            
            # Build discovery chain and association reason
            sources = asset_sources.get(domain, [])
            source_names = list(set(s["source"] for s in sources))
            primary_source = source_names[0] if source_names else "external_discovery"
            
            # Calculate confidence from sources (use highest confidence)
            confidence = max([s.get("confidence", 50) for s in sources]) if sources else 50
            
            # Build human-readable association reason with SPECIFIC match criteria
            if domain == request.domain:
                association_reason = f"Primary domain for organization"
                confidence = 100
            elif "whoxy" in source_names:
                # Find the specific match that caused this domain to be discovered
                whoxy_matches = [s for s in sources if s.get("source") == "whoxy"]
                match_details = []
                for match in whoxy_matches:
                    match_type = match.get("match_type", "unknown")
                    match_value = match.get("match_value", "unknown")
                    if match_type == "email":
                        match_details.append(f"registrant email '{match_value}'")
                    elif match_type == "company":
                        match_details.append(f"company name '{match_value}'")
                
                if match_details:
                    association_reason = f"Found via Whoxy reverse WHOIS - matched on {', '.join(match_details)}"
                else:
                    association_reason = f"Found via Whoxy reverse WHOIS lookup on {request.domain}"
            elif "securitytrails" in source_names:
                st_matches = [s for s in sources if s.get("source") == "securitytrails"]
                match_details = []
                for match in st_matches:
                    match_type = match.get("match_type", "reverse lookup")
                    match_value = match.get("match_value", "unknown")
                    match_details.append(f"{match_type} '{match_value}'")
                if match_details:
                    association_reason = f"Found via SecurityTrails reverse lookup - matched on {', '.join(match_details)}"
                else:
                    association_reason = f"Found via SecurityTrails reverse lookup on {request.domain}"
            elif "reverse_dns" in source_names:
                rd_matches = [s for s in sources if s.get("source") == "reverse_dns"]
                match_details = []
                for match in rd_matches:
                    match_type = match.get("match_type", "shared infrastructure")
                    match_value = match.get("match_value", "unknown")
                    match_details.append(f"{match_type} '{match_value}'")
                if match_details:
                    association_reason = f"Shares owned infrastructure - matched on {', '.join(match_details)}"
                else:
                    association_reason = f"Found via reverse-NS/MX on owned infrastructure"
            elif "m365" in source_names:
                association_reason = f"Found via Microsoft 365 federation from {request.domain}"
            elif "commoncrawl" in source_names or "commoncrawl_comprehensive" in source_names:
                association_reason = f"Found via Common Crawl data related to {request.domain}"
            else:
                association_reason = f"Discovered via {', '.join(source_names)} from {request.domain}"
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
                # Update existing asset with discovery info if not set
                if not existing.discovery_chain:
                    existing.discovery_chain = sources
                    existing.association_reason = association_reason
                    existing.association_confidence = confidence
            else:
                asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    root_domain=extract_root_domain(domain),  # Set root domain
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=primary_source,
                    discovery_chain=sources,
                    association_reason=association_reason,
                    association_confidence=confidence,
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
                created_hosts.append(domain)
        
        # Create subdomain assets
        for subdomain in aggregated["subdomains"]:
            all_hosts.append(subdomain)  # Track all hosts for tech scanning
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == subdomain,
                Asset.asset_type == AssetType.SUBDOMAIN
            ).first()
            
            # Build discovery chain
            sources = asset_sources.get(subdomain, [])
            source_names = list(set(s["source"] for s in sources))
            primary_source = source_names[0] if source_names else "external_discovery"
            
            # Determine parent domain
            parts = subdomain.split('.')
            parent_domain = '.'.join(parts[-2:]) if len(parts) > 2 else subdomain
            
            # Build association reason
            if "crtsh" in source_names:
                association_reason = f"Found in SSL certificate for {parent_domain}"
            elif "virustotal" in source_names:
                association_reason = f"Found via VirusTotal passive DNS for {parent_domain}"
            elif "otx" in source_names:
                association_reason = f"Found via AlienVault OTX for {parent_domain}"
            elif "wayback" in source_names:
                association_reason = f"Found in Wayback Machine archives for {parent_domain}"
            elif "rapiddns" in source_names:
                association_reason = f"Found via RapidDNS for {parent_domain}"
            elif "chained_subdomain_enum" in source_names:
                association_reason = f"Found via chained subdomain enumeration from discovered domain"
            else:
                association_reason = f"Subdomain of {parent_domain}, discovered via {', '.join(source_names)}"
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
                # Update existing asset with discovery info if not set
                if not existing.discovery_chain:
                    existing.discovery_chain = sources
                    existing.association_reason = association_reason
            else:
                # Use the helper to get the root domain
                root = extract_root_domain(subdomain)
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    root_domain=root,  # Set root domain for grouping
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=primary_source,
                    discovery_chain=sources,
                    association_reason=association_reason,
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
                created_hosts.append(subdomain)
        
        # Create IP assets
        # Track IP sources from results
        ip_sources: dict[str, list[dict]] = {}
        for source_name, result in results.items():
            for ip in result.ip_addresses:
                if ip not in ip_sources:
                    ip_sources[ip] = []
                ip_sources[ip].append({
                    "step": len(ip_sources[ip]) + 1,
                    "source": result.source,
                    "query_domain": request.domain,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        for ip in aggregated["ip_addresses"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == ip,
                Asset.asset_type == AssetType.IP_ADDRESS
            ).first()
            
            sources = ip_sources.get(ip, [])
            source_names = list(set(s["source"] for s in sources))
            primary_source = source_names[0] if source_names else "external_discovery"
            association_reason = f"IP address discovered via {', '.join(source_names) if source_names else 'DNS resolution'} for {request.domain}"
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
                if not existing.discovery_chain:
                    existing.discovery_chain = sources
                    existing.association_reason = association_reason
            else:
                asset = Asset(
                    name=ip,
                    asset_type=AssetType.IP_ADDRESS,
                    value=ip,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=primary_source,
                    discovery_chain=sources,
                    association_reason=association_reason,
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
        
        # Create IP range assets
        # Track IP range sources
        cidr_sources: dict[str, list[dict]] = {}
        for source_name, result in results.items():
            for cidr in result.ip_ranges:
                if cidr not in cidr_sources:
                    cidr_sources[cidr] = []
                cidr_sources[cidr].append({
                    "step": len(cidr_sources[cidr]) + 1,
                    "source": result.source,
                    "query": request.organization_names[0] if request.organization_names else request.domain,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        for cidr in aggregated["ip_ranges"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == cidr,
                Asset.asset_type == AssetType.IP_RANGE
            ).first()
            
            sources = cidr_sources.get(cidr, [])
            source_names = list(set(s["source"] for s in sources))
            primary_source = source_names[0] if source_names else "whoisxml"
            org_name = request.organization_names[0] if request.organization_names else "organization"
            association_reason = f"IP range registered to {org_name}, discovered via {', '.join(source_names) if source_names else 'WhoisXML'}"
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
                if not existing.discovery_chain:
                    existing.discovery_chain = sources
                    existing.association_reason = association_reason
            else:
                asset = Asset(
                    name=cidr,
                    asset_type=AssetType.IP_RANGE,
                    value=cidr,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=primary_source,
                    discovery_chain=sources,
                    association_reason=association_reason,
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
        
        db.commit()

        # Automated technology fingerprinting on ALL discovered hosts
        # This runs in background to avoid blocking the response
        if request.run_technology_scan and all_hosts:
            logger.info(f"Scheduling technology scan for {len(all_hosts)} hosts (max: {request.max_technology_scan})")
            background_tasks.add_task(
                run_technology_scan_for_hosts,
                organization_id=request.organization_id,
                hosts=all_hosts,  # Scan ALL discovered hosts, not just newly created
                max_hosts=request.max_technology_scan,
            )
        
        # Automated screenshot capture on ALL discovered hosts
        # This runs in background after tech scanning
        if request.run_screenshots and all_hosts:
            logger.info(f"Scheduling screenshot capture for {len(all_hosts)} hosts (max: {request.max_screenshots})")
            background_tasks.add_task(
                run_screenshots_for_hosts,
                organization_id=request.organization_id,
                hosts=all_hosts,
                max_hosts=request.max_screenshots,
                timeout=request.screenshot_timeout,
            )
        
        # HTTP probing - check if sites are live and get status codes
        # This runs FIRST since it also resolves IPs
        if request.run_http_probe and all_hosts:
            logger.info(f"Scheduling HTTP probe for {len(all_hosts)} hosts (max: {request.max_http_probe})")
            background_tasks.add_task(
                run_http_probe_for_hosts,
                organization_id=request.organization_id,
                hosts=all_hosts,
                max_hosts=request.max_http_probe,
            )
        
        # DNS resolution - get IP addresses (runs if HTTP probe didn't already resolve)
        if request.run_dns_resolution and all_hosts:
            logger.info(f"Scheduling DNS resolution for {len(all_hosts)} hosts (max: {request.max_dns_resolution})")
            background_tasks.add_task(
                run_dns_resolution_for_hosts,
                organization_id=request.organization_id,
                hosts=all_hosts,
                max_hosts=request.max_dns_resolution,
            )
        
        # Geolocation enrichment - get country data for mapping
        # This runs AFTER HTTP probe and DNS resolution to use the resolved IPs
        if request.run_geo_enrichment:
            logger.info(f"Scheduling geo enrichment for organization {request.organization_id} (max: {request.max_geo_enrichment})")
            # Enrich domain/subdomain assets with geo data based on their IPs
            background_tasks.add_task(
                run_geo_enrichment_for_org,
                organization_id=request.organization_id,
                max_assets=request.max_geo_enrichment,
                force=False,
            )
            # Also enrich IP address assets (from CIDR/netblocks)
            background_tasks.add_task(
                run_ip_assets_geo_enrichment,
                organization_id=request.organization_id,
                max_assets=request.max_geo_enrichment,
            )
    
    return ExternalDiscoveryResponse(
        domain=request.domain,
        organization_id=request.organization_id,
        total_domains=len(aggregated["domains"]),
        total_subdomains=len(aggregated["subdomains"]),
        total_ips=len(aggregated["ip_addresses"]),
        total_cidrs=len(aggregated["ip_ranges"]),
        source_results=source_results,
        domains=list(aggregated["domains"]),
        subdomains=list(aggregated["subdomains"]),
        ip_addresses=list(aggregated["ip_addresses"]),
        ip_ranges=list(aggregated["ip_ranges"]),
        assets_created=assets_created,
        assets_skipped=assets_skipped,
        total_elapsed_time=time.time() - start_time
    )


@router.post("/run/source", response_model=SingleSourceResponse)
async def run_single_source(
    request: SingleSourceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run discovery using a single external source.
    
    Available sources:
    - crtsh: Certificate transparency logs
    - virustotal: VirusTotal subdomain database
    - otx: AlienVault OTX passive DNS
    - wayback: Wayback Machine historical data
    - rapiddns: RapidDNS subdomain lookup
    - m365: Microsoft 365 federation discovery
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = ExternalDiscoveryService(db, request.organization_id)
    
    # Map source names to methods
    source_methods = {
        "crtsh": service.discover_crtsh,
        "shodan_ctl": service.discover_shodan_ctl,
        "crt_name": service.discover_crt_name,
        "virustotal": service.discover_virustotal,
        "otx": service.discover_otx,
        "wayback": service.discover_wayback,
        "rapiddns": service.discover_rapiddns,
        "m365": service.discover_m365,
        "commoncrawl": service.discover_commoncrawl,
        "securitytrails": service.discover_securitytrails,
        "reverse_dns": lambda d: service.discover_reverse_dns(domain=d, auto_seed=True),
    }
    
    if request.source not in source_methods:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown source: {request.source}. Available: {list(source_methods.keys())}"
        )
    
    # Run the source
    result = await source_methods[request.source](request.domain)
    
    # Create assets if requested
    assets_created = 0
    if request.create_assets and result.success:
        for subdomain in result.subdomains:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == subdomain
            ).first()
            
            if not existing:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=request.source,
                    tags=[f"source:{request.source}"],
                )
                db.add(asset)
                assets_created += 1
        
        for domain in result.domains:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain
            ).first()
            
            if not existing:
                asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=request.source,
                    tags=[f"source:{request.source}"],
                )
                db.add(asset)
                assets_created += 1
        
        db.commit()

    # Chain subdomain enumeration on any related domains this source surfaced
    # (e.g. reverse_dns / m365 / securitytrails), so new domains expand into
    # their subdomains right away instead of waiting for a scheduled sweep.
    if request.enumerate_discovered_domains and result.success and result.domains:
        chain_summary = await chain_enumerate_domains(
            db,
            request.organization_id,
            result.domains,
            create_assets=request.create_assets,
            max_domains=request.max_domains_to_enumerate,
        )
        assets_created += chain_summary["assets_created"]

    return SingleSourceResponse(
        source=result.source,
        domain=request.domain,
        success=result.success,
        domains=result.domains,
        subdomains=result.subdomains,
        ip_addresses=result.ip_addresses,
        ip_ranges=result.ip_ranges,
        error=result.error,
        elapsed_time=result.elapsed_time,
        assets_created=assets_created
    )


@router.post("/run/reverse", response_model=ReverseDiscoveryResponse)
async def run_reverse_discovery(
    request: ReverseDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Run reverse-NS/MX discovery on an EXPLICITLY-selected set of pivots.

    This is the "run what I previewed" companion to ``GET /reverse-pivots``:
    the user reviews the credit-free plan, unchecks noisy/shared hosts, and
    submits only the pivots they trust. No auto-seeding happens here — we
    pivot on exactly the hosts provided, so the run is predictable and the
    credit spend is bounded by the selection.
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    if not request.nameservers and not request.mailservers:
        raise HTTPException(
            status_code=400,
            detail="Select at least one nameserver or mailserver pivot to run on.",
        )

    service = ExternalDiscoveryService(db, request.organization_id)
    result = await service.discover_reverse_dns(
        domain=request.domain,
        pivot_nameservers=request.nameservers,
        pivot_mailservers=request.mailservers,
    )

    raw = result.raw_data or {}

    # Create discovered domains as assets, attributed to reverse_dns.
    assets_created = 0
    if request.create_assets and result.success:
        for domain in result.domains:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain,
            ).first()
            if not existing:
                asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    root_domain=extract_root_domain(domain),
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source="reverse_dns",
                    association_reason="Shares owned infrastructure (reverse-NS/MX pivot)",
                    association_confidence=85,
                    tags=["source:reverse_dns"],
                )
                db.add(asset)
                assets_created += 1
        if assets_created:
            db.commit()

    # Chain subdomain enumeration on the domains we just found so the attack
    # surface expands immediately (mirrors the main /run behavior).
    chain_summary = {"subdomains_found": 0, "assets_created": 0}
    if request.enumerate_discovered_domains and result.success and result.domains:
        chain_summary = await chain_enumerate_domains(
            db,
            request.organization_id,
            result.domains,
            create_assets=request.create_assets,
            max_domains=request.max_domains_to_enumerate,
        )

    return ReverseDiscoveryResponse(
        organization_id=request.organization_id,
        success=result.success,
        domains=result.domains,
        domains_by_nameserver=raw.get("domains_by_ns", {}),
        domains_by_mailserver=raw.get("domains_by_mx", {}),
        pivoted_nameservers=raw.get("pivoted_nameservers", []),
        pivoted_mailservers=raw.get("pivoted_mailservers", []),
        providers=raw.get("providers", []),
        total_domains_found=raw.get("total_domains_found", len(result.domains)),
        assets_created=assets_created,
        subdomains_enumerated=chain_summary["subdomains_found"],
        subdomain_assets_created=chain_summary["assets_created"],
        error=result.error,
        elapsed_time=result.elapsed_time,
    )


@router.post("/test/{service_name}")
async def test_api_config(
    service_name: str,
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Test an API configuration by making a simple request.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == service_name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="API config not found")
    
    service = ExternalDiscoveryService(db, organization_id)
    
    # Test with a simple domain
    test_domain = "example.com"
    
    test_methods = {
        "virustotal": lambda: service.discover_virustotal(test_domain),
        "otx": lambda: service.discover_otx(test_domain),
    }
    
    if service_name not in test_methods:
        return {
            "service": service_name,
            "success": True,
            "message": "API key stored (no test available for this service)"
        }
    
    result = await test_methods[service_name]()
    
    # Update config validity
    config.is_valid = result.success
    if not result.success:
        config.last_error = result.error
    else:
        config.last_error = None
    db.commit()
    
    return {
        "service": service_name,
        "success": result.success,
        "error": result.error,
        "message": "API key is valid" if result.success else f"API key test failed: {result.error}"
    }


@router.post("/validate-domains")
async def validate_domains(
    organization_id: int,
    domains: Optional[List[str]] = None,
    validate_all_whoxy: bool = False,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Validate domains for suspicious indicators (parking, privacy, squatting).
    
    - If domains list provided, validates those specific domains
    - If validate_all_whoxy=True, validates all domains discovered via Whoxy
    
    Returns suspicion scores and recommendations (keep, flag, review, remove).
    """
    from app.services.domain_validation_service import get_domain_validation_service
    from app.models.asset import Asset, AssetType
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get Whoxy API key for WHOIS lookups
    whoxy_config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == "whoxy"
    ).first()
    
    # Get domains to validate
    domains_to_validate = []
    
    if domains:
        domains_to_validate = domains[:limit]
    elif validate_all_whoxy:
        # Get all domains discovered via Whoxy
        assets = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.discovery_source.ilike('%whoxy%'),
            Asset.in_scope == True
        ).limit(limit).all()
        domains_to_validate = [a.value for a in assets]
    
    if not domains_to_validate:
        return {
            "message": "No domains to validate",
            "total": 0,
            "results": []
        }
    
    # Initialize validation service
    validation_service = get_domain_validation_service()
    if whoxy_config and whoxy_config.api_key:
        validation_service.set_whoxy_key(whoxy_config.api_key)
    
    # Validate domains
    validation_results = await validation_service.validate_domains_batch(domains_to_validate)
    
    # Optionally update assets in database
    updated_count = 0
    for result in validation_results.get("results", []):
        if result.get("is_suspicious"):
            # Find and update the asset
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == result.get("domain")
            ).first()
            
            if asset:
                # Add suspicion metadata
                metadata = asset.metadata_ or {}
                metadata["suspicion_score"] = result.get("suspicion_score", 0)
                metadata["suspicion_reasons"] = result.get("reasons", [])
                metadata["is_parked"] = result.get("is_parked", False)
                metadata["is_private"] = result.get("is_private", False)
                metadata["validation_recommendation"] = result.get("recommendation", "review")
                metadata["validated_at"] = result.get("checked_at")
                asset.metadata_ = metadata
                
                # Auto-mark as out-of-scope if highly suspicious
                if result.get("suspicion_score", 0) >= 75:
                    asset.in_scope = False
                    updated_count += 1
    
    db.commit()
    
    return {
        "message": f"Validated {len(domains_to_validate)} domains",
        "total": validation_results.get("total", 0),
        "suspicious": validation_results.get("suspicious", 0),
        "parked": validation_results.get("parked", 0),
        "private": validation_results.get("private", 0),
        "auto_removed": updated_count,
        "results": validation_results.get("results", [])
    }


@router.post("/enrich-dns")
async def enrich_domains_dns(
    organization_id: int = 1,
    domain_ids: Optional[List[int]] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich domain assets with DNS records from WhoisXML API.
    
    Fetches A, AAAA, MX, NS, TXT, SOA records and stores them on the asset.
    Also detects mail providers, CDN usage, and security features (SPF, DMARC, DKIM).
    """
    from app.services.dns_enrichment_service import DNSEnrichmentService
    
    # Get WhoisXML API key from config
    whoisxml_config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == "whoisxml"
    ).first()
    
    api_key = whoisxml_config.get_api_key() if whoisxml_config else None
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="WhoisXML API key not configured. Add it in Settings > External Discovery."
        )
    
    # Get domains to enrich
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type == 'domain',
        Asset.in_scope == True
    )
    
    if domain_ids:
        query = query.filter(Asset.id.in_(domain_ids))
    
    domains = query.limit(limit).all()
    
    if not domains:
        return {
            "message": "No domains found to enrich",
            "enriched": 0,
            "results": []
        }
    
    # Initialize DNS service
    dns_service = DNSEnrichmentService(api_key)
    
    results = []
    enriched_count = 0
    
    for domain_asset in domains:
        try:
            dns_data = await dns_service.enrich_domain(domain_asset.value)
            
            if "error" not in dns_data:
                # Update asset with DNS data
                metadata = domain_asset.metadata_ or {}
                metadata["dns_records"] = dns_data.get("records", {})
                metadata["dns_summary"] = dns_data.get("summary", {})
                metadata["dns_analysis"] = dns_data.get("analysis", {})
                metadata["dns_fetched_at"] = dns_data.get("fetched_at")
                domain_asset.metadata_ = metadata
                
                # Update IP addresses if found
                ips = dns_data.get("summary", {}).get("ip_addresses", [])
                if ips:
                    domain_asset.update_ip_addresses(ips)
                
                enriched_count += 1
                results.append({
                    "domain": domain_asset.value,
                    "asset_id": domain_asset.id,
                    "status": "enriched",
                    "records_found": {
                        "A": len(dns_data.get("records", {}).get("A", [])),
                        "AAAA": len(dns_data.get("records", {}).get("AAAA", [])),
                        "MX": len(dns_data.get("records", {}).get("MX", [])),
                        "NS": len(dns_data.get("records", {}).get("NS", [])),
                        "TXT": len(dns_data.get("records", {}).get("TXT", [])),
                    },
                    "has_mail": dns_data.get("summary", {}).get("has_mail", False),
                    "mail_providers": dns_data.get("summary", {}).get("mail_providers", []),
                    "security_features": dns_data.get("analysis", {}).get("security_features", []),
                })
            else:
                results.append({
                    "domain": domain_asset.value,
                    "asset_id": domain_asset.id,
                    "status": "error",
                    "error": dns_data.get("error")
                })
                
        except Exception as e:
            results.append({
                "domain": domain_asset.value,
                "asset_id": domain_asset.id,
                "status": "error",
                "error": str(e)
            })
    
    db.commit()
    
    return {
        "message": f"DNS enrichment complete",
        "total_domains": len(domains),
        "enriched": enriched_count,
        "results": results
    }


@router.get("/dns/{asset_id}")
async def get_asset_dns_records(
    asset_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Get DNS records for a specific asset.
    
    If refresh=True and WhoisXML API is configured, fetches fresh data.
    """
    from app.services.dns_enrichment_service import DNSEnrichmentService
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if asset.asset_type != 'domain':
        raise HTTPException(status_code=400, detail="Asset is not a domain")
    
    if refresh:
        # Get WhoisXML API key
        whoisxml_config = db.query(APIConfig).filter(
            APIConfig.organization_id == asset.organization_id,
            APIConfig.service_name == "whoisxml"
        ).first()
        
        api_key = whoisxml_config.get_api_key() if whoisxml_config else None
        if api_key:
            dns_service = DNSEnrichmentService(api_key)
            dns_data = await dns_service.enrich_domain(asset.value)
            
            if "error" not in dns_data:
                metadata = asset.metadata_ or {}
                metadata["dns_records"] = dns_data.get("records", {})
                metadata["dns_summary"] = dns_data.get("summary", {})
                metadata["dns_analysis"] = dns_data.get("analysis", {})
                metadata["dns_fetched_at"] = dns_data.get("fetched_at")
                asset.metadata_ = metadata
                
                ips = dns_data.get("summary", {}).get("ip_addresses", [])
                if ips:
                    asset.update_ip_addresses(ips)
                
                db.commit()
                db.refresh(asset)
    
    metadata = asset.metadata_ or {}
    
    return {
        "asset_id": asset.id,
        "domain": asset.value,
        "dns_records": metadata.get("dns_records", {}),
        "dns_summary": metadata.get("dns_summary", {}),
        "dns_analysis": metadata.get("dns_analysis", {}),
        "dns_fetched_at": metadata.get("dns_fetched_at"),
    }


@router.post("/enrich-whois")
async def enrich_domains_whois(
    organization_id: int = 1,
    domain_ids: Optional[List[int]] = None,
    expected_registrant: Optional[str] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich domain assets with WHOIS registration data.
    
    Fetches registrant info, creation/expiry dates, nameservers, and stores on the asset.
    Optionally validates ownership by checking if registrant matches expected_registrant.
    
    Args:
        organization_id: Organization to enrich domains for
        domain_ids: Optional specific domain IDs to enrich
        expected_registrant: Optional string to match against registrant (for ownership validation)
        limit: Maximum domains to enrich
    """
    from app.services.whoxy_service import WhoxyService
    
    # Get Whoxy API key from config
    whoxy_config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == "whoxy"
    ).first()
    
    api_key = whoxy_config.get_api_key() if whoxy_config else None
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Whoxy API key not configured. Add it in Settings > External Discovery."
        )
    
    # Get domains to enrich (both domains and subdomains, but WHOIS only makes sense for root domains)
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type == AssetType.DOMAIN,
        Asset.in_scope == True
    )
    
    if domain_ids:
        query = query.filter(Asset.id.in_(domain_ids))
    
    domains = query.limit(limit).all()
    
    if not domains:
        return {
            "message": "No domains found to enrich",
            "enriched": 0,
            "results": []
        }
    
    # Initialize Whoxy service
    whoxy_service = WhoxyService(api_key)
    
    results = []
    enriched_count = 0
    ownership_matches = 0
    ownership_mismatches = 0
    privacy_protected = 0
    
    for domain_asset in domains:
        try:
            whois_data = await whoxy_service.whois_lookup(domain_asset.value)
            
            if whois_data and whois_data.get('status') == 1:
                # Extract key WHOIS fields
                whois_summary = {
                    "domain_name": whois_data.get("domain_name", domain_asset.value),
                    "registrar": whois_data.get("domain_registrar", {}).get("registrar_name"),
                    "registrant_name": whois_data.get("registrant_contact", {}).get("full_name"),
                    "registrant_org": whois_data.get("registrant_contact", {}).get("company_name"),
                    "registrant_email": whois_data.get("registrant_contact", {}).get("email_address"),
                    "registrant_country": whois_data.get("registrant_contact", {}).get("country_name"),
                    "admin_name": whois_data.get("administrative_contact", {}).get("full_name"),
                    "admin_org": whois_data.get("administrative_contact", {}).get("company_name"),
                    "admin_email": whois_data.get("administrative_contact", {}).get("email_address"),
                    "tech_name": whois_data.get("technical_contact", {}).get("full_name"),
                    "tech_org": whois_data.get("technical_contact", {}).get("company_name"),
                    "creation_date": whois_data.get("create_date"),
                    "expiry_date": whois_data.get("expiry_date"),
                    "updated_date": whois_data.get("update_date"),
                    "nameservers": whois_data.get("name_servers", []),
                    "status": whois_data.get("domain_status", []),
                }
                
                # Check for privacy protection
                privacy_indicators = [
                    "privacy", "proxy", "whoisguard", "domains by proxy", 
                    "contact privacy", "redacted", "withheld", "private",
                    "whoisproxy", "domain protection"
                ]
                
                combined_registrant = " ".join([
                    str(whois_summary.get("registrant_name") or ""),
                    str(whois_summary.get("registrant_org") or ""),
                    str(whois_summary.get("registrant_email") or ""),
                ]).lower()
                
                is_private = any(p in combined_registrant for p in privacy_indicators)
                whois_summary["is_private"] = is_private
                
                if is_private:
                    privacy_protected += 1
                
                # Check ownership match if expected_registrant provided
                ownership_status = "unknown"
                if expected_registrant and not is_private:
                    expected_lower = expected_registrant.lower()
                    if expected_lower in combined_registrant:
                        ownership_status = "confirmed"
                        ownership_matches += 1
                    else:
                        ownership_status = "mismatch"
                        ownership_mismatches += 1
                elif is_private:
                    ownership_status = "private"
                
                whois_summary["ownership_status"] = ownership_status
                
                # Update asset metadata
                metadata = domain_asset.metadata_ or {}
                metadata["whois"] = whois_summary
                metadata["whois_raw"] = whois_data  # Store full response
                metadata["whois_fetched_at"] = datetime.utcnow().isoformat()
                domain_asset.metadata_ = metadata
                
                enriched_count += 1
                results.append({
                    "domain": domain_asset.value,
                    "asset_id": domain_asset.id,
                    "status": "enriched",
                    "registrant_org": whois_summary.get("registrant_org"),
                    "registrant_name": whois_summary.get("registrant_name"),
                    "registrar": whois_summary.get("registrar"),
                    "is_private": is_private,
                    "ownership_status": ownership_status,
                    "expiry_date": whois_summary.get("expiry_date"),
                })
            else:
                error_reason = whois_data.get("status_reason", "No WHOIS data returned") if whois_data else "WHOIS lookup failed"
                results.append({
                    "domain": domain_asset.value,
                    "asset_id": domain_asset.id,
                    "status": "error",
                    "error": error_reason
                })
                
        except Exception as e:
            results.append({
                "domain": domain_asset.value,
                "asset_id": domain_asset.id,
                "status": "error",
                "error": str(e)
            })
    
    db.commit()
    
    return {
        "message": "WHOIS enrichment complete",
        "total_domains": len(domains),
        "enriched": enriched_count,
        "ownership_matches": ownership_matches,
        "ownership_mismatches": ownership_mismatches,
        "privacy_protected": privacy_protected,
        "results": results
    }


@router.get("/whois/{asset_id}")
async def get_asset_whois(
    asset_id: int,
    refresh: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Get WHOIS data for a specific domain asset.
    
    If refresh=True and Whoxy API is configured, fetches fresh data.
    """
    from app.services.whoxy_service import WhoxyService
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    if asset.asset_type != AssetType.DOMAIN:
        raise HTTPException(status_code=400, detail="WHOIS data is only available for domain assets")
    
    if refresh:
        # Get Whoxy API key
        whoxy_config = db.query(APIConfig).filter(
            APIConfig.organization_id == asset.organization_id,
            APIConfig.service_name == "whoxy"
        ).first()
        
        api_key = whoxy_config.get_api_key() if whoxy_config else None
        if api_key:
            whoxy_service = WhoxyService(api_key)
            whois_data = await whoxy_service.whois_lookup(asset.value)
            
            if whois_data and whois_data.get('status') == 1:
                # Extract key WHOIS fields
                whois_summary = {
                    "domain_name": whois_data.get("domain_name", asset.value),
                    "registrar": whois_data.get("domain_registrar", {}).get("registrar_name"),
                    "registrant_name": whois_data.get("registrant_contact", {}).get("full_name"),
                    "registrant_org": whois_data.get("registrant_contact", {}).get("company_name"),
                    "registrant_email": whois_data.get("registrant_contact", {}).get("email_address"),
                    "registrant_country": whois_data.get("registrant_contact", {}).get("country_name"),
                    "admin_name": whois_data.get("administrative_contact", {}).get("full_name"),
                    "admin_org": whois_data.get("administrative_contact", {}).get("company_name"),
                    "admin_email": whois_data.get("administrative_contact", {}).get("email_address"),
                    "tech_name": whois_data.get("technical_contact", {}).get("full_name"),
                    "tech_org": whois_data.get("technical_contact", {}).get("company_name"),
                    "creation_date": whois_data.get("create_date"),
                    "expiry_date": whois_data.get("expiry_date"),
                    "updated_date": whois_data.get("update_date"),
                    "nameservers": whois_data.get("name_servers", []),
                    "status": whois_data.get("domain_status", []),
                }
                
                # Check for privacy
                privacy_indicators = [
                    "privacy", "proxy", "whoisguard", "domains by proxy",
                    "contact privacy", "redacted", "withheld", "private",
                    "whoisproxy", "domain protection"
                ]
                
                combined = " ".join([
                    str(whois_summary.get("registrant_name") or ""),
                    str(whois_summary.get("registrant_org") or ""),
                    str(whois_summary.get("registrant_email") or ""),
                ]).lower()
                
                whois_summary["is_private"] = any(p in combined for p in privacy_indicators)
                
                metadata = asset.metadata_ or {}
                metadata["whois"] = whois_summary
                metadata["whois_raw"] = whois_data
                metadata["whois_fetched_at"] = datetime.utcnow().isoformat()
                asset.metadata_ = metadata
                
                db.commit()
                db.refresh(asset)
    
    metadata = asset.metadata_ or {}
    
    return {
        "asset_id": asset.id,
        "domain": asset.value,
        "whois": metadata.get("whois", {}),
        "whois_fetched_at": metadata.get("whois_fetched_at"),
    }









