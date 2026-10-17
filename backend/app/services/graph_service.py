"""
Neo4j Graph Database Service

Stores the canonical chain:
  Domain → Subdomain → IP → Port → Service
  Asset → Technology; Asset → Vulnerability → CVE / CWE

Also keeps Asset nodes for API compatibility (get_asset_relationships, get_attack_paths).
"""

import hashlib
import ipaddress
import logging
import re
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from urllib.parse import urlparse

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.asset import Asset, AssetStatus, AssetType
from app.models.vulnerability import Vulnerability
from app.models.port_service import PortService
from app.models.technology import Technology
from app.services.graph_identity import canonical_script_url, script_key
from app.services.graph_ip_identity import graph_ip_identity

logger = logging.getLogger(__name__)

# These nodes are shared references. A prior sync may have left another
# organization's observation properties on them, so never return those fields.
_SHARED_REFERENCE_FIELDS = {
    "IP": {"address", "type", "scope_id"},
    "ASN": {"asn_number"},
    "Certificate": {"fingerprint", "common_name", "issuer", "expiry", "san_count"},
    "DiscoverySource": {"name", "display_name"},
    "HostingProvider": {"name"},
    "Service": {"name"},
    "Technology": {"name", "slug", "category", "categories", "website"},
}


def graph_node_properties(node) -> Dict[str, Any]:
    """Expose only invariant properties of shared reference nodes."""
    properties = dict(node)
    for label in getattr(node, "labels", ()):
        allowed = _SHARED_REFERENCE_FIELDS.get(label)
        if allowed is not None:
            return {key: value for key, value in properties.items() if key in allowed}
    return properties


class GraphService:
    """
    Service for managing the Neo4j graph database.

    Canonical chain (see docs/GRAPH_SCHEMA.md):
    - Domain -[:HAS_SUBDOMAIN]-> Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port
      -[:RUNS_SERVICE]-> Service; Asset -[:USES_TECHNOLOGY]-> Technology
    - Asset -[:HAS_VULNERABILITY]-> Vulnerability -[:REFERENCES]-> CVE
      and Vulnerability -[:MAPS_TO]-> MITRE (CWE)

    Asset nodes and Asset-based edges are kept for API compatibility.
    """
    
    def __init__(self):
        self.driver = None
        self._connected = False
    
    def connect(self) -> bool:
        """Connect to Neo4j database."""
        if self._connected and self.driver:
            return True
        if not settings.NEO4J_URI:
            return False
        try:
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            # Verify connection
            self.driver.verify_connectivity()
            self._connected = True
            logger.info(f"Connected to Neo4j at {settings.NEO4J_URI}")
            return True
        except ServiceUnavailable as e:
            logger.warning(f"Neo4j not available: {e}")
            self._connected = False
            if self.driver:
                self.driver.close()
                self.driver = None
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self._connected = False
            if self.driver:
                self.driver.close()
                self.driver = None
            return False
    
    def close(self):
        """Close the Neo4j connection."""
        if self.driver:
            self.driver.close()
            self._connected = False
    
    @contextmanager
    def session(self):
        """Get a Neo4j session context manager."""
        if not self._connected:
            self.connect()
        
        if not self._connected or not self.driver:
            raise RuntimeError("Neo4j not connected")
        
        session = self.driver.session()
        try:
            yield session
        finally:
            session.close()
    
    def initialize_schema(self):
        """Create indexes and constraints for the graph."""
        if not self._connected:
            self.connect()
        
        if not self._connected:
            logger.warning("Cannot initialize schema - Neo4j not connected")
            return
        
        with self.session() as session:
            # Create uniqueness constraints for all node types
            constraints = [
                # Canonical chain: Domain, Subdomain (composite for multi-tenant)
                "CREATE CONSTRAINT domain_org_name IF NOT EXISTS FOR (d:Domain) REQUIRE (d.organization_id, d.name) IS UNIQUE",
                "CREATE CONSTRAINT subdomain_org_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE (s.organization_id, s.name) IS UNIQUE",
                # Core asset nodes
                "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE",
                "CREATE CONSTRAINT ip_key IF NOT EXISTS FOR (i:IP) REQUIRE i.ip_key IS UNIQUE",
                "CREATE CONSTRAINT cloud_subscription_key IF NOT EXISTS FOR (c:CloudSubscription) REQUIRE c.key IS UNIQUE",
                "CREATE CONSTRAINT cloud_region_key IF NOT EXISTS FOR (c:CloudRegion) REQUIRE c.key IS UNIQUE",
                "CREATE CONSTRAINT zpa_source_key IF NOT EXISTS FOR (s:ZpaSource) REQUIRE s.key IS UNIQUE",
                "CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.port_id IS UNIQUE",
                "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
                "CREATE CONSTRAINT service_observation_id IF NOT EXISTS FOR (s:ServiceObservation) REQUIRE s.port_id IS UNIQUE",
                "CREATE CONSTRAINT tech_name IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE",
                "CREATE CONSTRAINT js_resource_id IF NOT EXISTS FOR (j:JSResource) REQUIRE j.script_id IS UNIQUE",
                # Vulnerability nodes
                "CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE",
                "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
                "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (w:CWE) REQUIRE w.cwe_id IS UNIQUE",
                # Web application layer
                "CREATE CONSTRAINT baseurl_id IF NOT EXISTS FOR (b:BaseURL) REQUIRE b.baseurl_id IS UNIQUE",
                "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE",
                "CREATE CONSTRAINT parameter_id IF NOT EXISTS FOR (p:Parameter) REQUIRE p.parameter_id IS UNIQUE",
                # Discovery provenance layer
                "CREATE CONSTRAINT discovery_source_name IF NOT EXISTS FOR (ds:DiscoverySource) REQUIRE ds.name IS UNIQUE",
                "CREATE CONSTRAINT asn_number IF NOT EXISTS FOR (a:ASN) REQUIRE a.asn_number IS UNIQUE",
                "CREATE CONSTRAINT hosting_provider_name IF NOT EXISTS FOR (h:HostingProvider) REQUIRE h.name IS UNIQUE",
                "CREATE CONSTRAINT cert_fingerprint IF NOT EXISTS FOR (c:Certificate) REQUIRE c.fingerprint IS UNIQUE",
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logger.debug(f"Constraint may already exist: {e}")
            
            # Create indexes for common queries
            indexes = [
                # Domain / Subdomain (canonical chain)
                "CREATE INDEX domain_org IF NOT EXISTS FOR (d:Domain) ON (d.organization_id)",
                "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
                "CREATE INDEX subdomain_org IF NOT EXISTS FOR (s:Subdomain) ON (s.organization_id)",
                "CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)",
                # Asset indexes
                "CREATE INDEX asset_org IF NOT EXISTS FOR (a:Asset) ON (a.organization_id)",
                "CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.asset_type)",
                "CREATE INDEX asset_value IF NOT EXISTS FOR (a:Asset) ON (a.value)",
                "CREATE INDEX asset_root_domain IF NOT EXISTS FOR (a:Asset) ON (a.root_domain)",
                "CREATE INDEX asset_risk IF NOT EXISTS FOR (a:Asset) ON (a.ars_score)",
                "CREATE INDEX asset_live IF NOT EXISTS FOR (a:Asset) ON (a.is_live)",
                # Port indexes
                "CREATE INDEX port_number IF NOT EXISTS FOR (p:Port) ON (p.port)",
                "CREATE INDEX port_risky IF NOT EXISTS FOR (p:Port) ON (p.is_risky)",
                # Vulnerability indexes
                "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                "CREATE INDEX vuln_status IF NOT EXISTS FOR (v:Vulnerability) ON (v.status)",
                "CREATE INDEX vuln_org IF NOT EXISTS FOR (v:Vulnerability) ON (v.organization_id)",
                # Technology indexes
                "CREATE INDEX tech_categories IF NOT EXISTS FOR (t:Technology) ON (t.categories)",
                # Web application layer
                "CREATE INDEX baseurl_org IF NOT EXISTS FOR (b:BaseURL) ON (b.organization_id)",
                "CREATE INDEX endpoint_org IF NOT EXISTS FOR (e:Endpoint) ON (e.organization_id)",
                "CREATE TEXT INDEX endpoint_path_text IF NOT EXISTS FOR (e:Endpoint) ON (e.path)",
                "CREATE INDEX js_resource_org IF NOT EXISTS FOR (j:JSResource) ON (j.organization_id)",
                "CREATE INDEX js_resource_url IF NOT EXISTS FOR (j:JSResource) ON (j.url)",
                "CREATE TEXT INDEX js_resource_url_text IF NOT EXISTS FOR (j:JSResource) ON (j.url)",
                "CREATE INDEX parameter_org IF NOT EXISTS FOR (p:Parameter) ON (p.organization_id)",
                # Discovery provenance layer
                "CREATE INDEX hosting_provider_name_idx IF NOT EXISTS FOR (h:HostingProvider) ON (h.name)",
                "CREATE FULLTEXT INDEX graph_knowledge_text IF NOT EXISTS FOR (n:JSResource|Endpoint|SourceFile|Vulnerability) ON EACH [n.url, n.path, n.title]",
            ]
            
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.debug(f"Index may already exist: {e}")
        
        logger.info("Neo4j schema initialized with full relationship chain support")
    
    def sync_organization(self, organization_id: int, asset_values: list[str] | None = None):
        """
        Sync all assets from an organization to the graph.
        
        This creates nodes for:
        - Assets (Domain, Subdomain, IP, URL)
        - Vulnerabilities
        - Ports
        - Technologies
        
        And relationships:
        - DISCOVERED_FROM (asset to parent asset)
        - RESOLVES_TO (domain/subdomain to IP)
        - HAS_VULNERABILITY
        - HAS_PORT
        - USES_TECHNOLOGY
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            logger.warning("Cannot sync - Neo4j not connected")
            return {"synced": 0, "error": "Neo4j not connected"}

        if organization_id is None:
            logger.warning("Cannot sync - no organization specified")
            return {"synced": 0, "error": "Select an organization to sync. Sync runs for one organization at a time."}
        
        db = SessionLocal()
        try:
            # Get all assets with related data so sync has ports, tech, vulns, endpoints
            query = db.query(Asset).options(
                selectinload(Asset.port_services),
                selectinload(Asset.technologies),
                selectinload(Asset.vulnerabilities),
            ).filter(
                Asset.organization_id == organization_id
            )
            if asset_values is not None:
                query = query.filter(Asset.value.in_(asset_values))
            assets = query.all()
            
            synced = 0
            
            with self.session() as session:
                for asset in assets:
                    session.execute_write(
                        lambda tx, item=asset: self._sync_asset(tx, item, organization_id)
                    )
                    synced += 1
                # New or updated subdomains can share an IP even in a partial sync.
                if synced:
                    session.execute_write(
                        lambda tx: self._create_same_ip_links(tx, organization_id)
                    )
            
            logger.info(f"Synced {synced} assets for organization {organization_id}")
            return {"synced": synced, "error": None}
        
        except Exception as e:
            logger.error(f"Sync error: {e}")
            return {"synced": 0, "error": str(e)}
        finally:
            db.close()
    
    def _sync_asset(self, session, asset: Asset, org_id: int):
        """
        Sync a single asset and all its relationships to the graph.
        
        Creates the full relationship chain:
        Domain → Subdomain → IP → Port → Service, with asset-scoped technology
        and vulnerability observations linked only when supported by evidence.
        """
        # Asset is an inventory identity. Domain, Subdomain and IP below are
        # canonical topology identities with their own uniqueness constraints.
        # Remove legacy subtype labels before updating a previously synced
        # Asset so a duplicate inventory row cannot violate those constraints.
        asset_is_active = getattr(asset, "is_active", None)
        if asset_is_active is None:
            asset_is_active = getattr(asset, "status", None) not in (
                AssetStatus.INACTIVE, AssetStatus.ARCHIVED
            )
        session.run("""
            MERGE (a:Asset {asset_id: $id})
            REMOVE a:Domain:Subdomain:IP:URL:Certificate
            SET a.value = $value,
                a.name = $name,
                a.asset_type = $type,
                a.organization_id = $org_id,
                a.root_domain = $root_domain,
                a.is_active = $is_active,
                a.is_public = $is_public,
                a.is_live = $is_live,
                a.first_seen = $first_seen,
                a.ars_score = $ars_score,
                a.acs_score = $acs_score,
                a.risk_score = $risk_score,
                a.criticality = $criticality,
                a.device_class = $device_class,
                a.device_subclass = $device_subclass,
                a.operating_system = $operating_system,
                a.hosting_type = $hosting_type,
                a.hosting_provider = $hosting_provider,
                a.country = $country,
                a.region = $region,
                a.in_scope = $in_scope,
                a.http_status = $http_status,
                a.has_login_portal = $has_login_portal
        """, {
            "id": asset.id,
            "value": asset.value,
            "name": asset.name,
            "type": asset.asset_type.value if asset.asset_type else None,
            "org_id": org_id,
            "root_domain": asset.root_domain,
            "is_active": asset_is_active,
            "is_public": bool(getattr(asset, 'is_public', False)),
            "is_live": getattr(asset, 'is_live', False),
            "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
            "ars_score": getattr(asset, 'ars_score', None),
            "acs_score": getattr(asset, 'acs_score', None),
            "risk_score": getattr(asset, 'risk_score', 0),
            "criticality": getattr(asset, 'criticality', 'medium'),
            "device_class": getattr(asset, 'device_class', None),
            "device_subclass": getattr(asset, 'device_subclass', None),
            "operating_system": getattr(asset, 'operating_system', None),
            "hosting_type": getattr(asset, 'hosting_type', None),
            "hosting_provider": getattr(asset, 'hosting_provider', None),
            "country": getattr(asset, 'country', None),
            "region": getattr(asset, 'region', None),
            "in_scope": getattr(asset, 'in_scope', True),
            "http_status": getattr(asset, 'http_status', None),
            "has_login_portal": getattr(asset, 'has_login_portal', False),
        })
        
        # ===== 1. CANONICAL CHAIN: Domain → Subdomain =====
        root_domain = getattr(asset, 'root_domain', None) or (
            asset.value if asset.asset_type == AssetType.DOMAIN else None
        )
        if asset.asset_type == AssetType.SUBDOMAIN and not root_domain:
            root_domain = asset.value  # use self as root if not set
        subdomain_name = (
            asset.value if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            else (getattr(asset, 'root_domain', None) or asset.value)
        )
        if root_domain and subdomain_name:
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                MERGE (d:Domain {organization_id: $org_id, name: $root_domain})
                SET d.discovered_at = coalesce(d.discovered_at, datetime($first_seen))
                MERGE (s:Subdomain {organization_id: $org_id, name: $subdomain_name})
                SET s.status = $status
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                FOREACH (_ IN CASE WHEN $asset_type = 'DOMAIN' THEN [1] ELSE [] END |
                    MERGE (a)-[:REPRESENTS]->(d))
                FOREACH (_ IN CASE WHEN $asset_type = 'SUBDOMAIN' THEN [1] ELSE [] END |
                    MERGE (a)-[:REPRESENTS]->(s))
            """, {
                "asset_id": asset.id,
                "org_id": org_id,
                "root_domain": root_domain,
                "subdomain_name": subdomain_name,
                "asset_type": asset.asset_type.value if asset.asset_type else None,
                "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                "status": (asset.status.value if asset.status else "discovered"),
            })

        # ===== 1b. PARENT RELATIONSHIP (Asset hierarchy, for compatibility) =====
        if asset.parent_id:
            session.run("""
                MATCH (child:Asset {asset_id: $child_id})
                MATCH (parent:Asset {asset_id: $parent_id})
                MERGE (parent)-[:HAS_CHILD]->(child)
                MERGE (child)-[:BELONGS_TO]->(parent)
            """, {
                "child_id": asset.id,
                "parent_id": asset.parent_id,
            })

        # ===== 2. IP RESOLUTION: Subdomain RESOLVES_TO IP, Asset RESOLVES_TO IP =====
        ip_addresses = getattr(asset, 'ip_addresses', None) or []
        if not ip_addresses and getattr(asset, 'ip_address', None):
            ip_addresses = [asset.ip_address]
        # IP_ADDRESS assets often store the IP only in `value`
        if (
            not ip_addresses
            and asset.asset_type == AssetType.IP_ADDRESS
            and isinstance(asset.value, str)
            and asset.value.strip()
        ):
            ip_addresses = [asset.value.strip()]
        # Reprojection may change an address's network scope. Retire links
        # created by this asset before writing its current observations.
        session.run("""
            MATCH (:Asset {asset_id: $asset_id})-[r:RESOLVES_TO]->(:IP)
            DELETE r
        """, {"asset_id": asset.id})
        session.run("""
            MATCH (:Subdomain {organization_id: $org_id})
                  -[r:RESOLVES_TO {source_asset_id: $asset_id}]->(:IP)
            DELETE r
        """, {"asset_id": asset.id, "org_id": org_id})
        for ip in ip_addresses:
            if ip:
                try:
                    identity = graph_ip_identity(ip, org_id, asset)
                except ValueError:
                    logger.warning("Skipping invalid IP %r on asset %s", ip, asset.id)
                    continue
                is_cdn = bool(getattr(asset, 'hosting_type', None) in ("cdn", "cloud") or getattr(asset, 'hosting_provider', None))
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})
                    MERGE (ip:IP {ip_key: $ip_key})
                    SET ip.address = $ip_address,
                        ip.scope_id = $scope_id,
                        ip.type = $ip_type
                    REMOVE ip.organization_id, ip.is_cdn, ip.is_live, ip.is_internet_facing
                    MERGE (a)-[resolution:RESOLVES_TO]->(ip)
                    SET resolution.organization_id = $org_id,
                        resolution.is_cdn = $is_cdn,
                        resolution.is_live = $is_live,
                        resolution.is_internet_facing = $is_internet_facing
                """, {
                    "asset_id": asset.id,
                    "ip_key": identity.key,
                    "ip_address": identity.address,
                    "scope_id": identity.scope_id,
                    "org_id": org_id,
                    "ip_type": identity.ip_type,
                    "is_cdn": is_cdn,
                    "is_live": bool(getattr(asset, 'is_live', False)),
                    "is_internet_facing": bool(getattr(asset, 'is_public', True)),
                })
                if root_domain and subdomain_name:
                    session.run("""
                        MERGE (s:Subdomain {organization_id: $org_id, name: $subdomain_name})
                        MATCH (ip:IP {ip_key: $ip_key})
                        MERGE (s)-[resolution:RESOLVES_TO {source_asset_id: $asset_id}]->(ip)
                        SET resolution.organization_id = $org_id
                    """, {
                        "org_id": org_id,
                        "asset_id": asset.id,
                        "subdomain_name": subdomain_name,
                        "ip_key": identity.key,
                    })
        
        # ===== 3. PORT/SERVICE: IP HAS_PORT Port, Port RUNS_SERVICE Service =====
        port_services = getattr(asset, 'port_services', None) or []
        for ps in port_services:
            port_num = ps.port
            protocol = ps.protocol.value if ps.protocol else 'tcp'
            state = ps.state.value if ps.state else 'open'
            service_name = ps.service_name or 'unknown'
            ip_for_port = ps.scanned_ip or (ip_addresses[0] if ip_addresses else None)

            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (p:Port {port_id: $port_id})
                SET p.port = $port,
                    p.protocol = $protocol,
                    p.state = $state,
                    p.is_risky = $is_risky,
                    p.scanned_ip = $scanned_ip,
                    p.organization_id = $org_id
                MERGE (a)-[:HAS_PORT]->(p)
            """, {
                "asset_id": asset.id,
                "port_id": ps.id,
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "is_risky": ps.is_risky,
                "scanned_ip": ps.scanned_ip,
                "org_id": org_id,
            })

            if ip_for_port:
                try:
                    port_ip = graph_ip_identity(ip_for_port, org_id, asset)
                    session.run("""
                        MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                              -[:RESOLVES_TO]->(ip:IP {ip_key: $ip_key})
                        MATCH (p:Port {port_id: $port_id})
                        MERGE (ip)-[:HAS_PORT]->(p)
                    """, {"asset_id": asset.id, "org_id": org_id,
                          "ip_key": port_ip.key, "port_id": ps.id})
                except ValueError:
                    logger.warning("Skipping invalid scanned IP %r on port %s", ip_for_port, ps.id)

            session.run("""
                MATCH (p:Port {port_id: $port_id})
                MERGE (s:Service {name: $service_name})
                REMOVE s.version, s.banner, s.product, s.cpe
                MERGE (o:ServiceObservation {port_id: $port_id})
                SET o.organization_id = $org_id,
                    o.version = $version,
                    o.banner = $banner,
                    o.product = $product,
                    o.cpe = $cpe
                MERGE (p)-[:HAS_SERVICE_OBSERVATION]->(o)
                MERGE (o)-[:IDENTIFIES]->(s)
                MERGE (p)-[:RUNS_SERVICE]->(s)
            """, {
                "port_id": ps.id,
                "org_id": org_id,
                "service_name": service_name,
                "version": ps.service_version,
                "banner": ps.banner,
                "product": ps.service_product,
                "cpe": ps.cpe,
            })
        
        # ===== 4. TECHNOLOGY: Asset USES_TECHNOLOGY, Service USES_TECHNOLOGY =====
        technologies = getattr(asset, 'technologies', None) or []
        for tech in technologies:
            categories = tech.categories if tech.categories else []
            category_str = ', '.join(categories) if categories else None
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (t:Technology {name: $name})
                SET t.slug = $slug,
                    t.category = $category,
                    t.categories = $categories,
                    t.website = $website
                REMOVE t.version, t.cpe, t.organization_id
                MERGE (a)-[observed:USES_TECHNOLOGY]->(t)
                SET observed.organization_id = $org_id,
                    observed.version = $version,
                    observed.cpe = $cpe
            """, {
                "asset_id": asset.id,
                "name": tech.name,
                "org_id": org_id,
                "slug": tech.slug,
                "version": getattr(tech, 'version', None),
                "category": categories[0] if categories else None,
                "categories": category_str,
                "cpe": tech.cpe,
                "website": tech.website,
            })
        
        # ===== 5. VULNERABILITY: Technology HAS_VULNERABILITY, REFERENCES CVE, MAPS_TO MITRE =====
        vulnerabilities = getattr(asset, 'vulnerabilities', None) or []
        for vuln in vulnerabilities:
            desc = (vuln.description or getattr(vuln, 'evidence', None) or vuln.title or "")[:2000]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (v:Vulnerability {vuln_id: $vuln_id})
                SET v.id = $vuln_id,
                    v.title = $title,
                    v.severity = $severity,
                    v.description = $description,
                    v.cvss_score = $cvss,
                    v.status = $status,
                    v.template_id = $template_id,
                    v.detected_by = $detected_by,
                    v.organization_id = $org_id
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
            """, {
                "asset_id": asset.id,
                "vuln_id": vuln.id,
                "title": vuln.title,
                "severity": vuln.severity.value if vuln.severity else None,
                "description": desc,
                "cvss": vuln.cvss_score,
                "status": vuln.status.value if vuln.status else None,
                "template_id": vuln.template_id,
                "detected_by": vuln.detected_by,
                "org_id": org_id,
            })
            if vuln.cve_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cve:CVE {cve_id: $cve_id})
                    SET cve.cvss_score = $cvss,
                        cve.cwe_id = $cwe_id
                    MERGE (v)-[:REFERENCES]->(cve)
                """, {
                    "vuln_id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "cvss": vuln.cvss_score,
                    "cwe_id": vuln.cwe_id,
                })
            if vuln.cwe_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cwe:CWE {cwe_id: $cwe_id})
                    MERGE (v)-[:MAPS_TO]->(cwe)
                """, {"vuln_id": vuln.id, "cwe_id": vuln.cwe_id})
                if vuln.cve_id:
                    session.run("""
                        MATCH (cve:CVE {cve_id: $cve_id})
                        MATCH (cwe:CWE {cwe_id: $cwe_id})
                        MERGE (cve)-[:EXPLOITS_WEAKNESS]->(cwe)
                    """, {"cve_id": vuln.cve_id, "cwe_id": vuln.cwe_id})
            
            # ===== 7b. FOUND_AT: link vulnerability to Endpoint when url/path known (web layer) =====
            path_for_endpoint = None
            meta = getattr(vuln, 'metadata_', None) or {}
            if isinstance(meta, dict):
                if meta.get('path'):
                    path_for_endpoint = (meta.get('path') or '').strip()
                elif meta.get('url'):
                    path_for_endpoint = urlparse(meta['url']).path or ''
            if not path_for_endpoint and getattr(vuln, 'evidence', None):
                try:
                    path_for_endpoint = urlparse(str(vuln.evidence)).path or ''
                except Exception:
                    pass
            if path_for_endpoint:
                path_for_endpoint = path_for_endpoint.strip()[:2000]
                endpoint_id = "ep_" + hashlib.sha256(f"{org_id}:{asset.id}:{path_for_endpoint}".encode()).hexdigest()[:20]
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MATCH (a:Asset {asset_id: $asset_id})-[:HAS_ENDPOINT]->(e:Endpoint {endpoint_id: $endpoint_id})
                    MERGE (v)-[:FOUND_AT]->(e)
                """, {"vuln_id": vuln.id, "asset_id": asset.id, "endpoint_id": endpoint_id})
        
        # ===== 8. BASEURL (live HTTP endpoint) =====
        live_url = getattr(asset, 'live_url', None) or (asset.value if getattr(asset, 'asset_type', None) and str(getattr(asset.asset_type, 'value', '')) == 'URL' else None)
        if live_url:
            baseurl_id = f"url_{org_id}_{asset.id}"
            http_headers = getattr(asset, 'http_headers', None) or {}
            server = http_headers.get('Server') or http_headers.get('server') if isinstance(http_headers, dict) else None
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (b:BaseURL {baseurl_id: $baseurl_id})
                SET b.url = $url,
                    b.status_code = $status_code,
                    b.title = $title,
                    b.server = $server,
                    b.organization_id = $org_id
                MERGE (a)-[:SERVES_URL]->(b)
            """, {
                "asset_id": asset.id,
                "baseurl_id": baseurl_id,
                "url": live_url,
                "status_code": getattr(asset, 'http_status', None),
                "title": getattr(asset, 'http_title', None),
                "server": server,
                "org_id": org_id,
            })
            # Link Service (80/443) to BaseURL when present
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})-[:HAS_PORT]->(p:Port)
                WHERE p.port IN [80, 443]
                WITH p LIMIT 1
                MATCH (p)-[:RUNS_SERVICE]->(s:Service)
                MATCH (b:BaseURL {baseurl_id: $baseurl_id})
                MERGE (s)-[:SERVES_URL]->(b)
            """, {"asset_id": asset.id, "baseurl_id": baseurl_id})
        
        # ===== 9. ENDPOINTS (discovered paths from Katana, ParamSpider, Wayback) =====
        endpoints = getattr(asset, 'endpoints', None) or []
        for path in endpoints[:500]:  # Cap for sync performance
            if not path or not isinstance(path, str):
                continue
            path_strip = path.strip()
            if not path_strip:
                continue
            endpoint_id = "ep_" + hashlib.sha256(f"{org_id}:{asset.id}:{path_strip}".encode()).hexdigest()[:20]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (e:Endpoint {endpoint_id: $endpoint_id})
                SET e.path = $path,
                    e.source = $source,
                    e.organization_id = $org_id
                MERGE (a)-[:HAS_ENDPOINT]->(e)
            """, {
                "asset_id": asset.id,
                "endpoint_id": endpoint_id,
                "path": path_strip[:2000],
                "source": "aggregated",
                "org_id": org_id,
            })
        
        # ===== 10. PARAMETERS (discovered params from Katana, ParamSpider) =====
        parameters = getattr(asset, 'parameters', None) or []
        for param_name in parameters[:300]:
            if param_name is None:
                continue
            name_str = str(param_name).strip()
            if not name_str:
                continue
            parameter_id = "pm_" + hashlib.sha256(f"{org_id}:{asset.id}:{name_str}".encode()).hexdigest()[:20]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (p:Parameter {parameter_id: $parameter_id})
                SET p.name = $name,
                    p.organization_id = $org_id
                MERGE (a)-[:HAS_PARAMETER]->(p)
            """, {
                "asset_id": asset.id,
                "parameter_id": parameter_id,
                "name": name_str[:500],
                "org_id": org_id,
            })

        self._sync_js_resources(session, asset, org_id)

        # ===== 11. DISCOVERY PROVENANCE: DiscoverySource nodes + DISCOVERED_VIA edges =====
        # Sync the discovery_chain JSON as a graph so we can visualize HOW each asset was found.
        # Each step in the chain becomes a DiscoverySource node linked by DISCOVERED_VIA.
        discovery_chain = getattr(asset, 'discovery_chain', None) or []
        if not discovery_chain and getattr(asset, 'discovery_source', None):
            # Build a minimal single-step chain from the flat field
            discovery_chain = [{"step": 1, "source": asset.discovery_source}]
        for step in discovery_chain[:20]:
            if not isinstance(step, dict):
                continue
            source_name = str(step.get('source') or '').strip()
            if not source_name:
                continue
            step_num = step.get('step', 1)
            found_value = str(step.get('found') or step.get('value') or '').strip()[:500]
            query_value = str(step.get('query') or '').strip()[:500]
            try:
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})
                    MERGE (ds:DiscoverySource {name: $source_name})
                    SET ds.display_name = $display_name
                    REMOVE ds.organization_id
                    MERGE (a)-[r:DISCOVERED_VIA]->(ds)
                    SET r.organization_id = $org_id,
                        r.step = $step,
                        r.found_value = $found_value,
                        r.query = $query_value,
                        r.confidence = $confidence
                """, {
                    "asset_id": asset.id,
                    "source_name": source_name,
                    "org_id": org_id,
                    "display_name": source_name.replace('_', ' ').title(),
                    "step": step_num,
                    "found_value": found_value,
                    "query_value": query_value,
                    "confidence": getattr(asset, 'association_confidence', 100),
                })
            except Exception as e:
                logger.debug(f"Discovery chain sync error for asset {asset.id}: {e}")

        # ===== 12. HOSTING PROVIDER: HostingProvider node + HOSTED_BY edge =====
        hosting_provider = getattr(asset, 'hosting_provider', None)
        if hosting_provider:
            try:
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})
                    MERGE (h:HostingProvider {name: $name})
                    REMOVE h.hosting_type, h.organization_id
                    MERGE (a)-[hosted:HOSTED_BY]->(h)
                    SET hosted.organization_id = $org_id,
                        hosted.hosting_type = $hosting_type
                """, {
                    "asset_id": asset.id,
                    "name": hosting_provider.lower(),
                    "org_id": org_id,
                    "hosting_type": getattr(asset, 'hosting_type', 'unknown'),
                })
                # Also link IPs to the hosting provider
                for ip in ip_addresses:
                    if ip:
                        try:
                            ip_key = graph_ip_identity(ip, org_id, asset).key
                            session.run("""
                                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                                      -[:RESOLVES_TO]->(ip:IP {ip_key: $ip_key})
                                MATCH (h:HostingProvider {name: $name})
                                MERGE (ip)-[:HOSTED_BY {organization_id: $org_id}]->(h)
                            """, {"asset_id": asset.id, "ip_key": ip_key,
                                  "name": hosting_provider.lower(), "org_id": org_id})
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"HostingProvider sync error for asset {asset.id}: {e}")

        # ===== 13. ASN: ASN node + BELONGS_TO edge from IP nodes =====
        asn_value = getattr(asset, 'asn', None)
        isp_value = getattr(asset, 'isp', None)
        if asn_value and ip_addresses:
            try:
                session.run("""
                    MERGE (asn:ASN {asn_number: $asn_number})
                    REMOVE asn.organization_id, asn.isp, asn.country
                """, {
                    "asn_number": str(asn_value),
                    "org_id": org_id,
                    "isp": isp_value,
                    "country": getattr(asset, 'country', None),
                })
                for ip in ip_addresses:
                    if ip:
                        try:
                            ip_key = graph_ip_identity(ip, org_id, asset).key
                            session.run("""
                                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                                      -[:RESOLVES_TO]->(ip:IP {ip_key: $ip_key})
                                MATCH (asn:ASN {asn_number: $asn_number})
                                MERGE (ip)-[association:BELONGS_TO_ASN {organization_id: $org_id}]->(asn)
                                SET association.isp = $isp,
                                    association.country = $country
                            """, {"asset_id": asset.id, "ip_key": ip_key,
                                  "asn_number": str(asn_value),
                                  "org_id": org_id, "isp": isp_value,
                                  "country": getattr(asset, 'country', None)})
                        except Exception:
                            pass
            except Exception as e:
                logger.debug(f"ASN sync error for asset {asset.id}: {e}")

        # ===== 14. SSL/TLS CERTIFICATE: Certificate node + SIGNED_BY / ALSO_COVERS edges =====
        # Expand SAN (Subject Alternative Names) as discovery relationships — each SAN entry
        # is a subdomain that may not yet be in the asset inventory.
        ssl_info = getattr(asset, 'ssl_info', None) or {}
        if isinstance(ssl_info, dict) and ssl_info:
            common_name = ssl_info.get('common_name') or ssl_info.get('subject', {}).get('CN') if isinstance(ssl_info.get('subject'), dict) else ssl_info.get('common_name')
            fingerprint = ssl_info.get('fingerprint') or ssl_info.get('sha256') or ssl_info.get('sha1')
            expiry = ssl_info.get('not_after') or ssl_info.get('expiry') or ssl_info.get('valid_to')
            issuer = ssl_info.get('issuer') or ''
            if isinstance(issuer, dict):
                issuer = issuer.get('O') or issuer.get('CN') or ''
            sans = ssl_info.get('san') or ssl_info.get('subject_alt_names') or ssl_info.get('dns_names') or []
            if isinstance(sans, str):
                sans = [s.strip() for s in sans.split(',') if s.strip()]

            if fingerprint or common_name:
                cert_id = fingerprint or hashlib.sha256(f"{org_id}:{common_name}".encode()).hexdigest()[:20]
                try:
                    session.run("""
                        MATCH (a:Asset {asset_id: $asset_id})
                        MERGE (cert:Certificate {fingerprint: $cert_id})
                        SET cert.common_name = $common_name,
                            cert.issuer = $issuer,
                            cert.expiry = $expiry,
                            cert.san_count = $san_count
                        REMOVE cert.organization_id
                        MERGE (a)-[signed:SIGNED_BY]->(cert)
                        SET signed.organization_id = $org_id
                    """, {
                        "asset_id": asset.id,
                        "cert_id": cert_id,
                        "common_name": common_name,
                        "issuer": str(issuer)[:255],
                        "expiry": str(expiry)[:50] if expiry else None,
                        "org_id": org_id,
                        "san_count": len(sans),
                    })
                    # Link each SAN to the certificate as ALSO_COVERS
                    for san in sans[:100]:
                        san = san.strip().lstrip('*.').lower()
                        if not san:
                            continue
                        try:
                            session.run("""
                                MATCH (cert:Certificate {fingerprint: $cert_id})
                                MERGE (s:Subdomain {organization_id: $org_id, name: $san_name})
                                MERGE (cert)-[covers:ALSO_COVERS]->(s)
                                SET covers.organization_id = $org_id
                            """, {
                                "cert_id": cert_id,
                                "org_id": org_id,
                                "san_name": san[:255],
                            })
                        except Exception:
                            pass
                except Exception as e:
                    logger.debug(f"Certificate sync error for asset {asset.id}: {e}")

        # ===== 15. INTERNET FACING: record asset-to-IP observations =====
        # Marks which IPs are publicly reachable — the boundary for internal hop modeling.
        is_public = getattr(asset, 'is_public', True)
        is_live = getattr(asset, 'is_live', False)
        for ip in ip_addresses:
            if ip:
                try:
                    ip_key = graph_ip_identity(ip, org_id, asset).key
                    session.run("""
                        MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                              -[resolution:RESOLVES_TO]->(ip:IP {ip_key: $ip_key})
                        SET resolution.is_internet_facing = $is_internet_facing,
                            resolution.is_live = $is_live
                        REMOVE ip.organization_id, ip.is_internet_facing, ip.is_live
                    """, {
                        "asset_id": asset.id,
                        "ip_key": ip_key,
                        "is_internet_facing": is_public,
                        "is_live": is_live,
                        "org_id": org_id,
                    })
                except Exception:
                    pass

        # ===== 16. F5 REACHABILITY: VIP IP FORWARDS_TO pool-member IP =====
        self._sync_wiz_cloud_context(session, asset, org_id)
        self._sync_f5_forwards_to(session, asset, org_id, ip_addresses)

    def _sync_wiz_cloud_context(self, session, asset: Asset, org_id: int) -> None:
        """Project Wiz's asserted cloud identity and location, not reachability."""
        session.run("""
            MATCH (:Asset {asset_id: $asset_id})
                  -[r:IN_CLOUD_SUBSCRIPTION|IN_CLOUD_REGION]->()
            DELETE r
        """, {"asset_id": asset.id})
        session.run("""
            MATCH (a:Asset {asset_id: $asset_id})
            REMOVE a.wiz_resource_id, a.cloud_provider_id,
                   a.cloud_platform, a.wiz_internet_exposure
        """, {"asset_id": asset.id})
        metadata = getattr(asset, "metadata_", None) or {}
        wiz = metadata.get("wiz") if isinstance(metadata, dict) else None
        if not isinstance(wiz, dict):
            return
        platform = str(wiz.get("cloud_platform") or "").strip().lower()
        subscription = str(
            wiz.get("subscription_external_id") or wiz.get("subscription_id") or ""
        ).strip()
        region = str(wiz.get("region") or "").strip()
        session.run("""
            MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
            SET a.wiz_resource_id = $wiz_id,
                a.cloud_provider_id = $provider_id,
                a.cloud_platform = $platform,
                a.wiz_internet_exposure = $exposure
        """, {
            "asset_id": asset.id, "org_id": org_id,
            "wiz_id": wiz.get("id"), "provider_id": wiz.get("provider_unique_id"),
            "platform": platform or None,
            "exposure": ("wide" if wiz.get("has_wide_internet_exposure") else
                         "limited" if wiz.get("has_limited_internet_exposure") else "none"),
        })
        if subscription:
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                MERGE (s:CloudSubscription {key: $key})
                SET s.organization_id = $org_id, s.platform = $platform,
                    s.subscription_id = $subscription,
                    s.name = $subscription_name
                MERGE (a)-[r:IN_CLOUD_SUBSCRIPTION]->(s)
                SET r.source = 'wiz', r.organization_id = $org_id
            """, {
                "asset_id": asset.id, "org_id": org_id,
                "key": f"{org_id}|{platform}|{subscription}",
                "platform": platform, "subscription": subscription,
                "subscription_name": wiz.get("subscription_name") or subscription,
            })
        if region:
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                MERGE (r:CloudRegion {key: $key})
                SET r.organization_id = $org_id, r.platform = $platform,
                    r.name = $region
                MERGE (a)-[observed:IN_CLOUD_REGION]->(r)
                SET observed.source = 'wiz', observed.organization_id = $org_id
            """, {
                "asset_id": asset.id, "org_id": org_id,
                "key": f"{org_id}|{platform}|{region}",
                "platform": platform, "region": region,
            })

    def _sync_js_resources(self, session, asset: Asset, org_id: int) -> None:
        """Link observed JS URLs to the asset, endpoints and finding evidence."""
        value = str(getattr(asset, "value", "") or "")
        base = getattr(asset, "live_url", None) or (
            value if value.startswith(("http://", "https://")) else f"https://{value}/"
        )
        raw_urls = list(getattr(asset, "js_files", None) or [])[:1000]
        vulnerabilities = getattr(asset, "vulnerabilities", None) or []
        for vuln in vulnerabilities:
            meta = getattr(vuln, "metadata_", None) or {}
            if isinstance(meta, dict) and meta.get("source_js"):
                raw_urls.append(meta["source_js"])

        urls = {url for raw in raw_urls if (url := canonical_script_url(raw, base))}
        if not urls:
            return
        rows = [{"id": script_key(org_id, url), "url": url} for url in sorted(urls)]
        session.run("""
            MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
            UNWIND $rows AS row
            MERGE (j:JSResource {script_id: row.id})
            ON CREATE SET j.first_seen = datetime()
            SET j.organization_id = $org_id,
                j.url = row.url,
                j.last_seen = datetime(),
                j.source = 'asset.js_files'
            MERGE (a)-[:LOADS_SCRIPT]->(j)
        """, {"asset_id": asset.id, "org_id": org_id, "rows": rows})

        evidence_rows = []
        for vuln in vulnerabilities:
            meta = getattr(vuln, "metadata_", None) or {}
            if not isinstance(meta, dict):
                continue
            url = canonical_script_url(meta.get("source_js"), base)
            if url:
                evidence_rows.append({
                    "script_id": script_key(org_id, url),
                    "vuln_id": vuln.id,
                    "path": str(meta.get("url") or "")[:2000],
                    "method": str(meta.get("method") or "GET")[:16],
                })
        if evidence_rows:
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id, organization_id: $org_id})
                UNWIND $rows AS row
                MATCH (a)-[:LOADS_SCRIPT]->(j:JSResource {script_id: row.script_id})
                MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability {vuln_id: row.vuln_id})
                MERGE (v)-[:EVIDENCED_BY]->(j)
                WITH a, j, row
                MATCH (a)-[:HAS_ENDPOINT]->(e:Endpoint {path: row.path})
                MERGE (j)-[r:REFERENCES_ENDPOINT {method: row.method}]->(e)
                SET r.source = 'jsluice'
            """, {"asset_id": asset.id, "org_id": org_id, "rows": evidence_rows})

    def sync_jsluice_paths(
        self, organization_id: int, paths: list, script_hashes: dict | None = None
    ) -> int:
        """Attach every extracted path to the JS file that supplied it."""
        rows = []
        for path in paths[:1000]:
            url = canonical_script_url(getattr(path, "source_js", None))
            raw_path = getattr(path, "url", None)
            if not url or not isinstance(raw_path, str) or not raw_path.strip():
                continue
            rows.append({
                "script_id": script_key(organization_id, url),
                "path": raw_path[:500],
                "method": str(getattr(path, "method", None) or "GET")[:16],
                "call_type": str(getattr(path, "url_type", None) or "")[:100],
            })
        hash_rows = []
        for raw_url, content_hash in (script_hashes or {}).items():
            url = canonical_script_url(raw_url)
            if url and re.fullmatch(r"[0-9a-f]{64}", str(content_hash)):
                hash_rows.append({"script_id": script_key(organization_id, url),
                                  "sha256": content_hash})
        if not rows and not hash_rows:
            return 0
        with self.session() as session:
            if hash_rows:
                session.run("""
                    UNWIND $rows AS row
                    MATCH (j:JSResource {script_id: row.script_id, organization_id: $org_id})
                    SET j.content_sha256 = row.sha256, j.last_analyzed = datetime()
                """, {"org_id": organization_id, "rows": hash_rows})
            if rows:
                session.run("""
                    UNWIND $rows AS row
                    MATCH (j:JSResource {script_id: row.script_id, organization_id: $org_id})
                    MATCH (a:Asset {organization_id: $org_id})-[:LOADS_SCRIPT]->(j)
                    MATCH (a)-[:HAS_ENDPOINT]->(e:Endpoint {path: row.path})
                    MERGE (j)-[r:REFERENCES_ENDPOINT {method: row.method}]->(e)
                    SET r.source = 'jsluice', r.call_type = row.call_type,
                        r.last_seen = datetime()
                """, {"org_id": organization_id, "rows": rows})
        return len(rows)

    def _sync_f5_forwards_to(self, session, asset: Asset, org_id: int, ip_addresses: list) -> None:
        """Link only the specific VIP and member assets named by F5 evidence."""
        meta = getattr(asset, "metadata_", None) or {}
        if not isinstance(meta, dict):
            return

        if meta.get("f5_integration_id"):
            session.run("""
                MATCH ()-[r:FORWARDS_TO {organization_id: $org_id}]->()
                WHERE r.source = 'f5' AND
                      (r.vip_asset_id = $asset_id OR r.member_asset_id = $asset_id)
                DELETE r
            """, {"org_id": org_id, "asset_id": asset.id})
        if getattr(asset, "status", None) in (AssetStatus.INACTIVE, AssetStatus.ARCHIVED):
            return

        try:
            members = meta.get("f5_pool_members")
            vip_ip = (ip_addresses[0] if ip_addresses else None) or asset.value
            if isinstance(members, list) and vip_ip:
                vip_address = graph_ip_identity(vip_ip, org_id, asset).address
                for member in members:
                    if not isinstance(member, dict) or not member.get("asset_id") or not member.get("ip"):
                        continue
                    member_address = graph_ip_identity(member["ip"], org_id, asset).address
                    session.run("""
                        MATCH (vip_asset:Asset {asset_id: $vip_asset_id, organization_id: $org_id})
                              -[:RESOLVES_TO]->(vip:IP {address: $vip_ip})
                        MATCH (member_asset:Asset {asset_id: $member_asset_id, organization_id: $org_id})
                              -[:RESOLVES_TO]->(member:IP {address: $member_ip})
                        MERGE (vip)-[r:FORWARDS_TO {
                            organization_id: $org_id, vip_asset_id: $vip_asset_id,
                            member_asset_id: $member_asset_id, port_key: $port_key
                        }]->(member)
                        SET r.source = 'f5', r.pool = $pool,
                            r.virtual = $virtual, r.port = $port
                    """, {"vip_asset_id": asset.id, "member_asset_id": member["asset_id"],
                          "vip_ip": vip_address, "member_ip": member_address,
                          "org_id": org_id, "pool": meta.get("f5_pool"),
                          "virtual": meta.get("f5_virtual_name"), "port": member.get("port"),
                          "port_key": str(member.get("port") or "")})

            member_ip = (ip_addresses[0] if ip_addresses else None) or asset.value
            vip_links = meta.get("f5_vip_links")
            if not isinstance(vip_links, list):
                vip_links = []
            if not vip_links:
                legacy_vip = meta.get("f5_reachable_via_vip")
                legacy_id = meta.get("f5_vip_asset_id") or getattr(asset, "parent_id", None)
                if legacy_vip and legacy_id:
                    vip_links = [{"ip": legacy_vip, "asset_id": legacy_id}]
            if member_ip and vip_links:
                member_address = graph_ip_identity(member_ip, org_id, asset).address
                for link in vip_links:
                    if not isinstance(link, dict) or not link.get("ip") or not link.get("asset_id"):
                        continue
                    vip_address = graph_ip_identity(link["ip"], org_id, asset).address
                    session.run("""
                        MATCH (vip_asset:Asset {asset_id: $vip_asset_id, organization_id: $org_id})
                              -[:RESOLVES_TO]->(vip:IP {address: $vip_ip})
                        MATCH (member_asset:Asset {asset_id: $member_asset_id, organization_id: $org_id})
                              -[:RESOLVES_TO]->(member:IP {address: $member_ip})
                        MERGE (vip)-[r:FORWARDS_TO {
                            organization_id: $org_id, vip_asset_id: $vip_asset_id,
                            member_asset_id: $member_asset_id, port_key: $port_key
                        }]->(member)
                        SET r.source = 'f5', r.pool = $pool,
                            r.virtual = $virtual, r.port = $port
                    """, {
                        "vip_asset_id": link["asset_id"],
                        "member_asset_id": asset.id,
                        "vip_ip": vip_address,
                        "member_ip": member_address,
                        "org_id": org_id,
                        "pool": meta.get("f5_pool"),
                        "virtual": meta.get("f5_virtual_name"),
                        "port": meta.get("f5_member_port"),
                        "port_key": str(meta.get("f5_member_port") or ""),
                    })
        except Exception as e:
            logger.debug(f"F5 FORWARDS_TO sync error for asset {getattr(asset, 'id', None)}: {e}")
    
    def _create_same_ip_links(self, session, org_id: int):
        """
        Create SAME_IP_AS relationships between Subdomains that resolve to the same IP.
        Enables queries like "what other subdomains share this IP?" (RedAmon-style graph robustness).
        """
        try:
            session.run("""
                MATCH (:Subdomain {organization_id: $org_id})-[r:SAME_IP_AS]->()
                DELETE r
            """, {"org_id": org_id})
            session.run("""
                MATCH (s1:Subdomain {organization_id: $org_id})-[r1:RESOLVES_TO]->(ip:IP)
                MATCH (s2:Subdomain {organization_id: $org_id})-[r2:RESOLVES_TO]->(ip)
                WHERE s1.name < s2.name
                  AND EXISTS { MATCH (a1:Asset)
                               WHERE a1.asset_id = r1.source_asset_id
                                 AND a1.organization_id = $org_id AND a1.is_active = true }
                  AND EXISTS { MATCH (a2:Asset)
                               WHERE a2.asset_id = r2.source_asset_id
                                 AND a2.organization_id = $org_id AND a2.is_active = true }
                MERGE (s1)-[forward:SAME_IP_AS]->(s2)
                SET forward.organization_id = $org_id
                MERGE (s2)-[reverse:SAME_IP_AS]->(s1)
                SET reverse.organization_id = $org_id
            """, {"org_id": org_id})
        except Exception as e:
            logger.debug(f"SAME_IP_AS links: {e}")

    def query(self, cypher: str, params: Dict[str, Any] = None) -> List[Dict]:
        """
        Execute a Cypher query and return results.
        
        Args:
            cypher: Cypher query string
            params: Query parameters
        
        Returns:
            List of result records as dictionaries
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return []
        
        with self.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]

    def lookup_for_agent(
        self, organization_id: int, kind: str, value: str, limit: int = 25
    ) -> List[Dict]:
        """Bounded graph lookups; agent-supplied text is always a parameter."""
        queries = {
            "asset": """
                MATCH (a:Asset {organization_id: $org_id})
                WHERE a.value CONTAINS $value
                RETURN a.asset_id AS asset_id, a.value AS asset,
                       a.asset_type AS type, a.last_seen AS last_seen
                LIMIT $limit
            """,
            "port": """
                MATCH (a:Asset {organization_id: $org_id})-[:HAS_PORT]->(p:Port {port: $port})
                OPTIONAL MATCH (p)-[:RUNS_SERVICE]->(s:Service)
                OPTIONAL MATCH (p)-[:HAS_SERVICE_OBSERVATION]->(o:ServiceObservation)
                RETURN a.value AS asset, p.port AS port, p.protocol AS protocol,
                       p.state AS state, s.name AS service, o.version AS version,
                       o.product AS product, a.last_seen AS last_seen
                LIMIT $limit
            """,
            "service": """
                MATCH (a:Asset {organization_id: $org_id})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
                WHERE s.name CONTAINS $value
                OPTIONAL MATCH (p)-[:HAS_SERVICE_OBSERVATION]->(o:ServiceObservation)
                RETURN a.value AS asset, p.port AS port, p.protocol AS protocol,
                       s.name AS service, o.version AS version, o.product AS product,
                       a.last_seen AS last_seen
                LIMIT $limit
            """,
            "technology": """
                MATCH (a:Asset {organization_id: $org_id})-[observed:USES_TECHNOLOGY]->(t:Technology)
                WHERE t.name CONTAINS $value
                RETURN a.value AS asset, t.name AS technology,
                       observed.version AS version, observed.cpe AS cpe,
                       a.last_seen AS last_seen
                LIMIT $limit
            """,
            "endpoint": """
                MATCH (a:Asset {organization_id: $org_id})-[:HAS_ENDPOINT]->(e:Endpoint)
                WHERE e.path CONTAINS $value
                WITH a, e LIMIT $limit
                OPTIONAL MATCH (j:JSResource)-[:REFERENCES_ENDPOINT]->(e)
                RETURN a.value AS asset, e.path AS path, e.source AS source,
                       collect(DISTINCT j.url)[..5] AS scripts, a.last_seen AS last_seen
            """,
            "script": """
                MATCH (a:Asset {organization_id: $org_id})-[:LOADS_SCRIPT]->(j:JSResource)
                WHERE j.url CONTAINS $value
                WITH a, j LIMIT $limit
                OPTIONAL MATCH (j)-[:REFERENCES_ENDPOINT]->(e:Endpoint)
                OPTIONAL MATCH (j)-[:MAPS_TO_SOURCE]->(f:SourceFile)
                RETURN a.value AS asset, j.url AS script,
                       j.last_seen AS last_seen, collect(DISTINCT e.path)[..10] AS paths,
                       collect(DISTINCT f.path)[..5] AS source_files
            """,
            "finding": """
                MATCH (a:Asset {organization_id: $org_id})-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE v.title CONTAINS $value
                WITH a, v LIMIT $limit
                OPTIONAL MATCH (v)-[:EVIDENCED_BY]->(j:JSResource)
                RETURN a.value AS asset, v.vuln_id AS finding_id,
                       v.title AS title, v.severity AS severity,
                       collect(DISTINCT j.url)[..5] AS scripts
            """,
            "memory": """
                MATCH (a:Asset {organization_id: $org_id})<-[:ABOUT_ASSET]-(f:ChainFinding)
                WHERE a.value CONTAINS $value
                RETURN a.value AS asset, f.finding_type AS type,
                       f.severity AS severity, f.description AS finding,
                       f.created_at AS recorded_at
                ORDER BY f.created_at DESC LIMIT $limit
            """,
            "source_file": """
                MATCH (c:SourceCommit {organization_id: $org_id})-[:CONTAINS_FILE]->(f:SourceFile)
                WHERE f.path CONTAINS $value
                WITH c, f ORDER BY c.ingested_at DESC LIMIT $limit
                OPTIONAL MATCH (f)-[:DECLARES]->(s:CodeSymbol)
                OPTIONAL MATCH (f)-[:USES_PACKAGE]->(p:PackageVersion)
                RETURN f.repository AS repository, c.sha AS commit,
                       f.path AS path, f.sha256 AS sha256,
                       collect(DISTINCT s.name)[..20] AS symbols,
                       collect(DISTINCT p.package_key)[..20] AS packages
            """,
            "package": """
                MATCH (f:SourceFile {organization_id: $org_id})-[:USES_PACKAGE]->(p:PackageVersion)
                WHERE p.name CONTAINS $value
                RETURN f.repository AS repository, f.commit AS commit,
                       f.path AS source_file, p.name AS package,
                       p.version AS version
                LIMIT $limit
            """,
            "source_route": """
                MATCH (c:SourceCommit {organization_id: $org_id})-[:CONTAINS_FILE]->(f:SourceFile)-[:IMPLEMENTS_ROUTE]->(r:SourceRoute)
                WHERE r.path CONTAINS $value
                RETURN r.path AS path, r.method AS method, f.path AS source_file,
                       f.repository AS repository, c.sha AS commit
                ORDER BY c.ingested_at DESC LIMIT $limit
            """,
            "search": """
                CALL db.index.fulltext.queryNodes('graph_knowledge_text', $search)
                YIELD node, score
                WHERE node.organization_id = $org_id
                RETURN labels(node) AS types,
                       coalesce(node.url, node.path, node.title) AS matched_text,
                       node.last_seen AS last_seen, node.commit AS commit,
                       score
                LIMIT $limit
            """,
        }
        if kind not in queries:
            raise ValueError(f"Unknown graph lookup kind: {kind}")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Graph lookup value is required")
        params = {"org_id": organization_id, "value": value.strip()[:500],
                  "limit": max(1, min(int(limit), 50))}
        if kind == "search":
            terms = re.findall(r"[A-Za-z0-9_]+", value)[:8]
            if not terms:
                raise ValueError("Search needs letters or numbers")
            params["search"] = " AND ".join(terms)
        if kind == "port":
            params["port"] = int(value)
            if not 0 < params["port"] <= 65535:
                raise ValueError("Port must be between 1 and 65535")
        return self.query(queries[kind], params)
    
    def get_attack_paths(
        self,
        organization_id: int,
        target_asset_id: Optional[int] = None,
        max_depth: int = 5
    ) -> List[Dict]:
        """
        Find potential attack paths in the graph.
        
        An attack path is a chain of relationships that could be
        exploited by an attacker to reach a critical asset.
        
        Args:
            organization_id: Organization to query
            target_asset_id: Optional specific target asset
            max_depth: Maximum path depth
        
        Returns:
            List of attack paths with nodes and relationships
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return []
        
        cypher = """
            CALL {
                MATCH path = (target:Asset {organization_id: $org_id})
                    -[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE target.is_active = true AND target.is_public = true
                  AND ($target_id IS NULL OR target.asset_id = $target_id)
                  AND v.severity IN ['critical', 'high']
                RETURN path, v
                UNION
                MATCH path = (start:Asset {organization_id: $org_id})
                    -[:RESOLVES_TO]->(:IP)-[forward:FORWARDS_TO]->(:IP)
                    <-[:RESOLVES_TO]-(target:Asset {organization_id: $org_id})
                    -[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE start.is_active = true AND start.is_public = true
                  AND target.is_active = true
                  AND ($target_id IS NULL OR target.asset_id = $target_id)
                  AND v.severity IN ['critical', 'high']
                  AND forward.organization_id = $org_id AND forward.source = 'f5'
                  AND forward.vip_asset_id = start.asset_id
                  AND forward.member_asset_id = target.asset_id
                RETURN path, v
            }
            RETURN path,
                   [node IN nodes(path) | node.value] AS assets,
                   [rel IN relationships(path) | type(rel)] AS relationships,
                   v.cve_id AS target_cve, v.severity AS severity
            LIMIT 20
        """
        return self.query(cypher, {"org_id": organization_id, "target_id": target_asset_id})
    
    def get_asset_relationships(
        self,
        asset_id: int,
        depth: int = 2,
        organization_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Get all relationships for an asset up to a given depth.
        
        Args:
            asset_id: Asset ID to query
            depth: Relationship depth
        
        Returns:
            Dict with nodes and edges for visualization
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return {"nodes": [], "edges": []}
        
        # Scope every path to the center asset's organization. Shared catalog
        # nodes (for example a technology name) may have no organization_id,
        # but traversal must never continue into another tenant's observations.
        safe_depth = max(1, min(int(depth), 5))
        cypher = f"""
            MATCH path = (center:Asset {{asset_id: $asset_id}})-[*0..{safe_depth}]-(connected)
            WHERE center.organization_id IS NOT NULL
              AND ($org_id IS NULL OR center.organization_id = $org_id)
              AND all(n IN nodes(path) WHERE
                  n.organization_id IS NULL OR n.organization_id = center.organization_id)
              AND all(r IN relationships(path) WHERE
                  CASE WHEN type(r) IN ['FORWARDS_TO', 'BELONGS_TO_ASN', 'HOSTED_BY']
                       THEN r.organization_id = center.organization_id
                       ELSE r.organization_id IS NULL OR r.organization_id = center.organization_id END)
            RETURN path
            LIMIT 200
        """
        seen_node_ids = set()
        seen_edges = set()
        nodes_out = []
        edges_out = []
        with self.session() as session:
            result = session.run(cypher, {"asset_id": asset_id, "org_id": organization_id})
            for record in result:
                path = record.get("path")
                if path is None:
                    continue
                for node in path.nodes:
                    nid = node.element_id
                    if nid not in seen_node_ids:
                        seen_node_ids.add(nid)
                        nodes_out.append({
                            "id": nid,
                            "labels": list(node.labels),
                            "properties": graph_node_properties(node),
                        })
                for rel in path.relationships:
                    sid = rel.start_node.element_id
                    tid = rel.end_node.element_id
                    key = rel.element_id
                    if key not in seen_edges:
                        seen_edges.add(key)
                        edges_out.append({"source": sid, "target": tid, "type": rel.type,
                                          "properties": dict(rel)})
        return {"nodes": nodes_out, "edges": edges_out}
    
    def get_discovery_tree(self, asset_id: int, organization_id: int) -> Dict[str, Any]:
        """
        Return the full discovery provenance graph for an asset.

        Traverses DISCOVERED_VIA, HOSTED_BY, BELONGS_TO_ASN, SIGNED_BY, and
        SAME_IP_AS edges to show how the asset was found and what infrastructure
        it shares with other assets.
        """
        if not self._connected:
            self.connect()
        if not self._connected:
            return {"nodes": [], "edges": []}

        cypher = """
            MATCH (a:Asset {asset_id: $asset_id})
            WHERE a.organization_id = $org_id
            OPTIONAL MATCH (a)-[r1:DISCOVERED_VIA]->(ds:DiscoverySource)
            WHERE r1.organization_id IS NULL OR r1.organization_id = $org_id
            OPTIONAL MATCH (a)-[r2:HOSTED_BY]->(h:HostingProvider)
            WHERE r2.organization_id IS NULL OR r2.organization_id = $org_id
            OPTIONAL MATCH (a)-[:RESOLVES_TO]->(ip:IP)-[r3:BELONGS_TO_ASN]->(asn:ASN)
            WHERE r3.organization_id = $org_id
            OPTIONAL MATCH (a)-[r4:SIGNED_BY]->(cert:Certificate)-[r5:ALSO_COVERS]->(san:Subdomain {organization_id: $org_id})
            WHERE (r4.organization_id IS NULL OR r4.organization_id = $org_id)
              AND r5.organization_id = $org_id
            OPTIONAL MATCH (a)-[:RESOLVES_TO]->(ip2:IP)<-[r6:RESOLVES_TO]-(sibling:Subdomain {organization_id: $org_id})
            RETURN a, ds, r1, h, r2, ip, asn, r3, cert, r4, san, r5, ip2, sibling, r6
            LIMIT 200
        """
        seen_node_ids: set = set()
        seen_edges: set = set()
        nodes_out: list = []
        edges_out: list = []

        try:
            with self.session() as session:
                result = session.run(cypher, {"asset_id": asset_id, "org_id": organization_id})
                for record in result:
                    for key in ["a", "ds", "h", "ip", "asn", "cert", "san", "ip2", "sibling"]:
                        node = record.get(key)
                        if node is None:
                            continue
                        nid = getattr(node, "element_id", None) or str(id(node))
                        if nid not in seen_node_ids:
                            seen_node_ids.add(nid)
                            nodes_out.append({
                                "id": nid,
                                "labels": list(getattr(node, "labels", [])),
                                "properties": graph_node_properties(node),
                            })
                    for rel_key in ["r1", "r2", "r3", "r4", "r5", "r6"]:
                        rel = record.get(rel_key)
                        if rel is None:
                            continue
                        sn = getattr(rel, "start_node", None)
                        en = getattr(rel, "end_node", None)
                        sid = getattr(sn, "element_id", None) or (str(id(sn)) if sn else "")
                        tid = getattr(en, "element_id", None) or (str(id(en)) if en else "")
                        rtype = getattr(rel, "type", None) or ""
                        ekey = (sid, tid, rtype)
                        if ekey not in seen_edges:
                            seen_edges.add(ekey)
                            edges_out.append({"source": sid, "target": tid, "type": rtype})
        except Exception as e:
            logger.error(f"Discovery tree query error: {e}")

        return {"nodes": nodes_out, "edges": edges_out}

    def get_shared_infrastructure(
        self, ip_address: str, organization_id: int, asset_id: int | None = None
    ) -> Dict[str, Any]:
        """
        Return in-org assets for one IP identity and its ASN/provider neighbors.
        Addresses present in multiple scopes require an asset ID to select one.
        """
        if not self._connected:
            self.connect()
        if not self._connected:
            return {"nodes": [], "edges": [], "summary": {}}

        try:
            normalized_ip = str(ipaddress.ip_address(ip_address.strip()))
        except ValueError:
            return {"nodes": [], "edges": [], "summary": {}}

        candidates = self.query("""
            MATCH (a:Asset {organization_id: $org_id})-[:RESOLVES_TO]->(ip:IP {address: $ip_address})
            WHERE a.is_active = true AND ($asset_id IS NULL OR a.asset_id = $asset_id)
            RETURN min(a.asset_id) AS asset_id, ip.scope_id AS scope_id,
                   ip.ip_key AS ip_key
            LIMIT 101
        """, {"org_id": organization_id, "ip_address": normalized_ip,
              "asset_id": asset_id})
        if asset_id is None and len({row.get("ip_key") for row in candidates}) > 1:
            return {
                "nodes": [], "edges": [], "summary": {}, "ambiguous": True,
                "scope_options": [
                    {"asset_id": row.get("asset_id"), "scope_id": row.get("scope_id")}
                    for row in candidates
                ],
            }

        cypher = """
            MATCH (seed:Asset {organization_id: $org_id})-[:RESOLVES_TO]->(ip:IP {address: $ip_address})
            WHERE seed.is_active = true AND ($asset_id IS NULL OR seed.asset_id = $asset_id)
            OPTIONAL MATCH (ip)<-[:RESOLVES_TO]-(direct:Asset {organization_id: $org_id})
            WHERE direct.is_active = true
            OPTIONAL MATCH (ip)-[asn_link:BELONGS_TO_ASN]->(asn:ASN)
            WHERE asn_link.organization_id = $org_id
            OPTIONAL MATCH (ip2:IP)-[asn_link2:BELONGS_TO_ASN]->(asn)
            WHERE ip2 <> ip AND asn_link2.organization_id = $org_id
              AND (ip.scope_id = 'global' OR ip2.scope_id = ip.scope_id)
              AND EXISTS { MATCH (owner:Asset {organization_id: $org_id})-[:RESOLVES_TO]->(ip2)
                           WHERE owner.is_active = true }
            OPTIONAL MATCH (ip2)<-[:RESOLVES_TO]-(asn_sibling:Asset {organization_id: $org_id})
            WHERE asn_sibling.is_active = true
            OPTIONAL MATCH (ip)-[host_link:HOSTED_BY]->(hp:HostingProvider)
            WHERE host_link.organization_id = $org_id
            OPTIONAL MATCH (ip3:IP)-[host_link2:HOSTED_BY]->(hp)
            WHERE ip3 <> ip AND host_link2.organization_id = $org_id
              AND (ip.scope_id = 'global' OR ip3.scope_id = ip.scope_id)
              AND EXISTS { MATCH (owner:Asset {organization_id: $org_id})-[:RESOLVES_TO]->(ip3)
                           WHERE owner.is_active = true }
            OPTIONAL MATCH (ip3)<-[:RESOLVES_TO]-(hp_sibling:Asset {organization_id: $org_id})
            WHERE hp_sibling.is_active = true
            RETURN ip, direct, asn, ip2, asn_sibling, hp, ip3, hp_sibling
            LIMIT 150
        """
        seen_node_ids: set = set()
        seen_edges: set = set()
        nodes_out: list = []
        edges_out: list = []

        try:
            with self.session() as session:
                result = session.run(cypher, {"ip_address": normalized_ip,
                                              "org_id": organization_id,
                                              "asset_id": asset_id})
                for record in result:
                    for key in ["ip", "direct", "asn", "ip2", "asn_sibling", "hp", "ip3", "hp_sibling"]:
                        node = record.get(key)
                        if node is None:
                            continue
                        nid = getattr(node, "element_id", None) or str(id(node))
                        if nid not in seen_node_ids:
                            seen_node_ids.add(nid)
                            nodes_out.append({
                                "id": nid,
                                "labels": list(getattr(node, "labels", [])),
                                "properties": graph_node_properties(node),
                            })
        except Exception as e:
            logger.error(f"Shared infrastructure query error: {e}")

        summary = {
            "total_nodes": len(nodes_out),
            "direct_assets": len([n for n in nodes_out if "Asset" in n.get("labels", [])]),
        }
        return {"nodes": nodes_out, "edges": edges_out, "summary": summary}

    def get_cert_expansion(self, domain: str, organization_id: int) -> Dict[str, Any]:
        """
        For a given domain, return all subdomains that share a TLS certificate via SAN entries.
        Traverses SIGNED_BY -> Certificate -> ALSO_COVERS.
        """
        if not self._connected:
            self.connect()
        if not self._connected:
            return {"nodes": [], "edges": [], "sans": []}

        cypher = """
            MATCH (a:Asset {organization_id: $org_id})
            WHERE a.value = $domain OR a.name = $domain
            MATCH (a)-[:SIGNED_BY]->(cert:Certificate)-[covers:ALSO_COVERS]->(san:Subdomain {organization_id: $org_id})
            WHERE covers.organization_id = $org_id
            RETURN a, cert, san
            LIMIT 200
        """
        seen_node_ids: set = set()
        seen_edges: set = set()
        nodes_out: list = []
        edges_out: list = []
        sans: list = []

        try:
            with self.session() as session:
                result = session.run(cypher, {"domain": domain, "org_id": organization_id})
                for record in result:
                    for key in ["a", "cert", "san"]:
                        node = record.get(key)
                        if node is None:
                            continue
                        nid = getattr(node, "element_id", None) or str(id(node))
                        if nid not in seen_node_ids:
                            seen_node_ids.add(nid)
                            nodes_out.append({
                                "id": nid,
                                "labels": list(getattr(node, "labels", [])),
                                "properties": graph_node_properties(node),
                            })
                    san_node = record.get("san")
                    if san_node and dict(san_node).get("name") not in sans:
                        sans.append(dict(san_node).get("name"))
        except Exception as e:
            logger.error(f"Cert expansion query error: {e}")

        return {"nodes": nodes_out, "edges": edges_out, "sans": sans}

    def get_discovery_sources_summary(self, organization_id: int) -> List[Dict]:
        """
        Return asset counts grouped by discovery source for the dashboard.
        Falls back gracefully when DiscoverySource nodes don't exist yet.
        """
        if not self._connected:
            self.connect()
        if not self._connected:
            return []

        cypher = """
            MATCH (a:Asset {organization_id: $org_id})-[r:DISCOVERED_VIA]->(ds:DiscoverySource)
            RETURN ds.name AS source,
                   ds.display_name AS display_name,
                   count(DISTINCT a) AS asset_count
            ORDER BY asset_count DESC
        """
        try:
            return self.query(cypher, {"org_id": organization_id})
        except Exception as e:
            logger.debug(f"Discovery sources summary query error: {e}")
            return []

    def get_vulnerability_impact(
        self,
        vulnerability_id: int,
        organization_id: int
    ) -> Dict[str, Any]:
        """
        Analyze the potential impact of a vulnerability.
        
        Finds all assets that could be affected through relationships.
        
        Args:
            vulnerability_id: Vulnerability ID
            organization_id: Organization ID
        
        Returns:
            Impact analysis with affected assets
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return {"direct": [], "indirect": [], "total_impact": 0}
        
        cypher = """
            MATCH (v:Vulnerability {vuln_id: $vuln_id})<-[:HAS_VULNERABILITY]-(direct:Asset)
            WHERE direct.organization_id = $org_id
            OPTIONAL MATCH path = (direct)<-[:DISCOVERED_FROM|RESOLVES_TO*1..3]-(indirect:Asset)
            WHERE indirect.organization_id = $org_id
              AND all(n IN nodes(path) WHERE n.organization_id = $org_id)
            RETURN 
                collect(DISTINCT {id: direct.asset_id, value: direct.value, type: direct.asset_type}) AS direct_assets,
                collect(DISTINCT {id: indirect.asset_id, value: indirect.value, type: indirect.asset_type}) AS indirect_assets
        """
        
        results = self.query(cypher, {
            "vuln_id": vulnerability_id,
            "org_id": organization_id
        })
        
        if results:
            result = results[0]
            direct = [a for a in result.get("direct_assets", []) if a.get("id")]
            indirect = [a for a in result.get("indirect_assets", []) if a.get("id") and a not in direct]
            
            return {
                "direct": direct,
                "indirect": indirect,
                "total_impact": len(direct) + len(indirect)
            }
        
        return {"direct": [], "indirect": [], "total_impact": 0}


# Global service instance
_graph_service: Optional[GraphService] = None


def get_graph_service() -> GraphService:
    """Get or create the global graph service."""
    global _graph_service
    if _graph_service is None:
        _graph_service = GraphService()
    if not _graph_service._connected and _graph_service.connect():
        _graph_service.initialize_schema()
    return _graph_service


def sync_asset_to_graph(asset_id: int, organization_id: int) -> bool:
    """
    Sync a single asset to the graph database.
    
    This is designed to be called after asset creation/updates
    to keep the graph in sync.
    
    Returns True if sync succeeded, False otherwise.
    """
    try:
        graph = get_graph_service()
        if not graph._connected:
            return False
        
        db = SessionLocal()
        try:
            asset = db.query(Asset).filter(
                Asset.id == asset_id, Asset.organization_id == organization_id
            ).first()
            if not asset:
                return False
            
            with graph.session() as session:
                session.execute_write(
                    lambda tx: graph._sync_asset(tx, asset, organization_id)
                )
            
            logger.info(f"Synced asset {asset_id} to graph")
            return True
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Failed to sync asset {asset_id} to graph: {e}")
        return False


def sync_organization_background(
    organization_id: int, asset_values: list[str] | None = None
) -> dict:
    """
    Sync all assets for an organization to the graph.
    
    This is designed to be called from background tasks.
    Returns sync statistics.
    """
    try:
        graph = get_graph_service()
        if not graph._connected:
            return {"synced": 0, "error": "Neo4j not connected"}
        
        return graph.sync_organization(organization_id, asset_values=asset_values)
    except Exception as e:
        logger.error(f"Background graph sync error: {e}")
        return {"synced": 0, "error": str(e)}
