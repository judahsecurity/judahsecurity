"""Read-only queries over the ASM inventory (assets, vulns, ports, tech, graph).

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Asset,
    AssetType,
    List,
    Optional,
    PortService,
    SessionLocal,
    Severity,
    Technology,
    Vulnerability,
    _tool_output_max_chars,
    get_tenant_context,
    json,
    logger,
)


class PlatformQueryToolsMixin:
    """Read-only queries over the ASM inventory (assets, vulns, ports, tech, graph)."""
    
    async def query_assets(
        self,
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query assets from the ASM database.
        
        Args:
            asset_type: Filter by asset type (domain, subdomain, ip_address, url, etc.)
            search: Search term to filter asset values
            limit: Maximum number of results
        
        Returns:
            JSON string with asset information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply type filter
            if asset_type:
                try:
                    asset_type_enum = AssetType(asset_type.lower())
                    query = query.filter(Asset.asset_type == asset_type_enum)
                except ValueError:
                    pass
            
            # Apply search filter
            if search:
                query = query.filter(Asset.value.ilike(f"%{search}%"))
            
            # Limit results
            assets = query.limit(limit).all()
            
            result = []
            for asset in assets:
                result.append({
                    "id": asset.id,
                    "value": asset.value,
                    "type": asset.asset_type.value if asset.asset_type else None,
                    "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                    "is_live": getattr(asset, 'is_live', None),
                    "risk_score": getattr(asset, 'ars_score', None),
                })
            
            return f"Found {len(result)} assets:\n" + "\n".join(
                f"- [{a['type']}] {a['value']} (ID: {a['id']}, Risk: {a.get('risk_score', 'N/A')})"
                for a in result
            )
        except Exception as e:
            logger.exception("query_assets failed")
            return f"Error querying assets: {e}"
        finally:
            db.close()
    
    async def query_vulnerabilities(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query vulnerabilities from the ASM database.
        
        Args:
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, in_progress, resolved, etc.)
            cve_id: Filter by CVE ID
            limit: Maximum number of results
        
        Returns:
            JSON string with vulnerability information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply severity filter (handles both string "critical" and list ["critical","high"])
            if severity:
                if isinstance(severity, list):
                    sev_enums = []
                    for s in severity:
                        try:
                            sev_enums.append(Severity(str(s).lower()))
                        except (ValueError, AttributeError):
                            pass
                    if sev_enums:
                        query = query.filter(Vulnerability.severity.in_(sev_enums))
                else:
                    try:
                        severity_enum = Severity(str(severity).lower())
                        query = query.filter(Vulnerability.severity == severity_enum)
                    except (ValueError, AttributeError):
                        pass
            
            # Apply CVE filter
            if cve_id:
                query = query.filter(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
            
            # Limit results
            vulns = query.limit(limit).all()
            
            result = []
            for vuln in vulns:
                result.append({
                    "id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity.value if vuln.severity else None,
                    "cvss_score": vuln.cvss_score,
                    "cve_id": vuln.cve_id,
                    "cwe_id": vuln.cwe_id,
                    "status": vuln.status.value if vuln.status else None,
                    "asset": vuln.asset.value if vuln.asset else None,
                })
            
            return f"Found {len(result)} vulnerabilities:\n" + "\n".join(
                f"- [{v['severity'].upper()}] {v['title']} ({v['cve_id'] or 'No CVE'}) on {v['asset']}"
                for v in result
            )
        except Exception as e:
            logger.exception("query_vulnerabilities failed")
            return f"Error querying vulnerabilities: {e}"
        finally:
            db.close()
    
    async def probe_pilot_ports(self, protocol: str, ports: List[int] | str) -> dict:
        """Probe at most 20 ports on the pilot host, with one shared reservation per attempt."""
        from app.services.agent.pilot_policy import PilotDenied, current_pilot
        from app.services.agent.pilot_port_probe import probe_ports

        pilot = current_pilot()
        if pilot is None:
            raise PilotDenied("This metered port probe is available only in a bounded pilot")
        return await probe_ports(pilot, protocol, ports)

    async def query_ports(
        self,
        port: Optional[int] = None,
        service: Optional[str] = None,
        is_risky: Optional[bool] = None,
        limit: int = 50
    ) -> str:
        """
        Query open ports and services from the ASM database.
        
        Args:
            port: Filter by port number
            service: Filter by service name
            is_risky: Filter by risky port flag
            limit: Maximum number of results
        
        Returns:
            String with port/service information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(PortService).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply port filter
            if port:
                query = query.filter(PortService.port == port)
            
            # Apply service filter
            if service:
                query = query.filter(PortService.service.ilike(f"%{service}%"))
            
            # Apply risky filter
            if is_risky is not None:
                query = query.filter(PortService.is_risky == is_risky)
            
            # Limit results
            ports = query.limit(limit).all()
            
            result = []
            for p in ports:
                result.append({
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "is_risky": p.is_risky,
                    "asset": p.asset.value if p.asset else None,
                })
            
            # Group by port for summary
            port_summary = {}
            for p in result:
                port_key = f"{p['port']}/{p['protocol']}"
                if port_key not in port_summary:
                    port_summary[port_key] = {"count": 0, "service": p["service"], "risky": p["is_risky"]}
                port_summary[port_key]["count"] += 1
            
            return f"Found {len(result)} open ports:\n" + "\n".join(
                f"- {pk}: {pv['service'] or 'unknown'} ({pv['count']} hosts){' [RISKY]' if pv['risky'] else ''}"
                for pk, pv in sorted(port_summary.items())
            )
        except Exception as e:
            logger.exception("query_ports failed")
            return f"Error querying ports: {e}"
        finally:
            db.close()
    
    async def query_technologies(
        self,
        category: Optional[str] = None,
        name: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query detected technologies from the ASM database.
        
        Args:
            category: Filter by technology category
            name: Filter by technology name
            limit: Maximum number of results
        
        Returns:
            String with technology information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Technology).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply category filter
            if category:
                query = query.filter(Technology.category.ilike(f"%{category}%"))
            
            # Apply name filter
            if name:
                query = query.filter(Technology.name.ilike(f"%{name}%"))
            
            # Limit results
            techs = query.limit(limit).all()
            
            # Group by technology
            tech_summary = {}
            for t in techs:
                key = f"{t.name} ({t.category})" if t.category else t.name
                if key not in tech_summary:
                    tech_summary[key] = {"count": 0, "versions": set()}
                tech_summary[key]["count"] += 1
                if t.version:
                    tech_summary[key]["versions"].add(t.version)
            
            return f"Found {len(tech_summary)} unique technologies:\n" + "\n".join(
                f"- {tk}: {tv['count']} instances" + (f" (versions: {', '.join(tv['versions'])})" if tv['versions'] else "")
                for tk, tv in sorted(tech_summary.items(), key=lambda x: -x[1]["count"])
            )
        except Exception as e:
            logger.exception("query_technologies failed")
            return f"Error querying technologies: {e}"
        finally:
            db.close()
    
    # Cypher keywords that are allowed in read-only queries
    async def query_graph(
        self,
        kind: str = "",
        value: str = "",
        limit: int = 25,
        **kwargs: Any,
    ) -> str:
        """
        Run a tenant-scoped, bounded lookup against the attack surface graph.

        Args:
            kind: asset, port, service, technology, endpoint, script, finding, memory, source_file, source_route, package, or search
            value: Exact port number or text to match in the selected kind
            limit: Maximum rows (1-50)

        Returns:
            JSON string of query results
        """
        if kwargs or not kind:
            return json.dumps({"error": "Use kind and value; free-form Cypher is unavailable to the agent."})
        user_id, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "No organization context. Set organization for this session."})

        try:
            from app.services.graph_service import get_graph_service
            graph = get_graph_service()
            if not graph.connect():
                return json.dumps({"error": "Neo4j graph not available."})
            results = graph.lookup_for_agent(org_id, kind, value, limit)
            return json.dumps(results, default=str)
        except ValueError as e:
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.exception("query_graph failed")
            return json.dumps({"error": str(e)})
    
    async def analyze_attack_surface(self) -> str:
        """
        Get a comprehensive attack surface summary.
        
        Returns:
            String with attack surface analysis
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            # Count assets by type
            asset_counts = {}
            for asset_type in AssetType:
                query = db.query(Asset).filter(Asset.asset_type == asset_type)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_counts[asset_type.value] = query.count()
            
            # Count vulnerabilities by severity
            vuln_counts = {}
            for severity in Severity:
                query = db.query(Vulnerability).join(Asset).filter(Vulnerability.severity == severity)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                vuln_counts[severity.value] = query.count()
            
            # Count risky ports
            query = db.query(PortService).join(Asset).filter(PortService.is_risky == True)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            risky_ports = query.count()
            
            # Total ports
            query = db.query(PortService).join(Asset)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            total_ports = query.count()
            
            report = "# Attack Surface Summary\n\n"
            
            report += "## Assets\n"
            for at, count in asset_counts.items():
                if count > 0:
                    report += f"- {at}: {count}\n"
            
            report += "\n## Vulnerabilities\n"
            total_vulns = sum(vuln_counts.values())
            report += f"- Total: {total_vulns}\n"
            for sev, count in vuln_counts.items():
                if count > 0:
                    report += f"  - {sev.upper()}: {count}\n"
            
            report += f"\n## Exposed Services\n"
            report += f"- Total open ports: {total_ports}\n"
            report += f"- Risky ports: {risky_ports}\n"
            
            return report
        except Exception as e:
            logger.exception("analyze_attack_surface failed")
            return f"Error analyzing attack surface: {e}"
        finally:
            db.close()

    async def rank_attack_surface(
        self,
        target: Optional[str] = None,
        limit: int = 20,
    ) -> str:
        """
        Rank assets by likely testing value using stored ASM data.

        This is a lightweight triage helper for the surface-ranking skill. It
        does not scan; it prioritizes known assets based on exposure, tech,
        existing findings, and high-value route/asset signals.

        Args:
            target: Optional hostname/domain substring to focus ranking.
            limit: Maximum ranked assets to return.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "No organization context."}, indent=2)

        limit = max(1, min(int(limit or 20), 100))
        focus = (target or "").strip().lower()

        db = SessionLocal()
        try:
            query = db.query(Asset).filter(Asset.organization_id == org_id)
            if focus:
                query = query.filter(Asset.value.ilike(f"%{focus}%"))
            assets = query.limit(500).all()

            ranked = []
            high_value_terms = {
                "admin": 20,
                "api": 18,
                "auth": 18,
                "login": 16,
                "sso": 16,
                "oauth": 16,
                "graphql": 16,
                "swagger": 15,
                "openapi": 15,
                "upload": 14,
                "files": 10,
                "export": 10,
                "webhook": 10,
                "payment": 12,
                "billing": 12,
                "chat": 10,
                "support": 8,
                "dev": 8,
                "staging": 8,
                "test": 6,
            }
            risky_ports = {21, 22, 23, 25, 445, 3389, 5432, 3306, 6379, 9200, 9300, 11211}
            severity_weight = {
                "critical": 40,
                "high": 28,
                "medium": 12,
                "low": 4,
                "info": 1,
            }
            tech_weight = {
                "wordpress": 12,
                "gitlab": 14,
                "jenkins": 16,
                "jira": 12,
                "confluence": 12,
                "spring": 10,
                "struts": 14,
                "apache tomcat": 12,
                "graphql": 12,
                "swagger": 10,
                "intercom": 10,
                "zendesk": 10,
                "drift": 10,
                "crisp": 10,
                "tawk": 10,
                "livechat": 10,
                "freshchat": 10,
                "custom chat widget": 10,
                "kubernetes": 14,
                "elasticsearch": 14,
            }

            for asset in assets:
                score = float(getattr(asset, "ars_score", None) or 0)
                reasons = []
                value = (asset.value or "").lower()

                if getattr(asset, "is_live", False):
                    score += 10
                    reasons.append("live asset")

                for term, weight in high_value_terms.items():
                    if term in value:
                        score += weight
                        reasons.append(f"name contains {term}")

                for vuln in getattr(asset, "vulnerabilities", [])[:50]:
                    sev = getattr(getattr(vuln, "severity", None), "value", None) or "info"
                    weight = severity_weight.get(str(sev).lower(), 1)
                    score += weight
                    reasons.append(f"{str(sev).upper()} finding: {vuln.title[:80]}")

                for port in getattr(asset, "ports", [])[:50]:
                    port_num = getattr(port, "port", None)
                    if getattr(port, "is_risky", False) or port_num in risky_ports:
                        score += 12
                        reasons.append(f"risky exposed port {port_num}")
                    elif port_num in (80, 443, 8080, 8443):
                        score += 4
                        reasons.append(f"web port {port_num}")

                for tech in getattr(asset, "technologies", [])[:50]:
                    name = (getattr(tech, "name", "") or "").lower()
                    for needle, weight in tech_weight.items():
                        if needle in name:
                            score += weight
                            label = getattr(tech, "name", "") or needle
                            reasons.append(f"high-value technology: {label}")

                if score <= 0 and not reasons:
                    continue

                ranked.append({
                    "asset_id": asset.id,
                    "asset": asset.value,
                    "type": asset.asset_type.value if asset.asset_type else None,
                    "score": round(score, 1),
                    "reasons": list(dict.fromkeys(reasons))[:8],
                    "recommended_next_skill": self._recommend_skill_for_asset(value, reasons),
                })

            ranked.sort(key=lambda item: item["score"], reverse=True)
            return json.dumps({
                "target_filter": focus or None,
                "ranked_count": len(ranked[:limit]),
                "ranked_assets": ranked[:limit],
            }, indent=2, default=str)[:_tool_output_max_chars()]
        except Exception as e:
            logger.exception("rank_attack_surface failed")
            return f"Error ranking attack surface: {e}"
        finally:
            db.close()

    def _recommend_skill_for_asset(self, asset_value: str, reasons: List[str]) -> str:
        reason_blob = " ".join(reasons).lower()
        if any(x in asset_value or x in reason_blob for x in ("chat", "intercom", "zendesk", "drift", "crisp", "tawk", "livechat")):
            return "llm-redteam"
        if any(x in asset_value or x in reason_blob for x in ("swagger", "openapi", "api", "graphql")):
            return "api-authz-validation"
        if any(x in asset_value or x in reason_blob for x in ("login", "auth", "sso", "oauth")):
            return "api-authz-validation"
        if any(x in asset_value or x in reason_blob for x in ("upload", "files")):
            return "vuln-scan"
        if "xss" in reason_blob:
            return "vuln-scan"
        if "sqli" in reason_blob or "sql injection" in reason_blob:
            return "vuln-scan"
        return "vuln-scan"
    
    async def get_asset_details(
        self,
        asset_id: Optional[int] = None,
        # Accept common LLM argument name variations
        asset_identifier: Optional[Any] = None,
        hostname: Optional[str] = None,
        asset: Optional[Any] = None,
        id: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        """
        Get detailed information about a specific asset.
        
        Args:
            asset_id: ID (integer) of the asset to retrieve. Use query_assets first to find asset IDs.
        
        Returns:
            String with detailed asset information
        """
        resolved_id = asset_id or id or asset_identifier or asset or kwargs.get("asset_value")
        lookup_by_name = hostname or (resolved_id if isinstance(resolved_id, str) and not str(resolved_id).isdigit() else None)

        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            if lookup_by_name:
                query = db.query(Asset).filter(Asset.value.ilike(f"%{lookup_by_name}%"))
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            else:
                try:
                    resolved_id = int(resolved_id)
                except (TypeError, ValueError):
                    return f"Invalid asset_id: {resolved_id}. Use query_assets to find integer asset IDs."
                query = db.query(Asset).filter(Asset.id == resolved_id)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            
            if not asset_obj:
                return f"Asset '{resolved_id or lookup_by_name}' not found. Use query_assets to list available assets."
            
            asset = asset_obj
            
            details = f"# Asset Details: {asset.value}\n\n"
            details += f"- **Type**: {asset.asset_type.value if asset.asset_type else 'Unknown'}\n"
            details += f"- **First Seen**: {asset.first_seen.isoformat() if asset.first_seen else 'Unknown'}\n"
            details += f"- **Live**: {'Yes' if getattr(asset, 'is_live', False) else 'No'}\n"
            
            if hasattr(asset, 'ars_score') and asset.ars_score:
                details += f"- **Risk Score (ARS)**: {asset.ars_score}/100\n"
            
            if hasattr(asset, 'acs_score') and asset.acs_score:
                details += f"- **Criticality Score (ACS)**: {asset.acs_score}/10\n"
            
            # Get vulnerabilities
            if asset.vulnerabilities:
                details += f"\n## Vulnerabilities ({len(asset.vulnerabilities)})\n"
                for vuln in asset.vulnerabilities[:10]:
                    details += f"- [{vuln.severity.value.upper()}] {vuln.title}\n"
                if len(asset.vulnerabilities) > 10:
                    details += f"... and {len(asset.vulnerabilities) - 10} more\n"
            
            # Get ports
            if hasattr(asset, 'ports') and asset.ports:
                details += f"\n## Open Ports ({len(asset.ports)})\n"
                for port in asset.ports[:10]:
                    risky = " [RISKY]" if port.is_risky else ""
                    details += f"- {port.port}/{port.protocol}: {port.service or 'unknown'}{risky}\n"
            
            # Get technologies
            if hasattr(asset, 'technologies') and asset.technologies:
                details += f"\n## Technologies ({len(asset.technologies)})\n"
                for tech in asset.technologies[:10]:
                    version = f" v{tech.version}" if tech.version else ""
                    details += f"- {tech.name}{version} ({tech.category or 'unknown'})\n"
            
            return details
        except Exception as e:
            logger.exception("get_asset_details failed")
            return f"Error getting asset details: {e}"
        finally:
            db.close()
