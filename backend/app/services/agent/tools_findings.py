"""Platform writes: assets, scans, findings, risk and evidence sanitising.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Asset,
    AssetStatus,
    AssetType,
    Dict,
    List,
    Optional,
    SessionLocal,
    Severity,
    Vulnerability,
    _emit_finding_to_sink,
    _re,
    _tool_output_max_chars,
    current_session_id,
    get_tenant_context,
    json,
    logger,
)


class PlatformWriteToolsMixin:
    """Platform writes: assets, scans, findings, risk and evidence sanitising."""

    def _resolve_asset_type(self, value: str) -> AssetType:
        """Infer AssetType from a raw value string."""
        import re
        v = value.strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            return AssetType.IP_ADDRESS
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", v):
            return AssetType.IP_RANGE
        if v.startswith(("http://", "https://")):
            return AssetType.URL
        if "." in v and v.count(".") >= 2:
            return AssetType.SUBDOMAIN
        if "." in v:
            return AssetType.DOMAIN
        return AssetType.OTHER

    def _extract_hostname(self, value: str) -> str:
        """Extract clean hostname/domain from a URL or value."""
        v = value.strip()
        if v.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(v)
                return (p.netloc or p.path.split("/")[0] or v).split(":")[0]
            except Exception:
                pass
        return v.rstrip("/").split("/")[0].split(":")[0]

    def _get_or_create_asset(self, db, org_id: int, target: str) -> "Asset":
        """Find existing asset or create a new one for the given target.

        Tries exact match, then case-insensitive, then creates a new asset.
        Returns the Asset ORM object (already flushed so it has an id).
        """
        target_clean = self._extract_hostname(target)
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value == target_clean)
            .first()
        )
        if asset:
            return asset
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
            .first()
        )
        if asset:
            return asset

        asset_type = self._resolve_asset_type(target)
        root = target_clean
        parts = target_clean.split(".")
        if len(parts) > 2:
            root = ".".join(parts[-2:])

        new_asset = Asset(
            organization_id=org_id,
            name=target_clean,
            value=target_clean,
            asset_type=asset_type,
            root_domain=root,
            discovery_source="agent",
            status=AssetStatus.DISCOVERED,
            is_monitored=True,
        )
        db.add(new_asset)
        db.flush()
        return new_asset

    async def add_asset(
        self,
        value: str,
        asset_type: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Add a target to the asset inventory so it can be scanned and receive findings.

        Use this when a target URL/domain/IP is not yet in the database. The asset
        will be created with status=discovered and can then be used with create_finding,
        query_assets, and scan tools.

        Args:
            value: The hostname, domain, IP, or URL to add (e.g. "test-git.glensserver.com")
            asset_type: Optional override — DOMAIN, SUBDOMAIN, IP_ADDRESS, URL, etc. Auto-detected if omitted.
            description: Optional description of the asset.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not value or not value.strip():
            return "Error: 'value' is required (hostname, domain, IP, or URL)."

        target_clean = self._extract_hostname(value.strip())

        db = SessionLocal()
        try:
            existing = (
                db.query(Asset)
                .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
                .first()
            )
            if existing:
                return (
                    f"Asset already exists: id={existing.id}, value={existing.value}, "
                    f"type={existing.asset_type.value if existing.asset_type else 'N/A'}. "
                    f"No action needed — you can now use create_finding with target='{existing.value}'."
                )

            resolved_type = self._resolve_asset_type(value.strip())
            if asset_type:
                try:
                    resolved_type = AssetType(asset_type.upper())
                except (ValueError, KeyError):
                    pass

            root = target_clean
            parts = target_clean.split(".")
            if len(parts) > 2:
                root = ".".join(parts[-2:])

            new_asset = Asset(
                organization_id=org_id,
                name=target_clean,
                value=target_clean,
                asset_type=resolved_type,
                root_domain=root,
                discovery_source="agent",
                status=AssetStatus.DISCOVERED,
                is_monitored=True,
                description=(description or "")[:2000] if description else None,
            )
            db.add(new_asset)
            db.commit()
            db.refresh(new_asset)
            return (
                f"Asset added: id={new_asset.id}, value={new_asset.value}, "
                f"type={new_asset.asset_type.value}. "
                f"You can now scan it and use create_finding with target='{new_asset.value}'."
            )
        except Exception as e:
            db.rollback()
            logger.exception("add_asset failed")
            return f"Error adding asset: {e}"
        finally:
            db.close()

    async def create_scan(
        self,
        scan_type: str,
        targets: Optional[List[str]] = None,
        name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Create an async scan job processed by the scanner worker. Use this for
        bulk operations (scanning many IPs/domains) instead of execute_* tools.

        The scan runs in the background — results appear in the Scans page and
        update asset records automatically.

        Args:
            scan_type: One of: port_scan, vulnerability, waybackurls, katana,
                       paramspider, http_probe, technology, screenshot,
                       login_portal, subdomain_enum, dns_resolution, discovery,
                       full, geo_enrich, tldfinder, whatweb, atlas_discovery,
                       argus_secrets, hermes_secrets, janus_dast, themis_cspm,
                       graphql_scan, subdomain_takeover, js_recon, jsluice_scan,
                       llm_red_team, commoncrawl_enum
            targets: List of hostnames, domains, or IPs to scan. If omitted,
                     scans all org domains/assets automatically.
            name: Optional scan name (auto-generated if omitted).
            config: Optional dict with scan-specific settings, e.g.
                    {"severity": ["critical","high"]} for vulnerability scans,
                    {"ports": "80,443,8080"} for port_scan.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not scan_type:
            return "Error: scan_type is required."

        from app.models.scan import Scan, ScanType as ST, ScanStatus

        type_map = {
            "port_scan": ST.PORT_SCAN,
            "vulnerability": ST.VULNERABILITY,
            "waybackurls": ST.WAYBACKURLS,
            "katana": ST.KATANA,
            "paramspider": ST.PARAMSPIDER,
            "http_probe": ST.HTTP_PROBE,
            "technology": ST.TECHNOLOGY,
            "whatweb": ST.WHATWEB,
            "screenshot": ST.SCREENSHOT,
            "login_portal": ST.LOGIN_PORTAL,
            "subdomain_enum": ST.SUBDOMAIN_ENUM,
            "dns_resolution": ST.DNS_RESOLUTION,
            "discovery": ST.DISCOVERY,
            "full": ST.FULL,
            "geo_enrich": ST.GEO_ENRICH,
            "tldfinder": ST.TLDFINDER,
            "atlas_discovery": ST.ATLAS_DISCOVERY,
            "argus_secrets": ST.ARGUS_SECRETS,
            "hermes_secrets": ST.HERMES_SECRETS,
            "janus_dast": ST.JANUS_DAST,
            "themis_cspm": ST.THEMIS_CSPM,
            "graphql_scan": ST.GRAPHQL_SCAN,
            "subdomain_takeover": ST.SUBDOMAIN_TAKEOVER,
            "js_recon": ST.JS_RECON,
            "jsluice_scan": ST.JSLUICE_SCAN,
            "llm_red_team": ST.LLM_RED_TEAM,
            "commoncrawl_enum": ST.COMMONCRAWL_ENUM,
        }
        st = type_map.get(scan_type.lower().strip())
        if not st:
            return (
                f"Unknown scan_type '{scan_type}'. Valid types: {', '.join(sorted(type_map.keys()))}"
            )

        auto_name = name or f"Agent {scan_type} scan"
        scan_config = dict(config or {})
        scan_config["created_by"] = "agent"

        db = SessionLocal()
        try:
            new_scan = Scan(
                name=auto_name[:255],
                scan_type=st,
                organization_id=org_id,
                targets=targets or [],
                config=scan_config,
                status=ScanStatus.PENDING,
                started_by="agent",
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            try:
                from app.api.routes.scans import send_scan_to_sqs
                send_scan_to_sqs(new_scan)
            except Exception:
                pass

            target_desc = f"{len(targets)} targets" if targets else "all org assets"
            return (
                f"Scan created: id={new_scan.id}, type={scan_type}, status=pending, "
                f"targets={target_desc}. The scanner worker will pick it up automatically. "
                f"Results will appear on the Scans page and update asset records."
            )
        except Exception as e:
            db.rollback()
            logger.exception("create_scan failed")
            return f"Error creating scan: {e}"
        finally:
            db.close()

    async def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        evidence: Optional[str] = None,
        cve_id: Optional[str] = None,
        remediation: Optional[str] = None,
        steps_to_reproduce: Optional[str] = None,
        proof_of_concept: Optional[str] = None,
        affected_component: Optional[str] = None,
        impact: Optional[str] = None,
        demonstrated_chain: Optional[str] = None,
        not_demonstrated: Optional[str] = None,
        context: Optional[str] = None,
        references: Optional[str] = None,
        risk_assessment: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Create a vulnerability/finding in the platform findings table.

        Medium+ requires independent_verify CONFIRMED once fireteam/candidates are in play;
        otherwise a prior validate_finding SUBMIT (Solomon judge gate).
        Write demonstrated-compromise reports, not scanner hits. Map onto these fields:
        - description: how access was obtained (product/version, credential or pattern, how it was found, rate-limit/lockout notes)
        - impact: what was retrieved (database counts, PII, hashes, topology, config) — not merely 'login succeeded'
        - target: full URL of the affected asset (scheme + host + port)
        - remediation: immediate credential rotation, access controls, password policy, follow-up resets
        - references: vendor hardening docs and OWASP/CWE URLs
        - demonstrated_chain: JSON array of proof steps [{summary, outcome, tool, args, result}]
        - not_demonstrated: what was NOT attempted (hash cracking, data modification, lateral movement)
        - risk_assessment: optional Leo RA JSON (verdict, why_not_higher, CVSS, retest_criteria).
          Medium+ findings without a passing RA stay RA-pending; call assess_finding_risk next.
          Complete is blocked while RA is pending.
        Default/weak login alone is not a finding until privileged impact is proven.
        If demonstrated_chain is omitted, the last live execute_* calls against this target are attached.
        - verification_level: pass "source_verified" for a static/source-only (SAST) finding
          with a reachable-exploit argument but no runtime reproduction. Such findings are
          capped at medium severity until a runtime proof upgrades them. A finding confirmed
          by the independent verifier is recorded as "exploit_verified" automatically; you
          cannot claim exploit_verified without that runtime proof.
        """
        from app.services.agent.independent_verify import finding_publish_allowed

        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context. create_finding requires an active session."

        # A version-only CVE claim is a lead: cap it at low instead of letting
        # it reach (and fail) the medium+ proof gate.
        from app.services.agent.finding_gate import cap_version_only_cve_severity

        severity, cve_capped = cap_version_only_cve_severity(
            f"{title or ''} {cve_id or ''}".strip(), description, severity)
        if cve_capped and not not_demonstrated:
            not_demonstrated = ("Vulnerable behavior not demonstrated; severity capped "
                                "at low for a version-range match.")

        # Independent verify (fireteam/candidates) or legacy Solomon SUBMIT gate
        ok, gate_msg = finding_publish_allowed(
            self,
            title=title or "",
            target=target or "",
            severity=severity or "info",
            skip=False,
        )
        if not ok:
            return gate_msg
        from app.services.agent.pilot_policy import current_pilot

        if current_pilot() is not None and not str(gate_msg).startswith("verify_ok:"):
            return (
                "INDEPENDENT VERIFY GATE: bounded pilots publish only findings "
                "with an independently confirmed candidate receipt."
            )

        verified = None
        if str(gate_msg).startswith("verify_ok"):
            from app.services.agent.independent_verify import (
                _brain, _candidate, verified_publication_claim, verify_receipt_key,
            )
            receipt = self._verify_receipts[verify_receipt_key(title, target)]
            verified = _candidate(_brain(self), receipt["candidate_id"])
            valid_claim, mismatch, description = verified_publication_claim(
                verified, title=title, target=target, severity=severity,
            )
            if not valid_claim:
                return mismatch

        # Label how the finding was verified, and bound an un-exploited source
        # finding so a SAST lead cannot be filed as high/critical without a
        # runtime proof.
        from app.services.agent.finding_gate import (
            cap_source_verified_severity,
            classify_verification_level,
        )

        verification_level = classify_verification_level(
            runtime_confirmed=verified is not None,
            explicit=kwargs.get("verification_level"),
            detected_by="agent",
            specialist=kwargs.get("specialist"),
            evidence=evidence,
        )
        requested_severity = (severity or "info").strip().lower()
        severity, severity_capped = cap_source_verified_severity(
            severity, verification_level
        )

        # Normalize target for asset lookup: strip scheme and path
        target_clean = (target or "").strip()
        if target_clean.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(target_clean)
                target_clean = p.netloc or p.path.split("/")[0] or target_clean
            except Exception:
                pass
        target_clean = target_clean.rstrip("/").split("/")[0].split(":")[0] or target
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        severity_enum = sev_map.get((severity or "info").strip().lower(), Severity.INFO)
        db = SessionLocal()
        try:
            asset = self._get_or_create_asset(db, org_id, target_clean)
            auto_added = not asset.id or db.is_modified(asset)
            if auto_added:
                db.flush()
                logger.info(f"create_finding auto-added asset: {asset.value} (id={asset.id})")
            steps = steps_to_reproduce or kwargs.get("steps_to_reproduce")
            poc = proof_of_concept or kwargs.get("proof_of_concept") or kwargs.get("poc")
            component = affected_component or kwargs.get("affected_component")
            impact_text = impact or kwargs.get("impact")
            chain_raw = demonstrated_chain or kwargs.get("demonstrated_chain")
            not_demo = not_demonstrated or kwargs.get("not_demonstrated")
            context_text = context or kwargs.get("context")
            refs_raw = references or kwargs.get("references")
            from app.services.agent.demonstrated_chain import (
                build_agent_detection,
                parse_references,
                select_verified_proof_invocations,
            )
            proof_invocations = list(getattr(self, "_recent_invocations", []))
            if verified is not None and not chain_raw:
                proof_invocations = select_verified_proof_invocations(
                    proof_invocations,
                    receipt.get("evidence_ids") or [],
                    target=target,
                )
            agent_detection = build_agent_detection(
                chain=chain_raw,
                invocations=proof_invocations,
                target=target_clean or target,
                context=context_text,
                not_demonstrated=not_demo,
                references=refs_raw,
                assets=target,
                session_id=current_session_id.get(),
            )
            parsed_refs = parse_references(refs_raw)
            trace_metadata = None
            if verified is not None:
                trace_metadata = {
                    key: getattr(verified, key, "")
                    for key in (
                        "coverage_cell_id", "operation_id", "hypothesis_id", "identity",
                        "tenant", "parameter", "test_type", "capture_id", "evidence_ids",
                        "proof_run_id",
                        "proof_escalation_id",
                        "verifier_run_id",
                    )
                }
                trace_metadata["candidate_id"] = verified.id
            vuln = Vulnerability(
                title=(title or "Agent finding")[:500],
                description=(description or "")[:10000] if description else None,
                severity=severity_enum,
                asset_id=asset.id,
                detected_by="agent",
                evidence=(evidence or "")[:5000] if evidence else None,
                cve_id=(cve_id or "").strip() or None,
                remediation=(remediation or "")[:5000] if remediation else None,
                steps_to_reproduce=(str(steps)[:10000] if steps else None),
                proof_of_concept=(str(poc)[:10000] if poc else None),
                affected_component=(str(component)[:1000] if component else None),
                impact=(str(impact_text)[:5000] if impact_text else None),
                references=parsed_refs or None,
                verification_level=verification_level,
                metadata_={"agent_detection": agent_detection,
                           "verification": self._verify_receipts.get(verify_receipt_key(title, target)) if str(gate_msg).startswith("verify_ok") else None,
                           "verification_level": verification_level,
                           "severity_cap": {"requested": requested_severity,
                                            "published": severity,
                                            "reason": "source_verified findings are "
                                            "capped at medium without a runtime proof"}
                           if severity_capped else None,
                           "trace": trace_metadata},
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            ra_msg = ""
            try:
                from app.services.agent.risk_assessment import (
                    attach_to_vulnerability,
                    complete_payload,
                    pending_payload,
                    queue_pending_ra,
                    severity_requires_ra,
                    validate_risk_assessment,
                )
                ra_raw = risk_assessment or kwargs.get("risk_assessment")
                needs_ra = severity_requires_ra(severity)
                if ra_raw:
                    parsed, gaps = validate_risk_assessment(
                        ra_raw, proposed_severity=severity
                    )
                    if parsed:
                        attach_to_vulnerability(
                            vuln, complete_payload(parsed, finding_id=vuln.id)
                        )
                        db.commit()
                        ra_msg = (
                            f", RA complete (Leo {parsed.get('verdict')} "
                            f"{parsed.get('confirmed_severity')} "
                            f"CVSS {parsed.get('cvss_score')})"
                        )
                    else:
                        attach_to_vulnerability(
                            vuln,
                            pending_payload(
                                title=title or "",
                                severity=severity or "info",
                                finding_id=vuln.id,
                            ),
                        )
                        db.commit()
                        from app.services.agent.risk_assessment import format_gaps
                        ra_msg = (
                            f", RA pending — {format_gaps(gaps)} "
                            "Call assess_finding_risk(finding_id="
                            f"{vuln.id}, assessment=<fixed JSON>)."
                        )
                        needs_ra = True
                elif needs_ra:
                    attach_to_vulnerability(
                        vuln,
                        pending_payload(
                            title=title or "",
                            severity=severity or "info",
                            finding_id=vuln.id,
                        ),
                    )
                    db.commit()
                    ra_msg = (
                        f", RA pending — call assess_finding_risk(finding_id={vuln.id}) "
                        "with the demonstrated packet (no live retest)."
                    )
                if needs_ra and "RA complete" not in ra_msg:
                    try:
                        from app.services.agent.engagement_brain import (
                            engagement_brain_from_dict,
                        )
                        brain = engagement_brain_from_dict(
                            getattr(self, "_engagement_brain", None)
                        )
                        queue_pending_ra(
                            brain,
                            finding_id=vuln.id,
                            title=title or "",
                            severity=severity or "info",
                        )
                        self._engagement_brain = brain.to_dict()
                    except Exception:
                        logger.debug("queue pending RA failed", exc_info=True)
            except Exception:
                logger.debug("create_finding RA attach failed", exc_info=True)
            # Optional benchmark sink: mirror the finding to a JSONL file so the
            # local harness can score the agent's output (see harness/README.md).
            _emit_finding_to_sink(
                title=title or "",
                description=description or "",
                severity=(severity or "info").strip().lower(),
                target=target or target_clean,
                host=target_clean,
                evidence=evidence,
                poc=poc,
                cve_id=cve_id,
                confirmed=str(gate_msg or "").startswith("verify_ok"),
            )
            try:
                from app.services.chat_notifier import notify_finding

                notify_finding(org_id, finding_id=vuln.id, title=vuln.title,
                               severity=vuln.severity.value, asset=asset.value,
                               verified=verification_level == "exploit_verified")
            except Exception:
                logger.debug("finding notification skipped", exc_info=True)
            chain_n = (agent_detection or {}).get("step_count") or 0
            msg = (
                f"Finding created: id={vuln.id}, title={vuln.title[:60]}..., "
                f"severity={vuln.severity.value}, asset={asset.value}"
                f"{f', demonstrated_chain={chain_n} steps' if chain_n else ''}"
                f"{ra_msg}"
            )
            # CVE→CWE loop-back into engagement brain methodologies
            if vuln.cve_id:
                try:
                    from app.services.vuln_intel_enrichment import enrich_cve_catalog
                    from app.services.agent.engagement_brain import (
                        engagement_brain_from_dict,
                        boost_methodologies_for_cwes,
                    )
                    catalog = enrich_cve_catalog(
                        vuln.cve_id, use_cache=True, include_exploit_sources=False
                    )
                    cwes = list(catalog.get("cwes") or [])
                    if cwes:
                        brain = engagement_brain_from_dict(
                            getattr(self, "_engagement_brain", None)
                        )
                        boosted = boost_methodologies_for_cwes(
                            brain,
                            cwes,
                            cve_id=vuln.cve_id,
                            evidence=title,
                        )
                        self._engagement_brain = brain.to_dict()
                        if boosted:
                            msg += (
                                f" | CVE→CWE loop-back boosted "
                                f"{len(boosted)} methodology card(s): "
                                + ", ".join(
                                    (h.methodology_id or h.id) for h in boosted[:4]
                                )
                            )
                        if catalog.get("cwe_intel"):
                            names = [
                                f"{r.get('cwe_id')} ({r.get('name')})"
                                for r in catalog["cwe_intel"][:3]
                            ]
                            msg += f" | CWEs: {', '.join(names)}"
                except Exception:
                    logger.debug("create_finding CVE→CWE loop-back failed", exc_info=True)
            try:
                from app.services.agent.engagement_brain import (
                    engagement_brain_from_dict,
                    record_surface_coverage,
                )
                brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                if verified is not None:
                    for candidate_row in brain.candidates:
                        if (
                            isinstance(candidate_row, dict)
                            and candidate_row.get("id") == verified.id
                        ):
                            candidate_row["finding_id"] = str(vuln.id)
                            if candidate_row.get("coverage_cell_id"):
                                self._record_followup_event(
                                    brain, kind="verified_finding",
                                    identity=verified.identity or "anonymous",
                                    evidence_ids=[
                                        *(candidate_row.get("evidence_ids") or []),
                                        str(verified.id),
                                    ],
                                    facts={
                                        "coverage_cell_id": candidate_row["coverage_cell_id"],
                                        "finding_id": str(vuln.id),
                                        "test_class": verified.test_type or "",
                                    },
                                )
                    if verified.proof_escalation_id:
                        for escalation in brain.proof_escalations:
                            if escalation.get("id") == verified.proof_escalation_id:
                                escalation.update(
                                    status="published",
                                    finding_id=str(vuln.id),
                                )
                # The finding is already committed. Save its candidate link
                # before the legacy coverage write, which may fail independently.
                # Coverage migration can then repair the exact cell on read.
                self._engagement_brain = brain.to_dict()
                record_surface_coverage(
                    brain,
                    path=target or target_clean,
                    status="finding",
                    finding_title=title or "",
                    reason="create_finding",
                    hypothesis_id=(verified.hypothesis_id if verified else ""),
                    identity=(verified.identity if verified else ""),
                    tenant=(verified.tenant if verified else ""),
                    test_type=(verified.test_type if verified else ""),
                    parameter=(verified.parameter if verified else ""),
                    evidence_id=(verified.evidence_ids[0] if verified and verified.evidence_ids else ""),
                    operation_id=(verified.operation_id if verified else ""),
                    coverage_cell_id=(verified.coverage_cell_id if verified else ""),
                    capture_id=(verified.capture_id if verified else ""),
                    candidate_id=(verified.id if verified else ""),
                    proof_run_id=(verified.proof_run_id if verified else ""),
                    verifier_run_id=(verified.verifier_run_id if verified else ""),
                    finding_id=str(vuln.id),
                )
                self._engagement_brain = brain.to_dict()
            except Exception:
                logger.warning("create_finding coverage update failed", exc_info=True)
            return msg
        except Exception as e:
            db.rollback()
            logger.exception("create_finding failed")
            return f"Error creating finding: {e}"
        finally:
            db.close()

    async def assess_finding_risk(
        self,
        finding_id: Optional[int] = None,
        assessment: Optional[str] = None,
        title: Optional[str] = None,
        verdict: Optional[str] = None,
        confirmed_severity: Optional[str] = None,
        why_this_severity: Optional[str] = None,
        why_not_higher: Optional[str] = None,
        why_not_lower: Optional[str] = None,
        cvss_score: Optional[str] = None,
        cvss_vector: Optional[str] = None,
        demonstrated: Optional[str] = None,
        not_demonstrated: Optional[str] = None,
        control_failures: Optional[str] = None,
        business_risk: Optional[str] = None,
        remediation_sequence: Optional[str] = None,
        retest_criteria: Optional[str] = None,
        ticket_title: Optional[str] = None,
        ra_note: Optional[str] = None,
        sla: Optional[str] = None,
        cwes: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Leo risk assessment — score a demonstrated finding. No live retest.

        Required for every medium+ finding after create_finding. Pass assessment
        as JSON (preferred) or flattened fields. Quality gate rejects inflation
        (Critical without write/RCE/cloud creds), missing why_not_higher,
        missing done_when close criteria, and missing retest_criteria.

        Args:
            finding_id: Platform finding id from create_finding (required to persist).
            assessment: JSON with verdict, confirmed_severity, why_this_severity,
                why_not_higher, why_not_lower, cvss_score, cvss_vector,
                demonstrated[], not_demonstrated[], control_failures[],
                business_risk, remediation_sequence[{when,action,done_when}],
                retest_criteria[], ticket_title, ra_note, sla, cwes.
        """
        from app.services.agent.risk_assessment import (
            attach_to_vulnerability,
            complete_payload,
            complete_pending_ra,
            format_gaps,
            validate_risk_assessment,
        )

        extra = {
            "verdict": verdict or kwargs.get("verdict"),
            "confirmed_severity": confirmed_severity or kwargs.get("confirmed_severity"),
            "why_this_severity": why_this_severity or kwargs.get("why_this_severity"),
            "why_not_higher": why_not_higher or kwargs.get("why_not_higher"),
            "why_not_lower": why_not_lower or kwargs.get("why_not_lower"),
            "cvss_score": cvss_score if cvss_score is not None else kwargs.get("cvss_score"),
            "cvss_vector": cvss_vector or kwargs.get("cvss_vector"),
            "demonstrated": demonstrated or kwargs.get("demonstrated"),
            "not_demonstrated": not_demonstrated or kwargs.get("not_demonstrated"),
            "control_failures": control_failures or kwargs.get("control_failures"),
            "business_risk": business_risk or kwargs.get("business_risk"),
            "remediation_sequence": remediation_sequence or kwargs.get("remediation_sequence"),
            "retest_criteria": retest_criteria or kwargs.get("retest_criteria"),
            "ticket_title": ticket_title or kwargs.get("ticket_title") or title,
            "ra_note": ra_note or kwargs.get("ra_note"),
            "sla": sla or kwargs.get("sla"),
            "cwes": cwes or kwargs.get("cwes"),
        }
        extra = {k: v for k, v in extra.items() if v is not None and v != ""}
        parsed, gaps = validate_risk_assessment(assessment, extra=extra or None)
        if gaps:
            return format_gaps(gaps)

        fid = finding_id or kwargs.get("finding_id")
        try:
            fid = int(fid) if fid is not None else None
        except (TypeError, ValueError):
            fid = None
        if not fid:
            return json.dumps({
                "status": "complete",
                "persisted": False,
                "warning": "No finding_id — RA validated but not saved. Pass finding_id from create_finding.",
                "assessment": parsed,
            }, indent=2)[:8000]

        _, org_id = get_tenant_context()
        db = SessionLocal()
        try:
            from app.models.vulnerability import Vulnerability
            from app.models.asset import Asset

            vuln = db.query(Vulnerability).filter(Vulnerability.id == fid).first()
            if not vuln:
                return f"Error: finding id={fid} not found."
            if org_id:
                asset = db.query(Asset).filter(Asset.id == vuln.asset_id).first()
                if asset and asset.organization_id != org_id:
                    return f"Error: finding id={fid} is out of organization scope."
            payload = attach_to_vulnerability(
                vuln, complete_payload(parsed, finding_id=fid)
            )
            db.commit()
            try:
                from app.services.agent.engagement_brain import engagement_brain_from_dict

                brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                complete_pending_ra(brain, fid)
                self._engagement_brain = brain.to_dict()
            except Exception:
                logger.debug("complete pending RA brain update failed", exc_info=True)
            return json.dumps({
                "status": "complete",
                "persisted": True,
                "finding_id": fid,
                "verdict": payload.get("verdict"),
                "confirmed_severity": payload.get("confirmed_severity"),
                "cvss_score": payload.get("cvss_score"),
                "cvss_vector": payload.get("cvss_vector"),
                "sla": payload.get("sla"),
                "ticket_title": payload.get("ticket_title"),
                "ra_note": payload.get("ra_note"),
            }, indent=2)
        except Exception as e:
            db.rollback()
            logger.exception("assess_finding_risk persist failed")
            return f"Error persisting RA: {e}"
        finally:
            db.close()

    async def sanitize_evidence(
        self,
        evidence: str,
        preserve_last: int = 4,
    ) -> str:
        """
        Redact sensitive values from evidence before creating a finding or report.

        Args:
            evidence: Raw request/response/log/screenshot OCR text to sanitize.
            preserve_last: Number of trailing characters to keep for token fingerprints.
        """
        if not evidence:
            return json.dumps({"sanitized": "", "redactions": []}, indent=2)

        preserve_last = max(0, min(int(preserve_last or 4), 8))
        redactions: List[Dict[str, Any]] = []

        def replacement(label: str, value: str) -> str:
            suffix = value[-preserve_last:] if preserve_last and len(value) > preserve_last else ""
            redactions.append({"type": label, "length": len(value)})
            return f"[REDACTED_{label}{':' + suffix if suffix else ''}]"

        sanitized = evidence

        header_patterns = [
            (r"(?i)(authorization:\s*bearer\s+)([A-Za-z0-9._~+/=-]{12,})", "BEARER_TOKEN"),
            (r"(?i)(api[-_]?key:\s*)([A-Za-z0-9._~+/=-]{12,})", "API_KEY"),
            (r"(?i)(x-api-key:\s*)([A-Za-z0-9._~+/=-]{12,})", "API_KEY"),
            (r"(?i)(cookie:\s*)([^\r\n]+)", "COOKIE_HEADER"),
            (r"(?i)(set-cookie:\s*)([^\r\n;]+)", "SET_COOKIE"),
        ]
        for pattern, label in header_patterns:
            sanitized = _re.sub(
                pattern,
                lambda m, lbl=label: m.group(1) + replacement(lbl, m.group(2)),
                sanitized,
            )

        value_patterns = [
            (r"\bAKIA[0-9A-Z]{16}\b", "AWS_ACCESS_KEY"),
            (r"\bASIA[0-9A-Z]{16}\b", "AWS_TEMP_ACCESS_KEY"),
            (r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "GITHUB_TOKEN"),
            (r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b", "SLACK_TOKEN"),
            (r"\bsk_live_[A-Za-z0-9]{16,}\b", "STRIPE_SECRET"),
            (r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", "PRIVATE_KEY"),
            (r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "JWT"),
            (r"\b(?:\d[ -]*?){13,19}\b", "PAYMENT_CARD"),
            (r"\b\d{3}-\d{2}-\d{4}\b", "SSN"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "EMAIL"),
        ]
        for pattern, label in value_patterns:
            flags = _re.DOTALL if label == "PRIVATE_KEY" else 0
            sanitized = _re.sub(
                pattern,
                lambda m, lbl=label: replacement(lbl, m.group(0)),
                sanitized,
                flags=flags,
            )

        # Redact common JSON/form secret fields while preserving field names.
        field_pattern = (
            r'(?i)("?(?:password|passwd|secret|token|access_token|refresh_token|'
            r'id_token|client_secret|api_key|apikey|session|sessionid|auth_code)"?\s*[:=]\s*)'
            r'("?)([^",\s&}]{6,})\2'
        )
        sanitized = _re.sub(
            field_pattern,
            lambda m: m.group(1) + m.group(2) + replacement("SECRET_FIELD", m.group(3)) + m.group(2),
            sanitized,
        )

        return json.dumps({
            "sanitized": sanitized[:_tool_output_max_chars()],
            "redaction_count": len(redactions),
            "redactions": redactions[:100],
        }, indent=2)
