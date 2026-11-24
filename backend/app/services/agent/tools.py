"""
Agent Tools

Tools for the AI agent to interact with the ASM platform.
"""

from app.services.agent.tools_common import (  # noqa: F401  re-exported for callers
    AgentNote,
    Any,
    AssessmentCapabilities,
    Asset,
    AssetStatus,
    AssetType,
    CAPABILITY_TOOLS,
    ContextVar,
    Dict,
    List,
    Optional,
    PortService,
    ScopedAssessmentTools,
    Session,
    SessionLocal,
    SessionValue,
    Severity,
    Technology,
    Vulnerability,
    _DOMAIN_IN_TEXT_RE,
    _FILE_SUFFIXES,
    _FOLLOWUP_EXCLUDED_MODES,
    _URL_IN_TEXT_RE,
    _default_args_for_tool,
    _emit_finding_to_sink,
    _format_vulnx_search_output,
    _lease_failure_reason,
    _re,
    _run_vulnx_binary,
    _tool_output_max_chars,
    asyncio,
    current_organization_id,
    current_seed_target,
    current_session_id,
    current_user_id,
    deepcopy,
    deque,
    extract_seed_target,
    get_tenant_context,
    hashlib,
    httpx,
    is_probable_file_target,
    json,
    logger,
    logging,
    normalize_execute_tool_args,
    os,
    re,
    recover_assessment_target,
    same_assessment_target,
    set_seed_target,
    set_tenant_context,
    settings,
    signal,
)
from app.services.agent.tools_scoped_probes import ScopedProbeToolsMixin
from app.services.agent.tools_platform import PlatformQueryToolsMixin
from app.services.agent.tools_research import ResearchToolsMixin
from app.services.agent.tools_findings import PlatformWriteToolsMixin
from app.services.agent.tools_js import JsAnalysisToolsMixin
from app.services.agent.tools_active_tests import ActiveTestToolsMixin
from app.services.agent.tools_memory import MemoryToolsMixin
from app.services.agent.tools_inputs import InputInventoryToolsMixin
from app.services.agent.tools_execution import ToolExecutionMixin
from app.services.agent.tools_request_mutation import RequestMutationToolsMixin
from app.services.agent.tools_proof import ProofToolsMixin
from app.services.agent.tools_http import HttpIdentityToolsMixin
from app.services.agent.tools_brain import EngagementBrainToolsMixin
from app.services.agent.tools_recon_fireteam import ReconFireteamToolsMixin
from app.services.agent.tools_threat_intel import ThreatIntelToolsMixin


class ASMToolsManager(
    ScopedProbeToolsMixin,
    PlatformQueryToolsMixin,
    ResearchToolsMixin,
    PlatformWriteToolsMixin,
    JsAnalysisToolsMixin,
    ActiveTestToolsMixin,
    MemoryToolsMixin,
    InputInventoryToolsMixin,
    ToolExecutionMixin,
    RequestMutationToolsMixin,
    ProofToolsMixin,
    HttpIdentityToolsMixin,
    EngagementBrainToolsMixin,
    ReconFireteamToolsMixin,
    ThreatIntelToolsMixin,
    ScopedAssessmentTools,
    AssessmentCapabilities,
):
    """Manager for ASM platform tools accessible by the AI agent."""
    
    _proof_plans = SessionValue(dict)
    _captured_proof_plans = SessionValue(dict)
    _request_capture_store = SessionValue(lambda: None)
    _pilot_request_cookie_headers = SessionValue(dict)
    _scoped_browser_exchanges = SessionValue(dict)
    _scoped_sweep_responses = SessionValue(dict)
    _scoped_link_baselines = SessionValue(dict)
    _scoped_get_count = SessionValue(lambda: 0)
    _scoped_verify_get_count = SessionValue(lambda: 0)
    _scoped_post_count = SessionValue(lambda: 0)
    _scoped_verifier_post_count = SessionValue(lambda: 0)
    _scoped_body_replay_paths = SessionValue(set)
    _scoped_policy_applied = SessionValue(lambda: False)
    _scoped_stored_xss_cleanup_paths = SessionValue(set)
    _scoped_race_action_paths = SessionValue(set)
    _scoped_race_cleanup_paths = SessionValue(set)
    _scoped_csrf_action_paths = SessionValue(set)
    _scoped_csrf_cleanup_paths = SessionValue(set)
    _scoped_owner_expectations = SessionValue(dict)
    _scoped_auth_login_path = SessionValue(lambda: "")
    _scoped_assessment_started = SessionValue(lambda: False)
    _scoped_assessment_partial_reason = SessionValue(lambda: "")
    _proof_engine = SessionValue(lambda: None)
    _js_intelligence = SessionValue(lambda: None)
    _secret_validation_policy = SessionValue(dict)
    _identity_captures = SessionValue(dict)
    _assessment_workflows = SessionValue(dict)
    _evidence_store = SessionValue(lambda: None)
    _identity_registry = SessionValue(lambda: None)
    _verify_receipts = SessionValue(dict)
    _finding_receipts = SessionValue(dict)
    _recent_invocations = SessionValue(lambda: deque(maxlen=48))
    _nonretryable_failures = SessionValue(dict)
    _auth_session = SessionValue(lambda: None)
    _engagement_brain = SessionValue(dict)
    _capability_map = SessionValue(lambda: None)
    _require_independent_verify = SessionValue(lambda: True)
    _assessment_scope = SessionValue(set)
    _fallback_target = SessionValue(lambda: "")
    _credential_testing_allowed = SessionValue(lambda: False)
    _oob_callbacks_allowed = SessionValue(lambda: False)

    def __init__(self):
        self.tools = self._register_tools()
        self._mcp_server = None
        from app.services.agent.followup_runtime import FollowupRuntime

        self._followup_runtime = FollowupRuntime()
        from app.services.agent.tool_singleflight import ToolSingleFlight

        self._tool_singleflight = ToolSingleFlight()
        # Solomon judge receipts: validate_finding SUBMIT → create_finding gate
        self._finding_receipts: Dict[str, Dict[str, Any]] = {}
        # Independent verifier receipts: confirmed → create_finding when fireteam is in play
        self._verify_receipts: Dict[str, Dict[str, Any]] = {}
        self._require_independent_verify = False
        # Live tool traces for Praetorian-style demonstrated chains
        self._recent_invocations: deque = deque(maxlen=48)
    
    def _get_mcp_server(self):
        """Lazy load MCP server."""
        if self._mcp_server is None:
            from app.services.mcp.server import get_mcp_server
            self._mcp_server = get_mcp_server()
        return self._mcp_server
    
    def _register_tools(self) -> Dict[str, callable]:
        """Register all available tools."""
        tools = {
            # ASM Query Tools
            "query_assets": self.query_assets,
            "query_vulnerabilities": self.query_vulnerabilities,
            "query_ports": self.query_ports,
            "probe_pilot_ports": self.probe_pilot_ports,
            "query_technologies": self.query_technologies,
            "query_graph": self.query_graph,
            "analyze_attack_surface": self.analyze_attack_surface,
            "rank_attack_surface": self.rank_attack_surface,
            "get_asset_details": self.get_asset_details,
            "search_cve": self.search_cve,
            # Asset management
            "add_asset": self.add_asset,
            # Scan management
            "create_scan": self.create_scan,
            # Session notes and findings
            "save_note": self.save_note,
            "get_notes": self.get_notes,
            "create_finding": self.create_finding,
            "assess_finding_risk": self.assess_finding_risk,
            "sanitize_evidence": self.sanitize_evidence,
            # LLM Red Team Scanner
            "execute_llm_red_team": self.execute_llm_red_team,
            # Garak LLM vulnerability scanner (NVIDIA) — CLI wrapper via MCP
            "execute_garak": self.execute_mcp_tool,
            "garak_help": self.execute_mcp_tool,
            # Injection testing tools (pure-Python, no external binary)
            "generate_injection_payloads": self.generate_injection_payloads,
            "discover_parameters": self.discover_parameters,
            "get_parameter_inventory": self.get_parameter_inventory,
            "get_api_operation_inventory": self.get_api_operation_inventory,
            # Auto tool selection
            "auto_select_tools": self.auto_select_tools,
            # MCP Security Tools (delegated)
            "execute_nuclei": self.execute_mcp_tool,
            "execute_naabu": self.execute_mcp_tool,
            "execute_httpx": self.execute_mcp_tool,
            "execute_subfinder": self.execute_mcp_tool,
            "execute_subfaster": self.execute_mcp_tool,
            "subfaster_help": self.execute_mcp_tool,
            "execute_dnsx": self.execute_mcp_tool,
            "execute_katana": self.execute_mcp_tool,
            "execute_curl": self.execute_mcp_tool,
            "execute_tldfinder": self.execute_mcp_tool,
            "execute_atlas": self.execute_mcp_tool,
            "execute_argus": self.execute_mcp_tool,
            "execute_hermes": self.execute_mcp_tool,
            "execute_themis": self.execute_mcp_tool,
            "execute_janus": self.execute_mcp_tool,
            "execute_waybackurls": self.execute_mcp_tool,
            "execute_nmap": self.execute_mcp_tool,
            "execute_masscan": self.execute_mcp_tool,
            "execute_ffuf": self.execute_mcp_tool,
            "execute_amass": self.execute_mcp_tool,
            "execute_whatweb": self.execute_mcp_tool,
            "execute_knockpy": self.execute_mcp_tool,
            "execute_gau": self.execute_mcp_tool,
            "execute_kiterunner": self.execute_mcp_tool,
            "execute_wappalyzer": self.execute_mcp_tool,
            "execute_crtsh": self.execute_mcp_tool,
            "execute_crt_name": self.execute_mcp_tool,
            "execute_schemathesis": self.execute_mcp_tool,
            "execute_astf": self.execute_mcp_tool,
            "astf_help": self.execute_mcp_tool,
            "execute_browser": self.execute_mcp_tool,
            "execute_deep_crawl": self.execute_mcp_tool,
            "execute_interceptor": self.execute_mcp_tool,
            # Guardian-parity tools
            "execute_sqlmap": self.execute_mcp_tool,
            "execute_nikto": self.execute_mcp_tool,
            "execute_wafw00f": self.execute_mcp_tool,
            "execute_testssl": self.execute_mcp_tool,
            "execute_sslyze": self.execute_mcp_tool,
            "execute_arjun": self.execute_mcp_tool,
            "execute_wpscan": self.execute_mcp_tool,
            "execute_xsstrike": self.execute_mcp_tool,
            "execute_dalfox": self.execute_mcp_tool,
            "execute_commix": self.execute_mcp_tool,
            "execute_hydra": self.execute_mcp_tool,
            "execute_feroxbuster": self.execute_mcp_tool,
            "execute_gitleaks": self.execute_mcp_tool,
            "scan_js_urls_for_secrets": self.scan_js_urls_for_secrets,
            "scan_assigned_js": self.scan_assigned_js,
            "execute_retirejs": self.scan_js_urls_for_vulns,
            "execute_jwt": self.execute_mcp_tool,
            "execute_interactsh": self.execute_mcp_tool,
            "run_oob_callback_workflow": self.run_oob_callback_workflow,
            "execute_semgrep": self.execute_mcp_tool,
            "execute_trivy": self.execute_mcp_tool,
            "execute_cmseek": self.execute_mcp_tool,
            "nuclei_help": self.execute_mcp_tool,
            "naabu_help": self.execute_mcp_tool,
            "httpx_help": self.execute_mcp_tool,
            "subfinder_help": self.execute_mcp_tool,
            "dnsx_help": self.execute_mcp_tool,
            "katana_help": self.execute_mcp_tool,
            "tldfinder_help": self.execute_mcp_tool,
            "atlas_help": self.execute_mcp_tool,
            "argus_help": self.execute_mcp_tool,
            "hermes_help": self.execute_mcp_tool,
            "themis_help": self.execute_mcp_tool,
            "janus_help": self.execute_mcp_tool,
            "waybackurls_help": self.execute_mcp_tool,
            "nmap_help": self.execute_mcp_tool,
            "masscan_help": self.execute_mcp_tool,
            "ffuf_help": self.execute_mcp_tool,
            "amass_help": self.execute_mcp_tool,
            "whatweb_help": self.execute_mcp_tool,
            "knockpy_help": self.execute_mcp_tool,
            "gau_help": self.execute_mcp_tool,
            "kiterunner_help": self.execute_mcp_tool,
            "schemathesis_help": self.execute_mcp_tool,
            "astf_help": self.execute_mcp_tool,
            "sqlmap_help": self.execute_mcp_tool,
            "nikto_help": self.execute_mcp_tool,
            "wafw00f_help": self.execute_mcp_tool,
            "testssl_help": self.execute_mcp_tool,
            "sslyze_help": self.execute_mcp_tool,
            "arjun_help": self.execute_mcp_tool,
            "wpscan_help": self.execute_mcp_tool,
            "xsstrike_help": self.execute_mcp_tool,
            "dalfox_help": self.execute_mcp_tool,
            "commix_help": self.execute_mcp_tool,
            "hydra_help": self.execute_mcp_tool,
            "feroxbuster_help": self.execute_mcp_tool,
            "gitleaks_help": self.execute_mcp_tool,
            "jwt_help": self.execute_mcp_tool,
            "semgrep_help": self.execute_mcp_tool,
            "trivy_help": self.execute_mcp_tool,
            "cmseek_help": self.execute_mcp_tool,
            # Fireteam: scatter-gather specialists in parallel
            "fireteam_dispatch": self.fireteam_dispatch,
            # Copilot-style parallel recon streams (non-blocking)
            "spawn_recon_workers": self.spawn_recon_workers,
            "wait_recon_workers": self.wait_recon_workers,
            "list_recon_workers": self.list_recon_workers,
            # Replay captured XHR/API requests (from capability map samples)
            "replay_http_request": self.replay_http_request,
            # EvoGraph: cross-session memory lookup
            "query_prior_sessions": self.query_prior_sessions,
            # ProjectDiscovery Uncover: multi-engine search
            "execute_uncover": self.execute_uncover,
            # Knowledge base (RAG) search — palace-backed
            "search_knowledge_base": self.search_knowledge_base,
            "search_memory": self.search_memory,
            "store_memory": self.store_memory,
            # Offensive workflow tools
            "validate_finding": self.validate_finding,
            "detect_bug_chains": self.detect_bug_chains,
            "bypass_403": self.bypass_403,
            "test_request_smuggling": self.test_request_smuggling,
            "test_cache_poisoning": self.test_cache_poisoning,
            "test_race_condition": self.test_race_condition,
            "test_saml_sso": self.test_saml_sso,
            "test_credential_spray": self.test_credential_spray,
            # Tester-process control plane
            "compare_requests": self.compare_requests,
            "sync_engagement_brain": self.sync_engagement_brain,
            "update_hypothesis": self.update_hypothesis,
            "queue_finding_followups": self.queue_finding_followups,
            "suggest_capability_chains": self.suggest_capability_chains,
            "analyze_screenshot": self.analyze_screenshot,
            "describe_tools": self.describe_tools,
            "log_engagement_approach": self.log_engagement_approach,
            "add_engagement_credential": self.add_engagement_credential,
            "get_engagement_brain": self.get_engagement_brain,
            "get_methodology_progress": self.get_methodology_progress,
            "lookup_methodology_procedure": self.lookup_methodology_procedure,
            "ingest_urls_into_map": self.ingest_urls_into_map,
            "build_threat_model": self.build_threat_model,
            "get_threat_model": self.get_threat_model,
            "update_threat_model": self.update_threat_model,
            "submit_finding_candidate": self.submit_finding_candidate,
            "independent_verify": self.independent_verify,
            "record_verify_verdict": self.record_verify_verdict,
            "read_evidence": self.read_evidence,
            "search_evidence": self.search_evidence,
            "run_assessment_workflow": self.run_assessment_workflow,
            # Private scoped executor: run binding and bearer tokens stay in Aegis.
            "scoped_assessment_observe": self.scoped_assessment_observe,
            "scoped_assessment_probe": self.scoped_assessment_probe,
            "scoped_assessment_probe_assigned": self.scoped_assessment_probe_assigned,
            "scoped_input_sweep_assigned": self.scoped_input_sweep_assigned,
            "scoped_input_probe_assigned": self.scoped_input_probe_assigned,
            "scoped_dom_xss_assigned": self.scoped_dom_xss_assigned,
            "scoped_response_probe_assigned": self.scoped_response_probe_assigned,
            "scoped_cors_probe_assigned": self.scoped_cors_probe_assigned,
            "scoped_race_assigned": self.scoped_race_assigned,
            "scoped_injection_probe_assigned": self.scoped_injection_probe_assigned,
            "scoped_csrf_assigned": self.scoped_csrf_assigned,
            "scoped_jwt_probe": self.scoped_jwt_probe,
            "scoped_jwt_key_url_probe": self.scoped_jwt_key_url_probe,
            "scoped_client_probe_assigned": self.scoped_client_probe_assigned,
            "scan_assigned_js_dependency": self.scan_assigned_js_dependency,
            "scoped_xml_entity_assigned": self.scoped_xml_entity_assigned,
            "scoped_stored_xss_assigned": self.scoped_stored_xss_assigned,
            "probe_observed_input_batch": self.probe_observed_input_batch,
            "scoped_assessment_candidate": self.scoped_assessment_candidate,
            "scoped_assessment_publish": self.scoped_assessment_publish,
            "scoped_assessment_status": self.scoped_assessment_status,
            "scoped_assessment_plan": self.scoped_assessment_plan,
            "scoped_assessment_memory": self.scoped_assessment_memory,
            "register_test_identity": self.register_test_identity,
            "list_test_identities": self.list_test_identities,
            "check_test_identity": self.check_test_identity,
            "test_authorization_boundary": self.test_authorization_boundary,
            "record_surface_coverage": self.record_surface_coverage,
            "get_coverage": self.get_coverage,
            "get_tool_execution": self.get_tool_execution,
            "wait_tool_execution": self.wait_tool_execution,
            "cancel_tool_execution": self.cancel_tool_execution,
            "list_tool_executions": self.list_tool_executions,
            "mcp_connect": self.mcp_connect,
            "mcp_list": self.mcp_list,
            "mcp_call": self.mcp_call,
            "mcp_disconnect": self.mcp_disconnect,
            "run_custom_probe": self.run_custom_probe,
            "run_poc_python": self.run_custom_probe,
            "sandbox_shell": self.sandbox_shell,
            "list_captured_requests": self.list_captured_requests,
            "plan_intruder_mutations": self.plan_intruder_mutations,
            "run_intruder_batch": self.run_intruder_batch,
            "mutate_captured_request": self.mutate_captured_request,
            "mutate_list": self.mutate_list,
            "fetch_lazy_chunks": self.fetch_lazy_chunks,
            "extract_js_endpoints": self.extract_js_endpoints,
            "scan_js_sinks": self.scan_js_sinks,
            "fingerprint_api": self.fingerprint_api,
            "fingerprint_passive_stack": self.fingerprint_passive_stack,
            "check_cve_applicability": self.check_cve_applicability,
            "lookup_component_vulns": self.lookup_component_vulns,
            "record_recon_inventory": self.record_recon_inventory,
            "probe_registry_anonymous": self.probe_registry_anonymous,
            "compact_context": self.compact_context,
            "load_prior_hunt": self.load_prior_hunt,
        }
        # Optional: web search (RedAmon-style) when Tavily API key is set
        if getattr(settings, "TAVILY_API_KEY", None):
            tools["web_search"] = self.web_search
        # vulnx: ProjectDiscovery vulnerability intelligence API (CVE ID lookup + search)
        # Available with or without PDCP_API_KEY (unauthenticated has rate limits)
        tools["search_vulnx"] = self.search_vulnx       # single CVE deep-dive by ID
        tools["vulnx_query"] = self.vulnx_query         # search CVEs by technology/query
        tools.update({name: getattr(self, name) for name in CAPABILITY_TOOLS})
        return tools

    def get_tool(self, name: str) -> Optional[callable]:
        """Get a tool by name."""
        return self.tools.get(name)
    
    def get_all_tools(self) -> Dict[str, callable]:
        """Get all registered tools."""
        return self.tools
    
    def record_invocation(
        self,
        tool_name: str,
        tool_args: Optional[Dict[str, Any]],
        result: Optional[Dict[str, Any]],
    ) -> None:
        """Keep a ring buffer of live tool calls for demonstrated-chain attach."""
        try:
            from app.services.agent.demonstrated_chain import should_record_tool

            if not should_record_tool(tool_name):
                return
            result = result or {}
            output = result.get("output")
            if output is not None and not isinstance(output, str):
                output = str(output)
            self._recent_invocations.append({
                "tool": tool_name,
                "args": (tool_args or {}).get("args", tool_args),
                "output": output or "",
                "error": result.get("error") or "",
                "exit_code": result.get("exit_code"),
                "success": bool(result.get("success")),
                "artifact_id": result.get("artifact_id") or "",
                "evidence_ids": result.get("evidence_ids") or [],
            })
        except Exception:
            logger.debug("record_invocation skipped", exc_info=True)

    async def execute(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute once for concurrent identical recon calls in this run."""
        from app.services.agent.action_fingerprint import action_fingerprint
        from app.services.agent.action_ledger import active_run_id, append_action
        from app.services.agent.evidence_store import verification_run
        from app.services.agent.pilot_policy import current_pilot
        from app.services.agent.tool_singleflight import SHAREABLE_TOOLS

        run_id = active_run_id.get()
        if (run_id and current_pilot() is not None and not verification_run.get()
                and tool_name in {"submit_finding_candidate", "record_surface_coverage",
                                  "record_verify_verdict"}):
            argument_hash = hashlib.sha256(json.dumps(
                tool_args, sort_keys=True, default=str,
            ).encode()).hexdigest()
            key = (run_id, "pilot_contract", tool_name, argument_hash)
            cached = self._nonretryable_failures.get(key)
            if cached:
                append_action(run_id, os.urandom(16).hex(), "skipped", tool_name,
                              detail="Suppressed identical pilot tool-contract error")
                return {
                    "success": False,
                    "error": "repeated_tool_contract_error",
                    "output": (
                        "This exact call already failed its tool contract. Use the "
                        "registered signature and valid status values; no call was retried."
                    ),
                    "suppressed_repeat": True,
                }
            result = await self._execute_recorded(tool_name, tool_args)
            error = str(result.get("error") or "").lower()
            if any(marker in error for marker in (
                "unexpected keyword", "missing required", "unknown coverage status",
                "invalid_arguments",
            )):
                self._nonretryable_failures[key] = (0, deepcopy(result))
            return result
        if (run_id and current_pilot() is not None and not verification_run.get()
                and tool_name == "compare_requests" and isinstance(tool_args, dict)):
            prior = [row for row in self._recent_invocations
                     if row.get("tool") == tool_name and row.get("args") == tool_args
                     and row.get("success")]
            if len(prior) >= 2:
                evidence = [str(prior[-1].get("artifact_id") or "")]
                evidence = [item for item in evidence if item]
                append_action(run_id, os.urandom(16).hex(), "skipped", tool_name,
                              target=current_seed_target.get() or "",
                              detail="Third identical Pilot comparison suppressed",
                              evidence_ids=evidence)
                return {
                    "success": False,
                    "error": "repeated_compare_suppressed",
                    "output": (
                        "This exact GET request pair already completed twice. "
                        "Use its prior evidence, test a different observed input, or complete. "
                        "No new request was sent."
                    ),
                    "evidence_ids": evidence,
                    "suppressed_repeat": True,
                }
        if (run_id and not verification_run.get() and tool_name in {
            "execute_browser", "execute_curl", "scoped_input_probe_assigned",
            "scoped_assessment_probe_assigned", "scoped_input_sweep_assigned",
        }):
            import time as _time

            args_dict = tool_args if isinstance(tool_args, dict) else {}
            target = str(args_dict.get("target") or args_dict.get("url") or
                         current_seed_target.get() or "")
            if tool_name == "execute_curl":
                from aegis_praetorium.censor import Censor

                normalized = normalize_execute_tool_args(
                    tool_name, args_dict,
                    fallback_target=str(args_dict.get("_fallback_target") or
                                        self._fallback_target or current_seed_target.get() or ""),
                )
                contract = Censor().validate(tool_name, normalized)
                if not contract.ok:
                    cached = self._nonretryable_failures.get(
                        (run_id, "curl_contract", contract.error.partition(";")[0])
                    )
                    if cached:
                        append_action(
                            run_id, os.urandom(16).hex(), "skipped", tool_name,
                            target=target, detail="Suppressed repeated curl contract failure",
                        )
                        return {
                            "success": False,
                            "output": (
                                "Repeated curl argument error suppressed. Use separate "
                                "supported flags or a structured request replay tool."
                            ),
                            "error": "repeated_curl_contract_error",
                            "suppressed_repeat": True,
                        }
            fingerprint = action_fingerprint(
                run_id=run_id, tool_name=tool_name, target=target,
                tool_args=args_dict, secret_key=settings.SECRET_KEY,
            )
            if fingerprint:
                scope_revision = (
                    tuple(sorted(self._assessment_scope)), self._fallback_target
                ) if tool_name == "execute_browser" else ()
                key = (run_id, fingerprint, scope_revision)
                cached = self._nonretryable_failures.get(key)
                if cached and (
                    tool_name != "execute_browser" or _time.time() - cached[0] < 60
                ):
                    append_action(
                        run_id, os.urandom(16).hex(), "skipped", tool_name,
                        target=target, detail="Suppressed exact repeat of non-retryable failure",
                    )
                    repeated = deepcopy(cached[1])
                    repeated["suppressed_repeat"] = True
                    return repeated
                result = await self._execute_recorded(tool_name, tool_args)
                inner = result.get("output") if isinstance(result.get("output"), dict) else result
                error = str(inner.get("error") or "") if isinstance(inner, dict) else ""
                if (error in {"invalid_coverage_lease", "assessment_scope_denied"}
                        or (tool_name == "execute_curl"
                            and error.startswith("Censor rejected execute_curl"))):
                    self._nonretryable_failures[key] = (_time.time(), deepcopy(result))
                    if tool_name == "execute_curl":
                        self._nonretryable_failures[
                            (run_id, "curl_contract", error.partition(";")[0])
                        ] = (_time.time(), deepcopy(result))
                    if len(self._nonretryable_failures) > 128:
                        self._nonretryable_failures.pop(next(iter(self._nonretryable_failures)))
                return result
        if not run_id or verification_run.get() or tool_name not in SHAREABLE_TOOLS:
            return await self._execute_recorded(tool_name, tool_args)

        args_dict = tool_args if isinstance(tool_args, dict) else {}
        target = str(args_dict.get("target") or args_dict.get("url") or
                     current_seed_target.get() or "")
        fingerprint = action_fingerprint(
            run_id=run_id, tool_name=tool_name, target=target,
            tool_args=args_dict, secret_key=settings.SECRET_KEY,
        )
        if not fingerprint:
            return await self._execute_recorded(tool_name, tool_args)
        user_id, org_id = get_tenant_context()
        key = f"{org_id}:{user_id}:{current_session_id.get()}:{fingerprint}"
        result, reused = await self._tool_singleflight.run(
            key, lambda: self._execute_recorded(tool_name, tool_args),
        )
        if not reused:
            return result
        referenced = result.get("evidence_ids")
        evidence_ids = list(referenced) if isinstance(referenced, list) else []
        if result.get("artifact_id"):
            evidence_ids.append(result["artifact_id"])
        append_action(
            run_id, os.urandom(16).hex(), "skipped", tool_name,
            target=target, detail="Reused identical in-flight result",
            fingerprint=fingerprint, evidence_ids=evidence_ids,
        )
        return deepcopy(result)

    async def _execute_recorded(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given arguments."""
        from app.services.agent.action_fingerprint import action_fingerprint
        from app.services.agent.action_ledger import active_run_id, append_action
        from app.services.agent.evidence_store import verification_run

        run_id = active_run_id.get()
        action_id = os.urandom(16).hex()
        args_dict = tool_args if isinstance(tool_args, dict) else {}
        nested = args_dict.get("body") if tool_name.startswith("scoped_assessment_") else None
        nested = nested if isinstance(nested, dict) else {}
        target = (args_dict.get("target") or args_dict.get("url") or
                  nested.get("target") or nested.get("url") or nested.get("url_template") or
                  current_seed_target.get() or "")
        verifier = verification_run.get()
        fingerprint = action_fingerprint(
            run_id=run_id, tool_name=tool_name, target=str(target),
            tool_args=args_dict, secret_key=settings.SECRET_KEY,
            verifier_run_id=verifier.id if verifier else "",
        )
        append_action(run_id, action_id, "started", tool_name, target=target,
                      fingerprint=fingerprint)
        try:
            result = await self._execute_impl(tool_name, tool_args)
            from app.services.agent.evidence_store import evidence_store
            if tool_name not in ("read_evidence", "search_evidence"):
                artifact_id = evidence_store(self).record("tool_output", result, success=result.get("success", False))
                result.setdefault("artifact_id", artifact_id)
            self.record_invocation(tool_name, tool_args, result)
            try:
                from app.services.agent.palace_memory import remember_tool_result
                remember_tool_result(tool_name, tool_args, result)
            except Exception as exc:
                logger.debug("palace remember skipped: %s", exc)
        except asyncio.CancelledError:
            append_action(run_id, action_id, "interrupted", tool_name,
                          target=target, detail="Tool cancelled before completion",
                          fingerprint=fingerprint)
            raise
        except Exception as exc:
            append_action(run_id, action_id, "failed", tool_name,
                          target=target, detail=type(exc).__name__,
                          fingerprint=fingerprint)
            raise
        published = (tool_name == "create_finding" and
                     str(result.get("output") or "").startswith("Finding created:"))
        completed = bool(result.get("success")) and (tool_name != "create_finding" or published)
        referenced = result.get("evidence_ids")
        evidence_ids = referenced if isinstance(referenced, list) else []
        failure_code = str(result.get("error") or "")
        if failure_code in {"assessment_scope_denied", "invalid_browser_args",
                            "blocked_by_guard", "invalid_coverage_lease"}:
            # The action ledger excludes raw arguments and output. A stable
            # reason code distinguishes bad browser args from a true host deny.
            failure_code += f":{str(result.get('reason') or 'unspecified')[:40]}"
        append_action(run_id, action_id, "completed" if completed else "failed",
                      tool_name, target=target,
                      detail="finding_published" if published else failure_code[:300],
                      fingerprint=fingerprint,
                      evidence_ids=[*evidence_ids,
                                    *([result["artifact_id"]] if result.get("artifact_id") else [])])
        return result

    def _ingest_scanner_leads(self, rows: List[Dict[str, Any]]) -> int:
        """Fold ffuf/sqlmap lead rows into the inventory and re-seed cells.

        Rows are leads, not findings: they become coverage cells that the typed
        scoped probes and the independent verifier must still confirm. Returns
        the number of new coverage cells created.
        """
        from app.services.agent.coverage_cells import seed_parameter_coverage_cells
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import collect_parameter_inventory

        if not rows:
            return 0
        cmap = dict(getattr(self, "_capability_map", None) or {})
        existing = [r for r in (cmap.get("parameter_inventory") or []) if isinstance(r, dict)]

        def _key(row: Dict[str, Any]):
            return (row.get("method"), row.get("url") or row.get("path"),
                    row.get("name"), row.get("location"), row.get("source"))

        seen = {_key(r) for r in existing}
        added = [r for r in rows if _key(r) not in seen]
        if not added:
            return 0
        cmap["parameter_inventory"] = existing + added
        self._capability_map = cmap
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        before = len(brain.coverage_cells)
        seed_parameter_coverage_cells(brain, collect_parameter_inventory(cmap))
        self._engagement_brain = brain.to_dict()
        return max(0, len(brain.coverage_cells) - before)

    async def _execute_impl(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given arguments."""
        tool_args = dict(tool_args or {}) if isinstance(tool_args, dict) else {}
        if self._scoped_policy_applied and tool_name in {"run_custom_probe", "run_poc_python"}:
            from app.services.agent.custom_probe import custom_probe_mode
            # The isolated runner's egress enforces the method policy itself;
            # only the in-process lane cannot, so only it stays denied.
            policy_enforceable = custom_probe_mode() == "isolated"
        else:
            policy_enforceable = True
        if not policy_enforceable:
            return {
                "success": False,
                "output": "Custom Python HTTP probes cannot enforce operator method and path approvals; use structured replay tools.",
                "error": "operator_method_policy_denied",
            }
        if self._scoped_policy_applied and tool_name == "execute_interceptor":
            return {
                "success": False,
                "output": "Interceptor workers cannot enforce operator method and path approvals; use execute_deep_crawl.",
                "error": "operator_method_policy_denied",
            }
        if tool_name in {"test_credential_spray", "execute_hydra", "execute_brutus"} and not self._credential_testing_allowed:
            return {
                "success": False,
                "output": "Credential testing requires explicit operator authorization for this run.",
                "error": "credential_testing_not_authorized",
            }
        if tool_name in {"execute_interactsh", "run_oob_callback_workflow"} and not self._oob_callbacks_allowed:
            return {
                "success": False,
                "output": "Out-of-band callbacks require explicit operator authorization for this run.",
                "error": "oob_callbacks_not_authorized",
            }
        from app.services.agent.pilot_policy import PilotDenied, current_pilot
        pilot = current_pilot()
        if pilot is not None:
            try:
                pilot.check_tool(tool_name)
                if tool_name == "execute_browser":
                    tool_args = normalize_execute_tool_args(
                        tool_name, tool_args, fallback_target=pilot.target,
                    )
                    if tool_args.get("identity") is not None:
                        raise PilotDenied("Pilot first pass is anonymous only")
                    spec = json.loads(str(tool_args.get("args") or "{}"))
                    if not isinstance(spec, dict) or not isinstance(spec.get("actions"), list):
                        raise PilotDenied("Pilot browser actions require a JSON object")
                    if any(key in spec for key in (
                        "login", "cookies", "storage_state", "headers", "basic_auth",
                        "extra_headers", "identity",
                    )):
                        raise PilotDenied("Pilot first pass does not accept credentials")
                    if len(spec["actions"]) > 10:
                        raise PilotDenied("Pilot browser call exceeds ten actions")
                    allowed_actions = {"navigate", "get_source", "screenshot", "wait", "check_response", "check_xss"}
                    if any(not isinstance(action, dict) or action.get("action") not in allowed_actions
                           for action in spec["actions"]):
                        raise PilotDenied("Pilot browser action is outside the read-only allowlist")
                    explicit_urls = [str(action.get("url")) for action in spec["actions"]
                                     if action.get("url")]
                    if explicit_urls:
                        from app.services.agent.pilot_policy import request_origin
                        if len({request_origin(url) for url in explicit_urls}) > 1:
                            raise PilotDenied("One browser action may visit only one origin")
                    allowed_origin = explicit_urls[0] if explicit_urls else pilot.target
                    pilot.check_request(allowed_origin, "GET")
                    spec["allowed_origin"] = allowed_origin
                    tool_args["args"] = json.dumps(spec)
            except (PilotDenied, ValueError, TypeError) as exc:
                logger.warning("Pilot rejected %s before execution: %s", tool_name, exc)
                return {"success": False, "output": str(exc), "error": "pilot_policy_denied"}

        browser_identity = None
        if tool_name in ("execute_browser", "execute_deep_crawl"):
            raw = tool_args.get("args")
            try:
                spec = json.loads(raw) if isinstance(raw, str) and raw.lstrip().startswith("{") else None
                browser_identity = tool_args.pop("identity", None)
                if isinstance(spec, dict):
                    browser_identity = spec.pop("identity", browser_identity)
                if browser_identity is not None:
                    if not isinstance(spec, dict):
                        return {"success": False, "output": "Named browser identities require JSON args", "error": "invalid_identity_args"}
                    from app.services.agent.assessment_sessions import identity_registry
                    registry = identity_registry(self)
                    urls = [spec.get("url") or spec.get("target")] + [a.get("url") for a in spec.get("actions", []) if isinstance(a, dict)]
                    urls = [url for url in urls if url]
                    if not urls:
                        raise ValueError("Provide an explicit browser/crawl URL")
                    session = registry.resolve(browser_identity, urls[0])
                    from app.services.agent.evidence_store import origin
                    for url in urls[1:]:
                        if origin(url) != origin(urls[0]):
                            raise ValueError("Named browser actions must stay on one origin")
                        registry.resolve(browser_identity, url)
                    if any(k in spec for k in ("login", "cookies", "storage_state", "headers", "basic_auth")):
                        raise ValueError("Do not mix named browser identity with other credential inputs")
                    from app.services.agent.assessment_sessions import browser_storage_state
                    spec["storage_state"] = browser_storage_state(session, urls[0])
                    spec["cookies"] = spec["storage_state"]["cookies"]
                    spec["allowed_origin"] = urls[0]
                    spec["identity"] = browser_identity
                    spec["extra_headers" if tool_name == "execute_browser" else "headers"] = session.get("headers", {})
                    tool_args["args"] = json.dumps(spec)
            except (ValueError, TypeError) as exc:
                return {"success": False, "output": str(exc), "error": "invalid_identity_args"}

        # Normalize execute_* BEFORE the confirmation gate so approvals show
        # real CLI args and empty-{} LLM calls never reach MCP.
        if tool_name.startswith("execute_"):
            fallback = str(tool_args.pop("_fallback_target", "") or "")
            if not fallback:
                fallback = getattr(self, "_fallback_target", "") or ""
            if not fallback:
                fallback = current_seed_target.get() or ""
            tool_args = normalize_execute_tool_args(
                tool_name,
                tool_args,
                fallback_target=fallback,
            )
            if not (tool_args.get("args") or "").strip():
                return {
                    "success": False,
                    "output": (
                        f"Error: Missing required parameter: args\n\n"
                        f"HINT: {tool_name} requires tool_args like "
                        f'{{"args": "-u https://target.com -json"}}. '
                        f"Do not call it with empty tool_args."
                    ),
                    "error": "Missing required parameter: args",
                }

        if tool_name == "execute_browser" and pilot is None:
            from app.services.agent.confirmation_service import autonomous_mode_enabled
            if autonomous_mode_enabled():
                try:
                    spec = json.loads(tool_args["args"])
                except (json.JSONDecodeError, TypeError):
                    return {
                        "success": False,
                        "output": "Browser actions require a JSON object with an actions array",
                        "error": "invalid_browser_args",
                        "reason": "invalid_json",
                    }
                if not isinstance(spec, dict) or not isinstance(spec.get("actions"), list):
                    return {
                        "success": False,
                        "output": "Browser actions require a JSON object with an actions array",
                        "error": "invalid_browser_args",
                        "reason": "missing_actions",
                    }
                try:
                    from app.services.agent.assessment_scope import prepare_browser_scope
                    spec = prepare_browser_scope(self, spec, fallback_target=fallback)
                    tool_args["args"] = json.dumps(spec)
                except (ValueError, TypeError, KeyError) as exc:
                    message = str(exc)
                    reason = (
                        "external_host" if message.startswith("Out-of-scope network destination") else
                        "mixed_origin" if "one origin per call" in message else
                        "embedded_credentials" if "Embedded URL credentials" in message else
                        "missing_target" if "assessment target" in message or "assessment URL" in message else
                        "invalid_url"
                    )
                    return {
                        "success": False, "output": message,
                        "error": "assessment_scope_denied", "reason": reason,
                    }

        if self._scoped_policy_applied and tool_name in {"execute_browser", "execute_deep_crawl"}:
            try:
                spec = json.loads(str(tool_args.get("args") or ""))
                if not isinstance(spec, dict):
                    raise ValueError("Scoped browser and crawl calls require JSON arguments")
                if tool_name == "execute_deep_crawl":
                    target = str(spec.get("url") or spec.get("target") or "").strip()
                    from app.services.agent.assessment_scope import assert_url_in_scope
                    assert_url_in_scope(self, target)
                    spec["allowed_origin"] = target
                spec["allowed_methods"] = ["GET", "HEAD"]
                spec["approved_post_paths"] = sorted(
                    self._scoped_body_replay_paths | self._scoped_race_action_paths
                    | self._scoped_csrf_action_paths
                    | ({self._scoped_auth_login_path} if self._scoped_auth_login_path else set())
                )
                spec["approved_delete_paths"] = sorted(
                    self._scoped_stored_xss_cleanup_paths | self._scoped_race_cleanup_paths
                    | self._scoped_csrf_cleanup_paths
                )
                tool_args["args"] = json.dumps(spec)
            except (ValueError, TypeError) as exc:
                return {"success": False, "output": str(exc), "error": "invalid_scoped_browser_args"}

        # -- Tool guard -------------------------------------------------------
        # Never-touch destinations (government/military domains by default,
        # plus operator rules) are refused before approval or execution. This
        # sits on top of the scope allow-list; a blocked call is not a failure.
        from app.services.agent.tool_guard import check_tool_call

        guard = check_tool_call(tool_name, tool_args)
        if guard.blocked:
            logger.warning("Tool guard blocked %s (rule=%s)", tool_name, guard.rule)
            return guard.to_result(tool_name)

        # Custom roles can withhold active testing from a user's agent runs.
        denied = self._active_testing_denied(tool_name)
        if denied:
            return denied

        # -- Per-tool confirmation gate ---------------------------------------
        # Consult the org's agent confirmation policy. Dangerous tools
        # (execute_*, create_scan, ...) either pause for a human ``approve`` or
        # are outright denied by policy. Read-only queries fast-path through.
        try:
            from app.services.agent.confirmation_service import gate as _gate_tool
            _, org_id = get_tenant_context()
            _sess = current_session_id.get()
            gate_result = await _gate_tool(tool_name, tool_args or {}, org_id, _sess)
            if gate_result.get("decision") == "deny":
                return {
                    "success": False,
                    "output": gate_result.get("reason")
                    or f"Tool '{tool_name}' is blocked by policy.",
                    "error": "policy_denied",
                }
            if gate_result.get("decision") == "confirm":
                token = gate_result.get("token") or ""
                # Notify the UI, then block until the operator decides.
                try:
                    from app.services.agent.orchestrator import _status_callback_var
                    cb = _status_callback_var.get(None)
                    if cb:
                        from app.services.agent.confirmation_service import preview_tool_args
                        await cb({
                            "type": "pending_confirmation",
                            "token": token,
                            "tool_name": tool_name,
                            "tool_args": preview_tool_args(gate_result.get("tool_args") or {}),
                            "expires_at": gate_result.get("expires_at"),
                            "message": (
                                f"Tool '{tool_name}' requires operator approval before continuing."
                            ),
                        })
                except Exception as emit_err:
                    logger.debug("Could not emit pending_confirmation: %s", emit_err)
                review_task = None
                if gate_result.get("ai_review"):
                    review_task = self._start_ai_review(token, tool_name, tool_args, org_id)
                from app.services.agent.confirmation_service import wait_for_decision
                try:
                    approved = await wait_for_decision(token)
                finally:
                    if review_task is not None and not review_task.done():
                        review_task.cancel()
                if not approved:
                    from app.services.agent.confirmation_service import get_store
                    confirmation = get_store().get(token)
                    confirmation_status = confirmation.status if confirmation else "expired"
                    return {
                        "success": False,
                        "output": (
                            f"Confirmation {confirmation_status} for '{tool_name}'."
                        ),
                        "error": ("confirmation_expired" if confirmation_status == "expired"
                                  else "confirmation_denied"),
                        "confirmation": {**gate_result, "status": confirmation_status},
                    }
                # Approved — fall through and execute the tool.
        except Exception as _gate_err:
            logger.exception("Confirmation policy evaluation failed")
            try:
                from app.services.agent.confirmation_service import READONLY_TOOLS
                policy_safe = tool_name in READONLY_TOOLS or tool_name.endswith("_help")
            except Exception:
                policy_safe = False
            if not policy_safe:
                return {
                    "success": False,
                    "output": "Tool execution blocked because confirmation policy could not be evaluated.",
                    "error": "confirmation_policy_unavailable",
                }

        # Approval gates have passed; a background execution's bounded wait
        # starts now (tool_executions.wait_until_settled).
        from app.services.agent.tool_executions import mark_running

        mark_running()

        # Route MCP tools: execute_* and *_help (dynamic CLI + help)
        if tool_name.startswith("execute_") or tool_name.endswith("_help"):
            try:
                if pilot is not None and tool_name == "execute_browser":
                    from app.services.browser_automation_service import execute_browser_actions

                    captured_keys = set()
                    capture_store = self._capture_requests()

                    def capture_pilot_request(request):
                        # The browser callback supplies observed HTTP
                        # responses. Store full URLs privately, before any
                        # redacted result crosses an MCP or model boundary.
                        if (len(captured_keys) >= 200 or not isinstance(request, dict)
                                or request.get("method", "").upper() not in {"GET", "HEAD"}):
                            return
                        from urllib.parse import urlsplit
                        if (not urlsplit(str(request.get("url") or "")).query
                                and request.get("resource_type") not in {"document", "xhr", "fetch"}):
                            return
                        try:
                            pilot.check_request(request["url"], request["method"])
                        except (KeyError, ValueError, TypeError):
                            return
                        key = (request["method"].upper(), request["url"])
                        if key in captured_keys:
                            return
                        captured_keys.add(key)
                        captured = capture_store.record(
                            request, identity="anonymous", source="pilot_browser",
                        )
                        if captured:
                            cookie_header = next((str(value) for name, value in
                                                  (request.get("headers") or {}).items()
                                                  if str(name).lower() == "cookie"), "")
                            if cookie_header:
                                cookies = dict(self._pilot_request_cookie_headers)
                                cookies[captured["id"]] = cookie_header
                                self._pilot_request_cookie_headers = cookies

                    result = await execute_browser_actions(
                        tool_args["args"], capture_callback=capture_pilot_request,
                        capture_non_2xx=True,
                    )
                else:
                    mcp = self._get_mcp_server()
                    result = await mcp.call_tool(tool_name, tool_args)
                from app.services.mcp.cli_results import normalize_cli_result
                result = normalize_cli_result(tool_name, result)

                from app.services.agent.evidence_store import evidence_store
                evidence_ids = []
                traffic_tools = {"execute_browser", "execute_deep_crawl", "execute_interceptor"}
                if tool_name in traffic_tools:
                    # A later action can fail after the browser has already
                    # observed useful traffic. Persist the request shapes and
                    # ingest in-scope operations regardless of overall success.
                    from app.services.agent.evidence_store import origin

                    browser_spec = {}
                    expected_origin = None
                    try:
                        raw_spec = tool_args.get("args") or "{}"
                        if isinstance(raw_spec, str) and raw_spec.startswith(("http://", "https://")):
                            browser_spec = {"url": raw_spec}
                        else:
                            browser_spec = json.loads(raw_spec) if isinstance(raw_spec, str) else raw_spec
                        target = (browser_spec.get("allowed_origin") or browser_spec.get("url")
                                  or browser_spec.get("target") or self._fallback_target)
                        candidate_origin = origin(target)
                        if candidate_origin[1] in self._assessment_scope:
                            expected_origin = candidate_origin
                    except (ValueError, TypeError, AttributeError):
                        pass
                    operations = []
                    for operation in result.get("application_operations") or []:
                        if not isinstance(operation, dict):
                            continue
                        try:
                            if expected_origin and origin(operation.get("url") or "") == expected_origin:
                                operations.append(operation)
                        except ValueError:
                            continue
                    if operations:
                        self._ingest_observed_operations(operations)
                    requests = [row for row in (result.get("network_requests") or [])
                                if isinstance(row, dict)]
                    if requests:
                        traffic_id = evidence_store(self).record(
                            "browser_traffic",
                            {
                                "requests": requests,
                                "observed_total": result.get("network_requests_total") or len(requests),
                                "metadata_rows_omitted": result.get("network_requests_dropped") or 0,
                                "operations_ingested": len(operations),
                            },
                            target=(browser_spec.get("allowed_origin") or browser_spec.get("url")
                                    or browser_spec.get("target") or "") if isinstance(browser_spec, dict) else "",
                            success=bool(result.get("success")),
                        )
                        evidence_ids.append(traffic_id)
                        try:
                            from app.services.agent.action_ledger import active_run_id, append_action

                            in_scope_count = sum(bool(row.get("in_scope")) for row in requests)
                            append_action(
                                active_run_id.get(), os.urandom(16).hex(), "completed",
                                "browser_traffic_capture", phase="surface_mapping",
                                target=(browser_spec.get("allowed_origin") or browser_spec.get("url")
                                        or browser_spec.get("target") or "") if isinstance(browser_spec, dict) else "",
                                detail=(f"{in_scope_count} in-scope request records; "
                                        f"{len(requests) - in_scope_count} blocked or external; "
                                        f"{result.get('network_requests_dropped') or 0} metadata rows omitted"),
                                evidence_ids=[traffic_id],
                            )
                        except Exception:
                            logger.exception("Could not record browser traffic capture")
                if tool_name == "execute_interactsh" and result.get("success"):
                    try:
                        observation = json.loads(result.get("output") or "{}")
                        subcommand = str(tool_args.get("args") or "").split()[0]
                        if subcommand in ("register", "poll"):
                            evidence_ids.append(evidence_store(self).record(
                                "oob_register" if subcommand == "register" else "oob_poll", observation))
                    except (ValueError, IndexError):
                        pass
                browser_proof_allowed = True
                if tool_name == "execute_browser":
                    try:
                        browser_spec = json.loads(tool_args.get("args") or "{}")
                        actions = browser_spec if isinstance(browser_spec, list) else browser_spec.get("actions", [])
                        browser_proof_allowed = not any(a.get("action") == "execute_js" for a in actions)
                    except (ValueError, AttributeError):
                        browser_proof_allowed = False
                from app.services.agent.engagement_brain import engagement_brain_from_dict
                from app.services.agent.coverage_cells import observed_xss_cell_for_browser_url

                xss_brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                linked_browser_proof = False
                for observation in (result.get("browser_evidence") or []) if browser_proof_allowed else []:
                    cell = (observed_xss_cell_for_browser_url(
                        xss_brain, str(observation.get("url") or ""),
                    ) if tool_name == "execute_browser" and isinstance(observation, dict) else None)
                    browser_id = evidence_store(self).record(
                        "browser_xss", observation, target=observation.get("url", ""),
                        coverage_cell_id=str(cell.get("id") or "") if cell else "",
                        parameter=str(cell.get("parameter") or "") if cell else "",
                        test_type="xss" if cell else "",
                        success=bool(observation.get("dialog_triggered")),
                    )
                    evidence_ids.append(browser_id)
                    if cell:
                        probes = list(cell.get("probe_artifact_ids") or [])
                        cell["probe_artifact_ids"] = list(dict.fromkeys([*probes, browser_id]))[-20:]
                        executed = bool(observation.get("dialog_triggered"))
                        if executed or cell.get("first_pass_outcome") != "proof_signal":
                            cell["first_pass_outcome"] = "proof_signal" if executed else "inconclusive"
                            cell["first_pass_evidence_id"] = browser_id
                            cell["first_pass_evidence_source"] = "browser"
                            cell["first_pass_signal"] = "browser_execution" if executed else "browser_no_execution"
                        linked_browser_proof = True
                    try:
                        from app.services.agent.action_ledger import active_run_id, append_action

                        append_action(
                            active_run_id.get(), os.urandom(16).hex(), "completed", "browser_xss_check",
                            target=observation.get("url", ""), phase="logic_testing",
                            detail=("dialog observed; independent finding verification required"
                                    if observation.get("dialog_triggered") else
                                    "browser check completed; no script execution observed"),
                            evidence_ids=[browser_id],
                        )
                    except Exception:
                        logger.exception("Could not record browser XSS check")
                if linked_browser_proof:
                    self._engagement_brain = xss_brain.to_dict()
                max_chars = _tool_output_max_chars()
                augur_block = result.get("augur")  # Augur reading: kept/dropped/next_steps/signals
                capability_map = result.get("capability_map")  # deep_crawl / interceptor map
                received_capability_map = isinstance(capability_map, dict)
                if (not capability_map and tool_name in traffic_tools and operations):
                    # Browser actions may return observed operations without a
                    # full crawl map. Their parameter inventory still needs to
                    # reach the orchestrator's durable state.
                    capability_map = getattr(self, "_capability_map", None)
                if tool_name in {"execute_deep_crawl", "execute_interceptor"} and result.get("success") and isinstance(capability_map, dict):
                    try:
                        from app.services.agent.action_ledger import active_run_id, append_action

                        run_id = active_run_id.get()
                        target_origin = str(capability_map.get("target") or "")
                        prior_map = getattr(self, "_capability_map", None)
                        if not isinstance(prior_map, dict):
                            prior_map = {}
                        prior_links = {
                            (str(row.get("url")), tuple(sorted(row.get("query_keys") or [])))
                            for row in (prior_map.get("discovered_links") or []) if isinstance(row, dict)
                        }
                        links = [row for row in (capability_map.get("discovered_links") or [])
                                 if isinstance(row, dict) and
                                 (str(row.get("url")), tuple(sorted(row.get("query_keys") or [])))
                                 not in prior_links]
                        if links:
                            link_id = evidence_store(self).record(
                                "link_discovery", {"count": len(links), "links": links[:100]},
                                target=target_origin,
                            )
                            evidence_ids.append(link_id)
                            append_action(
                                run_id, os.urandom(16).hex(), "completed", "link_discovery",
                                target=target_origin, phase="surface_mapping",
                                detail=f"{len(links)} in-scope links observed; query values omitted",
                                evidence_ids=[link_id],
                            )
                        parameters = capability_map.get("parameter_inventory") or []
                        if parameters:
                            parameter_id = evidence_store(self).record(
                                "parameter_discovery",
                                {"count": len(parameters), "parameters": parameters[:80]},
                                target=target_origin,
                            )
                            evidence_ids.append(parameter_id)
                            append_action(
                                run_id, os.urandom(16).hex(), "completed", "parameter_discovery",
                                target=target_origin, phase="surface_mapping",
                                detail=f"{len(parameters)} named inputs observed; no vulnerability inferred",
                                evidence_ids=[parameter_id],
                            )
                        for observation in (capability_map.get("reflection_observations") or [])[:20]:
                            if not isinstance(observation, dict):
                                continue
                            reflection_id = evidence_store(self).record(
                                "parameter_reflection_check", observation,
                                target=target_origin, parameter=str(observation.get("parameter") or ""),
                                test_type="benign_get_canary", success=True,
                            )
                            evidence_ids.append(reflection_id)
                            append_action(
                                run_id, os.urandom(16).hex(), "completed", "parameter_reflection_check",
                                target=target_origin, phase="surface_mapping",
                                detail=(f"{observation.get('path', '/')} "
                                        f"parameter={observation.get('parameter', '')} "
                                        f"reflected={bool(observation.get('reflected'))}; "
                                        "browser execution unverified"),
                                evidence_ids=[reflection_id],
                            )
                    except Exception:
                        logger.exception("Could not record crawl parameter evidence")
                if pilot is not None and tool_name == "execute_browser":
                    from app.services.agent.pilot_policy import PILOT_METHODS
                    observed = []
                    for item in result.get("network_requests") or []:
                        if not isinstance(item, dict):
                            continue
                        method = str(item.get("method") or "").upper()
                        url = str(item.get("url") or "")
                        try:
                            if method in PILOT_METHODS:
                                pilot.check_request(url, method)
                                observed.append({"method": method, "url": url})
                        except ValueError:
                            continue
                    observed.sort(key=lambda item: (
                        not ("?" in item["url"] or "/api/" in item["url"]),
                        item["url"],
                    ))
                    samples = list({(item["method"], item["url"]): item for item in observed}.values())[:40]
                    capability_map = {
                        "target": pilot.target,
                        "api_samples": samples,
                        "ready_for_attack": bool(samples),
                    }
                auth_session = result.get("auth_session")
                if browser_identity is not None:
                    if capability_map:
                        self._identity_captures[browser_identity] = capability_map
                    if auth_session and browser_identity != "anonymous":
                        current = registry.resolve(browser_identity, urls[0])
                        current["cookies"] = auth_session.get("cookies") or []
                        current["storage_state"] = auth_session.get("storage_state") or {}
                        current["authenticated"] = False  # Recheck the principal after browser changes.
                    auth_session = None  # Named sessions never overwrite the legacy handoff.
                if result.get("success"):
                    output = result.get("output", "")
                    payload = {
                        "success": True,
                        "output": output or "Command completed.",
                        "error": None,
                        "evidence_ids": evidence_ids,
                    }
                    if result.get("exit_code") is not None:
                        payload["exit_code"] = result.get("exit_code")
                    if augur_block:
                        payload["augur"] = augur_block
                    if tool_name not in traffic_tools and result.get("application_operations"):
                        self._ingest_observed_operations(result["application_operations"])
                    if (received_capability_map and capability_map
                            and capability_map.get("api_samples")):
                        from app.services.agent.capability_map import merge_capability_maps

                        # A crawl can export browser storage without logging in.
                        # Those requests belong to the anonymous test identity.
                        # Reserve "legacy" for an actual or explicitly supplied
                        # authenticated browser context.
                        prior_auth = getattr(self, "_auth_session", None)
                        prior_auth = prior_auth if isinstance(prior_auth, dict) else {}
                        crawl_auth = auth_session if isinstance(auth_session, dict) else {}
                        try:
                            crawl_spec = json.loads(tool_args.get("args") or "{}")
                        except (TypeError, ValueError):
                            crawl_spec = {}
                        explicit_auth = False
                        if isinstance(crawl_spec, dict):
                            inherited_storage = bool(prior_auth) and any(
                                crawl_spec.get(key) == prior_auth.get(key)
                                for key in ("cookies", "storage_state")
                                if crawl_spec.get(key)
                            )
                            explicit_auth = (
                                any(crawl_spec.get(key) for key in (
                                    "login", "basic_auth", "headers", "extra_headers",
                                ))
                                or (not inherited_storage and any(
                                    crawl_spec.get(key) for key in ("cookies", "storage_state")
                                ))
                            )
                        capture_identity = browser_identity or (
                            "legacy" if (crawl_auth.get("authenticated") is True
                                         or prior_auth.get("authenticated") is True
                                         or explicit_auth)
                            else "anonymous"
                        )
                        self._capability_map = merge_capability_maps(
                            getattr(self, "_capability_map", None), capability_map,
                        )
                        await self.map_application_traffic(
                            capability_map["api_samples"], identity=capture_identity,
                            source="crawl",
                        )
                        # The queue and scoped probes must use the same map.
                        capability_map = self._capability_map
                    if capability_map:
                        payload["capability_map"] = capability_map
                    if auth_session:
                        payload["auth_session"] = auth_session
                    if tool_name in ("execute_katana", "execute_feroxbuster"):
                        # Parse discovery from the complete tool output before
                        # shortening the text sent back to the model.
                        from app.services.agent.recon_workers import extract_recon_urls

                        url_match = _re.search(
                            r"(?:^|\s)-u(?:\s+|=)(\S+)",
                            str(tool_args.get("args") or ""),
                        )
                        crawl_target = url_match.group(1) if url_match else ""
                        kind = "katana_urls" if tool_name == "execute_katana" else "ferox_dirs"
                        streamed = result.get("observations")
                        if isinstance(streamed, list):
                            candidate_text = "\n".join(
                                str(item.get("target") or "") for item in streamed
                                if isinstance(item, dict) and item.get("type") == "HTTP_ENDPOINT"
                            )
                        else:
                            candidate_text = output
                        payload["observations"] = [
                            {"type": "HTTP_ENDPOINT", "target": discovered,
                             "source": tool_name}
                            for discovered in extract_recon_urls(kind, candidate_text, crawl_target)
                        ]
                    if tool_name in ("execute_ffuf", "execute_sqlmap"):
                        # Scanner hits are leads: normalize to in-scope coverage
                        # cells that the typed verifier must still confirm.
                        try:
                            from app.services.agent.assessment_scope import allowed_hosts
                            from app.services.agent.scoped_assessment.scanner_leads import scanner_rows

                            lead_rows = scanner_rows(
                                tool_name, output, allowed_hosts=allowed_hosts(self),
                            )
                            if lead_rows:
                                new_cells = self._ingest_scanner_leads(lead_rows)
                                payload["scanner_leads"] = {
                                    "source": lead_rows[0]["source"],
                                    "leads": len(lead_rows),
                                    "new_coverage_cells": new_cells,
                                    "note": "Leads only; confirmation runs through the "
                                            "scoped probes and independent verifier.",
                                }
                                if self._capability_map:
                                    payload["capability_map"] = self._capability_map
                        except Exception:
                            logger.exception("Scanner lead ingestion failed for %s", tool_name)
                    if len(output) > max_chars and not augur_block:
                        from app.services.agent.evidence_store import evidence_store
                        payload["artifact_id"] = evidence_store(self).record("tool_output", {"output": output})
                        payload["output"] = (
                            output[:max_chars]
                            + f"\n\n... (truncated; read_evidence({payload['artifact_id']}) for remaining output)"
                        )
                    return payload
                else:
                    err = result.get("error", "Unknown error")
                    out = result.get("output", "")
                    err_max = min(8000, max_chars)
                    hint = (
                        f"\n\nHINT: {tool_name} expects a single 'args' parameter with CLI arguments as a string. "
                        f"Example: {tool_name}(args=\"-u https://target.com -json\")"
                    ) if "Missing required parameter" in err or "unexpected keyword" in err else ""
                    combined = f"Error: {err}{hint}"
                    if out and out.strip():
                        combined += f"\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
                    fail_payload = {
                        "success": False,
                        "output": combined,
                        "error": err,
                        "evidence_ids": evidence_ids,
                    }
                    if capability_map:
                        fail_payload["capability_map"] = capability_map
                    if result.get("exit_code") is not None:
                        fail_payload["exit_code"] = result.get("exit_code")
                    return fail_payload
            except Exception as e:
                logger.error(f"MCP tool execution failed: {tool_name} - {e}")
                err_txt = str(e)
                # Only append the args-shape HINT when the failure is actually about params
                args_related = any(
                    m in err_txt.lower()
                    for m in (
                        "missing required",
                        "unexpected keyword",
                        "required parameter",
                        "got an unexpected",
                    )
                )
                hint = (
                    f"\n\nHINT: All execute_* tools accept a single 'args' parameter with CLI arguments. "
                    f"Example: {tool_name}(args=\"-u https://target.com\")"
                    if args_related
                    else ""
                )
                return {
                    "success": False,
                    "output": f"Error: {e}{hint}",
                    "error": err_txt,
                }
        
        # Scoped tools already return the standard tool-result envelope.
        if tool_name.startswith("scoped_assessment_"):
            tool = self.get_tool(tool_name)
            if tool is None:
                return {"success": False, "output": "Unknown scoped assessment tool", "error": "unknown_tool"}
            try:
                return await tool(**tool_args)
            except TypeError as exc:
                return {"success": False, "output": str(exc)[:300], "error": "invalid_arguments"}

        # Regular ASM tool
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' not found"
            }
        
        try:
            prior_parameter_map = self._capability_map if tool_name == "discover_parameters" else None
            result = await tool(**tool_args)
            # Many local tools return a JSON string instead of raising. An
            # error-shaped JSON result must not become a successful action or
            # a misleading "completed" verification receipt in the ledger.
            semantic_error = ""
            if isinstance(result, str) and result.lstrip().startswith("{"):
                try:
                    parsed_result = json.loads(result)
                except (TypeError, ValueError):
                    parsed_result = None
                if isinstance(parsed_result, dict) and parsed_result.get("error"):
                    semantic_error = str(parsed_result["error"])
            assigned_failure = (
                tool_name in {"scoped_input_probe_assigned", "scoped_input_sweep_assigned"}
                and isinstance(result, dict)
                and result.get("success") is False
            )
            payload = {
                "success": not assigned_failure and not semantic_error,
                "output": result,
                "error": (result.get("error") if assigned_failure else semantic_error) or None,
            }
            if ((tool_name == "scoped_browser_assessment" and self._capability_map) or
                    (tool_name == "discover_parameters"
                     and self._capability_map != prior_parameter_map)):
                payload["capability_map"] = self._capability_map
            return payload
        except TypeError as e:
            import inspect
            sig = inspect.signature(tool)
            params = [p for p in sig.parameters if p != "self"]
            hint = f"Tool '{tool_name}' accepts: {', '.join(params)}. You passed: {list(tool_args.keys())}."
            logger.error(f"Tool argument mismatch: {tool_name} - {e}. {hint}")
            return {
                "success": False,
                "output": hint,
                "error": f"{e}. {hint}"
            }
        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }
