"""Recon workers, URL map ingest and fireteam dispatch.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    SessionLocal,
    _FOLLOWUP_EXCLUDED_MODES,
    _re,
    _tool_output_max_chars,
    asyncio,
    current_seed_target,
    current_session_id,
    current_user_id,
    get_tenant_context,
    json,
    logger,
    settings,
)


class ReconFireteamToolsMixin:
    """Recon workers, URL map ingest and fireteam dispatch."""

    async def ingest_urls_into_map(
        self,
        urls: Optional[Any] = None,
        source: str = "passive",
        target: str = "",
        resync_brain: bool = True,
    ) -> str:
        """
        Merge katana/gau/wayback/httpx URL lists into the capability map so methodologies
        update from passive crawl observations (not only Playwright deep_crawl).

        urls: newline/comma-separated string, JSON array, or list of URL strings.
        """
        from app.services.agent.capability_map import ingest_passive_urls
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            seed_hypotheses_from_capability_map,
            methodology_progress,
        )

        raw = urls
        parsed: List[str] = []
        if isinstance(raw, list):
            parsed = [str(u) for u in raw]
        elif isinstance(raw, str):
            text = raw.strip()
            if text.startswith("["):
                try:
                    loaded = json.loads(text)
                    if isinstance(loaded, list):
                        parsed = [str(u) for u in loaded]
                except Exception:
                    parsed = []
            if not parsed:
                parsed = [p.strip() for p in _re.split(r"[\n,]+", text) if p.strip()]
        if not parsed:
            return json.dumps({"error": "urls required (list or newline/comma-separated)"}, indent=2)

        existing = getattr(self, "_capability_map", None)
        merged = ingest_passive_urls(
            existing if isinstance(existing, dict) else None,
            parsed,
            target=target or (existing or {}).get("target", "") if isinstance(existing, dict) else target,
            source=source,
        )
        self._capability_map = merged
        brain_out = None
        if resync_brain:
            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            brain = seed_hypotheses_from_capability_map(brain, merged)
            self._engagement_brain = brain.to_dict()
            brain_out = self._engagement_brain
        progress = methodology_progress(
            getattr(self, "_engagement_brain", None), cmap=merged
        )
        return json.dumps(
            {
                "ingested": len(parsed),
                "source": source,
                "pages": len(merged.get("pages_visited") or []),
                "apis": len(merged.get("api_endpoints") or []),
                "methodologies": len(merged.get("methodologies") or []),
                "methodology_progress": progress,
                "capability_map": merged,
                "engagement_brain": brain_out,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def spawn_recon_workers(
        self,
        target: str = "",
        pack: str = "",
        kinds: Optional[List[str]] = None,
    ) -> str:
        """Spawn parallel recon streams that run while the agent continues.

        Results inject automatically into the next think step. Use wait_recon_workers
        to block briefly for them.

        Args:
            target: URL/host (defaults to session seed).
            pack: ``early`` | ``enrich`` | ``nuclei_recon`` | ``full`` (optional if kinds set).
            kinds: Explicit list: httpx_tech, waf_probe, whatweb, nuclei_recon,
                ferox_dirs, katana_urls, archive_params.
        """
        import json as _json
        from app.services.agent import recon_workers

        url = (target or "").strip() or (current_seed_target.get() or "")
        url = url or (getattr(self, "_fallback_target", None) or "")
        if not url:
            return _json.dumps({
                "success": False,
                "error": "no_target",
                "hint": "Pass target=https://… or paste a URL in the objective first.",
            })

        _, org_id = get_tenant_context()
        session_id = current_session_id.get() or ""
        user_id = current_user_id.get()

        spawned = await recon_workers.spawn_workers(
            url=url,
            session_id=session_id,
            pack=(pack or None),
            kinds=kinds,
            tools_manager=self,
            user_id=user_id,
            organization_id=org_id,
        )
        return _json.dumps(
            {
                "success": True,
                "spawned": spawned,
                "note": (
                    "Streams are running in the background. Continue with execute_interceptor "
                    "or other tools; completed results inject on the next think. "
                    "Call wait_recon_workers(timeout_sec=45) to join, or "
                    "spawn_recon_workers(pack='enrich') for ferox+katana. "
                    "Archive parameter leads start in the early pack."
                ),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def wait_recon_workers(
        self,
        timeout_sec: float = 45.0,
        worker_ids: Optional[List[str]] = None,
    ) -> str:
        """Wait for parallel recon streams to finish and return their briefs."""
        import json as _json
        from app.services.agent import recon_workers

        session_id = current_session_id.get() or ""
        briefs = await recon_workers.wait_workers(
            session_id,
            timeout_sec=float(timeout_sec or 45.0),
            worker_ids=worker_ids,
        )
        return _json.dumps(
            {
                "success": True,
                "count": len(briefs),
                "results": briefs,
                "prompt_block": recon_workers.format_briefs_for_prompt(briefs),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def list_recon_workers(self) -> str:
        """List status of parallel recon streams for this session."""
        import json as _json
        from app.services.agent import recon_workers

        session_id = current_session_id.get() or ""
        rows = await recon_workers.list_workers(session_id)
        return _json.dumps({"success": True, "workers": rows}, indent=2)[
            :_tool_output_max_chars()
        ]

    async def fireteam_dispatch(
        self,
        mission: str = "",
        targets: Optional[List[str]] = None,
        specialists: Optional[Any] = None,
        max_parallel: int = 4,
        capability_map: Optional[Dict[str, Any]] = None,
        mode: str = "attack",
        surface_signature: str = "",
        hypothesis_signature: str = "",
        pending_input_count: int = 0,
        pending_coverage_count: int = 0,
        completed_coverage_count: int = 0,
    ) -> str:
        """Scatter-gather: spawn N parallel specialist sub-agents on the same mission.

        Args:
            mission: Plain-English task description. Optional when capability_map
                is provided (auto-built from the map).
            targets: Hostnames / URLs the specialists should focus on.
            specialists: Names from fireteam_service, or ``"auto"`` / ``["auto"]``
                to select from the capability map (tester branching). Defaults to
                map-based attack specialists when a map is present, else recon triad.
            max_parallel: How many specialists to run concurrently.
            capability_map: Structured map from execute_deep_crawl (optional if
                the orchestrator injects session state).
            mode: ``attack`` (default), ``observed_inputs`` (leased browser inputs),
                ``cms_followup`` (fingerprinted CMS), or ``recon`` (legacy triad).
            surface_signature: Value-free observed-input inventory revision for scheduling.
            hypothesis_signature: Value-free ready-hypothesis revision for scheduling.
            pending_input_count: Number of untested observed input cells when queued.
            pending_coverage_count: Number of unattempted non-SQLi/XSS checks when queued.
            completed_coverage_count: Number of completed coverage checks when queued.
        """
        from app.services.agent.capability_map import (
            build_capability_map_from_dict,
            mission_from_capability_map,
            select_specialists_for_map,
        )
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            ensure_spawned_hypotheses,
            mission_from_hypotheses,
            seed_hypotheses_from_capability_map,
            specialists_from_open_hypotheses,
        )
        from app.services.agent.fireteam_service import run_fireteam
        from app.services.agent.autonomy_limits import current_autonomy_limits
        import time as _time
        from app.services.agent.coverage_cells import CELL_OPEN, seed_js_coverage_cells, seed_parameter_coverage_cells
        from app.services.agent.penetration_task_graph import (
            apply_executor_summary,
            claim_task_leases,
            compact_scheduler_mission,
            format_graph_for_scheduler,
            parse_executor_summary,
            persist_graph,
            ready_wave,
            sync_graph_from_brain,
            wave_changes,
        )

        # The orchestrator has a hard per-tool deadline. Keep the entire
        # specialist wave, optional rewrite, and final verification inside it
        # so completed reports and leases are reconciled before returning.
        from app.services.agent.assessment_depth import assessment_depth, fireteam_dispatch_cap
        outer_cap = fireteam_dispatch_cap(
            max(1.0, float(getattr(settings, "AGENT_TOOL_HARD_TIMEOUT_SECONDS", 600) or 600))
        )
        depth = assessment_depth()
        if depth.max_parallel_specialists > int(max_parallel or 0):
            max_parallel = depth.max_parallel_specialists
        autonomy_limits = current_autonomy_limits.get()
        if autonomy_limits:
            max_parallel = min(max(1, int(max_parallel)), autonomy_limits.max_parallel_specialists)
        outer_margin = min(60.0, outer_cap * 0.1)
        dispatch_deadline = _time.monotonic() + outer_cap - outer_margin
        reserve = min(180.0, outer_cap * 0.3)

        def _remaining_dispatch_time() -> float:
            return max(0.0, dispatch_deadline - _time.monotonic())

        cmap_raw = capability_map or getattr(self, "_capability_map", None)
        cmap = build_capability_map_from_dict(cmap_raw) if cmap_raw else None

        # Keep engagement brain in sync with the map before specialist selection.
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if cmap:
            brain = seed_hypotheses_from_capability_map(brain, cmap.to_dict())
            from app.services.agent.parameter_inventory import collect_parameter_inventory
            dispatch_inventory = collect_parameter_inventory(cmap.to_dict())
            seed_parameter_coverage_cells(brain, dispatch_inventory)
            seed_js_coverage_cells(brain, cmap.to_dict())
            from app.services.agent.runtime_mapper import ingest_capability_map_operations
            ingest_capability_map_operations(brain, cmap.to_dict())
            followup_planning = self._refresh_followups(brain, dispatch_inventory)
            self._engagement_brain = brain.to_dict()
        else:
            followup_planning = self._refresh_followups(brain)
            self._engagement_brain = brain.to_dict()

        # This entry point can be called without sync_engagement_brain. Review
        # fresh observed inputs before choosing specialists and claiming cells.
        hypothesis_planning = await self._plan_brain_hypotheses(brain)

        # Resolve specialists: "auto" → open hypotheses, else capability-map selection
        auto = False
        if specialists is None:
            auto = bool(cmap) or mode == "attack" or bool(brain.hypotheses)
            chosen = None
        elif specialists in ("auto", ["auto"], ("auto",)):
            auto = True
            chosen = None
        elif isinstance(specialists, str):
            chosen = [s.strip() for s in specialists.split(",") if s.strip()]
        else:
            chosen = list(specialists)
            if chosen == ["auto"]:
                auto = True
                chosen = None

        graph = sync_graph_from_brain(brain)
        self._engagement_brain = brain.to_dict()

        def _checkpoint_task_graph() -> None:
            """Persist leases before execution so interrupted actions stay visible."""
            try:
                from app.services.agent.action_ledger import active_run_id, record_hypotheses
                from app.services.agent.run_snapshot import save_run_snapshot

                _user_id, organization_id = get_tenant_context()
                record_hypotheses(active_run_id.get(), graph.snapshot())
                save_run_snapshot(
                    organization_id,
                    current_session_id.get() or None,
                    {
                        "engagement_brain": self._engagement_brain,
                        "capability_map": getattr(self, "_capability_map", None),
                        "current_phase": brain.phase,
                    },
                )
            except Exception:
                logger.debug("task graph checkpoint skipped", exc_info=True)

        selection_source = "explicit"
        if auto:
            open_hyps = [h for h in brain.hypotheses if h.status in ("open", "in_progress")]
            wave = ready_wave(
                graph,
                max_specialists=6,
                include_app_mapper=bool(cmap and not cmap.ready_for_attack),
            )
            if wave and mode != "recon":
                chosen = wave
                selection_source = "task_graph"
            elif open_hyps and mode != "recon":
                chosen = specialists_from_open_hypotheses(brain)
                selection_source = "hypotheses"
            else:
                chosen = select_specialists_for_map(
                    cmap,
                    include_recon=(mode == "recon"),
                )
                selection_source = "capability_map"
        if not chosen:
            chosen = (
                ["web_recon", "vuln_triage", "secrets_hunter"]
                if mode == "recon"
                else select_specialists_for_map(cmap)
            )
            selection_source = selection_source if auto else "default"

        if auto:
            chosen = [
                n for n in (chosen or [])
                if n not in ("finding_judge", "independent_verifier", "risk_assessor")
            ]

        pending_inventory_specialists: set[str] = set()
        followup_specialists: set[str] = set()
        if mode != "recon":
            pending_inventory_specialists = {
                str(cell.get("specialist") or "")
                for cell in (brain.coverage_cells or [])
                if isinstance(cell, dict)
                and cell.get("source") in {
                    "parameter_inventory", "surface_applicability", "js_inventory",
                }
                and cell.get("status") in CELL_OPEN
                and (
                    cell.get("specialist") in {"xss", "sqli", "js_secrets"}
                    or mode == "coverage_followup"
                )
            }
            if auto:
                chosen = list(dict.fromkeys([
                    *[name for name in ("js_secrets", "xss", "sqli") if name in pending_inventory_specialists],
                    *(chosen or []),
                ]))
            if mode not in _FOLLOWUP_EXCLUDED_MODES:
                from app.services.agent.fireteam_service import get_specialist
                from app.services.agent.followup_runtime import (
                    followups_enabled, policy_for, specialists_with_followups,
                )

                if followups_enabled():
                    followup_specialists = {
                        name for name in specialists_with_followups(brain, policy_for(self, brain))
                        if get_specialist(name)
                    }
                    if auto:
                        # Model-proposed follow-ups go first so the cap below
                        # cannot starve work that a new observation created.
                        chosen = list(dict.fromkeys([
                            *sorted(followup_specialists), *(chosen or []),
                        ]))
            if mode not in {"observed_inputs", "cms_followup"}:
                pending_proof_specialists = [
                    str(row.get("specialist") or "")
                    for row in (brain.proof_escalations or [])
                    if isinstance(row, dict) and row.get("status") == "pending"
                ]
                for specialist_name in pending_proof_specialists:
                    if specialist_name and specialist_name not in (chosen or []):
                        chosen = list(chosen or []) + [specialist_name]
            chosen = list(chosen or [])[:8]

        from app.services.agent.risk_assessment import pending_ra_rows
        pending_ra = pending_ra_rows(brain)
        if mode not in {"observed_inputs", "cms_followup"} and pending_ra and "risk_assessor" not in (chosen or []):
            chosen = list(chosen or []) + ["risk_assessor"]

        from app.services.agent.run_permissions import permitted_specialists
        chosen = permitted_specialists(
            chosen or [],
            allow_credential_testing=bool(self._credential_testing_allowed),
        )

        if not mission or not str(mission).strip():
            if brain.hypotheses:
                mission = mission_from_hypotheses(brain)
            elif any(
                isinstance(row, dict) and row.get("status") == "pending"
                for row in (brain.proof_escalations or [])
            ):
                mission = (
                    "Resolve the pending structured proof escalation against its matched "
                    "negative control. A signal is not a finding; satisfy or refute the "
                    "directive's proof requirements with fresh evidence."
                )
            elif cmap and cmap.target:
                mission = mission_from_capability_map(cmap)
            else:
                return "Error: mission is required (or provide a capability_map)."

        # Executors get a compact mission + per-specialist slice on the directive.
        # Do not dump the full capability map or engagement brain into every hunter.
        map_digest = ""
        if cmap and cmap.ready_for_attack:
            map_digest = (
                f"Map digest: capabilities={', '.join((cmap.capabilities or [])[:8])}. "
                f"Use the operation directive evidence, not a scan dump."
            )
        mission = compact_scheduler_mission(
            f"{mission}\n{map_digest}".strip(),
            ready_count=len(chosen or []),
            target=(cmap.target if cmap else brain.target) or "",
        )

        target_list = list(targets or [])
        if not target_list and cmap and cmap.target:
            target_list = [cmap.target]
            target_list.extend(cmap.pages_visited[:5])
        elif not target_list and brain.target:
            target_list = [brain.target]

        # Resolve the specialists' LLM the same provider-aware way the main loop
        # does (honors AI_PROVIDER / per-org config, wraps with credit fallback),
        # so a dead primary cascades to a working provider instead of failing
        # every specialist.
        llm = self._cheap_llm()

        from app.services.agent.model_router import LLMTask as _LLMTask

        def _llm_for_profile(profile):
            task = getattr(profile, "llm_task", None) or _LLMTask.OFFENSIVE
            try:
                _, org_id = get_tenant_context()
                db = SessionLocal()
                try:
                    from app.services.agent.model_router import get_llm_for_task
                    return get_llm_for_task(
                        db, org_id, task,
                        temperature=0, timeout=120, max_retries=2,
                    )
                finally:
                    db.close()
            except Exception:
                logger.warning("per-specialist LLM failed for %s", getattr(profile, "name", ""), exc_info=True)
                return llm

        from app.services.agent.aegis_pantheon import epithet_for, pantheon_line
        from app.services.agent.fireteam_service import get_specialist
        from app.services.agent.operation_directive import directives_from_hypotheses

        profiles = {n: get_specialist(n) for n in chosen if get_specialist(n)}
        default_target = target_list[0] if target_list else (cmap.target if cmap else "")
        if hypothesis_signature:
            if hypothesis_signature in brain.hypothesis_wave_history:
                return json.dumps({"selection_source": "already_dispatched_hypothesis_revision",
                                   "hypothesis_signature": hypothesis_signature})
        # A class-coverage follow-up owns a coverage cell, not an arbitrary
        # methodology card of the same specialist. Claiming that card would
        # let a class probe close unrelated hypothesis work.
        task_leases = (
            {} if mode == "coverage_followup" else claim_task_leases(graph, chosen)
        )
        represented_specialists = {
            node.specialist for node in graph.nodes.values() if node.specialist
        }
        judge_roles = {"finding_judge", "independent_verifier", "risk_assessor"}
        chosen = [
            name
            for name in chosen
            if name in task_leases
            or name not in represented_specialists
            or name in pending_inventory_specialists
            or name in followup_specialists
            or name in judge_roles
        ]
        profiles = {name: profiles[name] for name in chosen if name in profiles}
        if not chosen:
            persist_graph(brain, graph)
            self._engagement_brain = brain.to_dict()
            _checkpoint_task_graph()
            return json.dumps(
                {
                    "specialists_requested": [],
                    "specialists_run": [],
                    "selection_mode": "auto" if auto else "explicit",
                    "selection_source": "no_ready_hypothesis",
                    "task_graph": graph.snapshot(),
                    "task_graph_prompt": format_graph_for_scheduler(graph),
                    "message": (
                        "No hypothesis can be leased. Resolve dependencies or "
                        "reconcile interrupted execution before dispatch."
                    ),
                },
                indent=2,
            )
        from app.services.agent.coverage_cells import claim_coverage_cell_leases
        from app.services.agent.engagement_brain import denominator_surfaces
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        # Model-proposed follow-ups claim first; each specialist holds at most
        # one coverage lease, so the ordinary lane fills only the rest.
        followup_leases = {}
        followup_policy = None
        if followup_specialists:
            from app.services.agent.followup_runtime import (
                claim_for_specialists, policy_for,
            )

            followup_policy = policy_for(self, brain)
            followup_leases = claim_for_specialists(
                brain, [name for name in chosen if name in followup_specialists],
                followup_policy,
            )
        coverage_leases = claim_coverage_cell_leases(
            brain,
            [name for name in chosen if name not in followup_leases],
            task_leases=task_leases,
            denominator=denominator_surfaces(brain),
            allowed_observation_sources=(
                OBSERVED_INPUT_SOURCES if mode == "observed_inputs" else None
            ),
            allowed_sources=(
                frozenset({"parameter_inventory", "surface_applicability", "js_inventory"})
                if mode == "coverage_followup" else None
            ),
            excluded_test_types=(
                frozenset({"xss", "sqli"}) if mode == "coverage_followup" else None
            ),
            first_pass_only=mode == "coverage_followup",
        )
        coverage_leases = {**coverage_leases, **followup_leases}
        directives = directives_from_hypotheses(
            brain=brain,
            profiles_by_name=profiles,
            specialists=chosen,
            default_target=default_target or "",
            task_leases=task_leases,
            coverage_leases=coverage_leases,
        )
        if followup_leases:
            from app.services.agent.followup_runtime import required_identities

            for name, lease in followup_leases.items():
                directive = directives.get(name)
                needed = required_identities(brain, lease)
                if directive is not None and needed:
                    # A follow-up runs only as the identities it was approved for.
                    allowed = set(directive.allowed_identities or needed)
                    directive.allowed_identities = [i for i in needed if i in allowed]

        persist_graph(brain, graph)
        self._engagement_brain = brain.to_dict()
        _checkpoint_task_graph()

        async def _fireteam_progress(label: str, status: str) -> None:
            from app.services.agent.orchestrator import _status_callback_var

            callback = _status_callback_var.get(None)
            if callback:
                message = callback({
                    "type": "thinking",
                    "phase": "execution",
                    "thought": f"Fireteam {label}: {status}",
                })
                if asyncio.iscoroutine(message):
                    await message

        from app.services.agent.independent_verify import (
            candidate_from_dict,
            ingest_report_findings,
            run_independent_verifiers,
            verify_receipt_key,
        )

        verify_lock = asyncio.Lock()
        verified_early: set[str] = set()
        early_verify_reports: list = []
        lifted_early: list = []
        early_verdicts: dict[str, dict] = {}
        ingested_reports: set[int] = set()

        def _remember_early_verdict(live, candidate) -> None:
            """Save a verdict at the moment it is written to shared state."""
            if not candidate or not candidate.verified_at:
                return
            receipt_key = verify_receipt_key(candidate.title, candidate.target)
            early_verdicts[candidate.id] = {
                "candidate": candidate.to_dict(),
                "receipt_key": receipt_key,
                "receipt": (live.verification_receipts or {}).get(receipt_key),
                "coverage_cell": next((
                    dict(cell) for cell in live.coverage_cells
                    if candidate.coverage_cell_id and cell.get("id") == candidate.coverage_cell_id
                ), None),
                "authorization_rows": [
                    dict(row) for row in live.authorization_matrix
                    if candidate.hypothesis_id
                    and row.get("hypothesis_id") == candidate.hypothesis_id
                ],
                "proof_escalation": next((
                    dict(row) for row in live.proof_escalations
                    if candidate.proof_escalation_id
                    and row.get("id") == candidate.proof_escalation_id
                ), None),
                "hypothesis": next((
                    h for h in live.hypotheses
                    if candidate.hypothesis_id and h.id == candidate.hypothesis_id
                ), None),
            }

        def _capture_early_verdicts(candidate_ids: set[str]) -> None:
            """Also capture test doubles and verifiers that update the brain directly."""
            live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            for raw in live.candidates or []:
                candidate = candidate_from_dict(raw)
                if candidate and candidate.id in candidate_ids and candidate.id not in early_verdicts:
                    _remember_early_verdict(live, candidate)

        async def _verify_completed_hunter(report) -> None:
            """Verify submitted candidates while sibling hunters keep working."""
            async with verify_lock:
                live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                lifted = ingest_report_findings(live, [report])
                ingested_reports.add(id(report))
                if getattr(report, "key_findings", None):
                    self._engagement_brain = live.to_dict()
                if lifted:
                    lifted_early.extend(lifted)
                pending = [
                    candidate
                    for candidate in (
                        candidate_from_dict(raw) for raw in (live.candidates or [])
                    )
                    if candidate and candidate.status == "pending"
                    and candidate.id not in verified_early
                ]
                if not pending:
                    return
                verified_early.update(candidate.id for candidate in pending)
                threat_slice = ""
                if live.threat_model:
                    try:
                        from app.services.agent.threat_model import format_threat_model_for_prompt
                        threat_slice = format_threat_model_for_prompt(live.threat_model)[:2500]
                    except Exception:
                        pass
                previous_observer = getattr(self, "_early_verdict_observer", None)
                self._early_verdict_observer = _remember_early_verdict
                try:
                    early_verify_reports.extend(await run_independent_verifiers(
                        pending,
                        llm=llm,
                        tools_manager=self,
                        targets=target_list,
                        threat_slice=threat_slice,
                        max_parallel=1,
                    ))
                    _capture_early_verdicts({candidate.id for candidate in pending})
                except Exception:
                    logger.exception("Early independent verification failed; final wave will retry pending candidates")
                finally:
                    self._early_verdict_observer = previous_observer

        def _preserve_live_execution_state() -> None:
            """Keep candidate and verifier writes made during a parallel hunt wave."""
            live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            for field_name in (
                "application_operations", "authorization_matrix", "proof_receipts",
                "candidates", "coverage", "coverage_cells", "proof_escalations",
                "verification_receipts",
            ):
                value = getattr(live, field_name, None)
                if value:
                    setattr(brain, field_name, value)
            applied_early_ids: set[str] = set()
            for snapshot in early_verdicts.values():
                candidate = snapshot["candidate"]
                current = next((raw for raw in brain.candidates
                                if isinstance(raw, dict) and raw.get("id") == candidate["id"]), None)
                if current and current.get("revision") != candidate.get("revision"):
                    continue
                applied_early_ids.add(candidate["id"])
                brain.candidates = [raw for raw in brain.candidates
                                    if not isinstance(raw, dict) or raw.get("id") != candidate["id"]]
                brain.candidates.append(dict(candidate))
                key, receipt = snapshot["receipt_key"], snapshot["receipt"]
                brain.verification_receipts.pop(key, None)
                if receipt:
                    brain.verification_receipts[key] = dict(receipt)
                for field_name, row in (
                    ("coverage_cells", snapshot["coverage_cell"]),
                    ("proof_escalations", snapshot["proof_escalation"]),
                ):
                    if row:
                        rows = getattr(brain, field_name)
                        rows[:] = [existing for existing in rows if existing.get("id") != row.get("id")]
                        rows.append(dict(row))
                if snapshot["authorization_rows"]:
                    brain.authorization_matrix = [
                        row for row in brain.authorization_matrix
                        if row.get("hypothesis_id") != candidate.get("hypothesis_id")
                    ] + [dict(row) for row in snapshot["authorization_rows"]]
                hypothesis = snapshot["hypothesis"]
                if hypothesis:
                    for existing in brain.hypotheses:
                        if existing.id == hypothesis.id:
                            existing.status = hypothesis.status
                            existing.evidence = hypothesis.evidence
                            break
            verified_hypotheses = {
                str(raw.get("hypothesis_id") or "")
                for raw in (brain.candidates or [])
                if isinstance(raw, dict) and raw.get("verified_at") and raw.get("hypothesis_id")
            }
            from app.services.agent.penetration_task_graph import NODE_PROVEN, NODE_RETRY

            live_hypotheses = {h.id: h for h in live.hypotheses if h.id in verified_hypotheses}
            live_hypotheses.update({
                snapshot["hypothesis"].id: snapshot["hypothesis"]
                for candidate_id, snapshot in early_verdicts.items()
                if candidate_id in applied_early_ids and snapshot["hypothesis"]
            })
            for hypothesis in brain.hypotheses:
                latest = live_hypotheses.get(hypothesis.id)
                if not latest:
                    continue
                hypothesis.status = latest.status
                hypothesis.evidence = latest.evidence
                node = graph.nodes.get(hypothesis.id)
                if node and latest.status == "proven":
                    node.status = NODE_PROVEN
                elif node and node.status == NODE_PROVEN:
                    node.status = NODE_RETRY

        from dataclasses import replace as _dc_replace

        bounded_first_pass = mode in {"observed_inputs", "coverage_followup"}
        first_wave_profiles = (
            [
                _dc_replace(
                    profiles[name],
                    max_iterations=min(profiles[name].max_iterations, 4),
                    max_tools_per_iteration=min(profiles[name].max_tools_per_iteration, 3),
                )
                for name in chosen if name in profiles
            ]
            if bounded_first_pass else chosen
        )
        # Deep waves may use the longer dispatch cap; the bounded observed-input
        # first pass stays a quick fixed-payload sweep in every mode.
        attack_wave_cap = 420.0 if depth.fireteam_timeout_seconds <= 0 else max(
            420.0, outer_cap - outer_margin - reserve,
        )
        first_wave_timeout = min(
            150.0 if bounded_first_pass else attack_wave_cap,
            max(1.0, _remaining_dispatch_time() - reserve),
        )
        result = await run_fireteam(
            mission=mission,
            targets=target_list,
            specialists=first_wave_profiles,
            llm=llm,
            tools_manager=self,
            max_parallel=max_parallel,
            directives=directives,
            llm_for_specialist=_llm_for_profile,
            progress_callback=_fireteam_progress,
            report_callback=_verify_completed_hunter,
            member_timeout_sec=max(1.0, first_wave_timeout - 10.0),
            wave_timeout_sec=first_wave_timeout,
        )

        from app.services.agent.auto_prompter import (
            apply_rewrite_to_directive,
            apply_rewrite_to_profile,
            record_failure_approach,
            should_rewrite,
        )
        executor_summaries = [parse_executor_summary(r) for r in result.reports]
        spawned: list = []
        rewrites: list = []
        for summary, report in zip(executor_summaries, result.reports):
            spawned.extend(apply_executor_summary(graph, brain, summary))
            if summary.rewrite_hint.startswith("execution_timeout"):
                continue
            rewrite = should_rewrite(graph, summary, report)
            if rewrite:
                rewrites.append(rewrite)
                record_failure_approach(brain, summary, rewrite.failure)

        if spawned:
            ensure_spawned_hypotheses(brain, spawned)
            graph = sync_graph_from_brain(brain)

        retry_names = []
        retry_window = min(180.0, _remaining_dispatch_time() - reserve)
        retry_deferred = bool(rewrites and (bounded_first_pass or retry_window < 90.0))
        if rewrites and retry_window >= 90.0 and not bounded_first_pass:
            retry_leases = claim_task_leases(
                graph, [rewrite.specialist for rewrite in rewrites]
            )
            retry_directive_bases = directives_from_hypotheses(
                brain=brain,
                profiles_by_name=profiles,
                specialists=retry_leases,
                default_target=default_target or "",
                task_leases=retry_leases,
                coverage_leases=coverage_leases,
            )
            retry_profiles = []
            retry_directives = {}
            for rewrite in rewrites:
                base = get_specialist(rewrite.specialist)
                if not base:
                    continue
                retry_profiles.append(
                    apply_rewrite_to_profile(_dc_replace(base), rewrite)
                )
                d = retry_directive_bases.get(rewrite.specialist)
                if d is not None:
                    retry_directives[rewrite.specialist] = apply_rewrite_to_directive(d, rewrite)
                retry_names.append(rewrite.specialist)
            if retry_profiles:
                _preserve_live_execution_state()
                persist_graph(brain, graph)
                self._engagement_brain = brain.to_dict()
                _checkpoint_task_graph()
                retry_result = await run_fireteam(
                    mission=mission,
                    targets=target_list,
                    specialists=retry_profiles,
                    llm=llm,
                    tools_manager=self,
                    max_parallel=max_parallel,
                    directives=retry_directives,
                    llm_for_specialist=_llm_for_profile,
                    progress_callback=_fireteam_progress,
                    report_callback=_verify_completed_hunter,
                    member_timeout_sec=max(1.0, retry_window - 10.0),
                    wave_timeout_sec=retry_window,
                )
                result.reports.extend(list(retry_result.reports))
                result.specialists_run = list(result.specialists_run) + list(
                    retry_result.specialists_run
                )
                result.total_tool_calls += retry_result.total_tool_calls
                result.duration_seconds += retry_result.duration_seconds
                result.merged_summary = (
                    (result.merged_summary or "")
                    + "\n\n# Auto-prompter rewrite wave\n"
                    + (retry_result.merged_summary or "")
                )
                retry_summaries = [parse_executor_summary(r) for r in retry_result.reports]
                executor_summaries.extend(retry_summaries)
                for summary in retry_summaries:
                    spawned.extend(apply_executor_summary(graph, brain, summary))
                if spawned:
                    ensure_spawned_hypotheses(brain, spawned)
                    graph = sync_graph_from_brain(brain)

        # Specialist and verifier tools write to the manager-owned brain while
        # the wave runs. Preserve those receipts before persisting graph results.
        _preserve_live_execution_state()
        if hypothesis_signature and result.specialists_run:
            # Record only an executed wave. An exception before run_fireteam
            # returns leaves this revision available for a bounded retry.
            brain.hypothesis_wave_history = [
                *brain.hypothesis_wave_history[-99:], hypothesis_signature,
            ]
        persist_graph(brain, graph)
        self._engagement_brain = brain.to_dict()
        _checkpoint_task_graph()

        self._require_independent_verify = True
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        lifted = [*lifted_early, *ingest_report_findings(
            brain, [report for report in result.reports if id(report) not in ingested_reports]
        )]
        from app.services.agent.coverage_cells import release_coverage_cell_lease

        reports_by_specialist = {}
        for report in result.reports:
            reports_by_specialist.setdefault(report.specialist, []).append(report)
        for specialist, lease in coverage_leases.items():
            reports = reports_by_specialist.get(specialist, [])
            if specialist in followup_leases:
                from app.services.agent.followup_runtime import finish_followup

                finish_followup(
                    brain, lease, reports, run_id=followup_policy.run_id,
                    candidate_id=next((
                        str(raw.get("id") or "") for raw in (brain.candidates or [])
                        if isinstance(raw, dict)
                        and raw.get("coverage_cell_id") == lease.coverage_cell_id
                    ), ""),
                )
                continue
            final_report = reports[-1] if reports else None
            evidence_ids = [
                evidence_id
                for report in reports
                for invocation in (report.tool_calls or [])
                for evidence_id in (invocation.evidence_ids or [])
            ]
            candidate_id = next(
                (
                    str(raw.get("id") or "")
                    for raw in (brain.candidates or [])
                    if isinstance(raw, dict)
                    and raw.get("coverage_cell_id") == lease.coverage_cell_id
                ),
                "",
            )
            release_coverage_cell_lease(
                brain,
                lease,
                verdict=(getattr(final_report, "verdict", "") or "inconclusive"),
                evidence_ids=evidence_ids,
                candidate_id=candidate_id,
                reason=(
                    getattr(final_report, "error", "")
                    or getattr(final_report, "evidence", "")
                    or getattr(final_report, "summary", "")
                    if final_report
                    else "Specialist did not return a coverage receipt"
                ),
            )
        # Endpoints a specialist saw outside its lane become capture events,
        # so the follow-up planner validates and assigns them like any capture.
        from urllib.parse import urlsplit

        from app.services.agent.fireteam_service import validated_leads
        from app.services.agent.observation_followups import capture_facts

        lead_hosts = {
            urlsplit(t if "://" in t else f"https://{t}").hostname or ""
            for t in [*target_list, default_target or ""] if t
        }
        leads_recorded = 0
        for report in result.reports:
            for lead in validated_leads(report, lead_hosts):
                if self._record_followup_event(
                    brain, kind="capture", identity="anonymous",
                    evidence_ids=lead["evidence_ids"],
                    facts=capture_facts(lead["method"], lead["url"]),
                ) is not None:
                    leads_recorded += 1
        # Apply planning that finished during the wave and queue the results
        # this wave produced, so the next dispatch can claim their follow-ups.
        followup_planning = self._refresh_followups(brain)
        self._engagement_brain = brain.to_dict()
        pending = [
            c
            for c in (candidate_from_dict(raw) for raw in (brain.candidates or []))
            if c and c.status == "pending"
        ]
        verify_reports: list = list(early_verify_reports)
        verification_window = _remaining_dispatch_time() - min(30.0, reserve / 2)
        verification_deferred = bool(pending and verification_window < 15.0)
        if pending and verification_window >= 15.0:
            threat_slice = ""
            if brain.threat_model:
                try:
                    from app.services.agent.threat_model import format_threat_model_for_prompt
                    threat_slice = format_threat_model_for_prompt(brain.threat_model)[:2500]
                except Exception:
                    threat_slice = ""
            try:
                verify_reports.extend(await asyncio.wait_for(
                    run_independent_verifiers(
                        pending,
                        llm=llm,
                        tools_manager=self,
                        targets=target_list,
                        threat_slice=threat_slice,
                        max_parallel=max_parallel,
                    ),
                    timeout=verification_window,
                ))
            except asyncio.TimeoutError:
                verification_deferred = True
                logger.warning("Fireteam verification deferred after %.0fs", verification_window)
            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            _checkpoint_task_graph()
        out = {
            # What this wave changed, first and compact, so the planner reacts
            # to it even when the large fields below are dropped for size.
            "wave_changes": wave_changes(
                executor_summaries,
                candidates_lifted=len(lifted),
                spawned=spawned,
                rewrites=[r.specialist for r in rewrites],
                leads_recorded=leads_recorded,
            ),
            "commander": pantheon_line("orchestrator"),
            "mission": result.mission[:2000],
            "surface_signature": surface_signature[:32],
            "pending_input_count": max(0, pending_input_count) if isinstance(pending_input_count, int) else 0,
            "specialists_requested": chosen,
            "specialists_epithets": {
                n: epithet_for(n) for n in chosen
            },
            "operation_directives": {
                n: d.to_dict() for n, d in directives.items()
            },
            "task_leases": {
                name: lease.to_dict() for name, lease in task_leases.items()
            },
            "coverage_leases": {
                name: lease.to_dict() for name, lease in coverage_leases.items()
            },
            "parameter_coverage": {
                name: {
                    "total": sum(1 for c in brain.coverage_cells if c.get("source") == "parameter_inventory" and c.get("specialist") == name),
                    "remaining": sum(1 for c in brain.coverage_cells if c.get("source") == "parameter_inventory" and c.get("specialist") == name and c.get("status") not in {"finding", "tested_clean", "skipped"}),
                }
                for name in ("xss", "sqli")
            },
            "js_coverage": {
                "total": sum(1 for c in brain.coverage_cells if c.get("source") == "js_inventory"),
                "remaining": sum(1 for c in brain.coverage_cells if c.get("source") == "js_inventory" and c.get("status") not in {"finding", "tested_clean", "skipped"}),
            },
            "specialists_run": result.specialists_run,
            "hypothesis_planning": hypothesis_planning,
            "followup_planning": followup_planning,
            "followup_leases": {
                name: lease.to_dict() for name, lease in followup_leases.items()
            },
            "selection_mode": "auto" if auto else "explicit",
            "selection_source": selection_source,
            "capability_map_ready": bool(cmap and cmap.ready_for_attack),
            "task_graph": graph.snapshot(),
            "task_graph_prompt": format_graph_for_scheduler(graph),
            "executor_summaries": [s.to_dict() for s in executor_summaries],
            "auto_prompter_rewrites": [
                {"specialist": r.specialist, "failure": r.failure}
                for r in rewrites
            ],
            "retry_deferred": retry_deferred,
            "verification_deferred": verification_deferred,
            "spawned": spawned,
            "open_hypotheses": [
                {"id": h.id, "title": h.title, "specialist": h.specialist, "status": h.status}
                for h in brain.hypotheses
                if h.status in ("open", "in_progress")
            ][:12],
            "engagement_brain": getattr(self, "_engagement_brain", None),
            "total_tool_calls": result.total_tool_calls,
            "duration_seconds": result.duration_seconds,
            "merged_summary": result.merged_summary,
            "candidates_lifted": [c.to_dict() for c in lifted],
            "verify_wave": verify_reports,
            "pending_candidates": [
                c for c in (brain.candidates or [])
                if (c.get("status") if isinstance(c, dict) else "") == "pending"
            ],
            "reports": [
                {
                    "specialist": r.specialist,
                    "epithet": epithet_for(r.specialist),
                    "role": r.role,
                    "summary": r.summary,
                    "verdict": r.verdict,
                    "hypothesis_ids": r.hypothesis_ids,
                    "coverage_cell_id": r.coverage_cell_id,
                    "coverage_lease_id": r.coverage_lease_id,
                    "evidence": (r.evidence or "")[:800],
                    "spawn": r.spawn,
                    "key_findings": r.key_findings,
                    "tool_calls": [
                        {"tool": t.tool, "success": t.success, "summary": t.summary[:500]}
                        for t in r.tool_calls
                    ],
                    "duration_seconds": r.duration_seconds,
                    "error": r.error,
                }
                for r in result.reports
            ],
        }
        output_limit = _tool_output_max_chars()
        serialized = json.dumps(out, indent=2)
        if len(serialized) <= output_limit:
            return serialized
        omitted = []
        for key in ("engagement_brain", "task_graph", "reports", "executor_summaries", "operation_directives"):
            out.pop(key, None)
            omitted.append(key)
            out["omitted_large_fields"] = omitted
            serialized = json.dumps(out, indent=2)
            if len(serialized) <= output_limit:
                return serialized
        return json.dumps({
            "wave_changes": out["wave_changes"],
            "specialists_run": out["specialists_run"],
            "hypothesis_planning": out["hypothesis_planning"],
            "followup_planning": out["followup_planning"],
            "followup_leases": out["followup_leases"],
            "selection_source": out["selection_source"],
            "task_leases": out["task_leases"],
            "coverage_leases": out["coverage_leases"],
            "parameter_coverage": out["parameter_coverage"],
            "js_coverage": out["js_coverage"],
            "task_graph_prompt": out["task_graph_prompt"][:2000],
            "merged_summary": out["merged_summary"][:2000],
            "retry_deferred": retry_deferred,
            "verification_deferred": verification_deferred,
            "omitted_large_fields": omitted,
        })
