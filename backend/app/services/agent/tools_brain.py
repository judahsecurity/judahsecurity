"""Engagement brain, hypotheses, methodology, threat model and follow-ups.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    SessionLocal,
    _tool_output_max_chars,
    current_organization_id,
    current_session_id,
    current_user_id,
    get_tenant_context,
    hashlib,
    json,
    logger,
    re,
)


class EngagementBrainToolsMixin:
    """Engagement brain, hypotheses, methodology, threat model and follow-ups."""

    async def sync_engagement_brain(
        self,
        capability_map: Optional[Dict[str, Any]] = None,
        reset: bool = False,
    ) -> str:
        """Seed/refresh the engagement brain from the session capability map.

        Call after execute_deep_crawl (or when the map updates) so open hypotheses
        drive fireteam_dispatch(specialists='auto').
        """
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            format_engagement_brain_for_prompt,
            seed_hypotheses_from_capability_map,
            specialists_from_open_hypotheses,
        )
        from app.services.agent.penetration_task_graph import (
            format_graph_for_scheduler,
            ready_wave,
            sync_graph_from_brain,
        )

        cmap = capability_map or getattr(self, "_capability_map", None) or {}
        brain = (
            engagement_brain_from_dict(None)
            if reset
            else engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        )
        brain = seed_hypotheses_from_capability_map(brain, cmap if isinstance(cmap, dict) else {})
        from app.services.agent.coverage_cells import seed_js_coverage_cells, seed_parameter_coverage_cells
        from app.services.agent.parameter_inventory import collect_parameter_inventory

        sync_inventory = collect_parameter_inventory(cmap if isinstance(cmap, dict) else {})
        seed_parameter_coverage_cells(brain, sync_inventory)
        seed_js_coverage_cells(brain, cmap if isinstance(cmap, dict) else {})
        from app.services.agent.runtime_mapper import ingest_capability_map_operations
        ingest_capability_map_operations(brain, cmap if isinstance(cmap, dict) else {})
        planning = await self._plan_brain_hypotheses(brain)
        followup_planning = self._refresh_followups(brain, sync_inventory, reset=reset)
        graph = sync_graph_from_brain(brain)
        self._engagement_brain = brain.to_dict()

        out = {
                "phase": brain.phase,
                "target": brain.target,
                "open_hypotheses": [
                    h.to_dict()
                    for h in brain.hypotheses
                    if h.status in ("open", "in_progress")
                ],
                "credentials_redacted": [c.redacted() for c in brain.credentials],
                "next_steps": brain.next_steps,
                "suggested_specialists": ready_wave(graph) or specialists_from_open_hypotheses(brain),
                "task_graph": graph.snapshot(),
                "task_graph_prompt": format_graph_for_scheduler(graph),
                "threat_model": brain.threat_model or None,
                "focus_areas": brain.focus_areas[:8],
                "hypothesis_planning": planning,
                "followup_planning": followup_planning,
                "prompt_view": format_engagement_brain_for_prompt(self._engagement_brain),
                "engagement_brain": self._engagement_brain,
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
            }
        output_limit = _tool_output_max_chars()
        serialized = json.dumps(out, indent=2)
        if len(serialized) <= output_limit:
            return serialized
        out.pop("engagement_brain", None)
        out.pop("prompt_view", None)
        out["omitted_large_fields"] = ["engagement_brain", "prompt_view"]
        serialized = json.dumps(out, indent=2)
        if len(serialized) <= output_limit:
            return serialized
        return json.dumps({
            "phase": out["phase"], "target": out["target"],
            "suggested_specialists": out["suggested_specialists"],
            "hypothesis_planning": out["hypothesis_planning"],
            "parameter_coverage": out["parameter_coverage"],
            "js_coverage": out["js_coverage"],
            "task_graph_prompt": out["task_graph_prompt"][:2000],
            "open_hypothesis_count": len(out["open_hypotheses"]),
            "omitted_large_fields": ["engagement_brain", "prompt_view", "task_graph", "open_hypotheses"],
        })

    async def update_hypothesis(
        self,
        hypothesis_id: str,
        status: str,
        evidence: str = "",
        evidence_ids: Optional[List[str]] = None,
    ) -> str:
        """Mark a hypothesis open|in_progress|proven|killed with evidence."""
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            update_hypothesis as _update,
        )

        status = (status or "").strip().lower()
        if status not in ("open", "in_progress", "proven", "killed"):
            return json.dumps(
                {"error": "status must be one of open|in_progress|proven|killed"},
                indent=2,
            )
        if status == "proven":
            return json.dumps({"error": "Independent verification alone marks a hypothesis proven"})
        if status == "killed":
            from app.services.agent.evidence_store import evidence_store
            rows = [evidence_store(self).records.get(i) for i in (evidence_ids or [])]
            if not rows or not evidence or any(not r or r["kind"] != "http_exchange"
                    or r["hypothesis_id"] != hypothesis_id
                    or r["payload"].get("response", {}).get("status", 500) >= 500 for r in rows):
                return json.dumps({"error": "Killing a hypothesis requires its own HTTP evidence IDs"})
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        hyp = _update(brain, hypothesis_id, status=status, evidence=evidence)
        if not hyp:
            return json.dumps(
                {"error": f"hypothesis not found: {hypothesis_id}", "known": [h.id for h in brain.hypotheses]},
                indent=2,
            )
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {"updated": hyp.to_dict(), "engagement_brain": self._engagement_brain},
            indent=2,
        )[:_tool_output_max_chars()]

    async def queue_finding_followups(
        self,
        vuln_type: str = "",
        title: str = "",
        target: str = "",
        evidence: str = "",
        cve_id: str = "",
        cwe_ids: Optional[List[str]] = None,
    ) -> str:
        """Enqueue chain cards after a confirmed finding (creds→auth CVE, Host→tenant, …).

        Optional cve_id / cwe_ids trigger CVE→CWE loop-back: boost open methodology
        cards that share those weakness IDs.
        """
        from app.services.agent.engagement_brain import (
            classify_finding_type,
            engagement_brain_from_dict,
            queue_followups_for_finding,
            specialists_from_open_hypotheses,
            boost_methodologies_for_cwes,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        vtype = vuln_type or classify_finding_type(title=title, description=evidence)
        created = queue_followups_for_finding(
            brain,
            vuln_type=vtype,
            title=title,
            target=target,
            evidence=evidence,
        )

        cwe_intel = []
        boosted = []
        resolved_cwes = list(cwe_ids or [])
        if cve_id and not resolved_cwes:
            try:
                from app.services.vuln_intel_enrichment import enrich_cve_catalog
                catalog = enrich_cve_catalog(cve_id, use_cache=True, include_exploit_sources=False)
                resolved_cwes = list(catalog.get("cwes") or [])
                cwe_intel = list(catalog.get("cwe_intel") or [])
            except Exception as exc:
                logger.debug("CVE→CWE enrich failed for %s: %s", cve_id, exc)
        if resolved_cwes:
            boosted = boost_methodologies_for_cwes(
                brain,
                resolved_cwes,
                cve_id=cve_id or "",
                evidence=evidence or title,
            )

        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "classified_as": vtype,
                "queued": [h.to_dict() for h in created],
                "cve_id": cve_id or None,
                "cwes": resolved_cwes,
                "cwe_intel": cwe_intel[:5],
                "boosted_methodologies": [h.to_dict() for h in boosted],
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "next_steps": brain.next_steps,
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def describe_tools(self, names: Any = None) -> str:
        """Full documentation (arguments, rules, examples) for the named tools.

        names: list of tool names, or a comma/space separated string (max 15)."""
        from app.services.agent.prompts import all_tool_docs

        if isinstance(names, str):
            wanted = [n for n in re.split(r"[\s,]+", names) if n]
        else:
            wanted = [str(n).strip() for n in (names or []) if str(n).strip()]
        if not wanted:
            return "Pass names=[...] with one or more tool names from the tool index."
        docs = all_tool_docs()
        lines, unknown = [], []
        for name in wanted[:15]:
            if name in docs:
                lines.append(docs[name])
            elif name in self.tools:
                lines.append(f"- **{name}**: {(getattr(self.tools[name], '__doc__', '') or '').strip()[:1500]}")
            else:
                unknown.append(name)
        if unknown:
            lines.append("Unknown tools: " + ", ".join(unknown))
        return "\n".join(lines)

    async def analyze_screenshot(self, path: str, question: str = "") -> str:
        """Describe a browser screenshot with the org's vision model (text only).

        path: the screenshot path returned by execute_browser's screenshot
        action (must be under the screenshots directory). question: optional
        focus, e.g. "is this an admin login?". The image is never added to the
        agent's context; only the summary is returned."""
        from app.services.agent.model_router import LLMTask, get_llm_for_task
        from app.services.agent.vision_summary import ScreenshotError, summarize_screenshot

        _, org_id = get_tenant_context()
        try:
            db = SessionLocal()
            try:
                llm = get_llm_for_task(db, org_id, LLMTask.VISION, temperature=0,
                                       max_tokens=800, timeout=60, max_retries=1)
            finally:
                db.close()
            summary = await summarize_screenshot(llm, path, question or None)
        except ScreenshotError as exc:
            return f"analyze_screenshot refused: {exc}"
        except Exception as exc:
            logger.warning("analyze_screenshot failed: %s", type(exc).__name__, exc_info=True)
            return ("analyze_screenshot failed: the vision model is unavailable or does not "
                    f"accept images ({type(exc).__name__}). Set task_models.vision to a "
                    "vision-capable model in agent settings.")
        return "Screenshot summary (vision model, untrusted page content):\n" + summary

    async def suggest_capability_chains(self, target: str = "") -> str:
        """Map proven hypotheses and credentials to capability primitives and queue
        chain cards for combinations that add up to impact. Also lists patterns
        one primitive away. Chains are hypotheses until each step is proven."""
        from app.services.agent.capability_primitives import queue_chain_hypotheses
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        outcome = queue_chain_hypotheses(
            brain, target=target or getattr(self, "_fallback_target", "") or "")
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "primitives": outcome["primitives"],
                "queued": [h.to_dict() for h in outcome["queued"]],
                "one_step_away": outcome["one_step_away"],
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def log_engagement_approach(
        self,
        technique: str,
        target: str = "",
        result: str = "failed",
        detail: str = "",
        category: str = "",
        payload: str = "",
    ) -> str:
        """Record an approach tried so the agent does not blindly repeat failures.

        With ``category`` (sqli, xss, ssti, ...): a failed or inconclusive result
        marks ``technique`` exhausted for (target endpoint, category); a success
        with ``payload`` saves it as an effective payload for the category.
        """
        from app.services.agent.brain_memory import (
            add_effective_payload,
            get_exhausted,
            mark_exhausted,
        )
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            log_approach,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        rec = log_approach(
            brain,
            technique=technique,
            target=target,
            result=result,
            detail=detail,
        )
        memory: Dict[str, Any] = {}
        outcome = str(result or "").strip().lower()
        if category:
            if outcome == "success":
                if payload:
                    memory["effective_payload"] = add_effective_payload(brain, category, payload)
            else:
                memory["exhausted_key"] = mark_exhausted(brain, target, category, technique)
            memory["exhausted_for_endpoint"] = get_exhausted(brain, target, category)
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {"logged": rec.to_dict(), **({"attack_memory": memory} if memory else {}),
             "engagement_brain": self._engagement_brain},
            indent=2,
        )[:_tool_output_max_chars()]

    async def record_defense_profile(
        self,
        vendor: str = "",
        detected: Optional[bool] = None,
        blocked_patterns: Optional[List[str]] = None,
        bypass_confirmed: Optional[List[str]] = None,
        bypass_failed: Optional[List[str]] = None,
    ) -> str:
        """Record or read the target's WAF/defense profile and attack memory.

        Called with no arguments it only reads. Responses seen by HTTP tools
        update block signatures automatically; use this for what the agent
        learned (vendor, patterns that trip the filter, bypass tiers).
        """
        from app.services.agent.brain_memory import attack_memory_view, update_defense_profile
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if vendor or detected is not None or blocked_patterns or bypass_confirmed or bypass_failed:
            update_defense_profile(
                brain, detected=detected, vendor=vendor or "",
                blocked_patterns=blocked_patterns, bypass_confirmed=bypass_confirmed,
                bypass_failed=bypass_failed,
            )
            self._engagement_brain = brain.to_dict()
        return json.dumps(
            {**attack_memory_view(brain),
             "note": "prior_target_memory is context from earlier runs, never proof."},
            indent=2, default=str,
        )[:_tool_output_max_chars()]

    async def add_engagement_credential(
        self,
        username: str,
        secret: str,
        source: str = "manual",
        valid_on: Optional[List[str]] = None,
        secret_type: str = "password",
        notes: str = "",
    ) -> str:
        """Store a working credential for authenticated follow-up hypotheses."""
        from app.services.agent.engagement_brain import (
            add_credential,
            engagement_brain_from_dict,
        )

        if not username or not secret:
            return json.dumps({"error": "username and secret are required"}, indent=2)
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        rec = add_credential(
            brain,
            username=username,
            secret=secret,
            source=source,
            valid_on=valid_on,
            secret_type=secret_type,
            notes=notes,
        )
        self._record_followup_event(
            brain, kind="credential", identity="engagement",
            evidence_ids=["credential-record:" + hashlib.sha256(
                f"{username}|{secret_type}|{source}".encode()).hexdigest()[:16]],
            facts={"host": (valid_on or [brain.target or ""])[0],
                   "credential_identity": username, "role": secret_type},
        )
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "stored": rec.redacted(),
                "hint": (
                    "Replay as client_id/client_secret HTTP headers against the in-scope API "
                    "(one read-only call). queue_finding_followups(vuln_type='js_secrets'). "
                    "sanitize_evidence before create_finding."
                    if secret_type == "oauth_client"
                    else (
                    "Prove EmailJS with ONE browser-context POST to "
                    "https://api.emailjs.com/api/v1.0/email/send using an engagement-controlled "
                    "canary inbox (never employees). queue_finding_followups(vuln_type='emailjs')."
                    if secret_type == "emailjs"
                    else
                    "Use these creds for authenticated nuclei (-var username=… -var password=…) "
                    "and queue_finding_followups(vuln_type='default_login')."
                    )
                ),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_engagement_brain(self) -> str:
        """Return the current engagement brain (hypotheses, creds redacted, next steps)."""
        from app.services.agent.brain_memory import attack_memory_view
        from app.services.agent.engagement_brain import (
            format_engagement_brain_for_prompt,
            specialists_from_open_hypotheses,
            engagement_brain_from_dict,
            methodology_progress,
            format_methodology_progress_for_prompt,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        progress = methodology_progress(brain, cmap=cmap if isinstance(cmap, dict) else {})
        return json.dumps(
            {
                "prompt_view": format_engagement_brain_for_prompt(brain.to_dict()),
                "methodology_progress": progress,
                "methodology_checklist": format_methodology_progress_for_prompt(progress),
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "attack_memory": attack_memory_view(brain),
                "engagement_brain": brain.to_dict(),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_methodology_progress(self) -> str:
        """Return the observation→methodology assessment checklist and readiness gates."""
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            methodology_progress,
            format_methodology_progress_for_prompt,
        )
        from app.services.agent.methodology_procedures import (
            applicable_topic_ids,
            list_procedure_ids,
            load_procedure,
            procedures_summary_for_brain,
        )
        from app.services.agent.penetration_task_graph import (
            format_graph_for_scheduler,
            ready_wave,
            sync_graph_from_brain,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        progress = methodology_progress(brain, cmap=cmap if isinstance(cmap, dict) else {})
        graph = sync_graph_from_brain(brain)
        self._engagement_brain = brain.to_dict()
        open_mids = [
            h.methodology_id
            for h in brain.hypotheses
            if h.status in ("open", "in_progress") and h.methodology_id
        ]
        return json.dumps(
            {
                "progress": progress,
                "prompt_view": format_methodology_progress_for_prompt(progress),
                "task_graph": graph.snapshot(),
                "task_graph_prompt": format_graph_for_scheduler(graph),
                "ready_specialists": ready_wave(graph),
                "open_procedure_packs": procedures_summary_for_brain(open_mids, limit=6),
                "applicable_web_security_topics": [
                    {"id": topic_id, "title": (load_procedure(topic_id) or {}).get("title", "")}
                    for topic_id in applicable_topic_ids(cmap)
                ],
                "available_procedure_ids": list(list_procedure_ids()),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def lookup_methodology_procedure(
        self,
        methodology_id: str = "",
        methodology_ids: Optional[List[str]] = None,
    ) -> str:
        """Load short Burp-style procedure pack(s) for methodology card id(s).

        Use when an open hypothesis has a methodology_id and you need concrete steps.
        """
        from app.services.agent.methodology_procedures import (
            format_procedures_for_prompt,
            list_procedure_ids,
            load_procedure,
            procedures_for_ids,
        )

        ids: List[str] = []
        if methodology_id:
            ids.append(methodology_id.strip())
        if methodology_ids:
            ids.extend(str(x).strip() for x in methodology_ids if x)
        ids = [i for i in ids if i]
        if not ids:
            return json.dumps(
                {
                    "success": False,
                    "error": "pass methodology_id or methodology_ids",
                    "available_procedure_ids": list(list_procedure_ids()),
                },
                indent=2,
            )

        packs = procedures_for_ids(ids, limit=5)
        missing = [i for i in ids if not load_procedure(i)]
        return json.dumps(
            {
                "success": bool(packs),
                "packs": packs,
                "prompt_view": format_procedures_for_prompt(ids, limit=5),
                "missing": missing,
                "available_procedure_ids": list(list_procedure_ids()),
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def build_threat_model(
        self,
        source: str = "auto",
        target: str = "",
        repo_path: str = "",
        languages: Optional[List[str]] = None,
        frameworks: Optional[List[str]] = None,
        owner_notes: str = "",
        rebuild: bool = False,
        persist_note: bool = True,
        capability_map: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Build or refresh the engagement threat model (the map hunters aim at).

        source: auto | url | map | code
        URL/map: uses the session capability map (crawl first) or a bare URL.
        code: inventories a local checkout — never executes target code.
        """
        from app.services.agent.engagement_brain import (
            engagement_brain_from_dict,
            ensure_threat_model,
            format_engagement_brain_for_prompt,
            specialists_from_open_hypotheses,
        )
        from app.services.agent.threat_model import format_threat_model_for_prompt, to_markdown, threat_model_from_dict

        cmap = capability_map or getattr(self, "_capability_map", None) or {}
        if isinstance(cmap, dict) and target and not cmap.get("target"):
            cmap = dict(cmap)
            cmap["target"] = target
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if target and not brain.target:
            brain.target = target
        brain = ensure_threat_model(
            brain,
            cmap if isinstance(cmap, dict) else {},
            repo_path=repo_path,
            url=target or (cmap.get("target") if isinstance(cmap, dict) else "") or "",
            source=source,
            owner_notes=owner_notes,
            languages=list(languages or []),
            frameworks=list(frameworks or []),
            rebuild=rebuild,
        )
        self._engagement_brain = brain.to_dict()
        model = threat_model_from_dict(brain.threat_model)
        markdown = to_markdown(model)
        note_status = None
        if persist_note:
            try:
                note_status = await self.save_note(
                    category="artifact",
                    content=markdown[:10000],
                    target=brain.target or target or None,
                )
            except Exception as exc:
                note_status = f"note skipped: {exc}"
        ranked = [
            {
                "id": t.id,
                "threat": t.threat,
                "actor": t.actor,
                "impact": t.impact,
                "likelihood": t.likelihood,
                "specialist": t.specialist,
                "shape": t.shape,
            }
            for t in model.ranked_threats()[:10]
        ]
        return json.dumps(
            {
                "mode": model.mode,
                "target": model.target or brain.target,
                "ranked_threats": ranked,
                "focus_areas": brain.focus_areas[:8],
                "open_questions": model.open_questions[:8],
                "suggested_specialists": specialists_from_open_hypotheses(brain),
                "prompt_view": format_threat_model_for_prompt(brain.threat_model),
                "brain_view": format_engagement_brain_for_prompt(self._engagement_brain),
                "markdown": markdown[:8000],
                "note": note_status,
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_threat_model(self) -> str:
        """Return the current threat model, surfaces, and focus-area partition."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.threat_model import format_threat_model_for_prompt, to_markdown, threat_model_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if not brain.threat_model:
            return json.dumps(
                {
                    "error": "no threat model yet",
                    "hint": "Call build_threat_model after a crawl (URL) or with repo_path (code).",
                },
                indent=2,
            )
        model = threat_model_from_dict(brain.threat_model)
        return json.dumps(
            {
                "prompt_view": format_threat_model_for_prompt(brain.threat_model),
                "focus_areas": brain.focus_areas,
                "surface_count": len(brain.surfaces),
                "markdown": to_markdown(model)[:8000],
                "threat_model": brain.threat_model,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def update_threat_model(
        self,
        threat_id: str,
        status: str = "",
        likelihood: str = "",
        controls: str = "",
        evidence: str = "",
        deprioritize_reason: str = "",
    ) -> str:
        """Refine a threat row after owner interview (status/likelihood/controls/deprioritize)."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.threat_model import (
            apply_threat_patch,
            format_threat_model_for_prompt,
            threat_model_from_dict,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        model = threat_model_from_dict(brain.threat_model)
        if not model.threats:
            return json.dumps({"error": "no threat model to update; call build_threat_model first"}, indent=2)
        patched = apply_threat_patch(
            model,
            threat_id,
            status=status or None,
            likelihood=likelihood or None,
            controls=controls or None,
            evidence=evidence or None,
            deprioritize_reason=deprioritize_reason or None,
        )
        if not patched:
            return json.dumps(
                {
                    "error": f"threat not found: {threat_id}",
                    "known": [t.id for t in model.threats],
                },
                indent=2,
            )
        brain.threat_model = model.to_dict()
        brain.focus_areas = [f.to_dict() for f in model.focus_areas]
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "updated": patched.to_dict(),
                "prompt_view": format_threat_model_for_prompt(brain.threat_model),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def _plan_brain_hypotheses(self, brain):
        """Reason over new evidence before assigning eligible coverage work."""
        from app.services.agent.brain_hypothesis_planner import (
            pending_hypothesis_cells, plan_coverage_hypotheses,
        )

        if not pending_hypothesis_cells(brain):
            return {"reviewed": 0, "hypotheses": 0, "status": "unchanged"}
        try:
            return await plan_coverage_hypotheses(brain, self._hypothesis_llm())
        except Exception as exc:
            logger.warning("Brain hypothesis planning unavailable: %s", type(exc).__name__)
            return {"reviewed": 0, "hypotheses": 0,
                    "status": "unavailable", "error_type": type(exc).__name__}

    def _followup_key(self, brain):
        """Keep follow-up planning inside one user, org, run, and target."""
        return (current_user_id.get(), current_organization_id.get(),
                current_session_id.get() or "", str(getattr(brain, "target", "") or ""))

    def _record_followup_event(self, brain, *, kind, identity, evidence_ids, facts):
        """Commit one observation event; a failure never blocks the caller."""
        from app.services.agent.followup_runtime import current_run_id, followups_enabled
        from app.services.agent.observation_followups import commit_observation

        if not followups_enabled():
            return None
        try:
            event, _created = commit_observation(
                brain, run_id=current_run_id(), kind=kind, identity=identity,
                evidence_ids=[str(v) for v in evidence_ids if v], facts=facts,
            )
            return event
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not record %s observation: %s", kind, type(exc).__name__)
            return None

    def _refresh_followups(self, brain, inventory=None, *, reset=False):
        """Record capture events, apply finished planning, queue new planning.

        Never waits for the model. The caller persists ``brain`` afterwards.
        """
        from app.services.agent.followup_runtime import (
            followups_enabled, policy_for, record_inventory_captures,
        )

        if not followups_enabled():
            return {"status": "disabled"}
        try:
            key = self._followup_key(brain)
            if reset:
                self._followup_runtime.cancel(key)
            policy = policy_for(self, brain)
            recorded = 0
            if inventory is not None:
                recorded = record_inventory_captures(brain, inventory, run_id=policy.run_id)
            out = self._followup_runtime.refresh(key, brain, policy, self._hypothesis_llm)
            if recorded:
                out["new_capture_events"] = recorded
            return out
        except Exception as exc:  # noqa: BLE001 - follow-ups must not break mapping or dispatch
            logger.warning("Observation follow-ups unavailable: %s", type(exc).__name__, exc_info=True)
            return {"status": "error", "error_type": type(exc).__name__}

    def _hypothesis_llm(self):
        """Use the engagement's reasoning model for Brain hypothesis planning."""
        from app.services.agent.model_router import LLMTask, get_llm_for_task

        _, org_id = get_tenant_context()
        db = SessionLocal()
        try:
            return get_llm_for_task(
                db, org_id, LLMTask.REASONING,
                temperature=0, max_tokens=2400, timeout=45, max_retries=1,
            )
        finally:
            db.close()

    def _cheap_llm(self):
        """Resolve a specialist/verifier LLM the same provider-aware way the main
        loop does: honor AI_PROVIDER / per-org config and wrap with the credit
        fallback so a dead primary (e.g. Anthropic out of credits) cascades to a
        working provider instead of failing every call. Only if router resolution
        is impossible do we build a client directly."""
        try:
            from app.services.agent.model_router import get_llm_for_task, LLMTask
            _, org_id = get_tenant_context()
            db = SessionLocal()
            try:
                return get_llm_for_task(
                    db, org_id, LLMTask.OFFENSIVE,
                    temperature=0, timeout=120, max_retries=2,
                )
            finally:
                db.close()
        except Exception:
            logger.warning(
                "Specialist LLM resolution via model_router failed; building a "
                "direct client as last resort", exc_info=True,
            )
        # Last resort only (router unreachable). Prefer a provider that both
        # constructs and is likely to have credits in this deployment — try
        # OpenAI before Anthropic so we don't dead-end on a keyed-but-empty
        # account the way the old hardcoded Anthropic default did.
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model="gpt-4o-mini", temperature=0)
        except Exception:
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model="claude-sonnet-4-6", temperature=0)

    async def record_surface_coverage(
        self,
        path: str,
        status: str = "tested_clean",
        method: str = "GET",
        reason: str = "",
        hypothesis_id: str = "",
        finding_title: str = "",
        host: str = "",
        identity: str = "",
        test_type: str = "",
        parameter: str = "",
        evidence_id: str = "",
        operation_id: str = "",
        tenant: str = "",
        coverage_cell_id: str = "",
        coverage_lease_id: str = "",
        capture_id: str = "",
        candidate_id: str = "",
        proof_run_id: str = "",
        verifier_run_id: str = "",
        finding_id: str = "",
    ) -> str:
        """Record one surface/test/identity result; inconclusive needs a proof gap.

        Use tested_clean only with validated negative execution evidence.
        """
        from app.services.agent.engagement_brain import (
            coverage_progress,
            engagement_brain_from_dict,
            record_surface_coverage,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        try:
            if not isinstance(status, str):
                raise ValueError("coverage status must be a string, not an HTTP status code")
            status = status.strip().lower()
            if not status:
                raise ValueError("coverage status is required")
            if coverage_cell_id:
                from app.services.agent.coverage_cells import (
                    migrate_coverage_cells,
                    trace_for_cell,
                )
                from app.services.agent.engagement_brain import denominator_surfaces

                migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
                trace = trace_for_cell(brain, coverage_cell_id)
                if not trace:
                    raise ValueError("Unknown coverage_cell_id")
                identity = identity or str(trace.get("identity") or "")
                tenant = tenant or str(trace.get("tenant") or "")
                test_type = test_type or str(trace.get("test_type") or "")
                parameter = parameter or str(trace.get("parameter") or "")
                operation_id = operation_id or str(trace.get("operation_id") or "")
                hypothesis_id = hypothesis_id or str(trace.get("hypothesis_id") or "")
            if status == "tested_clean":
                if not evidence_id or not test_type:
                    raise ValueError(
                        "tested_clean requires test_type and execution evidence_id"
                    )
                from app.services.agent.evidence_store import evidence_store

                evidence = evidence_store(self).records.get(evidence_id)
                kind = evidence.get("kind") if evidence else ""
                if kind not in (
                    "http_exchange", "browser_xss", "scoped_http_get",
                    "scoped_browser_check_xss", "scoped_string_sqli",
                ):
                    raise ValueError("tested_clean evidence_id must reference live transport evidence")
                if identity and evidence.get("identity") != identity:
                    raise ValueError("coverage identity does not match the cited evidence")
                if kind.startswith("scoped_"):
                    from urllib.parse import urlsplit

                    target_parts = urlsplit(evidence["target"])
                    expected_host = (host or target_parts.netloc).lower()
                    if (target_parts.netloc.lower() != expected_host
                            or (target_parts.path or "/") != (urlsplit(path).path or "/")
                            or method.upper() != "GET"):
                        raise ValueError("scoped evidence does not match the coverage surface")
                    payload = evidence["payload"]
                    if kind == "scoped_http_get":
                        if (test_type != "directory_index" or payload.get("status") != 200
                                or payload.get("directory_index") is not False
                                or payload.get("truncated") is not False
                                or payload.get("redirected") is not False):
                            raise ValueError("scoped HTTP evidence only closes a clean directory-index check")
                    elif kind == "scoped_string_sqli":
                        from app.services.agent.scoped_assessment.sqli_string import CHECK_ORDER

                        checks = payload.get("checks")
                        _, _, expected_parameter = parameter.partition(":")
                        if payload.get("proof_recipe") in {
                            "string_or_boolean_v1", "string_or_json_rows_v1",
                            "string_and_boolean_v1", "string_error_v1",
                        }:
                            raise ValueError(
                                "A negative Boolean recipe does not establish clean SQLi coverage"
                            )
                        if (test_type != "sqli" or expected_parameter != payload.get("parameter")
                                or payload.get("operation") != "sqli_boolean_string"
                                or payload.get("proof_confirmed") is not False
                                or payload.get("requests_sent") != len(CHECK_ORDER)
                                or not isinstance(checks, dict)
                                or any(not isinstance(checks.get(key), dict)
                                       or checks[key].get("status") != 200
                                       or not isinstance(checks[key].get("bytes_captured"), int)
                                       or checks[key].get("redirected") is not False
                                       or checks[key].get("truncated") is not False
                                       for key in CHECK_ORDER)):
                            raise ValueError("SQLi coverage needs a complete negative control sequence for this input")
                        sizes = [checks[key]["bytes_captured"] for key in CHECK_ORDER]
                        if max(sizes) - min(sizes) > max(64, max(sizes) // 100):
                            raise ValueError("SQLi response differences remain inconclusive")
                    elif (test_type not in ("xss", "reflected_xss")
                          or payload.get("operation") != "check_xss"
                          or payload.get("executed") is not False
                          or payload.get("status") != 200
                          or not payload.get("nonce")
                          or "__PROWL_NONCE__" not in payload.get("target_template", "")):
                        raise ValueError("scoped browser evidence only closes a clean executed XSS check")
                if coverage_cell_id and evidence.get("coverage_cell_id") not in (
                    "", coverage_cell_id
                ):
                    raise ValueError("coverage cell does not match the cited evidence")
            row = record_surface_coverage(
                brain,
                method=method or "GET",
                path=path or "",
                status=status,
                reason=reason or "",
                hypothesis_id=hypothesis_id or "",
                finding_title=finding_title or "",
                host=host or "",
                identity=identity or "",
                test_type=test_type or "",
                parameter=parameter or "",
                evidence_id=evidence_id or "",
                operation_id=operation_id or "",
                tenant=tenant or "",
                coverage_cell_id=coverage_cell_id or "",
                coverage_lease_id=coverage_lease_id or "",
                capture_id=capture_id or "",
                candidate_id=candidate_id or "",
                proof_run_id=proof_run_id or "",
                verifier_run_id=verifier_run_id or "",
                finding_id=finding_id or "",
            )
        except ValueError as exc:
            return json.dumps({"error": str(exc)}, indent=2)
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "row": row,
                "coverage": coverage_progress(brain),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]

    async def get_coverage(self) -> str:
        """Return inventory coverage (focus-area + takes_input denominator)."""
        from app.services.agent.engagement_brain import (
            coverage_progress,
            engagement_brain_from_dict,
            methodology_progress,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cmap = getattr(self, "_capability_map", None) or {}
        cov = coverage_progress(brain)
        self._engagement_brain = brain.to_dict()
        return json.dumps(
            {
                "coverage": cov,
                "assessment_coverage": json.loads(await self.get_assessment_coverage()),
                "methodology": methodology_progress(
                    brain, cmap=cmap if isinstance(cmap, dict) else {}
                ),
                "engagement_brain": self._engagement_brain,
            },
            indent=2,
        )[:_tool_output_max_chars()]
