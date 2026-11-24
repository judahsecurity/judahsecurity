"""Leased scoped-assessment probes (input, DOM, CORS, race, injection, JWT, CSRF, XXE, stored XSS).

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    Optional,
    SessionLocal,
    _lease_failure_reason,
    _re,
    _tool_output_max_chars,
    asyncio,
    current_session_id,
    get_tenant_context,
    json,
    logger,
    os,
)


class ScopedProbeToolsMixin:
    """Leased scoped-assessment probes (input, DOM, CORS, race, injection, JWT, CSRF, XXE, stored XSS)."""

    async def _scoped_assessment_operation(self, operation: str, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        from app.services.agent.prowl_service_bridge import hunter_operation, capability_map_from_observation

        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        if not user_id or not org_id or not session_id:
            return {"success": False, "error": "missing_agent_session", "output": "Agent session is required"}
        db = SessionLocal()
        try:
            result = await hunter_operation(
                db, organization_id=org_id, user_id=user_id, session_id=session_id,
                operation=operation, body=body,
            )
            visible = result
            if isinstance(result.get("result"), dict):
                detail = dict(result["result"])
                inventory = detail.pop("surface_inventory", None)
                specialists = detail.pop("recommended_specialists", None)
                visible = {
                    "run_id": result.get("run_id"), "signal": result.get("signal"),
                    "target": result.get("target"),
                    "artifact_ids": result.get("artifact_ids", []),
                    "surface_inventory": inventory,
                    "recommended_specialists": specialists,
                    "result": detail,
                }
            serialized = json.dumps(visible, default=str, separators=(",", ":"))
            payload = {
                "success": True,
                "output": serialized[:_tool_output_max_chars()],
                "run_id": result.get("run_id"),
                "candidate_id": result.get("candidate_id"),
                "service_artifact_ids": result.get("artifact_ids", []),
                "truncated": len(serialized) > _tool_output_max_chars(),
            }
            if operation in {"browser_check_xss", "http_query_probe", "http_body_probe", "http_sqli_boolean"}:
                probe = result.get("result") if isinstance(result.get("result"), dict) else {}
                payload["probe_result"] = {
                    key: probe[key]
                    for key in ("operation", "parameter", "changed", "inconclusive",
                                "proof_confirmed", "executed", "requests_sent", "target")
                    if key in probe
                }
            if operation in {"browser_map", "browser_crawl", "browser_inspect_js"}:
                capability_map = capability_map_from_observation(result)
                if capability_map:
                    payload["capability_map"] = capability_map
                    prior_map = getattr(self, "_capability_map", None)
                    if not isinstance(prior_map, dict):
                        prior_map = {}
                    prior_links = {
                        (str(row.get("url")), tuple(sorted(row.get("query_keys") or [])))
                        for row in (prior_map.get("discovered_links") or []) if isinstance(row, dict)
                    }
                    new_links = [row for row in (capability_map.get("discovered_links") or [])
                                 if isinstance(row, dict) and
                                 (str(row.get("url")), tuple(sorted(row.get("query_keys") or [])))
                                 not in prior_links]
                    if new_links:
                        try:
                            from app.services.agent.action_ledger import active_run_id, append_action
                            from app.services.agent.evidence_store import evidence_store

                            link_id = evidence_store(self).record(
                                "link_discovery", {"count": len(new_links), "links": new_links[:100]},
                                target=capability_map.get("scope") or "",
                            )
                            payload["evidence_ids"] = [link_id]
                            append_action(
                                active_run_id.get(), os.urandom(16).hex(), "completed", "link_discovery",
                                target=capability_map.get("scope") or "", phase="surface_mapping",
                                detail=f"{len(new_links)} in-scope links observed; query values omitted",
                                evidence_ids=[link_id],
                            )
                        except Exception:
                            logger.exception("Could not record scoped browser link evidence")
                    from app.services.agent.capability_map import merge_capability_maps
                    from app.services.agent.engagement_brain import (
                        engagement_brain_from_dict, seed_hypotheses_from_capability_map,
                    )
                    from app.services.agent.coverage_cells import (
                        seed_js_coverage_cells, seed_parameter_coverage_cells,
                    )
                    from app.services.agent.runtime_mapper import ingest_capability_map_operations
                    from app.services.agent.parameter_inventory import collect_parameter_inventory

                    merged = merge_capability_maps(getattr(self, "_capability_map", None), capability_map)
                    self._capability_map = merged
                    brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                    brain = seed_hypotheses_from_capability_map(brain, merged)
                    ingest_capability_map_operations(brain, merged)
                    merged_inventory = collect_parameter_inventory(merged)
                    seed_parameter_coverage_cells(brain, merged_inventory)
                    seed_js_coverage_cells(brain, merged)
                    self._refresh_followups(brain, merged_inventory)
                    self._engagement_brain = brain.to_dict()
                    # The service run is bound to one stored asset. Persist the
                    # value-free observation there even when its Asset.value is
                    # a URL, which the generic host lookup cannot match.
                    from app.models.scoped_assessment_run import ScopedAssessmentRun
                    from app.services.sitemap_service import persist_capability_map_safe

                    binding = db.query(ScopedAssessmentRun).filter_by(
                        organization_id=org_id, user_id=user_id,
                        session_id=session_id,
                    ).first()
                    if (binding is not None and
                            binding.allowed_origin == merged.get("scope")):
                        persist_capability_map_safe(
                            org_id, merged, source="scoped_assessment",
                            asset_id=binding.asset_id,
                        )
            return payload
        except ValueError as exc:
            return {"success": False, "error": "assessment_rejected", "output": str(exc)[:500]}
        except Exception:
            logger.exception("Scoped assessment operation failed")
            return {"success": False, "error": "assessment_unavailable",
                    "output": "Scoped assessment service is unavailable"}
        finally:
            db.close()

    async def scoped_assessment_observe(self, operation: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from app.services.agent.prowl_service_bridge import OBSERVE_OPERATIONS

        if operation not in OBSERVE_OPERATIONS:
            return {"success": False, "error": "invalid_operation", "output": "Unknown observation operation"}
        return await self._scoped_assessment_operation(operation, body)

    async def scoped_assessment_probe(self, operation: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        from app.services.agent.prowl_service_bridge import PROBE_OPERATIONS

        if operation not in PROBE_OPERATIONS:
            return {"success": False, "error": "invalid_operation", "output": "Unknown probe operation"}
        return await self._scoped_assessment_operation(operation, body)

    async def scoped_input_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        technique: str = "html_body", variant: str = "base",
    ) -> Dict[str, Any]:
        """Probe one leased, observed GET input or approved POST form.

        Browser links and forms do not always yield a private XHR capture. The
        scoped browser/SQLi tools can still test those exact observed inputs;
        this adapter binds their evidence to the assigned coverage cell.
        """
        import time
        from urllib.parse import parse_qsl, urlsplit

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.xss_feedback import (
            MAX_ATTEMPTS, payload_for, xss_trace,
        )
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        location, separator, parameter = str((cell or {}).get("parameter") or "").partition(":")
        method = str((cell or {}).get("method") or "").upper()
        form_xss = bool(cell and cell.get("test_type") == "xss"
                        and method == "POST" and location == "body_form")
        reason = (
            "missing_cell" if not cell else
            "not_leased" if cell.get("status") != "leased" else
            "lease_mismatch" if cell.get("lease_id") != coverage_lease_id else
            "lease_expired" if float(cell.get("lease_deadline") or 0) <= time.time() else
            "not_observed_input" if cell.get("source") != "parameter_inventory" or
                cell.get("observation_source") not in OBSERVED_INPUT_SOURCES else
            "unsupported_input" if cell.get("test_type") not in {"xss", "sqli"} or
                not ((method == "GET" and location == "query") or form_xss)
                or not separator or not parameter else
            "unsafe_path" if not allowed_discovery_path(str(cell.get("path") or "/")) else ""
        )
        if reason:
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": reason, "output": f"An active lease on an observed GET input is required ({reason})"}
        cmap = getattr(self, "_capability_map", None) or {}
        target = str(cmap.get("target") or cmap.get("scope") or
                     getattr(self, "_fallback_target", "") or "")
        scoped_origin = _origin(target)
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(
            f"{parts.scheme}://{cell.get('host') or ''}"
        ) != scoped_origin):
            return {"success": False, "error": "scope_mismatch",
                    "output": "Assigned input does not match the assessment origin"}
        url = f"{scoped_origin}{cell['path']}"
        try:
            self._scoped_origin(url)
        except ValueError as exc:
            return {"success": False, "error": "assessment_scope_denied",
                    "output": str(exc)[:300]}
        identity = str(cell.get("identity") or "anonymous")
        try:
            self._scoped_state(identity, url)
        except (KeyError, ValueError):
            return {"success": False, "error": "identity_unavailable",
                    "output": "Assigned input needs a usable session on this origin"}

        if cell["test_type"] == "sqli":
            if technique != "html_body" or variant != "base":
                return {"success": False, "error": "unsupported_technique"}
            numeric = cell.get("value_type") in {"positive_integer", "number"}
            if not numeric:
                try:
                    self._observed_numeric_baseline(url, parameter, identity, scoped_origin)
                    numeric = True
                except ValueError:
                    pass
            if numeric:
                proof = json.loads(await self.scoped_numeric_sqli(
                    parameter=parameter, identity=identity, url=url,
                ))
                operation = "scoped_numeric_sqli"
            else:
                proof = json.loads(await self.scoped_string_sqli(url, parameter, identity))
                operation = "scoped_string_sqli"
            confirmed = proof.get("proof_confirmed") is True
        else:
            # Both assigned probe adapters are exposed to specialists. Accept
            # the browser service's equivalent names on observed GET inputs.
            technique = {
                "xss_browser": "html_body",
                "xss_browser_svg": "html_body_svg",
                "xss_browser_attribute": "html_attribute",
                "xss_browser_attribute_single": "html_attribute_single",
                "xss_browser_js_single": "js_single",
                "xss_browser_js_double": "js_double",
            }.get(technique, technique)
            attempts = list(cell.get("xss_probe_attempts") or [])
            if len(attempts) >= MAX_ATTEMPTS:
                return {"success": False, "error": "xss_probe_budget_exhausted"}
            if any(row.get("technique") == technique
                   and row.get("variant", "base") == variant for row in attempts):
                return {"success": False, "error": "technique_already_attempted"}
            try:
                payload = payload_for(technique, variant, allow_double_url=not form_xss)
            except ValueError as exc:
                return {"success": False, "error": str(exc)}
            if form_xss:
                matching_forms = [form for form in (cmap.get("forms") or [])[:80]
                                  if isinstance(form, dict)
                                  and str(form.get("method") or "").upper() == "POST"
                                  and str(form.get("action") or "") == url
                                  and parameter in (form.get("inputs") or [])
                                  and isinstance(form.get("page"), str)
                                  and _origin(form["page"]) == scoped_origin
                                  and not urlsplit(form["page"]).query
                                  and not urlsplit(form["page"]).fragment]
                pages = sorted({str(form["page"]) for form in matching_forms})
                if not pages:
                    return {"success": False, "error": "observed_form_page_missing",
                            "output": "POST form needs its observed source page for browser proof"}
                proof = json.loads(await self.scoped_browser_assessment(
                    "check_form_xss", pages[0], identity=identity,
                    form_action=url, form_field=parameter,
                    form_payload_template=payload,
                ))
                request_context = "observed_post_form"
                operation = "scoped_browser_check_form_xss"
            else:
                captured = {}
                capture_id = str(cell.get("capture_id") or "")
                if capture_id:
                    try:
                        captured = json.loads(self._scoped_exchange(capture_id, identity))
                    except (TypeError, ValueError):
                        captured = {}
                page_url = str(captured.get("page_url") or "")
                captured_url = str(captured.get("url") or "")
                try:
                    captured_pairs = parse_qsl(
                        urlsplit(captured_url).query, keep_blank_values=True,
                        max_num_fields=40,
                    )
                except ValueError:
                    captured_pairs = []
                query_keys = sorted({name for name, _ in captured_pairs})
                if (captured.get("method") == "GET"
                        and captured.get("resource_type") in {"xhr", "fetch"}
                        and _origin(page_url) == scoped_origin
                        and not urlsplit(page_url).query
                        and not urlsplit(page_url).fragment
                        and urlsplit(page_url).path != cell["path"]
                        and urlsplit(captured_url).path == cell["path"]
                        and sum(name == parameter for name, _ in captured_pairs) == 1
                        and 1 <= len(query_keys) <= 20
                        and all(_re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", name)
                                for name in query_keys)):
                    proof = json.loads(await self.scoped_browser_assessment(
                        "check_xhr_xss", page_url, identity=identity,
                        xhr_path=cell["path"], xhr_parameter=parameter,
                        xhr_payload_template=payload,
                        xhr_query_keys=query_keys,
                        **({"xhr_actions": captured["replay_actions"]}
                           if captured.get("replay_actions") else {}),
                    ))
                    request_context = "observed_xhr_render_page"
                    operation = "scoped_browser_check_xhr_xss"
                else:
                    template, request_context = self._observed_get_query_template(
                        url, parameter, payload, identity,
                        capture_id=capture_id,
                    )
                    proof = json.loads(await self.scoped_browser_assessment(
                        "check_xss", template, identity=identity,
                    ))
                    operation = "scoped_browser_check_xss"
            confirmed = proof.get("executed") is True

        artifact_id = str(proof.get("evidence_id") or "")
        if not artifact_id:
            return {"success": False,
                    "error": str(proof.get("error") or "missing_probe_evidence")[:100],
                    "output": str(proof.get("output") or
                                  "The probe returned no execution-owned evidence receipt")[:300]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id and
                        row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed",
                    "output": "Coverage lease changed while the probe was running"}
        current["probe_artifact_ids"] = list(dict.fromkeys([
            *(current.get("probe_artifact_ids") or []), artifact_id,
        ]))[:20]
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        current["last_probe"] = operation
        if cell["test_type"] == "sqli":
            from app.services.agent.coverage_cells import record_sqli_trace

            record_sqli_trace(current, proof)
        if cell["test_type"] == "xss":
            current["xss_probe_attempts"] = [
                *(current.get("xss_probe_attempts") or []),
                {"technique": technique, "variant": variant,
                 "evidence_id": artifact_id, "executed": confirmed},
            ][:MAX_ATTEMPTS]
            trace = xss_trace(current, proof, technique=technique,
                              variant=variant, attempts=current["xss_probe_attempts"])
            current["xss_trace"] = trace
        if confirmed:
            current["status"] = "in_focus"
            current["reason"] = "Execution-owned proof signal; independent verification required"
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "operation": operation,
                "evidence_id": artifact_id, "proof_confirmed": confirmed,
                "probe_result": {key: proof[key] for key in (
                    "executed", "proof_confirmed", "requests_sent", "baseline_source",
                    "proof_recipe", "total_requests_sent",
                    "and_followup_error", "error_followup_error",
                ) if key in proof} | ({"request_context": request_context}
                                   if cell["test_type"] == "xss" else {})
                | ({"reflection_contexts": trace["rendered_contexts"],
                    "reflection_observations": trace["render_observations"]}
                   if cell["test_type"] == "xss" else {}),
                "funnel": parameter_test_funnel(live),
                **({"xss_trace": trace, "technique": technique, "variant": variant}
                   if cell["test_type"] == "xss" else {})}

    async def scoped_input_sweep_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> Dict[str, Any]:
        """Replay one observed GET and one mutation, retaining both responses."""
        import base64
        import secrets
        import time
        from urllib.parse import quote, unquote_plus, urlsplit, urlunsplit

        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.private_capture_store import persist_capture
        from app.services.agent.scoped_assessment import browser_post_replay, http_observe
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        location, separator, parameter = str((cell or {}).get("parameter") or "").partition(":")
        method = str((cell or {}).get("method") or "").upper()
        get_input = method == "GET" and location == "query"
        post_input = (method == "POST" and location in {"body_form", "body_json"}
                      and bool((cell or {}).get("capture_id"))
                      and (cell or {}).get("observation_source") == "browser_traffic")
        reason = (
            "missing_cell" if not cell else
            "not_leased" if cell.get("status") != "leased" else
            "lease_mismatch" if cell.get("lease_id") != coverage_lease_id else
            "lease_expired" if float(cell.get("lease_deadline") or 0) <= time.time() else
            "not_observed_input" if cell.get("source") != "parameter_inventory" or
                cell.get("observation_source") not in OBSERVED_INPUT_SOURCES else
            "unsupported_input" if cell.get("test_type") not in {"sqli", "xss"}
                or not (get_input or post_input) or not separator or not parameter else
            "unsafe_path" if not allowed_discovery_path(str(cell.get("path") or "/")) else ""
        )
        if reason:
            return {"success": False, "error": "invalid_coverage_lease", "reason": reason}
        if post_input:
            return await self._scoped_body_sweep_assigned(
                cell, coverage_cell_id, coverage_lease_id, parameter,
            )
        cmap = getattr(self, "_capability_map", None) or {}
        target = str(cmap.get("target") or cmap.get("scope") or
                     getattr(self, "_fallback_target", "") or "")
        scoped_origin = _origin(target)
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(
            f"{parts.scheme}://{cell.get('host') or ''}"
        ) != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        path_url = f"{scoped_origin}{cell['path']}"
        try:
            self._scoped_origin(path_url)
            identity = str(cell.get("identity") or "anonymous")
            state = self._scoped_state(identity, path_url)
            baseline_url, source, headers = self._observed_get_query_sample(
                path_url, parameter, identity, str(cell.get("capture_id") or ""),
            )
            fields = urlsplit(baseline_url).query.split("&")
            index = next(i for i, field in enumerate(fields)
                         if field and unquote_plus(field.split("=", 1)[0]) == parameter)
            name, _, value = fields[index].partition("=")
            marker = "prowlxss" + secrets.token_hex(8) if cell["test_type"] == "xss" else ""
            fields[index] = (name + "=" + quote(marker, safe="") if marker
                             else name + "=" + value + "%27")
            mutated_url = urlunsplit(urlsplit(baseline_url)._replace(query="&".join(fields)))
            self._scoped_origin(mutated_url)
            if len(mutated_url) > 2048:
                raise ValueError("mutated_query_too_long")
        except (KeyError, StopIteration, ValueError) as exc:
            return {"success": False, "error": str(exc)[:100]}

        self._scoped_assessment_started = True
        self._scoped_claim_gets(2)
        store = evidence_store(self)
        responses = getattr(self, "_scoped_sweep_responses", None)
        if responses is None:
            responses = {}
            self._scoped_sweep_responses = responses

        def save_response(kind: str, request_url: str, observed: dict) -> tuple[str, dict]:
            private_body = observed.pop("_private_body", b"")
            private_request_body = observed.pop("_private_request_body", b"")
            private_location = observed.pop("_private_location", "")
            private = json.dumps({
                "request_url": request_url,
                "request_body_base64": base64.b64encode(private_request_body).decode("ascii"),
                "replay_headers": headers,
                "response_body_base64": base64.b64encode(private_body).decode("ascii"),
                "response_location": private_location,
                "source_artifact_id": str(cell.get("capture_id") or ""),
            }, sort_keys=True).encode()
            metadata = {key: value for key, value in observed.items()
                        if key != "target_template"}
            metadata.update({"coverage_cell_id": coverage_cell_id,
                             "baseline_source": source, "response_kind": kind})
            artifact_id = store.record(
                "scoped_input_sweep_response", metadata,
                target=path_url, identity=identity,
            )
            responses[artifact_id] = private
            if len(responses) > 256:
                responses.pop(next(iter(responses)))
            persist_capture(store.namespace, artifact_id, {
                "identity": identity, "private": private,
                "verifier_run_id": None,
            })
            return artifact_id, metadata

        baseline_id = ""
        try:
            private_exchange = (self._scoped_exchange(str(cell["capture_id"]), identity)
                                if source == "browser_traffic" and cell.get("capture_id")
                                else b"")
            browser_ready = bool(private_exchange and
                                 json.loads(private_exchange).get("resource_type") in
                                 {"xhr", "fetch"} and
                                 browser_post_replay.has_replayable_source(
                                     private_exchange, [scoped_origin],
                                 ))
            if browser_ready:
                baseline = (await browser_post_replay.replay_observed_get_controls(
                    private_exchange, parameter=parameter,
                    variants={"baseline": baseline_url},
                    allowed_origins=[scoped_origin], storage_state=state,
                    capture_body=True,
                ))["baseline"]
            else:
                baseline = await asyncio.to_thread(
                    http_observe.observe_get, baseline_url, [scoped_origin], state,
                    replay_headers=headers, capture_body=True,
                )
            baseline_id, baseline_meta = save_response("baseline", baseline_url, baseline)
            if browser_ready:
                probe = (await browser_post_replay.replay_observed_get_controls(
                    private_exchange, parameter=parameter,
                    variants={"probe": mutated_url},
                    allowed_origins=[scoped_origin], storage_state=state,
                    capture_body=True,
                ))["probe"]
                probe["reflection_detected"] = bool(
                    marker and marker.encode() in probe.get("_private_body", b"")
                )
            else:
                probe = await asyncio.to_thread(
                    http_observe.observe_get, mutated_url, [scoped_origin], state,
                    replay_headers=headers, reflection_marker=marker, capture_body=True,
                )
            probe_id, probe_meta = save_response("probe", mutated_url, probe)
        except Exception as exc:
            return {"success": False, "error": "sweep_request_failed",
                    "reason": type(exc).__name__, "baseline_evidence_id": baseline_id}

        changed = (baseline_meta["status"] != probe_meta["status"] or
                   baseline_meta["body_sha256"] != probe_meta["body_sha256"] or
                   baseline_meta["location_sha256"] != probe_meta["location_sha256"])
        signal = ("reflected" if marker and probe_meta["reflection_detected"] else
                  "sql_difference" if not marker and
                  (changed or bool(probe_meta["sql_error_family"])) else "")
        inconclusive = any(row["truncated"] or
                           row["status"] in {401, 403}
                           for row in (baseline_meta, probe_meta))
        baseline_failure = (
            "response_truncated" if baseline_meta["truncated"] else
            "authentication_required" if baseline_meta["status"] in {401, 403} else ""
        )
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id and
                        row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed",
                    "baseline_evidence_id": baseline_id,
                    "probe_evidence_id": probe_id}
        current["first_pass_baseline_id"] = baseline_id
        current["first_pass_probe_id"] = probe_id
        current["first_pass_signal"] = signal
        current["first_pass_baseline_failure_reason"] = baseline_failure
        current["triage_pending"] = bool(signal and not inconclusive)
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), baseline_id, probe_id,
        ]))[:30]
        self._engagement_brain = live.to_dict()
        return {"success": True, "first_pass_mode": "sweep",
                "coverage_cell_id": coverage_cell_id,
                "baseline_evidence_id": baseline_id,
                "probe_evidence_id": probe_id, "evidence_id": probe_id,
                "proof_confirmed": False,
                "probe_result": {"lead_kind": signal, "changed": changed,
                                 "reflection_detected": bool(marker and signal),
                                 "inconclusive": inconclusive,
                                 "baseline_failure_reason": baseline_failure,
                                 "baseline_source": source,
                                 "baseline_status": baseline_meta["status"],
                                 "probe_status": probe_meta["status"],
                                 "sql_error_family": probe_meta["sql_error_family"]}}

    async def _scoped_body_sweep_assigned(
        self, cell: Dict[str, Any], coverage_cell_id: str,
        coverage_lease_id: str, parameter: str,
    ) -> Dict[str, Any]:
        """Replay an approved captured POST once clean and once with one mutation."""
        import base64
        import secrets
        from urllib.parse import urlsplit

        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.private_capture_store import persist_capture
        from app.services.agent.scoped_assessment import body_probe, browser_post_replay

        identity = str(cell.get("identity") or "anonymous")
        try:
            private = self._scoped_exchange(str(cell["capture_id"]), identity)
            captured = json.loads(private)
            url = str(captured.get("url") or "")
            allowed = self._scoped_origin(url)
            if (captured.get("method") != "POST"
                    or captured.get("resource_type") not in {"xhr", "fetch"}
                    or (urlsplit(url).path or "/") != cell.get("path")):
                raise ValueError("captured_post_shape_mismatch")
            if (urlsplit(url).path or "/") not in (
                getattr(self, "_scoped_body_replay_paths", None) or set()
            ):
                raise ValueError("operator_approval_required")
            marker = "prowlxss" + secrets.token_hex(8) if cell["test_type"] == "xss" else ""
            suffix = marker or "'"
            _, mime, baseline_body, probe_body = body_probe.plan_observed_body(
                private, parameter=parameter, allowed_origins=[allowed], payload=suffix,
            )
            state = self._scoped_state(identity, url)
        except (KeyError, TypeError, ValueError) as exc:
            return {"success": False, "error": str(exc)[:100]}

        self._scoped_assessment_started = True
        self._scoped_claim_posts(2)
        store = evidence_store(self)
        try:
            if (body_probe.captured_volatile_post_fields(baseline_body, mime)
                    or browser_post_replay.has_replayable_source(private, [allowed])):
                receipts = await browser_post_replay.replay_observed_post_controls(
                    private, parameter=parameter,
                    payloads={"baseline": "", "probe": suffix},
                    allowed_origins=[allowed], storage_state=state, capture_body=True,
                )
            else:
                replay_headers = body_probe.safe_replay_headers(private)
                receipts = {
                    "baseline": await asyncio.to_thread(
                        body_probe._observe_post, url, mime, baseline_body, [allowed], state,
                        replay_headers=replay_headers, capture_body=True,
                    ),
                    "probe": await asyncio.to_thread(
                        body_probe._observe_post, url, mime, probe_body, [allowed], state,
                        replay_headers=replay_headers, capture_body=True,
                    ),
                }
        except Exception as exc:
            return {"success": False, "error": "sweep_request_failed",
                    "reason": type(exc).__name__}

        responses = getattr(self, "_scoped_sweep_responses", None)
        if responses is None:
            responses = {}
            self._scoped_sweep_responses = responses
        saved: dict[str, tuple[str, dict]] = {}
        try:
            for kind in ("baseline", "probe"):
                observed = dict(receipts[kind])
                response_body = observed.pop("_private_body", b"")
                request_body = observed.pop("_private_request_body", b"")
                response_location = observed.pop("_private_location", "")
                metadata = {**observed, "coverage_cell_id": coverage_cell_id,
                            "response_kind": kind, "baseline_source": "browser_traffic"}
                private_response = json.dumps({
                    "request_url": url,
                    "request_body_base64": base64.b64encode(request_body).decode("ascii"),
                    "response_body_base64": base64.b64encode(response_body).decode("ascii"),
                    "response_location": response_location,
                    "source_artifact_id": cell["capture_id"],
                }, sort_keys=True).encode()
                artifact_id = store.record("scoped_input_sweep_response", metadata,
                                           target=allowed + (urlsplit(url).path or "/"),
                                           identity=identity)
                responses[artifact_id] = private_response
                if len(responses) > 256:
                    responses.pop(next(iter(responses)))
                persist_capture(store.namespace, artifact_id, {
                    "identity": identity, "private": private_response,
                    "verifier_run_id": None,
                })
                saved[kind] = artifact_id, metadata
        except Exception as exc:
            return {"success": False, "error": "sweep_capture_failed",
                    "reason": type(exc).__name__,
                    "baseline_evidence_id": saved.get("baseline", ("", {}))[0]}

        baseline_id, baseline = saved["baseline"]
        probe_id, probe = saved["probe"]
        changed = (baseline["status"] != probe["status"] or
                   baseline["body_sha256"] != probe["body_sha256"] or
                   baseline.get("location_sha256") != probe.get("location_sha256"))
        reflected = bool(marker and marker.encode() in receipts["probe"]["_private_body"])
        signal = ("reflected" if reflected else "sql_difference" if not marker and
                  (changed or bool(probe.get("sql_error_family"))) else
                  "sql_blind_followup" if not marker else "")
        inconclusive = any(row["truncated"] or
                           row["status"] in {401, 403}
                           for row in (baseline, probe))
        baseline_failure = (
            "response_truncated" if baseline["truncated"] else
            "authentication_required" if baseline["status"] in {401, 403} else ""
        )
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed",
                    "baseline_evidence_id": baseline_id,
                    "probe_evidence_id": probe_id}
        current["first_pass_baseline_id"] = baseline_id
        current["first_pass_probe_id"] = probe_id
        current["first_pass_signal"] = signal
        current["first_pass_baseline_failure_reason"] = baseline_failure
        current["triage_pending"] = bool(signal and not inconclusive)
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), baseline_id, probe_id,
        ]))[:30]
        self._engagement_brain = live.to_dict()
        return {"success": True, "first_pass_mode": "sweep",
                "coverage_cell_id": coverage_cell_id,
                "baseline_evidence_id": baseline_id,
                "probe_evidence_id": probe_id, "evidence_id": probe_id,
                "proof_confirmed": False,
                "probe_result": {"lead_kind": signal, "changed": changed,
                                 "reflection_detected": reflected,
                                 "inconclusive": inconclusive,
                                 "baseline_failure_reason": baseline_failure,
                                 "baseline_status": baseline["status"],
                                 "probe_status": probe["status"],
                                 "sql_error_family": probe.get("sql_error_family", "")}}

    async def probe_observed_input_batch(
        self, max_checks: int = 32, max_seconds: int = 180,
        surface_signature: str = "", pending_input_count: int = 0,
        pending_batch_signature: str = "",
        target: str = "",
    ) -> Dict[str, Any]:
        """Run a bounded first pass over queued observed SQLi and XSS checks."""
        from app.services.agent.observed_input_batch import run_observed_input_batch

        result = await run_observed_input_batch(
            self, target=target, max_checks=max_checks, max_seconds=max_seconds,
        )
        result["surface_signature"] = surface_signature
        result["pending_batch_signature"] = pending_batch_signature
        return result

    async def scoped_dom_xss_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        technique: str = "html_body", variant: str = "base",
    ) -> Dict[str, Any]:
        """Try one bounded browser technique on a leased DOM source."""
        import time
        from urllib.parse import quote, urlsplit
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.xss_feedback import (
            MAX_ATTEMPTS, payload_for, xss_trace,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "js_inventory"
                or cell.get("test_type") != "dom_xss"
                or cell.get("specialist") != "xss"
                or not any(isinstance(lead, dict) and lead.get("kind") in {"fragment", "query"}
                           for lead in cell.get("source_leads") or [])
                or not any(isinstance(lead, dict) and lead.get("kind") in
                           {"html_assignment", "dynamic_code"}
                           for lead in cell.get("sink_leads") or [])):
            return {"success": False, "error": "invalid_dom_xss_lease"}
        attempts = list(cell.get("dom_probe_attempts") or [])
        if len(attempts) >= MAX_ATTEMPTS:
            return {"success": False, "error": "dom_probe_budget_exhausted"}
        if any(row.get("technique") == technique
               and row.get("variant", "base") == variant for row in attempts):
            return {"success": False, "error": "technique_already_attempted"}
        try:
            payload = payload_for(technique, variant)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        location, separator, field = str(cell.get("parameter") or "").partition(":")
        source_kind = "query" if location == "query" and separator else "fragment"
        if (source_kind == "query"
                and (not field or len(field) > 80 or not any(
                    isinstance(lead, dict) and lead.get("kind") == "query"
                    for lead in cell.get("source_leads") or []))):
            return {"success": False, "error": "invalid_dom_xss_source"}
        if source_kind == "fragment" and not any(
            isinstance(lead, dict) and lead.get("kind") == "fragment"
            for lead in cell.get("source_leads") or []
        ):
            return {"success": False, "error": "invalid_dom_xss_source"}
        page_path = str(cell.get("page_path") or "")
        if (not page_path or not page_path.startswith("/") or page_path.startswith("//")
                or any(char in page_path for char in "?#\\\r\n\t ")
                or not allowed_discovery_path(page_path)):
            return {"success": False, "error": "observed_rendering_page_missing"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        identity = str(cell.get("identity") or "anonymous")
        page_url = scoped_origin + page_path
        if source_kind == "query":
            template, request_context = self._observed_get_query_template(
                page_url, field, payload, identity,
            )
            if request_context == "single_parameter":
                return {"success": False, "error": "observed_query_baseline_missing"}
        else:
            template = page_url + "#" + quote(payload, safe="")
            request_context = "observed_fragment_render_page"
        proof = json.loads(await self.scoped_browser_assessment(
            "check_xss", template, identity=identity,
        ))
        artifact_id = str(proof.get("evidence_id") or "")
        if not artifact_id:
            return {"success": False, "error": str(proof.get("error") or "missing_probe_evidence")[:100]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed"}
        current["probe_artifact_ids"] = list(dict.fromkeys([
            *(current.get("probe_artifact_ids") or []), artifact_id,
        ]))[:20]
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        operation = "scoped_browser_check_xss_" + source_kind
        current["last_probe"] = operation
        current["dom_probe_attempts"] = [
            *(current.get("dom_probe_attempts") or []),
            {"technique": technique, "variant": variant,
             "evidence_id": artifact_id,
             "executed": proof.get("executed") is True},
        ][:MAX_ATTEMPTS]
        trace = xss_trace(current, proof, technique=technique,
                          variant=variant, attempts=current["dom_probe_attempts"])
        current["xss_trace"] = trace
        if proof.get("executed") is True:
            current["status"] = "in_focus"
            current["reason"] = "Browser execution signal; independent verification required"
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "operation": operation,
                "technique": technique, "variant": variant,
                "proof_confirmed": proof.get("executed") is True,
                "xss_trace": trace,
                "probe_result": {"executed": proof.get("executed") is True,
                                 "request_context": request_context,
                                 "reflection_contexts": trace["rendered_contexts"],
                                 "reflection_observations": trace["render_observations"]}}

    async def scoped_client_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> Dict[str, Any]:
        """Replay one observed client source with a fixed, harmless marker."""
        import time
        from urllib.parse import quote, urlsplit

        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

        classes = {"dom_open_redirect", "dom_link_manipulation",
                   "dom_data_manipulation", "request_url_override",
                   "client_template_injection", "client_prototype_pollution"}
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        test_type = str((cell or {}).get("test_type") or "")
        source_kind, separator, field = str((cell or {}).get("parameter") or "").partition(":")
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "js_inventory"
                or cell.get("specialist") != "spa_client"
                or test_type not in classes
                or cell.get("method") != "GET"
                or source_kind not in {"fragment", "query"}
                or (source_kind == "query" and (not separator or not field or len(field) > 80))
                or not any(isinstance(row, dict) and row.get("kind") == source_kind
                           for row in cell.get("source_leads") or [])
                or not any(isinstance(row, dict) and row.get("kind") ==
                           ("prototype_pollution" if test_type == "client_prototype_pollution"
                            else test_type) for row in cell.get("client_leads") or [])):
            return {"success": False, "error": "invalid_client_lease"}
        page_path = str(cell.get("page_path") or "")
        if (not page_path or page_path != cell.get("path")
                or not page_path.startswith("/") or page_path.startswith("//")
                or any(char in page_path for char in "?#\\\r\n\t ")
                or not allowed_discovery_path(page_path)):
            return {"success": False, "error": "observed_rendering_page_missing"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        page_url = scoped_origin + page_path
        payload = {
            "dom_open_redirect": "https://prowl.invalid/__PROWL_NONCE__",
            "dom_link_manipulation": "https://prowl.invalid/__PROWL_NONCE__",
            "dom_data_manipulation": "__PROWL_NONCE__",
            "request_url_override": "https://prowl.invalid/__PROWL_NONCE__",
            "client_template_injection": "{{7*7}}__PROWL_NONCE__",
            "client_prototype_pollution": "__proto__[prowl___PROWL_NONCE__]=1",
        }[test_type]
        identity = str(cell.get("identity") or "anonymous")
        if source_kind == "fragment":
            template = page_url + "#" + payload
            request_context = "observed_fragment_render_page"
        elif test_type == "client_prototype_pollution" and field == "__proto__":
            template = page_url + "?" + quote("__proto__[prowl___PROWL_NONCE__]", safe="") + "=1"
            request_context = "static_parser_lead_on_observed_page"
        else:
            template, request_context = self._observed_get_query_template(
                page_url, field, payload, identity,
            )
            if request_context == "single_parameter":
                return {"success": False, "error": "observed_query_baseline_missing"}
        try:
            proof = json.loads(await self.scoped_browser_assessment(
                "check_client", template, identity=identity,
                client_test_type=test_type,
            ))
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__}
        artifact_id = str(proof.get("evidence_id") or "")
        if not artifact_id:
            return {"success": False, "error": str(proof.get("error") or "missing_probe_evidence")[:100]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed"}
        observed = proof.get("behavior_observed") is True
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        current["last_probe"] = "scoped_browser_check_client"
        if observed:
            current["status"] = "in_focus"
            current["reason"] = "Observed browser behavior requires impact and independent verification"
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "test_type": test_type, "request_context": request_context,
                "behavior_observed": observed, "proof_confirmed": False,
                "observations": proof.get("observations") or {}}

    async def scoped_response_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> Dict[str, Any]:
        """Test one observed GET input for response-header or redirect control."""
        import asyncio
        import secrets
        import time
        from urllib.parse import urlsplit

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.response_probe import probe_response
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        location, separator, parameter = str((cell or {}).get("parameter") or "").partition(":")
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "parameter_inventory"
                or cell.get("observation_source") not in OBSERVED_INPUT_SOURCES
                or cell.get("test_type") not in {"crlf", "open_redirect"}
                or cell.get("method") != "GET" or location != "query"
                or not separator or not parameter
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        url = scoped_origin + cell["path"]
        identity = str(cell.get("identity") or "anonymous")
        nonce = secrets.token_hex(8)
        test_type = cell["test_type"]
        if test_type == "crlf":
            control_value = "%0D%0AX-Prowl-Probe: " + nonce
            probe_value = "\r\nX-Prowl-Probe: " + nonce
        else:
            control_value = scoped_origin + "/__prowl_control_" + nonce
            probe_value = "https://prowl.invalid/" + nonce
        control_url, control_source = self._observed_get_query_template(
            url, parameter, control_value, identity, capture_id=cell.get("capture_id") or "",
        )
        probe_url, probe_source = self._observed_get_query_template(
            url, parameter, probe_value, identity, capture_id=cell.get("capture_id") or "",
        )
        if control_source == "single_parameter" or probe_source != control_source:
            return {"success": False, "error": "observed_query_baseline_missing"}
        try:
            self._scoped_origin(control_url)
            self._scoped_origin(probe_url)
            self._scoped_claim_gets(2)
            proof = await asyncio.to_thread(
                probe_response, control_url, probe_url, test_type=test_type,
                allowed_origin=scoped_origin, state=self._scoped_state(identity, url),
                nonce=nonce,
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__}
        summary = {"test_type": test_type, "parameter": parameter,
                   "path": cell["path"], "request_context": control_source,
                   "nonce": nonce,
                   **proof}
        artifact_id = evidence_store(self).record(
            "scoped_response_probe", summary, target=url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type=test_type,
            capture_id=str(cell.get("capture_id") or ""),
            success=proof["proof_confirmed"],
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = "scoped_response_probe"
        if proof["proof_confirmed"]:
            cell["status"] = "in_focus"
            cell["reason"] = "Response-header signal requires independent verification"
        self._engagement_brain = brain.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": proof, "funnel": parameter_test_funnel(brain)}

    async def scoped_cors_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> Dict[str, Any]:
        """Test one leased endpoint for credentialed CORS origin reflection."""
        import asyncio
        import secrets
        import time
        from urllib.parse import urlsplit

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.response_probe import probe_cors

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "surface_applicability"
                or cell.get("test_type") != "cors"
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        url = scoped_origin + cell["path"]
        identity = str(cell.get("identity") or "anonymous")
        nonce = secrets.token_hex(8)
        try:
            self._scoped_origin(url)
            self._scoped_claim_gets(2)
            proof = await asyncio.to_thread(
                probe_cors, url, allowed_origin=scoped_origin,
                state=self._scoped_state(identity, url), nonce=nonce,
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__}
        summary = {"test_type": "cors", "parameter": "origin",
                   "path": cell["path"], "request_context": "origin_header",
                   "nonce": nonce,
                   **proof}
        artifact_id = evidence_store(self).record(
            "scoped_response_probe", summary, target=url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type="cors",
            success=proof["proof_confirmed"],
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = "scoped_cors_probe"
        if proof["proof_confirmed"]:
            cell["status"] = "in_focus"
            cell["reason"] = "Credentialed CORS reflection requires independent verification"
        self._engagement_brain = brain.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": proof, "funnel": parameter_test_funnel(brain)}

    async def scoped_race_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        field: str, readback_url: str, cleanup_url_template: str,
        concurrency: int = 10,
    ) -> Dict[str, Any]:
        """Prove a limit the server enforces in series but not under concurrency."""
        import secrets
        import time
        from urllib.parse import urlsplit

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.race_probe import probe_race

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "surface_applicability"
                or cell.get("test_type") != "race_condition"
                or str(cell.get("method") or "POST").upper() not in {"POST", "PUT", "PATCH"}
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        action_path = str(cell.get("path") or "/")
        if action_path not in (getattr(self, "_scoped_race_action_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "race action path is not in race_action_paths"}
        if "__PROWL_NONCE__" not in cleanup_url_template:
            return {"success": False, "error": "cleanup_template_missing_nonce"}
        cleanup_path = urlsplit(cleanup_url_template.replace("__PROWL_NONCE__", "x")).path or "/"
        if cleanup_path not in (getattr(self, "_scoped_race_cleanup_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "cleanup path is not in race_cleanup_paths"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        observed = set(cmap.get("pages_visited") or []) | {
            row.get("url") for row in (cmap.get("discovered_links") or [])
            if isinstance(row, dict)}
        if readback_url not in observed or _origin(readback_url) != scoped_origin:
            return {"success": False, "error": "observed_readback_page_missing"}
        action_url = scoped_origin + action_path
        identity = str(cell.get("identity") or "anonymous")
        method = str(cell.get("method") or "POST").upper()
        nonce = secrets.token_hex(8)
        try:
            self._scoped_origin(action_url)
            self._scoped_claim_race()
            proof = await probe_race(
                action_url, readback_url, cleanup_url_template, method=method,
                field=str(field or ""), allowed_origin=scoped_origin,
                state=self._scoped_state(identity, action_url), nonce=nonce,
                concurrency=int(concurrency or 10),
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__,
                    "reason": str(exc)[:200]}
        summary = {"nonce": nonce, "path": action_path,
                   "readback_url": readback_url,
                   "cleanup_template": cleanup_url_template, **proof}
        artifact_id = evidence_store(self).record(
            "scoped_race_probe", summary, target=action_url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type="race_condition",
            success=proof["proof_confirmed"],
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = "scoped_race_probe"
        if proof["proof_confirmed"]:
            cell["status"] = "in_focus"
            cell["reason"] = "Concurrency overrun signal requires independent verification"
        self._engagement_brain = brain.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": {k: proof[k] for k in
                                 ("control", "probe", "cleanup_confirmed", "requests_sent")},
                "funnel": parameter_test_funnel(brain)}

    async def scoped_injection_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> Dict[str, Any]:
        """Test one observed input for SSTI, command injection, traversal, or NoSQL.

        Computed-output (SSTI/command injection), known-file (traversal), or
        operator-differential (NoSQL) proofs only. Observed GET query inputs and
        operator-approved, browser-captured POST bodies (form or JSON) are
        supported. The model chooses the leased cell; payloads, factors, and
        requests are fixed here.
        """
        import secrets
        import time

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.injection_probe import (
            TEST_TYPES, new_factors, recipes_for,
        )
        from app.services.agent.tester_loop import OBSERVED_INPUT_SOURCES

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        location, separator, parameter = str((cell or {}).get("parameter") or "").partition(":")
        method = str((cell or {}).get("method") or "").upper()
        get_input = method == "GET" and location == "query"
        post_input = (method == "POST" and location in {"body_form", "body_json"}
                      and bool((cell or {}).get("capture_id"))
                      and (cell or {}).get("observation_source") == "browser_traffic"
                      and location in {"body_form", "body_json"})
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "parameter_inventory"
                or cell.get("observation_source") not in OBSERVED_INPUT_SOURCES
                or cell.get("test_type") not in TEST_TYPES
                or not (get_input or post_input)
                or not separator or not parameter
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        if post_input and str(cell.get("path") or "/") not in (
                getattr(self, "_scoped_body_replay_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "POST path is not in body_replay_paths"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        from urllib.parse import urlsplit
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        url = scoped_origin + cell["path"]
        identity = str(cell.get("identity") or "anonymous")
        test_type = cell["test_type"]
        nonce = secrets.token_hex(8)
        factors = new_factors() if test_type != "path_traversal" else (0, 0)
        try:
            proof, context = await self._run_injection_probe(
                cell, url, parameter, test_type, nonce, factors, identity,
                scoped_origin=scoped_origin, recipe="",
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
        summary = {"test_type": test_type, "parameter": parameter, "location": location,
                   "path": cell["path"], "request_context": context, "nonce": nonce,
                   "recipes_available": list(recipes_for(test_type)), **proof}
        artifact_id = evidence_store(self).record(
            "scoped_injection_probe", summary, target=url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type=test_type,
            capture_id=str(cell.get("capture_id") or ""),
            success=proof["proof_confirmed"],
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = "scoped_injection_probe"
        if proof["proof_confirmed"]:
            cell["status"] = "in_focus"
            cell["reason"] = "Server-side injection signal requires independent verification"
        self._engagement_brain = brain.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": {k: proof.get(k) for k in
                                 ("test_type", "recipe", "control", "probes", "requests_sent")},
                "funnel": parameter_test_funnel(brain)}

    async def _run_injection_probe(
        self, cell: Dict[str, Any], url: str, parameter: str, test_type: str,
        nonce: str, factors: tuple, identity: str, *, scoped_origin: str,
        recipe: str = "",
    ) -> tuple[dict, str]:
        """Build and send one injection proof for a GET query or captured POST body.

        ``recipe`` restricts a verifier replay to the hunter's recipe.
        """
        import asyncio

        from app.services.agent.scoped_assessment import injection_probe

        location = str(cell.get("parameter") or "").partition(":")[0]
        state = self._scoped_state(identity, url)
        if location in {"body_form", "body_json"}:
            requests, context, fetch = self._injection_probe_bodies(
                cell, parameter, test_type, nonce, factors, identity, scoped_origin)
            if test_type == "nosql":
                self._scoped_claim_posts(len(requests))
                proof = await asyncio.to_thread(
                    injection_probe.probe_nosql, requests, allowed_origin=scoped_origin,
                    state=state, nonce=nonce, fetch=fetch,
                )
                return proof, context
            if recipe:
                if recipe not in requests:
                    raise ValueError("Observed injection baseline changed")
                requests = {"control": requests["control"], recipe: requests[recipe]}
            self._scoped_claim_posts(len(requests))
            proof = await asyncio.to_thread(
                injection_probe.probe_injection, requests, test_type=test_type,
                allowed_origin=scoped_origin, state=state, nonce=nonce,
                factors=factors, fetch=fetch,
            )
            return proof, context
        urls, context = self._injection_probe_urls(
            url, parameter, test_type, nonce, factors, identity,
            capture_id=str(cell.get("capture_id") or ""),
        )
        if test_type == "nosql":
            self._scoped_claim_gets(len(urls))
            proof = await asyncio.to_thread(
                injection_probe.probe_nosql, urls, allowed_origin=scoped_origin,
                state=state, nonce=nonce,
            )
            return proof, context
        if recipe:
            if recipe not in urls:
                raise ValueError("Observed injection baseline changed")
            urls = {"control": urls["control"], recipe: urls[recipe]}
        self._scoped_claim_gets(min(9, len(urls)))
        proof = await asyncio.to_thread(
            injection_probe.probe_injection, urls, test_type=test_type,
            allowed_origin=scoped_origin, state=state, nonce=nonce, factors=factors,
        )
        return proof, context

    def _injection_probe_bodies(
        self, cell: Dict[str, Any], parameter: str, test_type: str, nonce: str,
        factors: tuple, identity: str, scoped_origin: str,
    ):
        """Control and fixed probe bodies from one approved, captured POST."""
        from urllib.parse import urlsplit

        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.injection_probe import (
            control_value, probe_value, recipes_for,
        )

        private = self._scoped_exchange(str(cell["capture_id"]), identity)
        captured = json.loads(private)
        url = str(captured.get("url") or "")
        allowed = self._scoped_origin(url)
        if (allowed != scoped_origin or captured.get("method") != "POST"
                or captured.get("resource_type") not in {"xhr", "fetch"}
                or (urlsplit(url).path or "/") != cell.get("path")):
            raise ValueError("captured_post_shape_mismatch")
        if cell.get("path") not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            raise ValueError("operator_approval_required")
        a, b = factors
        replace = test_type == "path_traversal"

        def plan(value: str) -> tuple[str, bytes]:
            _url, mime, _baseline, changed = body_probe.plan_observed_body(
                private, parameter=parameter, allowed_origins=[allowed],
                payload=value, replace=replace,
            )
            return mime, changed

        if test_type == "nosql":
            from app.services.agent.scoped_assessment.injection_probe import NOSQL_SEQUENCE

            literal = control_value(test_type, nonce)
            location = str(cell.get("parameter") or "").partition(":")[0]
            values = {"control": literal, "true": {"$ne": literal}, "false": {"$eq": literal}}
            operators = {"control": "", "true": "$ne", "false": "$eq"}
            requests = {}
            for step in NOSQL_SEQUENCE:
                kind = step.split("_", 1)[0]
                if location == "body_form":
                    _url, mime, requests[step] = body_probe.plan_form_operator_body(
                        private, parameter=parameter, allowed_origins=[allowed],
                        operator=operators[kind], value=literal,
                    )
                else:
                    _url, mime, requests[step] = body_probe.plan_json_value_body(
                        private, parameter=parameter, allowed_origins=[allowed],
                        value=values[kind],
                    )
        else:
            mime, control = plan(control_value(test_type, nonce))
            requests = {"control": control}
            for name in recipes_for(test_type):
                requests[name] = plan(probe_value(test_type, name, a, b))[1]
        headers = body_probe.safe_replay_headers(private)
        state = self._scoped_state(identity, url)

        def fetch(body: bytes, **_ignored) -> tuple[int, bytes]:
            result = body_probe._observe_post(url, mime, body, [allowed], state,
                                              replay_headers=headers, capture_body=True)
            return int(result.get("status") or 0), bytes(result.get("_private_body") or b"")

        return requests, f"captured_post:{mime}", fetch

    def _injection_probe_urls(
        self, url: str, parameter: str, test_type: str, nonce: str,
        factors: tuple, identity: str, capture_id: str = "",
    ) -> tuple[dict, str]:
        """Build control and fixed probe URLs from one observed GET baseline."""
        from app.services.agent.scoped_assessment.injection_probe import (
            control_value, probe_value, recipes_for,
        )

        a, b = factors
        control_url, context = self._observed_get_query_template(
            url, parameter, control_value(test_type, nonce), identity, capture_id=capture_id,
        )
        if context == "single_parameter":
            raise ValueError("observed_query_baseline_missing")
        self._scoped_origin(control_url)
        if test_type == "nosql":
            from app.services.agent.scoped_assessment.injection_probe import (
                NOSQL_SEQUENCE, nosql_field_name, rename_query_field,
            )

            urls = {step: rename_query_field(control_url, parameter,
                                             nosql_field_name(parameter, step))
                    for step in NOSQL_SEQUENCE}
            return urls, context
        urls = {"control": control_url}
        for recipe in recipes_for(test_type):
            probe_url, probe_context = self._observed_get_query_template(
                url, parameter, probe_value(test_type, recipe, a, b), identity,
                capture_id=capture_id,
            )
            if probe_context != context:
                raise ValueError("observed_query_baseline_missing")
            self._scoped_origin(probe_url)
            urls[recipe] = probe_url
        return urls, context

    async def scoped_jwt_probe(self, target_url: str, identity: str,
                               jwks_url: str = "") -> Dict[str, Any]:
        """Check whether an observed endpoint verifies the identity's JWT signature.

        Uses the registered identity's own token, adds a nonce claim, and sends it
        unsigned (alg none) or with a non-matching signature. The model supplies
        only the observed URL and identity name.
        """
        import asyncio
        import secrets

        from app.services.agent.assessment_sessions import identity_registry
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment import jwt_probe

        identity = str(identity or "")
        if identity in {"", "anonymous", "unspecified", "legacy"}:
            return {"success": False, "error": "registered_identity_required"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        observed = set(cmap.get("pages_visited") or []) | {
            row.get("url") for row in (cmap.get("discovered_links") or []) if isinstance(row, dict)
        } | {row.get("url") for row in (cmap.get("api_samples") or []) if isinstance(row, dict)}
        if (not scoped_origin or target_url not in observed
                or _origin(str(target_url)) != scoped_origin):
            return {"success": False, "error": "observed_endpoint_required"}
        nonce = secrets.token_hex(8)
        try:
            self._scoped_origin(target_url)
            session = identity_registry(self).resolve(identity, target_url)
            public_pem = None
            if jwks_url:
                if _origin(str(jwks_url)) != scoped_origin:
                    raise ValueError("jwks_url must be on the assessed origin")
                self._scoped_origin(jwks_url)
                self._scoped_claim_gets(1)
                jwks = await asyncio.to_thread(
                    jwt_probe.fetch_jwks, jwks_url, allowed_origin=scoped_origin)
                _, _, _, header, _ = jwt_probe._decode(jwt_probe.locate_token(session)[2])
                public_pem = jwt_probe.jwk_to_pem(jwks, header.get("kid"))
            self._scoped_claim_gets(8)
            proof = await asyncio.to_thread(
                jwt_probe.probe_jwt, target_url, allowed_origin=scoped_origin,
                session=session, nonce=nonce, public_pem=public_pem,
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
        summary = {"nonce": nonce, "jwks_url": str(jwks_url or ""), **proof}
        artifact_id = evidence_store(self).record(
            "scoped_jwt_probe", summary, target=target_url, identity=identity,
            test_type="jwt", success=proof["proof_confirmed"],
        )
        return {"success": True, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": {k: proof[k] for k in
                                 ("auth_enforced", "recipe", "probes", "requests_sent")}}

    async def scoped_jwt_key_url_probe(self, target_url: str, identity: str,
                                       header: str = "jku") -> Dict[str, Any]:
        """Check whether an observed endpoint fetches a jku/x5u URL from the token.

        Needs out-of-band callbacks authorized for the run. Registers a fresh
        collaborator, puts its URL in the identity's token header, and confirms
        only on an HTTP fetch of that registration.
        """
        import asyncio
        import secrets

        from app.services import interactsh_service
        from app.services.agent.assessment_sessions import identity_registry
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment import jwt_probe

        if not getattr(self, "_oob_callbacks_allowed", False):
            return {"success": False, "error": "oob_not_authorized"}
        if header not in jwt_probe.KEY_URL_HEADERS:
            return {"success": False, "error": "header must be jku or x5u"}
        identity = str(identity or "")
        if identity in {"", "anonymous", "unspecified", "legacy"}:
            return {"success": False, "error": "registered_identity_required"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        observed = set(cmap.get("pages_visited") or []) | {
            row.get("url") for row in (cmap.get("discovered_links") or []) if isinstance(row, dict)
        } | {row.get("url") for row in (cmap.get("api_samples") or []) if isinstance(row, dict)}
        if (not scoped_origin or target_url not in observed
                or _origin(str(target_url)) != scoped_origin):
            return {"success": False, "error": "observed_endpoint_required"}
        nonce = secrets.token_hex(8)
        try:
            self._scoped_origin(target_url)
            session = identity_registry(self).resolve(identity, target_url)
            self._scoped_claim_gets(2)
            proof = await asyncio.to_thread(
                jwt_probe.probe_jwt_key_url, target_url, allowed_origin=scoped_origin,
                session=session, nonce=nonce, header_name=header,
                register=interactsh_service.register, poll=interactsh_service.poll,
                stop=interactsh_service.stop,
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
        artifact_id = evidence_store(self).record(
            "scoped_jwt_probe", {"nonce": nonce, **proof}, target=target_url,
            identity=identity, test_type="jwt", success=proof["proof_confirmed"],
        )
        return {"success": True, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": {k: proof.get(k) for k in
                                 ("auth_enforced", "recipe", "interactions", "requests_sent")}}

    async def scoped_csrf_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        field: str, readback_url: str, cleanup_url_template: str,
    ) -> Dict[str, Any]:
        """Prove a cross-site, token-less form POST changes the victim's state."""
        import secrets
        import time
        from urllib.parse import urlsplit

        from app.services.agent.coverage_cells import parameter_test_funnel
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path
        from app.services.agent.scoped_assessment.csrf_probe import probe_csrf

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "surface_applicability"
                or cell.get("test_type") != "csrf"
                or str(cell.get("method") or "POST").upper() != "POST"
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": _lease_failure_reason(cell, coverage_lease_id)}
        action_path = str(cell.get("path") or "/")
        if action_path not in (getattr(self, "_scoped_csrf_action_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "CSRF action path is not in csrf_action_paths"}
        if "__PROWL_NONCE__" not in str(cleanup_url_template or ""):
            return {"success": False, "error": "cleanup_template_missing_nonce"}
        cleanup_path = urlsplit(cleanup_url_template.replace("__PROWL_NONCE__", "x")).path or "/"
        if cleanup_path not in (getattr(self, "_scoped_csrf_cleanup_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "cleanup path is not in csrf_cleanup_paths"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        observed = set(cmap.get("pages_visited") or []) | {
            row.get("url") for row in (cmap.get("discovered_links") or [])
            if isinstance(row, dict)}
        if readback_url not in observed or _origin(readback_url) != scoped_origin:
            return {"success": False, "error": "observed_readback_page_missing"}
        identity = str(cell.get("identity") or "anonymous")
        if identity in {"", "anonymous", "unspecified"}:
            return {"success": False, "error": "authenticated_identity_required"}
        action_url = scoped_origin + action_path
        nonce = secrets.token_hex(8)
        try:
            self._scoped_origin(action_url)
            self._scoped_claim_posts(2)
            self._scoped_claim_gets(3)
            proof = await probe_csrf(
                action_url, readback_url, cleanup_url_template, field=str(field or ""),
                allowed_origin=scoped_origin, state=self._scoped_state(identity, action_url),
                nonce=nonce,
            )
        except (ValueError, OSError) as exc:
            return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}
        summary = {"nonce": nonce, "path": action_path, "readback_url": readback_url,
                   "cleanup_template": cleanup_url_template, **proof}
        artifact_id = evidence_store(self).record(
            "scoped_csrf_probe", summary, target=action_url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type="csrf",
            success=proof["proof_confirmed"],
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = "scoped_csrf_probe"
        if proof["proof_confirmed"]:
            cell["status"] = "in_focus"
            cell["reason"] = "Cross-site state change requires independent verification"
        self._engagement_brain = brain.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"],
                "probe_result": {k: proof[k] for k in
                                 ("control", "probe", "cross_site_cookie_eligible",
                                  "cleanup_confirmed", "requests_sent")},
                "funnel": parameter_test_funnel(brain)}

    async def scoped_xml_entity_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        technique: str = "parser_control",
    ) -> Dict[str, Any]:
        """Test one leased, browser-captured XML POST without model-supplied bytes."""
        import time
        from urllib.parse import urlsplit

        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.parameter_inventory import _origin
        from app.services.agent.scoped_assessment.xml_entity import (
            plan_xml_entity_probe, send_xml_callback,
        )

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "parameter_inventory"
                or cell.get("observation_source") != "browser_traffic"
                or cell.get("test_type") != "xxe"
                or cell.get("method") != "POST"
                or cell.get("parameter") != "body_xml:document"
                or not cell.get("capture_id")):
            return {"success": False, "error": "invalid_xml_coverage_lease"}
        if technique not in {"parser_control", "external_callback"}:
            return {"success": False, "error": "unsupported_technique"}
        if technique in {row.get("technique") for row in cell.get("xxe_probe_attempts") or []}:
            return {"success": False, "error": "technique_already_attempted"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or
                                    getattr(self, "_fallback_target", "") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        path = str(cell.get("path") or "")
        if path not in (getattr(self, "_scoped_body_replay_paths", None) or set()):
            return {"success": False, "error": "operator_approval_required",
                    "reason": "The exact XML POST path needs approved replay"}
        identity = str(cell.get("identity") or "anonymous")
        try:
            private = self._scoped_exchange(str(cell["capture_id"]), identity)
            plan = plan_xml_entity_probe(
                private, allowed_origin=scoped_origin, expected_path=path,
            )
            self._scoped_origin(plan["url"])
        except (TypeError, ValueError) as exc:
            return {"success": False, "error": "invalid_xml_capture",
                    "reason": str(exc)[:200]}
        if technique == "external_callback" and not self._oob_callbacks_allowed:
            return {"success": False, "error": "oob_callbacks_not_authorized"}
        try:
            if technique == "parser_control":
                self._scoped_claim_posts(1)
                exchange = await self._http_exchange(
                    method="POST", url=plan["url"],
                    headers={**plan["headers"], "Content-Type": plan["mime"]},
                    body=plan["control_body"], identity=identity,
                    use_auth_session=False, follow_redirects=False,
                    coverage_cell_id=coverage_cell_id,
                )
                evidence_id = str(exchange["evidence_id"])
                probe = {"status": exchange["response"]["status"],
                         "parser_control_sent": True}
                extra_ids: list[str] = []
                confirmed = False
            else:
                callback = await send_xml_callback(self, plan, identity=identity)
                extra_ids = [str(item) for item in callback.get("evidence_ids") or []]
                confirmed = callback.get("callback_observed") is True
                probe = {"callback_observed": confirmed,
                         "poll_attempts": int(callback.get("poll_attempts") or 0)}
                evidence_id = evidence_store(self).record(
                    "scoped_xml_xxe", {
                        "operation": "external_callback", "target": plan["url"],
                        "source_artifact_id": cell["capture_id"],
                        "callback_observed": confirmed,
                        "oob_evidence_ids": extra_ids,
                    }, target=plan["url"], identity=identity, success=confirmed,
                )
        except (KeyError, TypeError, ValueError) as exc:
            return {"success": False, "error": "xml_probe_failed",
                    "reason": str(exc)[:200]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed"}
        current["probe_artifact_ids"] = list(dict.fromkeys([
            *(current.get("probe_artifact_ids") or []), evidence_id,
        ]))[:20]
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), evidence_id, *extra_ids,
        ]))[:30]
        current["xxe_probe_attempts"] = [
            *(current.get("xxe_probe_attempts") or []),
            {"technique": technique, "evidence_id": evidence_id,
             "callback_observed": confirmed},
        ][:2]
        current["last_probe"] = "scoped_xml_" + technique
        if confirmed:
            current["status"] = "in_focus"
            current["reason"] = "XML callback signal; independent verification required"
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "operation": current["last_probe"],
                "technique": technique, "evidence_id": evidence_id,
                "proof_confirmed": confirmed, "probe_result": probe}

    async def scoped_stored_xss_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        readback_url: str, cleanup_url_template: str,
    ) -> Dict[str, Any]:
        """Submit, independently read, and clean up one approved stored XSS canary."""
        import time
        from urllib.parse import urlsplit
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.parameter_inventory import _origin

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        location, separator, field = str((cell or {}).get("parameter") or "").partition(":")
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "parameter_inventory"
                or cell.get("test_type") != "stored_xss"
                or cell.get("method") != "POST"
                or location != "body_form" or not separator or not field):
            return {"success": False, "error": "invalid_stored_xss_lease"}
        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if (not scoped_origin or _origin(f"{parts.scheme}://{cell.get('host') or ''}")
                != scoped_origin):
            return {"success": False, "error": "scope_mismatch"}
        action = scoped_origin + str(cell.get("path") or "/")
        pages = sorted({str(form.get("page")) for form in (cmap.get("forms") or [])[:80]
                        if isinstance(form, dict)
                        and str(form.get("method") or "").upper() == "POST"
                        and form.get("action") == action
                        and field in (form.get("inputs") or [])
                        and _origin(str(form.get("page") or "")) == scoped_origin
                        and not urlsplit(str(form.get("page") or "")).query
                        and not urlsplit(str(form.get("page") or "")).fragment})
        if len(pages) != 1:
            return {"success": False, "error": "observed_form_page_missing"}
        if (readback_url not in (cmap.get("pages_visited") or [])
                and readback_url not in [row.get("url") for row in
                                         (cmap.get("discovered_links") or []) if isinstance(row, dict)]):
            return {"success": False, "error": "observed_readback_page_missing"}
        payload = '<img src=x onerror=alert("__PROWL_NONCE__")>'
        try:
            proof = json.loads(await self.scoped_browser_assessment(
                "check_stored_xss", pages[0], identity=str(cell.get("identity") or "anonymous"),
                form_action=action, form_field=field, form_payload_template=payload,
                readback_url=readback_url, cleanup_url_template=cleanup_url_template,
            ))
        except ValueError as exc:
            return {"success": False, "error": "operator_approval_required",
                    "reason": str(exc)[:200]}
        artifact_id = str(proof.get("evidence_id") or "")
        if not artifact_id:
            return {"success": False, "error": str(proof.get("error") or "missing_probe_evidence")[:100]}
        live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        current = next((row for row in live.coverage_cells
                        if row.get("id") == coverage_cell_id
                        and row.get("lease_id") == coverage_lease_id), None)
        if current is None:
            return {"success": False, "error": "lease_changed"}
        current["probe_artifact_ids"] = list(dict.fromkeys([
            *(current.get("probe_artifact_ids") or []), artifact_id,
        ]))[:20]
        current["evidence_ids"] = list(dict.fromkeys([
            *(current.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        current["last_probe"] = "scoped_browser_check_stored_xss"
        if proof.get("executed") is True:
            current["status"] = "in_focus"
            current["reason"] = "Stored readback execution signal; independent verification required"
        self._engagement_brain = live.to_dict()
        return {"success": True, "coverage_cell_id": coverage_cell_id,
                "coverage_lease_id": coverage_lease_id, "evidence_id": artifact_id,
                "operation": "scoped_browser_check_stored_xss",
                "proof_confirmed": proof.get("executed") is True,
                "probe_result": {"executed": proof.get("executed") is True,
                                 "readback_executed": proof.get("readback_executed") is True,
                                 "cleanup_success": proof.get("cleanup_success") is True}}

    async def scoped_assessment_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str,
        technique: str = "captured",
    ) -> Dict[str, Any]:
        """Replay exactly the specialist's leased PROWL browser input."""
        import time
        from urllib.parse import quote, urlsplit
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        lease_error = (
            "missing_cell" if not cell else
            "not_leased" if cell.get("status") != "leased" else
            "lease_mismatch" if cell.get("lease_id") != coverage_lease_id else
            "lease_expired" if float(cell.get("lease_deadline") or 0) <= time.time() else
            "not_parameter_inventory" if cell.get("source") != "parameter_inventory" else
            "wrong_specialist" if cell.get("specialist") not in {"xss", "sqli"} else
            "not_private_browser_capture" if cell.get("observation_source") != "browser_traffic" else
            "missing_capture" if not cell.get("capture_id") else ""
        )
        if lease_error:
            return {"success": False, "error": "invalid_coverage_lease",
                    "reason": lease_error,
                    "output": f"An active lease on a browser-captured parameter is required ({lease_error})"}
        location, separator, parameter = str(cell.get("parameter") or "").partition(":")
        xss_payloads = {
            "xss_browser": '<img src=x onerror=alert("__PROWL_NONCE__")>',
            "xss_browser_svg": '<svg onload=alert("__PROWL_NONCE__")>',
            "xss_browser_attribute": '"><img src=x onerror=alert("__PROWL_NONCE__")>',
            "xss_browser_attribute_single": "'><img src=x onerror=alert(\"__PROWL_NONCE__\")>",
            "xss_browser_js_single": "';alert(\"__PROWL_NONCE__\");//",
            "xss_browser_js_double": '\";alert(\'__PROWL_NONCE__\');//',
        }
        if not separator or not parameter or technique not in {"captured", "xss_reflection", *xss_payloads}:
            return {"success": False, "error": "invalid_parameter_probe",
                    "output": "Unsupported parameter or technique"}
        identity = str(cell.get("identity") or "anonymous")
        body = {"artifact_id": cell["capture_id"], "parameter": parameter, "identity": identity}
        method = str(cell.get("method") or "GET")
        if cell.get("specialist") == "xss" and method == "POST" and location in {"body_json", "body_form"}:
            if technique not in {"captured", "xss_reflection", *xss_payloads}:
                return {"success": False, "error": "unsupported_xss_browser",
                        "output": "POST XSS requires an approved captured body"}
            captured_row = self._scoped_capture_row(str(cell["capture_id"]))
            captured = {}
            if captured_row and captured_row.get("identity") == identity:
                try:
                    captured = json.loads(captured_row["private"])
                except (TypeError, ValueError):
                    pass
            page_url = str(captured.get("page_url") or "")
            captured_url = str(captured.get("url") or "")
            browser_ready = (technique != "xss_reflection"
                             and captured.get("method") == "POST"
                             and captured.get("resource_type") in {"xhr", "fetch"}
                             and (urlsplit(captured_url).path or "/") == cell.get("path")
                             and bool(page_url)
                             and not urlsplit(page_url).query
                             and not urlsplit(page_url).fragment)
            if browser_ready:
                try:
                    proof = json.loads(await self.scoped_browser_assessment(
                        "check_xhr_xss", page_url, identity=identity,
                        xhr_path=cell["path"], xhr_parameter=parameter,
                        xhr_payload_template=xss_payloads.get(
                            technique, xss_payloads["xss_browser"]),
                        xhr_query_keys=[], xhr_capture_id=cell["capture_id"],
                        xhr_actions=captured.get("replay_actions") or [],
                    ))
                except ValueError as exc:
                    return {"success": False, "error": "post_xhr_replay_blocked",
                            "reason": str(exc)[:200]}
                artifact_id = str(proof.get("evidence_id") or "")
                if not artifact_id:
                    return {"success": False, "error": "missing_probe_evidence"}
                live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                current = next((row for row in live.coverage_cells
                                if row.get("id") == coverage_cell_id
                                and row.get("lease_id") == coverage_lease_id), None)
                if current is None:
                    return {"success": False, "error": "lease_changed"}
                current["probe_artifact_ids"] = list(dict.fromkeys([
                    *(current.get("probe_artifact_ids") or []), artifact_id,
                ]))[:20]
                current["evidence_ids"] = list(dict.fromkeys([
                    *(current.get("evidence_ids") or []), artifact_id,
                ]))[:30]
                current["last_probe"] = "scoped_browser_check_xhr_xss"
                if proof.get("executed") is True:
                    current["status"] = "in_focus"
                    current["reason"] = "Captured POST XHR executed in browser; independent verification required"
                self._engagement_brain = live.to_dict()
                return {"success": True, "coverage_cell_id": coverage_cell_id,
                        "coverage_lease_id": coverage_lease_id,
                        "operation": "scoped_browser_check_xhr_xss",
                        "evidence_id": artifact_id,
                        "proof_confirmed": proof.get("executed") is True,
                        "probe_result": {"executed": proof.get("executed") is True,
                                         "xhr_mutated": proof.get("xhr_mutated") is True,
                                         "xhr_response_seen": proof.get("xhr_response_seen") is True,
                                         "reflection_contexts": proof.get("reflection_contexts") or [],
                                         "reflection_observations": proof.get("reflection_observations") or []}}
            try:
                proof = json.loads(await self.scoped_body_xss_reflection(
                    cell["capture_id"], parameter, identity,
                ))
            except ValueError as exc:
                return {"success": False, "error": "operator_approval_required",
                        "reason": str(exc)[:200], "output": "POST replay needs an approved path and capture"}
            artifact_id = str(proof.get("evidence_id") or "")
            if not artifact_id:
                return {"success": False, "error": "missing_probe_evidence"}
            live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            current = next((row for row in live.coverage_cells
                            if row.get("id") == coverage_cell_id and row.get("lease_id") == coverage_lease_id), None)
            if current is None:
                return {"success": False, "error": "lease_changed"}
            current["probe_artifact_ids"] = list(dict.fromkeys([
                *(current.get("probe_artifact_ids") or []), artifact_id,
            ]))[:20]
            current["evidence_ids"] = list(dict.fromkeys([
                *(current.get("evidence_ids") or []), artifact_id,
            ]))[:30]
            current["last_probe"] = "scoped_body_xss_reflection"
            self._engagement_brain = live.to_dict()
            return {"success": True, "coverage_cell_id": coverage_cell_id,
                    "coverage_lease_id": coverage_lease_id,
                    "operation": "scoped_body_xss_reflection", "evidence_id": artifact_id,
                    "proof_confirmed": False,
                    "probe_result": {"reflection_detected": proof["reflection_detected"],
                                     "raw_html_reflection": proof["raw_html_reflection"]}}
        local_capture = self._scoped_capture_row(str(cell.get("capture_id") or ""))
        if (cell.get("specialist") == "sqli" and local_capture
                and local_capture.get("identity") == identity):
            try:
                if method == "GET" and location == "query":
                    if cell.get("value_type") in {"positive_integer", "number"}:
                        operation = "scoped_numeric_sqli"
                        proof = json.loads(await self.scoped_numeric_sqli(
                            artifact_id=cell["capture_id"], parameter=parameter,
                            identity=identity,
                        ))
                    else:
                        operation = "scoped_string_sqli"
                        url = json.loads(self._scoped_exchange(cell["capture_id"], identity))["url"]
                        proof = json.loads(await self.scoped_string_sqli(
                            url, parameter, identity, artifact_id=cell["capture_id"],
                        ))
                elif method == "POST" and location in {"body_json", "body_form"}:
                    operation = "scoped_body_probe"
                    proof = json.loads(await self.scoped_body_probe(
                        cell["capture_id"], parameter, identity,
                    ))
                    if proof.get("proof_recipe") in {"post_form_error_v1", "post_json_error_v1"}:
                        operation = "scoped_body_sqli_error"
                    elif proof.get("proof_recipe") == "post_or_boolean_v1":
                        operation = "scoped_body_sqli_boolean"
                else:
                    return {"success": False, "error": "unsupported_capture",
                            "output": "No built-in replay for this captured input shape"}
            except ValueError as exc:
                reason = str(exc)
                error = (
                    "browser_replay_request_cap" if reason == "Browser replay request cap exceeded" else
                    "browser_replay_no_match" if reason == "Fresh browser request did not match captured input and replay action" else
                    "browser_replay_response_missing" if reason == "Browser replay response missing" else
                    "browser_replay_source_missing" if reason == "Captured request has no safe source page for fresh replay" else
                    "local_probe_blocked"
                )
                return {"success": False, "error": error, "reason": reason[:200]}
            artifact_id = str(proof.get("evidence_id") or "")
            if not artifact_id:
                return {"success": False, "error": "missing_probe_evidence"}
            live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            current = next((row for row in live.coverage_cells
                            if row.get("id") == coverage_cell_id and row.get("lease_id") == coverage_lease_id), None)
            if current is None:
                return {"success": False, "error": "lease_changed"}
            current["probe_artifact_ids"] = list(dict.fromkeys([
                *(current.get("probe_artifact_ids") or []), artifact_id,
            ]))[:20]
            current["evidence_ids"] = list(dict.fromkeys([
                *(current.get("evidence_ids") or []), artifact_id,
            ]))[:30]
            current["last_probe"] = operation
            from app.services.agent.coverage_cells import record_sqli_trace

            record_sqli_trace(current, proof)
            if proof.get("proof_confirmed") is True:
                current["status"] = "in_focus"
                current["reason"] = "Execution-owned SQLi proof signal; independent verification required"
            self._engagement_brain = live.to_dict()
            return {"success": True, "coverage_cell_id": coverage_cell_id,
                    "coverage_lease_id": coverage_lease_id, "operation": operation,
                    "evidence_id": artifact_id,
                    "proof_confirmed": proof.get("proof_confirmed") is True,
                    "probe_result": {key: proof[key] for key in (
                        "proof_recipe", "changed", "inconclusive", "requests_sent",
                    ) if key in proof}}
        if technique in xss_payloads:
            if cell.get("specialist") != "xss" or method != "GET" or location != "query":
                return {"success": False, "error": "unsupported_xss_browser",
                        "output": "Browser XSS check requires a captured GET query parameter"}
            local_capture = self._scoped_capture_row(str(cell.get("capture_id") or ""))
            if local_capture and local_capture.get("identity") == identity:
                result = await self.scoped_input_probe_assigned(
                    coverage_cell_id, coverage_lease_id, technique={
                        "xss_browser": "html_body",
                        "xss_browser_svg": "html_body_svg",
                        "xss_browser_attribute": "html_attribute",
                        "xss_browser_attribute_single": "html_attribute_single",
                        "xss_browser_js_single": "js_single",
                        "xss_browser_js_double": "js_double",
                    }[technique],
                )
                result["assigned_operation"] = result.get("operation", "")
                return result
            cmap = getattr(self, "_capability_map", None) or {}
            origin = urlsplit(str(cmap.get("scope") or cmap.get("target") or ""))
            if (origin.scheme not in {"http", "https"} or
                    origin.netloc.lower() != str(cell.get("host") or "").lower()):
                return {"success": False, "error": "scope_mismatch",
                        "output": "Assigned input does not match the scoped origin"}
            payload = xss_payloads[technique]
            template = (f"{origin.scheme}://{origin.netloc}{cell['path']}?"
                        f"{quote(parameter, safe='')}={quote(payload, safe='')}")
            operation = "browser_check_xss"
            body = {"url_template": template, "identity": identity}
        elif method == "GET" and location == "query":
            operation = (
                "http_sqli_boolean"
                if cell.get("specialist") == "sqli" and cell.get("value_type") == "positive_integer"
                else "http_query_probe"
            )
        elif method == "POST" and location in {"body_json", "body_form"}:
            operation = "http_body_probe"
        else:
            return {"success": False, "error": "unsupported_capture",
                    "output": "The scoped service cannot replay this input shape"}
        result = await self._scoped_assessment_operation(operation, body)
        result["coverage_cell_id"] = coverage_cell_id
        result["coverage_lease_id"] = coverage_lease_id
        result["assigned_operation"] = operation
        if result.get("success") and result.get("service_artifact_ids"):
            live = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            current = next((row for row in live.coverage_cells
                            if row.get("id") == coverage_cell_id and
                            row.get("lease_id") == coverage_lease_id), None)
            if current:
                current["service_probe_artifact_ids"] = list(dict.fromkeys([
                    *(current.get("service_probe_artifact_ids") or []),
                    *result["service_artifact_ids"],
                ]))[:20]
                current["last_service_probe"] = operation
                proof = result.get("probe_result") or {}
                if proof.get("proof_confirmed") is True or proof.get("executed") is True:
                    current["status"] = "in_focus"
                    current["reason"] = "Scoped service returned a proof signal; independent verification required"
                self._engagement_brain = live.to_dict()
        return result

    async def scoped_assessment_candidate(
        self, body: Dict[str, Any], verification_recipe: str = "",
        verification_identity: str = "anonymous",
        verification_page_url: str = "", verification_parameter: str = "",
    ) -> Dict[str, Any]:
        submitted = await self._scoped_assessment_operation("submit_candidate", body)
        if not submitted.get("success") or not verification_recipe:
            return submitted
        from app.services.agent.prowl_service_bridge import verify_candidate_with_fresh_proof

        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        db = SessionLocal()
        try:
            verification = await verify_candidate_with_fresh_proof(
                db, organization_id=org_id, user_id=user_id, session_id=session_id,
                candidate_id=submitted["candidate_id"], recipe=verification_recipe,
                identity=verification_identity, page_url=verification_page_url,
                parameter=verification_parameter,
            )
            submitted["verification"] = verification
            submitted["output"] += "\nVerification: " + json.dumps(verification)
        except ValueError as exc:
            submitted["verification_error"] = str(exc)[:300]
            submitted["output"] += "\nCandidate remains pending: " + str(exc)[:300]
        except Exception:
            logger.exception("Scoped assessment verification failed")
            submitted["verification_error"] = "verification_unavailable"
            submitted["output"] += "\nCandidate remains pending: verification unavailable"
        finally:
            db.close()
        return submitted

    async def scoped_assessment_status(self, operation: str = "assessment_summary") -> Dict[str, Any]:
        if operation not in ("coverage", "assessment_summary", "threat_model_get"):
            return {"success": False, "error": "invalid_operation", "output": "Unknown status operation"}
        return await self._scoped_assessment_operation(operation, None)

    async def scoped_assessment_plan(self, operation: str, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if operation not in ("threat_model_set", "coverage_create", "coverage_update", "complete_assessment"):
            return {"success": False, "error": "invalid_operation", "output": "Unknown planning operation"}
        return await self._scoped_assessment_operation(operation, body)

    async def scoped_assessment_memory(self, target: Optional[str] = None) -> Dict[str, Any]:
        return await self._scoped_assessment_operation("memory_recall", {"target": target} if target else {})

    async def scoped_assessment_publish(self, candidate_id: str) -> Dict[str, Any]:
        """Retry publication of a service-confirmed candidate after intake recovery."""
        from app.services.agent.prowl_service_bridge import publish_confirmed_candidate

        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        if not user_id or not org_id or not session_id:
            return {"success": False, "error": "missing_agent_session", "output": "Agent session is required"}
        db = SessionLocal()
        try:
            result = await publish_confirmed_candidate(
                db, organization_id=org_id, user_id=user_id, session_id=session_id,
                candidate_id=candidate_id,
            )
            return {"success": True, "output": json.dumps(result), "publication": result}
        except ValueError as exc:
            return {"success": False, "error": "publication_rejected", "output": str(exc)[:500]}
        except Exception:
            logger.exception("Scoped assessment publication failed")
            return {"success": False, "error": "publication_unavailable",
                    "output": "Scoped assessment publication is unavailable"}
        finally:
            db.close()
