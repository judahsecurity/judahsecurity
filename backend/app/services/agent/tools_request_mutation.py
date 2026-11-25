"""Custom probes, sandbox shell, captured-request mutation and intruder batches.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    _tool_output_max_chars,
    asyncio,
    current_seed_target,
    json,
    settings,
)


class RequestMutationToolsMixin:
    """Custom probes, sandbox shell, captured-request mutation and intruder batches."""

    def _record_probe_exchanges(self, exchanges: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Store probe-egress recordings as redacted http_exchange evidence.

        The model gets evidence IDs and a one-line index; bodies stay in the
        evidence store, readable with read_evidence/search_evidence.
        """
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.response_classification import classify_response

        store = evidence_store(self)
        index: List[Dict[str, Any]] = []
        for exchange in exchanges:
            request = exchange.get("request") if isinstance(exchange.get("request"), dict) else {}
            response = exchange.get("response") if isinstance(exchange.get("response"), dict) else {}
            url = str(request.get("url") or "")
            body = str(response.get("body") or "")
            classes = classify_response(request, response)
            payload = {
                "request": {**request, "body_len": request.get("length", 0)},
                "response": {**response, "body_preview": body[:4000], "classes": classes},
                "source": "custom_probe",
            }
            status = response.get("status") or 0
            evidence_id = store.record(
                "http_exchange", payload, target=url, test_type="custom_probe",
                success=isinstance(status, int) and 0 < status < 400,
            )
            index.append({"evidence_id": evidence_id, "method": request.get("method"),
                          "url": url, "status": status, "length": response.get("length"),
                          "classes": classes})
        return index

    async def run_custom_probe(
        self,
        source: str,
        allowed_hosts: Optional[str] = None,
        timeout_sec: float = 20,
        **kwargs: Any,
    ) -> str:
        """Run a one-off Python HTTP probe in a sandbox (bounded CodeAgent).

        Allowed imports: json, re, httpx, hashlib, hmac, base64, time, math,
        datetime, collections, urllib.parse. Hosts must be in engagement scope.
        Print results to stdout. Runs only when AGENT_CUSTOM_PROBE_MODE allows it;
        "isolated" executes in the probe-runner container behind a scope proxy.
        """
        from app.services.agent.custom_probe import (
            custom_probe_mode,
            run_custom_probe_async,
            run_custom_probe_isolated,
        )

        mode = custom_probe_mode()
        if self._scoped_policy_applied and mode != "isolated":
            return json.dumps({"error": "In-process custom probes cannot enforce operator method and path approvals; use structured replay tools or the isolated probe runner."})
        if mode == "off":
            return json.dumps({
                "error": "custom_probe_disabled",
                "detail": "Custom Python probes are disabled on this deployment "
                          "(AGENT_CUSTOM_PROBE_MODE=off). Use mutate_captured_request, "
                          "replay_http_request, compare_requests, or mutate_list.",
            })
        hosts = self._probe_scope_hosts(allowed_hosts)
        if mode == "isolated":
            result = await run_custom_probe_isolated(
                source, allowed_hosts=hosts, timeout_sec=timeout_sec,
                method_policy=self._probe_method_policy(),
                oob_allowed=bool(self._oob_callbacks_allowed),
            )
        else:
            result = await run_custom_probe_async(source, allowed_hosts=hosts, timeout_sec=timeout_sec)
        result["execution"] = mode
        if result.get("exchanges"):
            result["exchanges"] = self._record_probe_exchanges(result["exchanges"])
        oob_allowed = mode != "isolated" or bool(self._oob_callbacks_allowed)
        result["oob_allowed"] = oob_allowed
        result["hint"] = (
            ("In-scope hosts plus Interactsh/OAST. " if oob_allowed else "In-scope hosts only. ")
            + "Never fetch 169.254.169.254 or localhost — Lictor blocks those. "
            "Print JSON proof to stdout."
        )
        if self._scoped_policy_applied:
            result["hint"] += (" Operator method policy: GET/HEAD only; POST/DELETE need an "
                               "approved path; raw TCP is unavailable.")
        if result.get("exchanges"):
            result["hint"] += (
                " Every request this probe sent is recorded under exchanges[].evidence_id "
                "(full redacted request/response). Read one with read_evidence, search "
                "bodies with search_evidence, and cite the evidence_id in "
                "submit_finding_candidate instead of pasting stdout."
            )
        return json.dumps(result, default=str)[: int(getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000) or 20000)]

    async def sandbox_shell(
        self,
        command: str,
        allowed_hosts: Optional[str] = None,
        timeout_sec: float = 60,
        **kwargs: Any,
    ) -> str:
        """Run a shell command in the isolated probe runner (bash, curl, jq,
        sqlmap, ffuf, nmap, nc, python with requests/httpx/pyjwt). Network
        leaves only through scope-checked proxies, to in-scope hosts and OAST.
        HTTP(S): curl, wget and python use the recording proxy automatically
        (every exchange becomes evidence); pass ffuf -x "$PROBE_PROXY" and
        sqlmap --proxy="$PROBE_PROXY". Other TCP: prefix with proxychains4,
        e.g. proxychains4 nmap -sT -Pn -sV -p 22,3306,6379 host (connect scans
        only; SYN/UDP/OS detection are unavailable); connections are logged in
        tcp. Nothing persists between calls.
        """
        from app.services.agent.custom_probe import custom_probe_mode, run_sandbox_shell

        if custom_probe_mode() != "isolated" or not getattr(settings, "AGENT_SANDBOX_SHELL", False):
            return json.dumps({
                "error": "sandbox_shell_disabled",
                "detail": "Requires AGENT_CUSTOM_PROBE_MODE=isolated and AGENT_SANDBOX_SHELL=true.",
            })
        result = await run_sandbox_shell(
            command, allowed_hosts=self._probe_scope_hosts(allowed_hosts), timeout_sec=timeout_sec,
            method_policy=self._probe_method_policy(),
            oob_allowed=bool(self._oob_callbacks_allowed),
        )
        result["execution"] = "isolated"
        if result.get("exchanges"):
            result["exchanges"] = self._record_probe_exchanges(result["exchanges"])
            result["hint"] = (
                "Every request is recorded under exchanges[].evidence_id. Read bodies "
                "with read_evidence, search with search_evidence, cite the IDs in "
                "submit_finding_candidate."
            )
        return json.dumps(result, default=str)[: int(getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000) or 20000)]

    def _probe_method_policy(self) -> Optional[Dict[str, List[str]]]:
        """The operator method policy for probe-egress to enforce, if one applies."""
        if not self._scoped_policy_applied:
            return None
        return {
            "approved_post_paths": sorted(
                self._scoped_body_replay_paths | self._scoped_race_action_paths
                | self._scoped_csrf_action_paths
                | ({self._scoped_auth_login_path} if self._scoped_auth_login_path else set())
            ),
            "approved_delete_paths": sorted(
                self._scoped_stored_xss_cleanup_paths | self._scoped_race_cleanup_paths
                | self._scoped_csrf_cleanup_paths
            ),
        }

    def _probe_scope_hosts(self, allowed_hosts: Optional[str]) -> List[str]:
        hosts: List[str] = []
        if allowed_hosts:
            hosts.extend(
                p.strip() for p in str(allowed_hosts).replace(",", "\n").splitlines() if p.strip()
            )
        fallback = (getattr(self, "_fallback_target", "") or "").strip()
        if fallback:
            hosts.append(fallback)
        cmap = getattr(self, "_capability_map", None) or {}
        if isinstance(cmap, dict) and cmap.get("target"):
            hosts.append(str(cmap.get("target")))
        return hosts

    def _remember_sample_classes(self, sample_ref: str, capture_id: str, classes: List[str]) -> None:
        """Keep response labels seen when replaying a sample (labels only, bounded)."""
        from app.services.agent.request_capture import _known_classes

        labels = _known_classes(classes)
        if not labels:
            return
        if capture_id and self._capture_requests().classify(capture_id, labels):
            return
        if not sample_ref:
            return
        store = getattr(self, "_sample_response_classes", None)
        if not isinstance(store, dict):
            store = {}
            self._sample_response_classes = store
        store[sample_ref] = _known_classes([*(store.pop(sample_ref, None) or []), *labels])
        while len(store) > 500:
            store.pop(next(iter(store)))

    def _sample_classes(self, raw: Dict[str, Any], row: Dict[str, Any]) -> List[str]:
        from app.services.agent.request_capture import _known_classes
        from app.services.agent.response_classification import classify_response

        # Crawl samples carry status/failed but no body: status labels only.
        observed = classify_response({}, {
            "status": raw.get("status"), "failed": raw.get("failed"),
        }) if raw.get("status") is not None or raw.get("failed") else []
        stored: List[str] = []
        capture_id = str(row.get("capture_id") or "")
        if capture_id:
            try:
                stored = list(self._capture_requests().get(capture_id).get("response_classes") or [])
            except ValueError:
                stored = []
        remembered = (getattr(self, "_sample_response_classes", None) or {}).get(row["sample_ref"]) or []
        return _known_classes([*observed, *stored, *remembered])

    async def list_captured_requests(self, limit: int = 40, identity: Optional[str] = None,
                                     classification: str = "", **kwargs: Any) -> str:
        """Index captured XHR/API samples from the capability map for mutate_captured_request.

        Each sample lists response classes (sql_error, template_error,
        filter_blocked, input_reflected, debug_error, rate_limited, ...) seen
        when it was captured or replayed; ``classification`` keeps only
        samples with that class.
        """
        from app.services.agent.request_mutate import sample_reference, samples_from_map, summarize_samples
        from app.services.agent.pilot_policy import current_pilot
        from app.services.agent.response_classification import RESPONSE_CLASSES, adaptive_hints
        from urllib.parse import urlsplit, urlunsplit

        classification = str(classification or "").strip().lower()
        if classification and classification not in RESPONSE_CLASSES:
            return json.dumps({"ok": False, "error": "unknown classification",
                               "classifications": list(RESPONSE_CLASSES)})

        cmap = self._identity_captures.get(identity, {}) if identity is not None else (getattr(self, "_capability_map", None) or {})
        origin = ""
        if isinstance(cmap, dict):
            origin = str(cmap.get("target") or "")
        origin = origin or (getattr(self, "_fallback_target", None) or "") or (current_seed_target.get() or "")
        pilot = current_pilot()
        if pilot is not None:
            identity = None
            origin = pilot.target
            capture_store = self._capture_requests()
            samples = [capture_store.get(row["id"])["request"] | {"capture_id": row["id"]}
                       for row in capture_store.list() if row.get("source") == "pilot_browser"]
            samples = list({sample_reference(sample): sample for sample in samples}.values())
            samples.sort(key=lambda sample: (not bool(urlsplit(sample["url"]).query), sample["url"]))
        else:
            samples = samples_from_map(cmap if isinstance(cmap, dict) else {})
        cap = max(1, min(int(limit or 40), 80))
        rows = summarize_samples(samples, fallback_origin=origin,
                                 limit=len(samples) if classification else cap)
        for row in rows:
            row["classes"] = self._sample_classes(samples[row["index"]], row)
            hints = adaptive_hints(row["classes"])
            if hints:
                row["adaptive_hints"] = hints
        if classification:
            rows = [row for row in rows if classification in row["classes"]][:cap]
        if pilot is not None:
            for row in rows:
                parts = urlsplit(row["url"])
                row["url"] = urlunsplit(parts._replace(query="", fragment=""))
        return json.dumps({
            "ok": True,
            "count": len(rows),
            "origin": origin,
            "identity": identity,
            "classification": classification or None,
            "samples": rows,
            "next": (
                "mutate_captured_request(sample_ref='req-...', location='query|header|body_json|body_form|path|method', "
                "field='url', value='https://<interactsh>') — one field only."
            ) if pilot is None else (
                "Use mutate_captured_request with sample_ref, location='query', one listed field, "
                "and a harmless value. It replays the private original request and its one-field mutation."
            ) if rows else (
                "No replayable GET/HEAD request was captured. Browser traffic metadata and XHR capture "
                "are separate inventories; inspect an observed same-origin link or try a different page."
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def diff_stored_exchanges(self, baseline_id: str, candidate_id: str, **kwargs: Any) -> str:
        """Diff two recorded HTTP exchanges by id without sending anything.

        Ids are http_exchange evidence ids (from replay_http_request,
        compare_requests, mutate_captured_request, custom probes) or capture
        ids (resolved to the exchange that created the capture). Returns
        status, length, body similarity, timing, response-header name deltas
        and class deltas. A difference is a lead, not a finding.
        """
        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.response_classification import diff_exchanges

        store = evidence_store(self)

        def resolve(ref: str) -> tuple[Optional[Dict[str, Any]], str]:
            ref = str(ref or "").strip()
            record = store.records.get(ref) if ref else None
            if record is None and ref:
                try:
                    capture = self._capture_requests().get(ref)
                except ValueError:
                    capture = None
                evidence_id = str((capture or {}).get("evidence_id") or "")
                record = store.records.get(evidence_id) if evidence_id else None
            if record is None or record.get("kind") != "http_exchange":
                return None, ref
            return record, record["id"]

        baseline, baseline_ref = resolve(baseline_id)
        candidate, candidate_ref = resolve(candidate_id)
        if baseline is None or candidate is None:
            return json.dumps({
                "ok": False,
                "error": "Unknown or expired http_exchange evidence or capture id",
                "missing": [ref for ref, row in ((baseline_ref, baseline), (candidate_ref, candidate))
                            if row is None],
            })
        if baseline.get("truncated") or candidate.get("truncated"):
            return json.dumps({"ok": False, "error": "An exchange was too large to store; re-run a bounded request"})
        diff = diff_exchanges(baseline.get("payload") or {}, candidate.get("payload") or {})
        return json.dumps({
            "ok": True,
            "baseline_evidence_id": baseline_ref,
            "candidate_evidence_id": candidate_ref,
            "same_target": baseline.get("target") == candidate.get("target"),
            **diff,
            "note": "Computed from stored, redacted exchanges; nothing was sent. "
                    "A difference is a lead; prove it with the class-specific tool.",
        }, indent=2, default=str)[:_tool_output_max_chars()]

    async def plan_intruder_mutations(
        self,
        max_mutations: int = 12,
        allow_state_change: bool = False,
        categories: Optional[List[str]] = None,
        identity: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Create a bounded Intruder-style queue from captured API requests."""
        from app.services.agent.intruder_automation import plan_intruder_mutations
        from app.services.agent.request_mutate import samples_from_map

        cmap = self._identity_captures.get(identity, {}) if identity is not None else (
            getattr(self, "_capability_map", None) or {}
        )
        origin = str(cmap.get("target") or "") if isinstance(cmap, dict) else ""
        origin = origin or (getattr(self, "_fallback_target", None) or "") or (
            current_seed_target.get() or ""
        )
        samples = samples_from_map(cmap if isinstance(cmap, dict) else {})
        plan = plan_intruder_mutations(
            samples,
            fallback_origin=origin,
            max_mutations=max_mutations,
            allow_state_change=allow_state_change,
            categories=categories,
        )
        plan["identity"] = identity
        plan["next"] = (
            "Review the queue, then call run_intruder_batch with the same filters. "
            "Execution requires operator confirmation."
        )
        return json.dumps(plan, indent=2)[:_tool_output_max_chars()]

    async def run_intruder_batch(
        self,
        max_mutations: int = 6,
        allow_state_change: bool = False,
        categories: Optional[List[str]] = None,
        identity: Optional[str] = None,
        use_auth_session: bool = True,
        timeout: int = 25,
        hypothesis_id: str = "",
        **kwargs: Any,
    ) -> str:
        """Execute a confirmation-gated queue of one-field differential tests."""
        from app.services.agent.intruder_automation import plan_intruder_mutations
        from app.services.agent.request_mutate import samples_from_map

        cap = max(1, min(int(max_mutations or 6), 12))
        cmap = self._identity_captures.get(identity, {}) if identity is not None else (
            getattr(self, "_capability_map", None) or {}
        )
        origin = str(cmap.get("target") or "") if isinstance(cmap, dict) else ""
        origin = origin or (getattr(self, "_fallback_target", None) or "") or (
            current_seed_target.get() or ""
        )
        samples = samples_from_map(cmap if isinstance(cmap, dict) else {})
        plan = plan_intruder_mutations(
            samples,
            fallback_origin=origin,
            max_mutations=cap,
            allow_state_change=allow_state_change,
            categories=categories,
        )
        results: List[Dict[str, Any]] = []
        for mutation in plan["mutations"]:
            raw = await self.mutate_captured_request(
                sample_index=mutation["sample_index"],
                location=mutation["location"],
                field=mutation["field"],
                value=mutation["value"],
                compare=True,
                use_auth_session=use_auth_session,
                timeout=max(5, min(int(timeout or 25), 60)),
                identity=identity,
                hypothesis_id=hypothesis_id,
            )
            try:
                observation: Any = json.loads(raw)
            except Exception:
                observation = {"output": str(raw)[:2000]}
            results.append({"mutation": mutation, "observation": observation})
            # At most two comparisons per second; scope checks still run per request.
            await asyncio.sleep(0.5)

        return json.dumps({
            "ok": True,
            "dry_run": False,
            "executed": len(results),
            "skipped_state_changing": plan["skipped_state_changing"],
            "allow_state_change": bool(allow_state_change),
            "results": results,
            "note": "A response difference is a lead, not a confirmed finding.",
        }, indent=2, default=str)[:_tool_output_max_chars()]

    async def mutate_captured_request(
        self,
        sample_index: int = 0,
        location: str = "query",
        field: str = "",
        value: str = "",
        compare: bool = True,
        use_auth_session: bool = True,
        timeout: int = 25,
        identity: Optional[str] = None,
        hypothesis_id: str = "",
        sample_ref: str = "",
        **kwargs: Any,
    ) -> str:
        """Change one field on a captured request and send it (Repeater + one mutation)."""
        from app.services.agent.pilot_policy import current_pilot
        from urllib.parse import urlsplit
        from app.services.agent.parameter_inventory import is_credential_cookie
        from app.services.agent.request_mutate import (
            apply_one_mutation,
            normalize_sample,
            sample_reference,
            samples_from_map,
            set_cookie_pair,
        )

        cmap = self._identity_captures.get(identity, {}) if identity is not None else (getattr(self, "_capability_map", None) or {})
        origin = ""
        if isinstance(cmap, dict):
            origin = str(cmap.get("target") or "")
        origin = origin or (getattr(self, "_fallback_target", None) or "") or (current_seed_target.get() or "")
        pilot = current_pilot()
        if pilot is not None:
            use_auth_session = False
            identity = None
            origin = pilot.target
            capture_store = self._capture_requests()
            samples = [capture_store.get(row["id"])["request"] | {"capture_id": row["id"]}
                       for row in capture_store.list() if row.get("source") == "pilot_browser"]
            samples = list({sample_reference(sample): sample for sample in samples}.values())
            samples.sort(key=lambda sample: (not bool(urlsplit(sample["url"]).query), sample["url"]))
        else:
            samples = samples_from_map(cmap if isinstance(cmap, dict) else {})
        if sample_ref:
            matches = [(i, row) for i, row in enumerate(samples)
                       if isinstance(row, dict)
                       and sample_reference(row, fallback_origin=origin) == sample_ref]
            if len(matches) != 1:
                return json.dumps({
                    "ok": False,
                    "error": "sample_ref missing or ambiguous — refresh list_captured_requests",
                    "matches": len(matches),
                })
            idx, sample = matches[0]
        else:
            try:
                idx = int(sample_index)
                sample = samples[idx]
            except Exception:
                return json.dumps({
                    "ok": False,
                    "error": "sample_index out of range — call list_captured_requests first",
                    "count": len(samples),
                })
        if not isinstance(sample, dict):
            return json.dumps({"ok": False, "error": "Captured sample is invalid"})
        try:
            baseline, mutant = apply_one_mutation(
                sample,
                location=location,
                field=field,
                value=value,
                fallback_origin=origin,
            )
        except ValueError as exc:
            return json.dumps({"ok": False, "error": str(exc)})

        if pilot is not None:
            # Browser state came from a fresh anonymous context. Keep any
            # server-issued cookie paired with the original observed request.
            compare = True
            cookie_header = self._pilot_request_cookie_headers.get(str(sample.get("capture_id") or ""))
            if cookie_header:
                baseline["headers"]["Cookie"] = cookie_header
                mutant["headers"]["Cookie"] = (
                    set_cookie_pair(cookie_header, field, value)
                    if str(location).lower() == "cookie" else cookie_header
                )

        if str(location).lower() == "cookie" and is_credential_cookie(field):
            return json.dumps({"ok": False, "error": (
                "Session, credential, and CSRF cookies are not injection targets; "
                "test application-state cookies (language, region, branch, cart, ...)"
            )})
        if identity is not None and location == "header" and field.lower() in ("cookie", "authorization"):
            return json.dumps({"error": "Use explicit unauthenticated requests for credential-header mutations"})
        if identity is not None:
            for request in (baseline, mutant):
                request["identity"] = identity
                request["headers"] = {k: v for k, v in (request.get("headers") or {}).items()
                                      if k.lower() not in ("cookie", "authorization")}
        source_ref = sample_reference(sample, fallback_origin=origin)
        source_capture_id = str(sample.get("artifact_id") or sample.get("capture_id") or "")[:80]
        if compare:
            compared = await self.compare_requests(
                baseline=baseline,
                mutant=mutant,
                use_auth_session=use_auth_session,
                timeout=timeout,
                hypothesis_id=hypothesis_id,
            )
            try:
                result = json.loads(compared)
                if isinstance(result, dict):
                    labels = result.get("classification") or {}
                    self._remember_sample_classes(
                        source_ref, str(sample.get("capture_id") or ""),
                        [*(labels.get("baseline") or []), *(labels.get("mutant") or [])],
                    )
                    result["source_sample_ref"] = source_ref
                    if source_capture_id:
                        result["source_capture_id"] = source_capture_id
                    return json.dumps(result, default=str)[:_tool_output_max_chars()]
            except (TypeError, ValueError):
                pass
            return compared
        try:
            exchange = await self._http_exchange(
                method=mutant["method"],
                url=mutant["url"],
                headers=mutant.get("headers"),
                body=mutant.get("body"),
                use_auth_session=use_auth_session,
                timeout=timeout,
                follow_redirects=False,
                identity=identity,
                hypothesis_id=hypothesis_id,
            )
            exchange.pop("_body_text", None)
            self._remember_sample_classes(
                source_ref, str(sample.get("capture_id") or ""),
                list((exchange.get("response") or {}).get("classes") or []),
            )
            return json.dumps({
                "ok": True,
                "source_sample_ref": source_ref,
                "source_capture_id": source_capture_id,
                "mutation": {"location": location, "field": field, "value": value},
                "baseline": normalize_sample(baseline, fallback_origin=origin),
                "sent": mutant,
                "response": exchange.get("response"),
                "request": exchange.get("request"),
                "evidence_id": exchange.get("evidence_id"),
                "adaptive_hints": exchange.get("adaptive_hints") or [],
            }, indent=2)[:_tool_output_max_chars()]
        except Exception as exc:
            return json.dumps({"ok": False, "error": f"mutate send failed: {exc}"})

    async def mutate_list(
        self,
        kind: str = "paths",
        observed: str = "",
        count: int = 30,
        **kwargs: Any,
    ) -> str:
        """Single-shot mutation list (paths/params/xss/passwords/subdomains). Not a ReAct loop."""
        from app.services.agent.single_shot_mutate import generate_mutations

        blob = observed or ""
        if not blob:
            cmap = getattr(self, "_capability_map", None) or {}
            if isinstance(cmap, dict):
                blob = " ".join(
                    [
                        str(cmap.get("target") or ""),
                        " ".join(str(p) for p in (cmap.get("pages_visited") or [])[:8]),
                    ]
                )
            blob = blob or (getattr(self, "_fallback_target", None) or "")
        result = generate_mutations(kind, blob, count=count)
        return json.dumps(result, indent=2)[:_tool_output_max_chars()]
