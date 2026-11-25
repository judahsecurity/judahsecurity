"""Test identities, authorization boundary checks and raw HTTP replay/compare.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    _tool_output_max_chars,
    httpx,
    json,
)


class HttpIdentityToolsMixin:
    """Test identities, authorization boundary checks and raw HTTP replay/compare."""

    async def register_test_identity(self, name: str, target: str, cookies=None, headers=None,
                                     storage_state=None, role: str = "", tenant: str = "") -> str:
        """Register an operator-provided test account session. Secrets are not returned."""
        from app.services.agent.assessment_sessions import identity_registry
        return json.dumps(identity_registry(self).register(name, target, cookies=cookies, headers=headers,
                         storage_state=storage_state, role=role, tenant=tenant))

    async def list_test_identities(self) -> str:
        """List test identities and their verified login state without credentials."""
        from app.services.agent.assessment_sessions import identity_registry
        registry = identity_registry(self)
        return json.dumps(registry.describe_all())

    async def check_test_identity(self, identity: str, url: str, field: str, expected: Any) -> str:
        """Verify an account using a known identity endpoint and exact JSON principal field."""
        from app.services.agent.assessment_sessions import identity_registry
        registry = identity_registry(self)
        session = registry.resolve(identity, url)
        session["authenticated"] = False
        exchange = await self._http_exchange("GET", url, identity=identity, follow_redirects=False)
        try:
            data = json.loads(exchange["_body_text"])
            ok = (exchange["response"]["status"] == 200 and isinstance(data, dict)
                  and field in data and expected not in (None, "") and data[field] == expected)
        except (ValueError, TypeError):
            ok = False
        session["authenticated"] = bool(ok)
        if ok:
            session["identity_check"] = {"url": url, "field": field, "expected": expected}
        return json.dumps({"identity": identity, "authenticated": bool(ok), "evidence_id": exchange["evidence_id"]})

    async def test_authorization_boundary(self, url: str, owner_identity: str, other_identity: str,
                                           object_field: str, hypothesis_id: str = "",
                                           coverage_cell_id: str = "") -> str:
        """Replay a known protected test object with its owner and a different test identity.

        The operator must establish that this object is private. A match is a candidate,
        not automatic proof that a deliberately public object violates policy.
        """
        from app.services.agent.assessment_sessions import identity_registry
        registry = identity_registry(self)
        if owner_identity == other_identity or owner_identity == "anonymous":
            raise ValueError("Use an owner and a distinct second identity")
        for name in (owner_identity, other_identity):
            session = registry.resolve(name, url)
            if name != "anonymous":
                check = session.get("identity_check")
                if not check:
                    raise ValueError(f"Verify {name} with check_test_identity first")
                result = json.loads(await self.check_test_identity(name, **check))
                if not result["authenticated"]:
                    return json.dumps({"verdict": "blocked", "reason": f"Session expired for {name}"})
        raw = await self.compare_requests(
            {"method": "GET", "url": url, "identity": owner_identity},
            {"method": "GET", "url": url, "identity": other_identity},
            interest_fields=[object_field], use_auth_session=False, hypothesis_id=hypothesis_id,
            coverage_cell_id=coverage_cell_id,
        )
        result = json.loads(raw)
        fields = result.get("interest_fields") or {}
        baseline_value = (fields.get("baseline") or {}).get(object_field)
        mutant_value = (fields.get("mutant") or {}).get(object_field)
        matched_private_object = (
            baseline_value not in (None, "")
            and mutant_value == baseline_value
            and int((result.get("status") or {}).get("baseline") or 0) in range(200, 300)
            and int((result.get("status") or {}).get("mutant") or 0) in range(200, 300)
        )
        if not matched_private_object:
            return raw

        result["verdict"] = "LIKELY_IMPACT"
        result["signals"] = list(
            dict.fromkeys(
                [
                    *(result.get("signals") or []),
                    "verified_cross_identity_object_match",
                ]
            )
        )
        result["guidance"] = (
            "A distinct verified identity received the owner's matched object field. "
            "This is a proof candidate, not a finding; complete the structured proof "
            "and independent verification chain."
        )
        if coverage_cell_id and not result.get("proof_escalation"):
            from app.services.agent.engagement_brain import engagement_brain_from_dict
            from app.services.agent.signal_escalation import queue_signal_escalation

            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            mutant = result.get("mutant") or {}
            trace = mutant.get("trace") or {}
            escalation = queue_signal_escalation(
                brain,
                verdict=result["verdict"],
                signals=result["signals"],
                evidence_ids=[
                    str((result.get("baseline") or {}).get("evidence_id") or ""),
                    str(mutant.get("evidence_id") or ""),
                ],
                target=url,
                source_tool="test_authorization_boundary",
                coverage_cell_id=coverage_cell_id,
                hypothesis_id=hypothesis_id or str(trace.get("hypothesis_id") or ""),
                operation_id=str(trace.get("operation_id") or ""),
                identity=other_identity,
                tenant=str(trace.get("tenant") or ""),
                parameter=str(trace.get("parameter") or ""),
                test_type=str(trace.get("test_type") or "authorization"),
            )
            if escalation:
                result["proof_escalation"] = escalation
                result["next_action"] = (
                    "Complete the structured authorization proof before submitting "
                    "a finding candidate."
                )
                self._engagement_brain = brain.to_dict()
                result["engagement_brain"] = self._engagement_brain
        return json.dumps(result, indent=2)[:_tool_output_max_chars()]

    def _resolve_request_cookies(self, headers, cookies, use_auth_session, url: str = ""):
        # Compatibility helper; the live transport uses the jar itself for redirects.
        from app.services.agent.assessment_sessions import cookie_jar
        stored = (getattr(self, "_auth_session", None) or {}).get("cookies", []) if use_auth_session else []
        request = httpx.Request("GET", url, headers=headers)
        if "cookie" not in request.headers:
            cookie_jar(url, stored, cookies).set_cookie_header(request)
        return dict(request.headers)

    async def _http_exchange(self, method: str, url: str, headers=None, body=None, cookies=None,
                             use_auth_session: bool = True, timeout: int = 25,
                             follow_redirects: bool = True, identity: Optional[str] = None,
                             hypothesis_id: str = "", coverage_cell_id: str = "",
                             max_response_bytes: Optional[int] = None,
                             http2: bool = False, return_bytes: bool = False) -> Dict[str, Any]:
        import time as _time
        from app.services.agent.assessment_sessions import cookie_jar, identity_registry
        from app.services.agent.evidence_store import evidence_store, verification_run, origin
        from app.services.agent.request_mutate import coerce_request_body
        origin(url)
        from app.services.agent.assessment_scope import assert_method_allowed, assert_url_in_scope
        assert_url_in_scope(self, url)
        from app.services.agent.pilot_policy import current_pilot
        pilot = current_pilot()
        from app.services.agent.parameter_inventory import is_credential_cookie

        def _cookie_override_names(value) -> list[str]:
            if isinstance(value, dict):
                return [str(k) for k in value]
            if isinstance(value, list):
                return [str(c.get("name") or "") for c in value if isinstance(c, dict)]
            return ["<unparsed>"] if value else []

        override_names = _cookie_override_names(cookies)
        # Application-state cookies (language, region, branch) are request data,
        # not credentials; only those may be overridden alongside a session.
        credential_override = any(not name or is_credential_cookie(name) or name == "<unparsed>"
                                  for name in override_names)
        if pilot is not None:
            if identity not in (None, "anonymous") or credential_override:
                raise ValueError("Pilot first pass is anonymous only")
            if any(str(key).lower() in {
                "authorization", "cookie", "proxy-authorization", "host",
                "x-forwarded-host", "forwarded",
            } for key in (headers or {})):
                raise ValueError("Pilot first pass cannot override credentials or host routing")
            use_auth_session = False
        method = (method or "GET").upper().strip()
        assert_method_allowed(self, url, method)
        raw_body, hdrs = coerce_request_body({"body": body, "headers": headers or {}}, headers or {})
        session = {}
        if identity is not None:
            session = identity_registry(self).resolve(identity, url)
            protected_headers = {k.lower() for k in session.get("headers", {})} | {"host", "cookie", "authorization", "proxy-authorization"}
            identity_cookie_names = {str(c.get("name") or "") for c in session.get("cookies", [])
                                     if isinstance(c, dict)}
            if (credential_override or identity_cookie_names.intersection(override_names)
                    or any(k.lower() in protected_headers for k in hdrs)):
                raise ValueError("Named identities cannot be combined with credential overrides")
            hdrs = {**session.get("headers", {}), **hdrs}
        elif use_auth_session:
            session = getattr(self, "_auth_session", None) or {}
        label = identity or ("legacy" if session else "anonymous")
        trace = {}
        if coverage_cell_id:
            from app.services.agent.coverage_cells import (
                migrate_coverage_cells,
                trace_for_cell,
            )
            from app.services.agent.engagement_brain import (
                denominator_surfaces,
                engagement_brain_from_dict,
            )

            brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
            trace = trace_for_cell(brain, coverage_cell_id)
            if not trace:
                raise ValueError("Unknown coverage_cell_id")
            expected_identity = str(trace.get("identity") or "")
            if expected_identity not in ("", "unspecified", label):
                raise ValueError("Coverage cell identity does not match the executing identity")
            if hypothesis_id and trace.get("hypothesis_id") not in ("", hypothesis_id):
                raise ValueError("Coverage cell does not belong to this hypothesis")
            hypothesis_id = hypothesis_id or str(trace.get("hypothesis_id") or "")
            self._engagement_brain = brain.to_dict()
        stored = session.get("cookies", [])
        if identity is None and session:
            stored = [c for c in stored if isinstance(c, dict) and c.get("domain")]
        jar = cookie_jar(url, stored, cookies)
        run = verification_run.get()
        if run:
            hdrs["X-Aegis-Verify"] = run.nonce
        start = _time.monotonic()
        # Follow redirects manually: retain RFC cookie scope and never forward an
        # explicit Cookie/Authorization header to a different origin.
        from app.services.agent.assessment_proxy import assessment_httpx_options
        protocol = {}
        if http2:
            # gRPC needs HTTP/2: ALPN for https, prior knowledge (h2c) for http.
            protocol = {"http2": True}
            if httpx.URL(url).scheme == "http":
                protocol["http1"] = False
        async with httpx.AsyncClient(
            cookies=jar, follow_redirects=False, timeout=timeout,
            **protocol, **assessment_httpx_options(),
        ) as client:
            req = client.build_request(method, url, headers=hdrs, content=raw_body)
            if not any(k.lower() == "cookie" for k in hdrs):
                req.headers.pop("cookie", None)
                jar.set_cookie_header(req)
            for hop in range(11):
                if pilot is not None:
                    await pilot.acquire(str(req.url), req.method)
                resp = await client.send(req, stream=max_response_bytes is not None)
                if max_response_bytes is not None:
                    chunks, size = [], 0
                    try:
                        async for chunk in resp.aiter_bytes():
                            size += len(chunk)
                            if size > max_response_bytes:
                                raise ValueError("Response exceeds configured collection byte budget")
                            chunks.append(chunk)
                        resp._content = b"".join(chunks)
                    finally:
                        await resp.aclose()
                jar.extract_cookies(resp)
                if not follow_redirects or not resp.next_request:
                    break
                if hop == 10:
                    raise ValueError("Too many redirects")
                nxt = resp.next_request
                assert_url_in_scope(self, str(nxt.url))
                assert_method_allowed(self, str(nxt.url), nxt.method)
                if origin(str(nxt.url)) != origin(str(req.url)):
                    nxt.headers.pop("authorization", None)
                    if identity not in (None, "anonymous"):
                        raise ValueError("Named identity redirect left its registered origin")
                nxt.headers.pop("cookie", None)
                jar.set_cookie_header(nxt)
                req = nxt
        if identity not in (None, "anonymous"):
            session["cookies"] = [dict(name=c.name, value=c.value, domain=c.domain, path=c.path,
                                       secure=c.secure, expires=c.expires) for c in client.cookies.jar]
        body_text = resp.text or ""
        if resp.status_code == 401:
            session["authenticated"] = False
        exchange = {
            "request": {"method": method, "url": url, "identity": label,
                        "identity_verified": bool(session.get("authenticated")),
                        "principal_id": session.get("identity_check", {}).get("expected"),
                        "headers": dict(req.headers), "body": raw_body or "", "body_len": len(raw_body or "")},
            "response": {"status": resp.status_code, "url": str(resp.url), "headers": dict(resp.headers),
                         "body": body_text, "body_preview": body_text[:4000], "length": len(resp.content),
                         "elapsed_s": round(_time.monotonic() - start, 3)},
        }
        from app.services.agent.brain_memory import observe_response
        observe_response(self, method=method, url=url, status=resp.status_code,
                         headers=dict(resp.headers), body=body_text)
        from app.services.agent.response_classification import adaptive_hints, classify_response

        # Labels only: safe on the evidence record, the capture and tool output.
        exchange["response"]["classes"] = classify_response(exchange["request"], exchange["response"])
        await self.map_application_traffic([dict(method=method, url=url, headers=hdrs, body=raw_body)],
                                           identity=label, source="http_exchange")
        if not trace.get("operation_id"):
            from app.services.agent.runtime_mapper import normalize_request

            operations = normalize_request(
                dict(method=method, url=url, headers=hdrs, body=raw_body),
                identity=label,
                source="http_exchange",
            )
            if operations:
                trace["operation_id"] = operations[0]["id"]
        artifact_id = evidence_store(self).record("http_exchange", exchange, target=url, identity=label,
                                                  hypothesis_id=hypothesis_id,
                                                  operation_id=trace.get("operation_id", ""),
                                                  coverage_cell_id=coverage_cell_id,
                                                  tenant=trace.get("tenant", ""),
                                                  parameter=trace.get("parameter", ""),
                                                  test_type=trace.get("test_type", ""),
                                                  proof_escalation_id=trace.get("proof_escalation_id", ""),
                                                  success=resp.status_code < 400)
        capture = None
        if (identity not in (None, "anonymous") and not hypothesis_id and not run
                and 200 <= resp.status_code < 300 and req.method == method
                and str(req.url) == str(httpx.URL(url))):
            capture = self._capture_requests().record(
                dict(method=method, url=str(req.url), headers=dict(req.headers), body=raw_body),
                identity=label, source="http_exchange", evidence_id=artifact_id,
                hypothesis_id=hypothesis_id,
                coverage_cell_id=coverage_cell_id,
                tenant=trace.get("tenant", ""),
                parameter=trace.get("parameter", ""),
                test_type=trace.get("test_type", ""),
                proof_escalation_id=trace.get("proof_escalation_id", ""),
                response_classes=exchange["response"]["classes"])
            if capture:
                self._queue_captured_authorization_leads()
        from app.services.agent.evidence_store import redact_artifact
        public = redact_artifact(exchange)
        public["response"].pop("body", None)
        public["request"].pop("body", None)
        hints = adaptive_hints(exchange["response"]["classes"])
        return {
            **public,
            **({"adaptive_hints": hints} if hints else {}),
            "evidence_id": artifact_id,
            "capture": capture,
            "trace": {**trace, "coverage_cell_id": coverage_cell_id},
            "_body_text": body_text,
            **({"_body_bytes": resp.content} if return_bytes else {}),
        }

    async def replay_http_request(
        self,
        method: str = "GET",
        url: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        cookies: Optional[Any] = None,
        use_auth_session: bool = True,
        timeout: int = 25,
        identity: Optional[str] = None,
        hypothesis_id: str = "",
        coverage_cell_id: str = "",
    ) -> str:
        """Replay a captured HTTP request (tester-style request tampering).

        Prefer samples from the capability map (api_samples). Optionally attaches
        cookies from the session auth handoff after deep_crawl login.
        """
        if not url or not str(url).strip():
            return "Error: url is required (e.g. from capability_map.api_samples)."

        from app.services.agent.lane_proof import (
            sanitize_live_request,
            should_force_unauth_session as lane_force_unauth,
        )
        from app.services.agent.request_mutate import coerce_request_body

        raw_body, hdrs = coerce_request_body(
            {"body": body, "headers": headers or {}},
            headers or {},
        )
        raw_body, hdrs, rewrite_note, blocked = sanitize_live_request(
            url, method, raw_body, hdrs
        )
        if blocked:
            return json.dumps({"error": blocked}, indent=2)
        force_unauth, force_note = lane_force_unauth(url, url, hdrs, hdrs)
        if force_unauth:
            use_auth_session = False
            if force_note:
                rewrite_note = (
                    f"{rewrite_note}; {force_note}" if rewrite_note else force_note
                )

        try:
            exchange = await self._http_exchange(
                method=method,
                url=url,
                headers=hdrs,
                body=raw_body,
                cookies=cookies,
                use_auth_session=use_auth_session,
                timeout=timeout,
                identity=identity,
                hypothesis_id=hypothesis_id,
                coverage_cell_id=coverage_cell_id,
            )
            note = (
                "Use this to tamper method/headers/body on captured APIs. "
                "Prefer compare_requests when proving authz/tenant/Host logic bugs. "
                "Pair with execute_interactsh for blind OOB sinks."
            )
            if rewrite_note:
                note = rewrite_note + " " + note
            if not use_auth_session:
                note = "use_auth_session=false (unauth gold-bar pair). " + note
            out = {
                "evidence_id": exchange["evidence_id"],
                "capture": exchange.get("capture"),
                "trace": exchange.get("trace"),
                "request": exchange["request"],
                "response": exchange["response"],
                "note": note,
            }
            if exchange.get("adaptive_hints"):
                out["adaptive_hints"] = exchange["adaptive_hints"]
            return json.dumps(out, indent=2)[:_tool_output_max_chars()]
        except Exception as exc:
            return f"Error replaying request: {exc}"

    async def compare_requests(
        self,
        baseline: Dict[str, Any],
        mutant: Dict[str, Any],
        interest_fields: Optional[List[str]] = None,
        use_auth_session: bool = True,
        timeout: int = 30,
        hypothesis_id: Optional[str] = None,
        coverage_cell_id: str = "",
        identity: Optional[str] = None,
    ) -> str:
        """Differential HTTP proof — baseline vs one mutation (tester core loop).

        Use for IDOR, host-header tenant bypass, authz, and workflow tampers.
        A 200 alone is never enough; this tool diffs status/length/body/fields.

        Args:
            baseline: {method, url, headers?, body?, json?, cookies?}
            mutant: same shape; typically one trust signal changed (Host, object id, header).
              ``json`` is accepted as an alias for a JSON body (dict or list).
            interest_fields: optional JSON/body keys to extract and compare (owner_id, email, tenant…)
            use_auth_session: attach deep_crawl auth cookies when Cookie absent.
              For missing-[Authorize] / unauth writes / email-change / auth-header skip,
              pass **false** (session cookies would hide the 401 sibling). Forced false
              on those gold-bar pairs when Authorization is absent.
            timeout: per-request timeout
            hypothesis_id: optional engagement hypothesis to annotate with result
            identity: optional default identity for both requests; a request-level
              identity takes precedence when comparing two named identities.
        """
        import json as _json
        import re as _re

        rewrite_notes: List[str] = []

        def _norm(spec: Optional[Dict[str, Any]], label: str) -> Dict[str, Any]:
            if not isinstance(spec, dict):
                raise ValueError(f"{label} must be an object with at least url")
            url = str(spec.get("url") or "").strip()
            if not url:
                raise ValueError(f"{label}.url is required")
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            from app.services.agent.lane_proof import sanitize_live_request
            from app.services.agent.request_mutate import coerce_request_body

            raw_body, hdrs = coerce_request_body(spec, spec.get("headers") or {})
            raw_body, hdrs, note, blocked = sanitize_live_request(
                url,
                spec.get("method") or "GET",
                raw_body,
                hdrs,
            )
            if blocked:
                raise ValueError(blocked)
            if note:
                rewrite_notes.append(f"{label}: {note}")
            return {
                "method": spec.get("method") or "GET",
                "url": url,
                "headers": hdrs,
                "body": raw_body,
                "cookies": spec.get("cookies"),
                "identity": spec.get("identity") if spec.get("identity") is not None else identity,
            }

        try:
            b = _norm(baseline, "baseline")
            m = _norm(mutant, "mutant")
        except ValueError as exc:
            return json.dumps({"error": str(exc)}, indent=2)

        from app.services.agent.lane_proof import should_force_unauth_session as lane_force_unauth

        force_unauth, force_note = lane_force_unauth(
            b["url"], m["url"], b["headers"], m["headers"]
        )
        if force_unauth:
            use_auth_session = False
            if force_note:
                rewrite_notes.append(force_note)

        try:
            base_ex = await self._http_exchange(
                method=b["method"],
                url=b["url"],
                headers=b["headers"],
                body=b["body"],
                cookies=b["cookies"],
                identity=b.get("identity"),
                hypothesis_id=hypothesis_id or "",
                # The exact coverage cell belongs to the mutant under test.
                # Keep the control linked by hypothesis without mislabeling its
                # endpoint or identity as execution of the mutant cell.
                coverage_cell_id="",
                use_auth_session=use_auth_session,
                timeout=timeout,
                follow_redirects=False,
            )
            mut_ex = await self._http_exchange(
                method=m["method"],
                url=m["url"],
                headers=m["headers"],
                body=m["body"],
                cookies=m["cookies"],
                identity=m.get("identity"),
                hypothesis_id=hypothesis_id or "",
                coverage_cell_id=coverage_cell_id,
                use_auth_session=use_auth_session,
                timeout=timeout,
                follow_redirects=False,
            )
        except Exception as exc:
            return json.dumps({"error": f"compare_requests failed: {exc}"}, indent=2)

        def _extract_fields(text: str) -> Dict[str, Any]:
            found: Dict[str, Any] = {}
            if not interest_fields:
                return found
            # Try JSON first
            try:
                data = _json.loads(text)
            except Exception:
                data = None
            for field_name in interest_fields:
                if data is not None:
                    # shallow + one-level nested
                    if isinstance(data, dict) and field_name in data:
                        found[field_name] = data.get(field_name)
                        continue
                    if isinstance(data, dict):
                        for v in data.values():
                            if isinstance(v, dict) and field_name in v:
                                found[field_name] = v.get(field_name)
                                break
                if field_name not in found:
                    mobj = _re.search(
                        rf'"{_re.escape(field_name)}"\s*:\s*"?([^",\s\}}]+)"?',
                        text or "",
                    )
                    if mobj:
                        found[field_name] = mobj.group(1)
            return found

        b_body = base_ex.pop("_body_text", "")
        m_body = mut_ex.pop("_body_text", "")
        b_fields = _extract_fields(b_body)
        m_fields = _extract_fields(m_body)

        status_delta = mut_ex["response"]["status"] - base_ex["response"]["status"]
        length_delta = mut_ex["response"]["length"] - base_ex["response"]["length"]
        body_changed = b_body != m_body
        b_elapsed = float(base_ex.get("response", {}).get("elapsed_s") or 0)
        m_elapsed = float(mut_ex.get("response", {}).get("elapsed_s") or 0)
        elapsed_delta = round(m_elapsed - b_elapsed, 3)
        field_deltas = {
            k: {"baseline": b_fields.get(k), "mutant": m_fields.get(k)}
            for k in set(b_fields) | set(m_fields)
            if b_fields.get(k) != m_fields.get(k)
        }

        # Heuristic signals (not auto-confirm — agent must interpret)
        signals: List[str] = []
        if status_delta != 0:
            signals.append(f"status_delta={status_delta}")
        if abs(length_delta) >= 32:
            signals.append(f"length_delta={length_delta}")
        if body_changed:
            signals.append("body_changed")
        if field_deltas:
            signals.append(f"interest_field_deltas={list(field_deltas)}")
        if elapsed_delta >= 1.5:
            signals.append(f"elapsed_delta_s={elapsed_delta}")

        interesting = bool(signals) and mut_ex["response"]["status"] < 400
        verdict = "NEEDS_INTERPRETATION"
        if elapsed_delta >= 1.5 and mut_ex["response"]["status"] < 500:
            verdict = "TIME_BASED_INJECTION_CANDIDATE"
        elif interesting and field_deltas:
            verdict = "LIKELY_IMPACT"
        elif not body_changed and status_delta == 0 and abs(length_delta) < 16 and elapsed_delta < 1.5:
            verdict = "NO_MATERIAL_DIFF"
        elif mut_ex["response"]["status"] in (401, 403, 404) and base_ex["response"]["status"] < 400:
            verdict = "MUTANT_DENIED"
        elif base_ex["response"]["status"] in (401, 403) and mut_ex["response"]["status"] < 400:
            verdict = "MUTANT_BYPASS_CANDIDATE"
        # ASP.NET Core void-action: unauth write accepted (200 + empty body) while
        # a sibling write is 401. This is the SaveSettings missing-[Authorize] proof.
        if (
            base_ex["response"]["status"] in (401, 403)
            and mut_ex["response"]["status"] in (200, 204)
            and int(mut_ex["response"].get("length") or 0) == 0
        ):
            signals.append("aspnet_void_unauth_write")
            verdict = "MUTANT_BYPASS_CANDIDATE"

        from app.services.agent.lane_proof import annotate_compare_proof as lane_annotate

        extra_signals, proof, proof_verdict = lane_annotate(
            baseline_url=b["url"],
            mutant_url=m["url"],
            baseline_headers=b["headers"],
            mutant_headers=m["headers"],
            baseline_status=base_ex["response"]["status"],
            mutant_status=mut_ex["response"]["status"],
            baseline_body=b_body,
            mutant_body=m_body,
        )
        signals.extend(extra_signals)
        if proof_verdict:
            verdict = proof_verdict

        out = {
            "verdict": verdict,
            "signals": signals,
            "status": {
                "baseline": base_ex["response"]["status"],
                "mutant": mut_ex["response"]["status"],
                "delta": status_delta,
            },
            "length": {
                "baseline": base_ex["response"]["length"],
                "mutant": mut_ex["response"]["length"],
                "delta": length_delta,
            },
            "elapsed_s": {
                "baseline": b_elapsed,
                "mutant": m_elapsed,
                "delta": elapsed_delta,
            },
            "interest_fields": {"baseline": b_fields, "mutant": m_fields, "deltas": field_deltas},
            # Response labels are leads for the next probe; they do not feed
            # the verdict or signal escalation above.
            "classification": {
                "baseline": base_ex["response"].get("classes") or [],
                "mutant": mut_ex["response"].get("classes") or [],
                "added": sorted(set(mut_ex["response"].get("classes") or [])
                                - set(base_ex["response"].get("classes") or [])),
            },
            "adaptive_hints": mut_ex.get("adaptive_hints") or [],
            "baseline": base_ex,
            "mutant": mut_ex,
            "notes": rewrite_notes or None,
            "proof": proof,
            "guidance": (
                "All comparison verdicts are candidate signals. Status differences, empty writes, "
                "errors, and matching public bodies do not prove impact. Cite evidence_id from "
                "each exchange, verify the intended boundary, and submit_finding_candidate. "
                "Only independent verification can confirm a finding. Untested mutations stay open."
            ),
        }

        evidence_ids = [
            str(base_ex.get("evidence_id") or ""),
            str(mut_ex.get("evidence_id") or ""),
        ]
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.coverage_cells import record_input_first_pass_pair
        from app.services.agent.signal_escalation import queue_signal_escalation

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        if record_input_first_pass_pair(brain, b, m, *evidence_ids):
            self._engagement_brain = brain.to_dict()
        trace = mut_ex.get("trace") or {}
        escalation = queue_signal_escalation(
            brain,
            verdict=verdict,
            signals=signals,
            evidence_ids=evidence_ids,
            target=m["url"],
            source_tool="compare_requests",
            coverage_cell_id=coverage_cell_id,
            hypothesis_id=hypothesis_id or str(trace.get("hypothesis_id") or ""),
            operation_id=str(trace.get("operation_id") or ""),
            identity=str(m.get("identity") or trace.get("identity") or "anonymous"),
            tenant=str(trace.get("tenant") or ""),
            parameter=str(trace.get("parameter") or ""),
            test_type=str(trace.get("test_type") or ""),
            proof=proof or {},
        )
        if escalation:
            out["proof_escalation"] = escalation
            out["next_action"] = (
                "Complete the structured proof escalation before submitting a candidate; "
                "the differential signal alone cannot publish a finding."
            )
            self._engagement_brain = brain.to_dict()

        # Annotate engagement brain if present on the tool manager
        if hypothesis_id:
            try:
                from app.services.agent.engagement_brain import (
                    engagement_brain_from_dict,
                    update_hypothesis,
                )
                brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                status = "in_progress"  # A heuristic comparison cannot close the hypothesis.
                evidence = (
                    f"compare_requests verdict={verdict}; signals={signals}; "
                    f"status {base_ex['response']['status']}→{mut_ex['response']['status']}; "
                    f"len {base_ex['response']['length']}→{mut_ex['response']['length']}"
                )
                update_hypothesis(brain, hypothesis_id, status=status, evidence=evidence)
                self._engagement_brain = brain.to_dict()
                out["hypothesis_update"] = {"id": hypothesis_id, "status": status}
            except Exception as exc:
                out["hypothesis_update_error"] = str(exc)

        # The orchestrator reads the updated brain from this manager. Embedding
        # the entire brain in the comparison result can cut the JSON mid-object
        # at the tool-output limit, making the proof result unreadable.
        serialized = json.dumps(out, indent=2)
        if len(serialized) > _tool_output_max_chars():
            for key in ("baseline", "mutant"):
                exchange = out.get(key) or {}
                request = exchange.get("request") or {}
                response = exchange.get("response") or {}
                out[key] = {
                    "evidence_id": exchange.get("evidence_id"),
                    "request": {field: request.get(field) for field in ("method", "url", "identity")},
                    "response": {field: response.get(field)
                                 for field in ("status", "length", "elapsed_s", "classes")},
                    "trace": exchange.get("trace") or {},
                }
            out["output_compacted"] = True
            serialized = json.dumps(out, indent=2)
        if len(serialized) > _tool_output_max_chars():
            escalation = out.get("proof_escalation") or {}
            serialized = json.dumps({
                "verdict": out["verdict"],
                "signals": [str(value)[:200] for value in out["signals"][:8]],
                "baseline_evidence_id": out["baseline"].get("evidence_id"),
                "mutant_evidence_id": out["mutant"].get("evidence_id"),
                "proof_escalation": {
                    field: escalation.get(field) for field in ("id", "status", "strategy", "evidence_ids")
                } if escalation else None,
                "next_action": str(out.get("next_action") or "")[:300],
                "output_compacted": True,
            })
        return serialized
