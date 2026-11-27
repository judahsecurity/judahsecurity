"""Injection payloads, parameter and API-operation inventories.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    List,
    Optional,
    httpx,
    json,
)


class InputInventoryToolsMixin:
    """Injection payloads, parameter and API-operation inventories."""
    
    async def generate_injection_payloads(
        self,
        vuln_type: str = "sqli",
        technique: Optional[str] = None,
        max_payloads: int = 20,
        collaborator_url: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Generate injection payloads for a given vulnerability type.

        Args:
            vuln_type: sqli, xss, ssti, cmdi, path_traversal, xxe, ssrf, crlf, open_redirect
            technique: Sub-technique (e.g. "time_based" for sqli, "encoded" for xss).
                       SQLi defaults to low-impact error and Boolean controls.
            max_payloads: Max payloads to return (default 20).
            collaborator_url: Replace COLLABORATOR placeholder for out-of-band payloads.
        """
        from app.services.agent.injection_payloads import generate_payloads
        result = generate_payloads(
            vuln_type=vuln_type,
            technique=technique,
            max_payloads=max_payloads,
            collaborator_url=collaborator_url,
        )
        return json.dumps(result, indent=2)

    async def get_parameter_inventory(
        self,
        specialist: str = "all",
        offset: int = 0,
        limit: int = 40,
    ) -> str:
        """Read the observed, value-free input worklist with stable pagination."""
        from app.services.agent.parameter_inventory import (
            collect_parameter_inventory,
            parameters_for_specialist,
        )
        from app.services.agent.coverage_cells import coverage_cell_id
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.vulnerability_catalog import parameter_test_classes

        if specialist not in {"all", "xss", "sqli", "injection", "server_injection"}:
            return json.dumps({"error": "specialist must be all, xss, sqli, injection, or server_injection"})
        cmap = getattr(self, "_capability_map", None) or {}
        if not isinstance(cmap, dict):
            cmap = {}
        inventory = collect_parameter_inventory(cmap)
        rows = inventory if specialist == "all" else parameters_for_specialist(cmap, specialist)
        try:
            start = max(0, int(offset))
            page_size = max(1, min(100, int(limit)))
        except (TypeError, ValueError):
            return json.dumps({"error": "offset and limit must be integers"})
        end = min(start + page_size, len(rows))
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cells = {cell.get("id"): cell for cell in brain.coverage_cells
                 if isinstance(cell, dict) and cell.get("source") == "parameter_inventory"}
        page = []
        unscheduled = 0
        for row in rows[start:end]:
            checks = []
            if row["testable"]:
                for test_type in parameter_test_classes(row):
                    cell_id = coverage_cell_id(
                        method=row["method"], host=row["host"], path=row["path"],
                        identity=row["identity"],
                        parameter=f"{row['location']}:{row['name']}", test_type=test_type,
                    )
                    cell = cells.get(cell_id)
                    if cell is None:
                        unscheduled += 1
                    checks.append({
                        "test_type": test_type,
                        "coverage_cell_id": cell_id if cell else None,
                        "status": cell.get("status", "untested") if cell else "not_scheduled",
                        "first_pass_outcome": cell.get("first_pass_outcome") if cell else None,
                    })
            page.append({**row, "checks": checks})
        return json.dumps({
            "specialist": specialist,
            "total": len(rows),
            "excluded_protected": sum(not row["testable"] for row in inventory),
            "unscheduled_checks_on_page": unscheduled,
            "offset": start,
            "next_offset": end if end < len(rows) else None,
            "parameters": page,
        })

    async def get_api_operation_inventory(
        self, offset: int = 0, limit: int = 40,
    ) -> str:
        """Read the central API operation ledger without request values."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        try:
            start = max(0, int(offset))
            page_size = max(1, min(100, int(limit)))
        except (TypeError, ValueError):
            return json.dumps({"error": "offset and limit must be integers"})
        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        rows = [row for row in brain.application_operations
                if isinstance(row, dict) and row.get("protocol") in
                {"rest", "graphql", "soap", "grpc-web", "websocket"}]
        page = [{key: row.get(key) for key in (
            "id", "method", "url", "path", "protocol", "operation", "parameters",
            "identities", "sources", "capture_ids", "status", "content_type",
            "request_content_type",
            "discovery_only",
        ) if key in row} for row in rows[start:start + page_size]]
        return json.dumps({"total": len(rows), "offset": start,
                           "next_offset": start + len(page) if start + len(page) < len(rows) else None,
                           "operations": page})

    async def discover_parameters(
        self,
        url: str = "",
        **kwargs: Any,
    ) -> str:
        """Fetch a URL and extract injectable parameters from HTML forms, URL query strings, and JavaScript.

        Args:
            url: The URL to analyze for parameters.

        Returns:
            JSON with discovered parameters, their locations, and which vuln classes they may be prone to.
        """
        if not url or not url.strip():
            return json.dumps({"error": "url is required"})

        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        import re as _re_local
        from app.services.agent.injection_payloads import INTERESTING_PARAM_NAMES

        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True, verify=False) as client:
                resp = await client.get(url)
        except Exception as e:
            return json.dumps({"error": f"Failed to fetch {url}: {e}"})

        body = resp.text
        params_found: Dict[str, Dict[str, Any]] = {}

        # 1. Query string params from the final URL
        from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qs
        parsed = urlparse(str(resp.url))
        observed_inputs: List[Dict[str, str]] = []
        response_url = str(resp.url)
        value_free_url = urlunsplit(urlsplit(response_url)._replace(query="", fragment=""))
        for name in parse_qs(parsed.query, keep_blank_values=True):
            params_found[name] = {"source": "query_string", "method": "GET"}
            observed_inputs.append({
                "url": value_free_url, "method": "GET", "name": name,
                "location": "query", "source": "page_url",
            })

        # 2. HTML form inputs
        form_pattern = _re_local.compile(
            r'<form[^>]*>(.*?)</form>', _re_local.DOTALL | _re_local.IGNORECASE
        )
        input_pattern = _re_local.compile(
            r'<(?:input|textarea|select)[^>]*?name=["\']([^"\']+)["\']', _re_local.IGNORECASE
        )
        action_pattern = _re_local.compile(
            r'action=["\']([^"\']*)["\']', _re_local.IGNORECASE
        )
        method_pattern = _re_local.compile(
            r'method=["\']([^"\']*)["\']', _re_local.IGNORECASE
        )

        for form_match in form_pattern.finditer(body):
            form_html = form_match.group(0)
            action = action_pattern.search(form_html)
            method = method_pattern.search(form_html)
            form_action = action.group(1) if action else ""
            form_method = (method.group(1) if method else "GET").upper()
            action_url = urljoin(response_url, form_action) if form_action else value_free_url
            action_url = urlunsplit(urlsplit(action_url)._replace(query="", fragment=""))

            for inp in input_pattern.finditer(form_html):
                name = inp.group(1)
                params_found[name] = {
                    "source": "form",
                    "method": form_method,
                    "form_action": form_action,
                }
                if form_method in {"GET", "POST"}:
                    observed_inputs.append({
                        "url": action_url, "method": form_method, "name": name,
                        "location": "query" if form_method == "GET" else "body_form",
                        "source": "observed_form",
                    })

        # 3. Hidden inputs (sometimes outside forms)
        hidden_pattern = _re_local.compile(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']', _re_local.IGNORECASE
        )
        for m in hidden_pattern.finditer(body):
            name = m.group(1)
            if name not in params_found:
                params_found[name] = {"source": "hidden_input", "method": "POST"}

        # 4. JavaScript variable names and AJAX params
        js_param_patterns = [
            _re_local.compile(r'[?&](\w+)=', _re_local.IGNORECASE),
            _re_local.compile(r'["\']([\w]+)["\']:\s*["\']', _re_local.IGNORECASE),
        ]
        for pat in js_param_patterns:
            for m in pat.finditer(body):
                name = m.group(1)
                if len(name) >= 2 and name not in params_found and not name.startswith(("__", "0x")):
                    params_found[name] = {"source": "javascript", "method": "GET/POST"}

        # 5. Classify parameters by vulnerability proneness
        for name, info in params_found.items():
            name_lower = name.lower()
            prone_to = []
            for vuln_class, param_names in INTERESTING_PARAM_NAMES.items():
                if name_lower in param_names:
                    prone_to.append(vuln_class.replace("_prone", ""))
            if prone_to:
                info["likely_vulnerable_to"] = prone_to

        queued_inputs = 0
        cmap = getattr(self, "_capability_map", None) or {}
        if isinstance(cmap, dict) and observed_inputs:
            from app.services.agent.coverage_cells import seed_parameter_coverage_cells
            from app.services.agent.engagement_brain import engagement_brain_from_dict
            from app.services.agent.parameter_inventory import collect_parameter_inventory

            prior = collect_parameter_inventory(cmap)
            inventory = collect_parameter_inventory({
                **cmap, "parameter_inventory": [
                    *(cmap.get("parameter_inventory") or []), *observed_inputs,
                ],
            })
            queued_inputs = sum(row not in prior for row in inventory)
            if queued_inputs:
                self._capability_map = {**cmap, "parameter_inventory": inventory}
                brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
                seed_parameter_coverage_cells(brain, inventory)
                self._refresh_followups(brain, inventory)
                self._engagement_brain = brain.to_dict()

        return json.dumps({
            "url": str(resp.url),
            "status_code": resp.status_code,
            "parameter_count": len(params_found),
            "queued_inputs": queued_inputs,
            "parameters": params_found,
        }, indent=2)
