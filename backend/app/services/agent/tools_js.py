"""JavaScript secret, dependency, sink and endpoint analysis.

Mixin for ASMToolsManager; methods moved verbatim from tools.py.
"""

from app.services.agent.tools_common import (
    Any,
    List,
    _tool_output_max_chars,
    current_seed_target,
    current_session_id,
    get_tenant_context,
    json,
    logger,
)


class JsAnalysisToolsMixin:
    """JavaScript secret, dependency, sink and endpoint analysis."""

    async def scan_js_urls_for_secrets(
        self,
        urls: str,
        max_urls: int = 30,
    ) -> str:
        """Fetch remote JS/text URLs, run Gitleaks --no-git, regex hints, and CWE-321 client HMAC/MQTT/RFID reconstruction. urls = newline- or comma-separated https URLs."""
        import asyncio

        from app.services.js_url_secrets_service import scan_js_urls_for_secrets as run_scan

        try:
            mu = int(max_urls) if max_urls is not None else 30
        except (TypeError, ValueError):
            mu = 30
        mu = max(1, min(mu, 100))
        try:
            result = await asyncio.to_thread(run_scan, urls, mu)
        except Exception as e:
            logger.exception("scan_js_urls_for_secrets failed")
            return json.dumps({"success": False, "error": str(e)}, indent=2)
        dumped = json.dumps(result, indent=2, default=str)
        cap = _tool_output_max_chars()
        if len(dumped) > cap:
            dumped = dumped[:cap] + f"\n... (truncated, total {len(dumped)} chars)"
        return dumped

    async def scan_assigned_js(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> str:
        """Scan the exact first-party script leased to the JS specialist."""
        import asyncio
        import time
        from urllib.parse import urlsplit

        from app.services.agent.coverage_cells import record_coverage_cell
        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.js_url_secrets_service import scan_js_urls_for_secrets as run_scan

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased" or
                cell.get("lease_id") != coverage_lease_id or
                float(cell.get("lease_deadline") or 0) <= time.time() or
                cell.get("source") != "js_inventory" or
                cell.get("specialist") != "js_secrets"):
            return json.dumps({"success": False, "error": "invalid_coverage_lease"})
        url = str(cell.get("script_url") or "")
        target = urlsplit(str((getattr(self, "_capability_map", None) or {}).get("scope") or
                              (getattr(self, "_capability_map", None) or {}).get("target") or ""))
        script = urlsplit(url)
        if ((script.scheme, script.netloc) != (target.scheme, target.netloc) or
                script.scheme not in {"http", "https"} or not script.path or
                script.query or script.fragment or script.path != cell.get("path")):
            return json.dumps({"success": False, "error": "scope_mismatch"})
        try:
            result = await asyncio.to_thread(
                run_scan, url, 1, same_origin_only=True,
            )
        except Exception as exc:
            logger.exception("Assigned JS scan failed")
            result = {"success": False, "error": type(exc).__name__, "downloads": []}
        downloads = result.get("downloads") or []
        fetched = (len(downloads) == 1 and downloads[0].get("url") == url
                   and downloads[0].get("ok") is True)
        expected_sha256 = str(cell.get("expected_sha256") or "")
        source_matched = (not expected_sha256 or
                          fetched and downloads[0].get("sha256") == expected_sha256)
        complete = (fetched and not downloads[0].get("truncated") and
                    source_matched and not result.get("gitleaks_error") and
                    result.get("success") is True)
        counts = {
            "gitleaks": len(result.get("gitleaks_findings") or []),
            "regex": len(result.get("regex_hints") or []),
            "client_signing": len(result.get("client_signing_findings") or []),
        }
        hits = sum(counts.values())
        status = "in_focus" if hits else "tested_clean" if complete else "inconclusive"
        summary = {
            "url": url, "fetched": fetched, "source_matched": source_matched,
            "complete": complete,
            "counts": counts, "status": status,
            "truncated": bool(downloads and downloads[0].get("truncated")),
            "scanner_error": bool(result.get("gitleaks_error")),
        }
        evidence_id = evidence_store(self).record(
            "js_secret_review", summary, target=url,
            coverage_cell_id=coverage_cell_id, test_type="js_secret_review",
            capture_id=str(cell.get("capture_id") or ""), success=fetched,
        )
        updated = record_coverage_cell(
            brain, method=cell["method"], path=cell["path"], host=cell["host"],
            status=status, identity=cell["identity"], parameter=cell["parameter"],
            test_type=cell["test_type"], coverage_cell_id_value=coverage_cell_id,
            coverage_lease_id=coverage_lease_id, evidence_id=evidence_id,
            reason=("Potential sensitive data requires specialist review" if hits else
                    "Complete bounded scan found no candidate" if complete else
                    "Fetch or scanner incomplete; JS review remains open"),
        )
        self._engagement_brain = brain.to_dict()
        from app.services.sitemap_service import persist_js_review_safe

        _user_id, organization_id = get_tenant_context()
        asset_saved = persist_js_review_safe(
            organization_id, current_session_id.get(), url, summary, evidence_id,
        )
        return json.dumps({
            "success": True, "coverage_cell_id": updated["id"],
            "evidence_id": evidence_id, "asset_review_saved": asset_saved,
            "summary": summary,
            "findings": {
                "gitleaks_findings": result.get("gitleaks_findings") or [],
                "regex_hints": result.get("regex_hints") or [],
                "client_signing_findings": result.get("client_signing_findings") or [],
            },
        }, default=str)[:_tool_output_max_chars()]

    async def scan_assigned_js_dependency(
        self, coverage_cell_id: str, coverage_lease_id: str,
    ) -> str:
        """Run Retire.js on one leased first-party script and retain its provenance."""
        import asyncio
        import time
        from urllib.parse import urlsplit

        from app.services.agent.engagement_brain import engagement_brain_from_dict
        from app.services.agent.evidence_store import evidence_store
        from app.services.retirejs_service import scan_js_urls_for_vulns

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "js_inventory"
                or cell.get("specialist") != "spa_client"
                or cell.get("test_type") != "js_dependency_review"):
            return json.dumps({"success": False, "error": "invalid_coverage_lease"})
        url = str(cell.get("script_url") or "")
        cmap = getattr(self, "_capability_map", None) or {}
        target = urlsplit(str(cmap.get("scope") or cmap.get("target") or ""))
        script = urlsplit(url)
        if ((script.scheme, script.netloc) != (target.scheme, target.netloc)
                or script.scheme not in {"http", "https"} or not script.path
                or script.path != cell.get("path") or script.query or script.fragment):
            return json.dumps({"success": False, "error": "scope_mismatch"})
        try:
            result = await asyncio.to_thread(
                scan_js_urls_for_vulns, url, 1, same_origin_only=True,
            )
        except Exception:
            logger.exception("Assigned dependency review failed")
            result = {"success": False, "downloads": [], "retire_error": "scanner_failed"}
        downloads = result.get("downloads") or []
        fetched = (len(downloads) == 1 and downloads[0].get("url") == url
                   and downloads[0].get("ok") is True)
        expected = str(cell.get("expected_sha256") or "")
        source_matched = bool(fetched and (not expected or
                              downloads[0].get("sha256") == expected))
        complete = bool(source_matched and not result.get("retire_error")
                        and result.get("success") is True)
        candidates = [
            {key: item.get(key) for key in ("component", "version", "severity", "cve")}
            for item in (result.get("vulnerable_components") or [])[:20]
            if isinstance(item, dict) and item.get("source_url") == url
        ] if source_matched else []
        status = "in_focus" if complete and candidates else "tested_clean" if complete else "inconclusive"
        summary = {"url": url, "fetched": fetched, "source_matched": source_matched,
                   "complete": complete, "candidate_count": len(candidates),
                   "scanner_error": bool(result.get("retire_error")),
                   "status": status, "candidates": candidates,
                   "proof_confirmed": False}
        artifact_id = evidence_store(self).record(
            "js_dependency_review", summary, target=url,
            coverage_cell_id=coverage_cell_id, test_type="js_dependency_review",
            capture_id=str(cell.get("capture_id") or ""), success=complete,
        )
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["status"] = status
        cell["reason"] = (
            "Known-vulnerability component match needs reachability validation" if candidates else
            "Complete dependency scan found no known match" if complete else
            "Script fetch, content hash, or Retire.js scan incomplete"
        )
        self._engagement_brain = brain.to_dict()
        return json.dumps({"success": True, "coverage_cell_id": coverage_cell_id,
                           "coverage_lease_id": coverage_lease_id,
                           "evidence_id": artifact_id, "summary": summary})

    async def scan_js_urls_for_vulns(
        self,
        urls: str,
        max_urls: int = 30,
    ) -> str:
        """Fetch remote JS bundle URLs and run Retire.js to detect vulnerable libraries (by CVE). urls = newline- or comma-separated https URLs (or a JSON object)."""
        import asyncio

        from app.services.retirejs_service import scan_js_urls_for_vulns as run_scan

        # Accept a JSON object {"urls": ..., "max_urls": ...} as well as a bare list.
        url_input = urls
        if isinstance(urls, str) and urls.strip().startswith("{"):
            try:
                obj = json.loads(urls)
                url_input = obj.get("urls", "")
                if obj.get("max_urls") is not None:
                    max_urls = obj.get("max_urls")
            except json.JSONDecodeError:
                pass

        try:
            mu = int(max_urls) if max_urls is not None else 30
        except (TypeError, ValueError):
            mu = 30
        mu = max(1, min(mu, 100))
        try:
            result = await asyncio.to_thread(run_scan, url_input, mu)
        except Exception as e:
            logger.exception("scan_js_urls_for_vulns failed")
            return json.dumps({"success": False, "error": str(e)}, indent=2)
        return json.dumps(result, indent=2, default=str)

    def _js_urls_from_map(self) -> List[str]:
        cmap = getattr(self, "_capability_map", None) or {}
        if not isinstance(cmap, dict):
            return []
        urls: List[str] = []
        for u in list(cmap.get("js_files") or []) + list(cmap.get("js_endpoints") or []):
            s = str(u).strip()
            if s.startswith("http"):
                urls.append(s)
        return urls

    def _origin_host(self) -> str:
        cmap = getattr(self, "_capability_map", None) or {}
        origin = ""
        if isinstance(cmap, dict):
            origin = str(cmap.get("target") or "")
        origin = origin or (getattr(self, "_fallback_target", None) or "") or (current_seed_target.get() or "")
        from urllib.parse import urlparse

        return (urlparse(origin if "://" in origin else f"https://{origin}").hostname or "").lower()

    async def fetch_lazy_chunks(
        self,
        bundle_url: str = "",
        base_url: str = "",
        dry_run: bool = False,
        **kwargs: Any,
    ) -> str:
        """Reconstruct webpack/Vite/Next lazy-chunk URLs from a first-party bundle, then fetch in-scope."""
        from app.services.agent.lazy_chunks import fetch_lazy_chunks as run_fetch

        url = (bundle_url or "").strip()
        if not url:
            js = self._js_urls_from_map()
            preferred = [u for u in js if "/_next/" in u or "chunk" in u.lower() or "webpack" in u.lower()]
            url = (preferred or js or [""])[0]
        if not url:
            return json.dumps({
                "ok": False,
                "error": "bundle_url required (or crawl a page so js_files is populated)",
            })
        origin = (base_url or "").strip()
        if not origin:
            cmap = getattr(self, "_capability_map", None) or {}
            if isinstance(cmap, dict):
                origin = str(cmap.get("target") or "")
            origin = origin or (getattr(self, "_fallback_target", None) or "") or url
        result = await run_fetch(bundle_url=url, base_url=origin, dry_run=bool(dry_run))
        fetched_urls = [
            str(row.get("url"))
            for row in (result.get("fetched") or [])
            if isinstance(row, dict) and row.get("url")
        ]
        if fetched_urls:
            cmap = getattr(self, "_capability_map", None)
            if isinstance(cmap, dict):
                js = list(cmap.get("js_files") or [])
                for u in fetched_urls:
                    if u not in js:
                        js.append(u)
                cmap = dict(cmap)
                cmap["js_files"] = js[:160]
                self._capability_map = cmap
                result["capability_map"] = cmap
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]

    async def extract_js_endpoints(
        self,
        urls: str = "",
        **kwargs: Any,
    ) -> str:
        """Extract and triage API paths/URLs from in-scope JavaScript (local analysis after fetch)."""
        from app.services.agent.js_endpoints import extract_js_endpoints as run_extract

        raw = urls or kwargs.get("url") or ""
        parsed: List[str] = []
        if isinstance(raw, list):
            parsed = [str(u).strip() for u in raw]
        else:
            blob = str(raw).strip()
            if blob.startswith("["):
                try:
                    parsed = [str(u).strip() for u in json.loads(blob)]
                except json.JSONDecodeError:
                    parsed = []
            if not parsed:
                parsed = [p.strip() for p in blob.replace(",", "\n").splitlines() if p.strip()]
        if not parsed:
            parsed = self._js_urls_from_map()
        result = await run_extract(parsed, origin_host=self._origin_host())
        origin = ""
        cmap = getattr(self, "_capability_map", None) or {}
        if isinstance(cmap, dict):
            origin = str(cmap.get("target") or "")
        origin = origin or (getattr(self, "_fallback_target", None) or "")
        to_ingest: List[str] = []
        for ep in result.get("endpoints") or []:
            s = str(ep).strip()
            if s.startswith("http"):
                to_ingest.append(s)
            elif s.startswith("/") and origin.startswith("http"):
                to_ingest.append(origin.rstrip("/") + s)
        if to_ingest:
            from app.services.agent.capability_map import ingest_passive_urls

            merged = ingest_passive_urls(
                cmap if isinstance(cmap, dict) else None,
                to_ingest,
                target=origin,
                source="js_analysis",
            )
            self._capability_map = merged
            result["ingested"] = len(to_ingest)
            result["capability_map"] = merged
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]

    async def scan_js_sinks(self, urls: str = "", **kwargs: Any) -> str:
        """Scan first-party JS for DOM sinks (eval, innerHTML, postMessage, location)."""
        from app.services.agent.js_sinks import scan_js_sinks as run_scan

        raw = urls or kwargs.get("url") or ""
        parsed: List[str] = []
        if isinstance(raw, list):
            parsed = [str(u).strip() for u in raw]
        else:
            blob = str(raw).strip()
            if blob.startswith("["):
                try:
                    parsed = [str(u).strip() for u in json.loads(blob)]
                except json.JSONDecodeError:
                    parsed = []
            if not parsed:
                parsed = [p.strip() for p in blob.replace(",", "\n").splitlines() if p.strip()]
        if not parsed:
            parsed = self._js_urls_from_map()
        from urllib.parse import urlsplit

        cmap = getattr(self, "_capability_map", None) or {}
        target = str(cmap.get("target") or cmap.get("scope") or "") if isinstance(cmap, dict) else ""
        parts = urlsplit(target)
        origin = f"{parts.scheme}://{parts.netloc}" if parts.scheme in {"http", "https"} and parts.netloc else ""
        result = await run_scan(parsed, origin_host=origin or self._origin_host())
        if origin and result.get("analyzed_urls") and isinstance(cmap, dict):
            from app.services.agent.coverage_cells import seed_js_coverage_cells
            from app.services.agent.engagement_brain import engagement_brain_from_dict

            updated = dict(cmap)
            known = {str(row.get("url")): dict(row) for row in (cmap.get("js_sources") or [])
                     if isinstance(row, dict) and isinstance(row.get("url"), str)}
            before = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
            prior_ids = {cell.get("id") for cell in before.coverage_cells}
            for url in result["analyzed_urls"]:
                if urlsplit(url).scheme != parts.scheme or urlsplit(url).netloc != parts.netloc:
                    continue
                row = known.setdefault(url, {"url": url})
                row["source_leads"] = [
                    {"kind": lead["kind"], "line": lead["line"]}
                    for lead in result.get("dom_sources", []) if lead.get("source") == url
                ][:10]
                row["sink_leads"] = [
                    {"kind": lead["type"], "line": lead["line"]}
                    for lead in result.get("sinks", []) if lead.get("source") == url
                ][:30]
            updated["js_sources"] = list(known.values())[:160]
            updated["js_files"] = list(dict.fromkeys([
                *(cmap.get("js_files") or []), *result["analyzed_urls"]
            ]))[:160]
            self._capability_map = updated
            seed_js_coverage_cells(before, updated)
            self._engagement_brain = before.to_dict()
            result["coverage_cells_added"] = len([
                cell for cell in before.coverage_cells
                if cell.get("id") not in prior_ids and cell.get("test_type") == "dom_xss"
            ])
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]
