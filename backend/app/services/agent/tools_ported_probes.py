"""Probe and recon tools ported from Aegis Vanguard.

Mixin for ASMToolsManager. Request plans and verdicts live in
``ported_probes`` (transport-free, unit-tested); this module binds them to the
scope-checked, method-policy-enforcing, evidence-recording ``_http_exchange``.
Every tool returns leads; none creates a finding.
"""

from app.services.agent.tools_common import (
    Any,
    Dict,
    Optional,
    _tool_output_max_chars,
    json,
    logger,
)

# Errors from _http_exchange that mean "policy refused this request", as
# opposed to a network failure. They are reported as skipped vectors.
_POLICY_MARKERS = (
    "operator-approved",
    "Out-of-scope",
    "network scope",
    "Pilot first pass",
    "Named identit",
    "Embedded URL credentials",
    "absolute HTTP(S)",
)


def _normalize_url(raw: Any, *, websocket: bool = False) -> str:
    url = str(raw or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = f"https://{url}"
    if websocket:
        from app.services.agent.ported_probes import ws_http_url

        return ws_http_url(url)
    return url


class PortedProbeToolsMixin:
    """Server-side prototype pollution, GraphQL, VCS exposure, gRPC reflection,
    WebSocket Origin, GitLab fingerprint, mail security and vendor intel."""

    def _ported_target(self, url: Any, *, websocket: bool = False) -> str:
        from app.services.agent.assessment_scope import assert_url_in_scope

        target = _normalize_url(url or getattr(self, "_fallback_target", "") or "", websocket=websocket)
        if not target:
            raise ValueError("url is required")
        assert_url_in_scope(self, target)
        return target

    def _ported_sender(self, *, use_auth_session: bool = False, identity: Optional[str] = None,
                       hypothesis_id: str = "", coverage_cell_id: str = "",
                       follow_redirects: bool = False, timeout: int = 20,
                       max_response_bytes: int = 2_000_000):
        """An ``async send(method, url, headers, body, http2=False)`` over _http_exchange."""

        async def send(method: str, url: str, headers: Dict[str, str], body: str,
                       http2: bool = False) -> Dict[str, Any]:
            try:
                exchange = await self._http_exchange(
                    method, url, headers=dict(headers or {}), body=body or None,
                    use_auth_session=use_auth_session, identity=identity,
                    hypothesis_id=hypothesis_id, coverage_cell_id=coverage_cell_id,
                    follow_redirects=follow_redirects, timeout=timeout,
                    max_response_bytes=max_response_bytes, http2=http2, return_bytes=True,
                )
            except ImportError as exc:
                return {"skipped": f"HTTP/2 support is not installed ({exc.__class__.__name__})"}
            except ValueError as exc:
                message = str(exc)
                if any(marker in message for marker in _POLICY_MARKERS):
                    return {"skipped": message}
                return {"error": message}
            except Exception as exc:  # network errors are data, not tool failures
                logger.debug("ported probe request failed: %s %s", method, url, exc_info=True)
                return {"error": f"{exc.__class__.__name__}: {str(exc)[:200]}"}
            request_headers = exchange.get("request", {}).get("headers") or {}
            response = exchange.get("response") or {}
            return {
                "status": response.get("status"),
                "headers": response.get("headers") or {},
                "body": exchange.get("_body_text") or "",
                "body_bytes": exchange.get("_body_bytes"),
                "evidence_id": exchange.get("evidence_id", ""),
                "cookie_sent": any(str(k).lower() == "cookie" for k in request_headers),
            }

        return send

    @staticmethod
    def _ported_output(result: Dict[str, Any]) -> str:
        return json.dumps(result, indent=2, default=str)[:_tool_output_max_chars()]

    @staticmethod
    def _ported_error(tool: str, exc: Exception) -> str:
        return json.dumps({"tool": tool, "verdict": "BLOCKED", "error": str(exc)})

    @staticmethod
    def _ported_nonce() -> str:
        import secrets

        return secrets.token_hex(6)

    async def probe_server_prototype_pollution(
        self, url: str = "", use_auth_session: bool = True, identity: Optional[str] = None,
        hypothesis_id: str = "", coverage_cell_id: str = "", **kwargs: Any,
    ) -> str:
        """Server-side prototype pollution probe (query + JSON body vectors).

        Sends an inert nonce property via __proto__ / constructor.prototype with a
        plain-property control per vector, then re-fetches the baseline to see
        whether the property persisted. JSON POST vectors need an operator-approved
        path when a scoped policy is applied; they are skipped otherwise.
        """
        from app.services.agent.ported_probes import run_prototype_pollution

        try:
            target = self._ported_target(url or kwargs.get("target_url") or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("probe_server_prototype_pollution", exc)
        send = self._ported_sender(use_auth_session=use_auth_session, identity=identity,
                                   hypothesis_id=hypothesis_id, coverage_cell_id=coverage_cell_id)
        return self._ported_output(await run_prototype_pollution(target, send, self._ported_nonce()))

    async def probe_graphql(
        self, url: str = "", use_auth_session: bool = True, identity: Optional[str] = None,
        hypothesis_id: str = "", coverage_cell_id: str = "", **kwargs: Any,
    ) -> str:
        """GraphQL introspection, field-suggestion, batching and GET-query probe.

        One request per check (batch size 2). Falls back to GET introspection when
        POST is not approved by the scoped method policy.
        """
        from app.services.agent.ported_probes import run_graphql

        try:
            target = self._ported_target(url or kwargs.get("endpoint_url") or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("probe_graphql", exc)
        send = self._ported_sender(use_auth_session=use_auth_session, identity=identity,
                                   hypothesis_id=hypothesis_id, coverage_cell_id=coverage_cell_id)
        return self._ported_output(await run_graphql(target, send))

    async def probe_vcs_exposure(self, url: str = "", hypothesis_id: str = "", **kwargs: Any) -> str:
        """Anonymous GETs of /.git/{HEAD,config,index,logs/HEAD,packed-refs} and
        /.svn/{wc.db,entries}; confirm by file signature and extract remotes,
        refs and credentials from .git/config. Credentials are returned only as
        secret_safety fingerprints, never as values."""
        from urllib.parse import urlsplit

        from app.services.agent.ported_probes import origin_of, run_vcs_dump

        try:
            target = self._ported_target(url or kwargs.get("base_url") or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("probe_vcs_exposure", exc)
        # Probe under the given path (a sub-app may own its own checkout).
        base = origin_of(target) + urlsplit(target).path.rstrip("/")
        send = self._ported_sender(use_auth_session=False, hypothesis_id=hypothesis_id,
                                   max_response_bytes=4_000_000)
        return self._ported_output(await run_vcs_dump(base, send))

    async def probe_grpc_reflection(self, url: str = "", hypothesis_id: str = "", **kwargs: Any) -> str:
        """Anonymous gRPC server-reflection ListServices over HTTP/2 (v1, v1alpha),
        then gRPC-Web over HTTP/1.1. Lists service names only; never calls
        application methods. POST needs an operator-approved path under a scoped
        policy."""
        from app.services.agent.ported_probes import origin_of, run_grpc_reflection

        try:
            target = self._ported_target(url or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("probe_grpc_reflection", exc)
        send = self._ported_sender(use_auth_session=False, hypothesis_id=hypothesis_id,
                                   timeout=15, max_response_bytes=1_000_000)
        return self._ported_output(await run_grpc_reflection(origin_of(target), send))

    async def probe_websocket_origin(
        self, url: str = "", subprotocol: str = "", use_auth_session: bool = True,
        identity: Optional[str] = None, hypothesis_id: str = "", coverage_cell_id: str = "",
        **kwargs: Any,
    ) -> str:
        """WebSocket Origin check (CSWSH): same-origin control handshake, then a
        nonce foreign Origin, Origin: null and no Origin. Accepts ws://, wss://,
        http:// or https:// URLs. Handshakes only; no frames are sent."""
        from app.services.agent.ported_probes import run_websocket_origin

        try:
            target = self._ported_target(url or kwargs.get("ws_url") or kwargs.get("target"),
                                         websocket=True)
        except ValueError as exc:
            return self._ported_error("probe_websocket_origin", exc)
        send = self._ported_sender(use_auth_session=use_auth_session, identity=identity,
                                   hypothesis_id=hypothesis_id, coverage_cell_id=coverage_cell_id,
                                   timeout=10, max_response_bytes=200_000)
        return self._ported_output(await run_websocket_origin(target, send, self._ported_nonce(),
                                                              subprotocol=str(subprotocol or "")))

    async def fingerprint_gitlab(self, url: str = "", max_assets: int = 20, **kwargs: Any) -> str:
        """GitLab version fingerprint by SHA-256 of /help stylesheets, correlated
        with a local hash DB (GITLAB_HASH_DB_PATH), plus the CVE-2021-22205 range.
        Anonymous, read-only GETs; cross-origin stylesheets are skipped."""
        from app.services.agent.ported_probes import load_gitlab_hash_db, run_gitlab_fingerprint

        try:
            target = self._ported_target(url or kwargs.get("target_url") or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("fingerprint_gitlab", exc)
        try:
            limit = max(1, min(int(max_assets or 20), 50))
        except (TypeError, ValueError):
            limit = 20
        send = self._ported_sender(use_auth_session=False, follow_redirects=True, timeout=20,
                                   max_response_bytes=5_000_000)
        return self._ported_output(await run_gitlab_fingerprint(target, send, load_gitlab_hash_db(),
                                                                max_assets=limit))

    async def query_mail_security(self, domain: str = "", **kwargs: Any) -> str:
        """DNS-only mail posture: MX/provider, SPF (all-qualifier, duplicates, lookup
        count), DMARC policy, DKIM at common selectors, BIMI, MTA-STS, DANE TLSA."""
        from urllib.parse import urlsplit

        from app.services.agent.evidence_store import evidence_store
        from app.services.agent.ported_probes import run_mail_intel

        raw = str(domain or kwargs.get("target") or kwargs.get("url") or "").strip()
        host = (urlsplit(raw if "://" in raw else f"https://{raw}").hostname or "").rstrip(".")
        try:
            self._ported_target(f"https://{host}/" if host else "")
        except ValueError as exc:
            return self._ported_error("query_mail_security", exc)
        result = await run_mail_intel(host, _dns_resolve)
        result["evidence_ids"] = [evidence_store(self).record(
            "dns_mail_intel", {"domain": host, "records": result.get("records")},
            target=host, identity="anonymous", success=True,
        )]
        return self._ported_output(result)

    async def detect_third_party_vendors(self, url: str = "", **kwargs: Any) -> str:
        """Third-party vendor inventory for one page (body + CSP against Vanguard's
        VENDOR_PATTERNS), plus external scripts lacking Subresource Integrity."""
        from app.services.agent.ported_probes import run_third_party_intel

        try:
            target = self._ported_target(url or kwargs.get("target"))
        except ValueError as exc:
            return self._ported_error("detect_third_party_vendors", exc)
        send = self._ported_sender(use_auth_session=False, follow_redirects=True,
                                   max_response_bytes=3_000_000)
        return self._ported_output(await run_third_party_intel(target, send))


async def _dns_resolve(name: str, rtype: str) -> list:
    """Public-DNS lookup returning record text (MX as "<pref> <host>")."""
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = 5.0
    answer = await resolver.resolve(name, rtype)
    out = []
    for record in answer:
        if rtype == "MX":
            out.append(f"{record.preference} {str(record.exchange).rstrip('.')}")
        else:
            out.append(record.to_text())
    return out
