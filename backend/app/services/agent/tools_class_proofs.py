"""Leased, receipt-backed proofs for classes that used to be lead-only.

Mixin for ASMToolsManager; declared with tool specs (tool_specs.py). Request
plans and verdicts live in ``scoped_assessment/class_probes.py``. Every tool
here checks the lease (where the class has coverage cells), the assessment
scope, operator approvals for any POST/DELETE, and the scoped request budget,
then records one ``scoped_class_probe`` receipt. A positive receipt is a
candidate, never a finding: the independent verifier repeats the same plan
with a fresh nonce (``replay_class_probe``) before publication.

Approvals:
- POST upload, JSON gadget (and its malformed-JSON error readback) and LLM
  requests: ``body_replay_paths``.
- Login/reset enumeration POST: ``body_replay_paths`` or ``auth_login_path``.
  Timing-only enumeration runs only on reset forms (never a login: it would
  send repeated wrong passwords to the test account) and only with the
  operator's ``timing_enumeration_allowed`` policy flag.
- Upload and indirect-LLM cleanup DELETE: only a ``stored_xss_cleanup_paths`` entry.
- Indirect LLM injection: one ``llm_indirect_fields`` entry approves the POST
  to its write_path (or, for a record_path with ``{id}``, PUT/PATCH on a
  Prowl-owned test record only) and the chat POST on its read_path.
- LLM out-of-band fetch variants: ``oob_callbacks_allowed``.
- OAuth authorization requests and WebSocket handshakes are GETs.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from app.services.agent.tool_specs import ACTIVE_PHASES, write_tool
from app.services.agent.tools_common import _lease_failure_reason

# 2 timing runs per session for the hunter and for the verifier.
TIMING_POST_BUDGET = 80

_CELL_RULES = {
    # test_type of the coverage cell -> (proof class, allowed methods)
    "file_upload": ("file_upload", {"POST"}),
    "auth": ("account_enumeration", {"POST"}),
    "oauth": ("oauth", {"GET"}),
    "prototype_pollution": ("server_prototype_pollution", {"POST"}),
    "llm_ai": ("prompt_injection", {"POST"}),
}


class ClassProofToolsMixin:
    """Upload, account enumeration, OAuth redirect_uri, CSWSH, server-side
    prototype pollution and LLM canary proofs."""

    # ------------------------------------------------------------ shared

    def _class_scoped_origin(self, host: str = "") -> str:
        from app.services.agent.parameter_inventory import _origin

        cmap = getattr(self, "_capability_map", None) or {}
        scoped_origin = _origin(str(cmap.get("target") or cmap.get("scope") or ""))
        parts = urlsplit(scoped_origin)
        if not scoped_origin or (host and _origin(f"{parts.scheme}://{host}") != scoped_origin):
            raise ValueError("scope_mismatch")
        return scoped_origin

    def _class_leased_cell(self, brain, coverage_cell_id: str, coverage_lease_id: str,
                           cell_test_type: str) -> Tuple[Optional[dict], Optional[dict]]:
        from app.services.agent.scoped_assessment.browser_actions import allowed_discovery_path

        cell = next((row for row in brain.coverage_cells
                     if row.get("id") == coverage_cell_id), None)
        _claim, methods = _CELL_RULES[cell_test_type]
        if (not cell or cell.get("status") != "leased"
                or cell.get("lease_id") != coverage_lease_id
                or float(cell.get("lease_deadline") or 0) <= time.time()
                or cell.get("source") != "surface_applicability"
                or cell.get("test_type") != cell_test_type
                or str(cell.get("method") or "GET").upper() not in methods
                or not allowed_discovery_path(str(cell.get("path") or "/"))):
            return None, {"success": False, "error": "invalid_coverage_lease",
                          "reason": _lease_failure_reason(cell, coverage_lease_id)}
        return cell, None

    def _class_cell_for_candidate(self, cand: Any, cell_test_type: str) -> Optional[dict]:
        """The candidate's own coverage cell (any status) for verifier re-checks."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        _claim, methods = _CELL_RULES[cell_test_type]
        return next((row for row in brain.coverage_cells
                     if row.get("id") == cand.coverage_cell_id
                     and row.get("source") == "surface_applicability"
                     and row.get("test_type") == cell_test_type
                     and str(row.get("method") or "GET").upper() in methods
                     and row.get("path") == (urlsplit(cand.target).path or "/")), None)

    def _class_record(self, summary: dict, *, url: str, identity: str, test_type: str,
                      coverage_cell_id: str = "", capture_id: str = "") -> str:
        from app.services.agent.evidence_store import evidence_store

        return evidence_store(self).record(
            "scoped_class_probe", summary, target=url, identity=identity,
            coverage_cell_id=coverage_cell_id, test_type=test_type, capture_id=capture_id,
            success=bool(summary.get("proof_confirmed")),
        )

    def _class_settle(self, brain, cell: dict, artifact_id: str, confirmed: bool,
                      probe: str, reason: str) -> None:
        cell["evidence_ids"] = list(dict.fromkeys([
            *(cell.get("evidence_ids") or []), artifact_id,
        ]))[:30]
        cell["last_probe"] = probe
        if confirmed:
            cell["status"] = "in_focus"
            cell["reason"] = reason
        self._engagement_brain = brain.to_dict()

    def _class_approved_post(self, path: str, *, login: bool = False) -> bool:
        approved = set(getattr(self, "_scoped_body_replay_paths", None) or set())
        if login and getattr(self, "_scoped_auth_login_path", ""):
            approved.add(self._scoped_auth_login_path)
        return path in approved

    def _class_capture(self, capture_id: str, identity: str, path: str) -> Tuple[dict, bytes]:
        """The cell's browser-observed POST JSON capture (hunter-owned in a verifier run)."""
        from app.services.agent.evidence_store import evidence_store, verification_run

        record = evidence_store(self).records.get(capture_id) if capture_id else None
        row = self._scoped_capture_row(capture_id) if capture_id else None
        run = verification_run.get()
        owner = row.get("verifier_run_id") if row else None
        if (not record or record.get("kind") != "scoped_browser_exchange" or not row
                or row.get("identity") != identity
                or owner not in ({None, run.id} if run else {None})):
            raise ValueError("A browser-observed capture for this identity is required")
        private = row["private"]
        captured = json.loads(private)
        url = str(captured.get("url") or "")
        mime = str(captured.get("request_content_type") or "")
        if (captured.get("method") != "POST" or (urlsplit(url).path or "/") != path
                or not (mime == "application/json" or mime.endswith("+json"))):
            raise ValueError("The capture must be a JSON POST to this endpoint")
        import base64

        document = json.loads(base64.b64decode(captured.get("request_body_base64") or "",
                                               validate=True) or b"null")
        return document, private

    def _class_find_capture(self, identity: str, path: str) -> Tuple[dict, bytes]:
        """The newest browser-observed JSON POST capture of ``path`` for ``identity``."""
        for capture_id in reversed(list(self._scoped_capture_ids())):
            try:
                return self._class_capture(capture_id, identity, path)
            except (ValueError, TypeError, KeyError):
                continue
        raise ValueError("No browser-observed JSON POST capture of the write_path for this identity")

    def _class_claim_timing(self, count: int) -> None:
        """Dedicated bounded budget for timing samples (hunter and verifier)."""
        from app.services.agent.evidence_store import verification_run

        verifier = verification_run.get() is not None
        counter = "_class_timing_verifier_post_count" if verifier else "_class_timing_post_count"
        used = int(getattr(self, counter, 0) or 0)
        if used + count > TIMING_POST_BUDGET:
            raise ValueError("Timing enumeration request budget exhausted for this session")
        setattr(self, counter, used + count)

    def _class_oob(self) -> Tuple[Any, Any, Any]:
        """Collector callables (provider chosen by operator settings only)."""
        from app.services import oob_collectors

        if not getattr(self, "_oob_callbacks_allowed", False):
            raise PermissionError("out-of-band callbacks are not authorized for this run")
        return (lambda: oob_collectors.oob_register(),
                lambda session_id: oob_collectors.oob_poll(session_id),
                lambda session_id: oob_collectors.oob_stop(session_id))

    def _class_observed_urls(self, identity: str) -> List[str]:
        cmap = getattr(self, "_capability_map", None) or {}
        urls = [*(cmap.get("pages_visited") or [])]
        urls += [row.get("url") for row in (cmap.get("discovered_links") or [])
                 if isinstance(row, dict)]
        urls += [row.get("url") for row in (cmap.get("api_samples") or [])
                 if isinstance(row, dict)
                 and str(row.get("method") or "GET").upper() == "GET"
                 and str(row.get("identity") or "anonymous") == identity]
        urls += list(((getattr(self, "_scoped_link_baselines", None) or {}).get(identity)) or [])
        return [u for u in urls if isinstance(u, str) and u]

    @staticmethod
    def _class_error(exc: Exception) -> dict:
        return {"success": False, "error": type(exc).__name__, "reason": str(exc)[:200]}

    # ------------------------------------------------------------ file upload

    async def _class_upload_run(self, url: str, identity: str, *, file_field: str,
                                served_url_template: str, cleanup_url_template: str) -> dict:
        from app.services.agent.scoped_assessment.class_probes import FILE_MARKER, probe_upload

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if not self._class_approved_post(path):
            raise PermissionError("upload path is not in body_replay_paths")
        if served_url_template:
            if (FILE_MARKER not in served_url_template
                    or self._scoped_origin(served_url_template.replace(FILE_MARKER, "x")) != allowed):
                raise ValueError("served_url_template must be same-origin and contain __PROWL_FILE__")
        if cleanup_url_template:
            cleanup = cleanup_url_template.replace(FILE_MARKER, "x")
            if (FILE_MARKER not in cleanup_url_template
                    or self._scoped_origin(cleanup) != allowed
                    or (urlsplit(cleanup).path or "/") not in
                    (getattr(self, "_scoped_stored_xss_cleanup_paths", None) or set())):
                raise PermissionError("cleanup path is not an approved stored_xss_cleanup_paths entry")
        self._scoped_claim_posts(4 if cleanup_url_template else 2)
        self._scoped_claim_gets(4)
        nonce = secrets.token_hex(8)
        return await asyncio.to_thread(
            probe_upload, url, file_field=file_field,
            served_url_template=served_url_template,
            cleanup_url_template=cleanup_url_template, allowed_origin=allowed,
            state=self._scoped_state(identity, url), nonce=nonce,
        )

    async def scoped_upload_probe_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, file_field: str = "file",
        served_url_template: str = "", cleanup_url_template: str = "", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Upload a benign nonce HTML/SVG canary and fetch it back from the target origin."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id,
                                              "file_upload")
        if error:
            return error
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            identity = str(cell.get("identity") or "anonymous")
            proof = await self._class_upload_run(
                url, identity, file_field=str(file_field or "file"),
                served_url_template=str(served_url_template or ""),
                cleanup_url_template=str(cleanup_url_template or ""))
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        proof.update(served_url_template=served_url_template,
                     cleanup_url_template=cleanup_url_template)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="file_upload", coverage_cell_id=coverage_cell_id)
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_upload_probe",
                           "Same-origin active upload requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "served": proof["served"],
                "leftovers": proof["leftovers"], "cleanup": proof["cleanup"],
                "requests_sent": proof["requests_sent"]}

    # ------------------------------------------------------------ account enumeration

    def _class_enum_template(self, url: str, identity: str) -> Tuple[str, dict, str]:
        """(body kind, fields, artifact id) of the operator's own captured login request."""
        from app.services.agent.evidence_store import evidence_store, origin
        from app.services.agent.scoped_assessment.class_probes import enum_template

        store = evidence_store(self)
        target = urlsplit(url)
        rows = []
        for artifact_id in list(store.records):
            record = store.records.get(artifact_id)
            payload = (record or {}).get("payload") if isinstance((record or {}).get("payload"), dict) else {}
            request = payload.get("request") if isinstance(payload.get("request"), dict) else {}
            try:
                same = (record.get("kind") == "http_exchange"
                        and payload.get("source") == "operator_capture"
                        and record.get("identity") == identity
                        and str(request.get("method") or "").upper() == "POST"
                        and origin(str(request.get("url") or "")) == origin(url)
                        and (urlsplit(str(request["url"])).path or "/") == (target.path or "/"))
            except ValueError:
                same = False
            if same:
                rows.append((record["created_at"], artifact_id, request))
        if not rows:
            raise ValueError("No operator-captured login/reset request for this identity")
        _created, artifact_id, request = max(rows, key=lambda row: row[0])
        headers = {str(k).lower(): str(v) for k, v in (request.get("headers") or {}).items()}
        kind, fields = enum_template(str(request.get("body") or ""),
                                     headers.get("content-type", ""))
        return kind, fields, artifact_id

    async def _class_enum_run(self, url: str, identity: str, username_field: str = "",
                              mode: str = "differential") -> dict:
        from app.services.agent.assessment_sessions import identity_registry
        from app.services.agent.scoped_assessment.class_probes import (
            REGISTRATION_PATH, TIMING_INTERVAL_S, TIMING_REQUESTS, enum_fields,
            probe_account_enum, probe_account_enum_timing,
        )

        if mode not in {"differential", "timing"}:
            raise ValueError("mode must be differential or timing")

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if REGISTRATION_PATH.search(path):
            raise ValueError("Registration endpoints would create accounts; use login or reset")
        if not self._class_approved_post(path, login=True):
            raise PermissionError("login/reset path is not in body_replay_paths or auth_login_path")
        if identity in {"", "anonymous", "legacy"}:
            raise ValueError("Name an operator-registered test identity")
        identity_registry(self).resolve(identity, url)
        kind, fields, template_id = self._class_enum_template(url, identity)
        user_field, password_field = enum_fields(fields, username_field)
        test_username = str(fields.get(user_field) or "")
        if mode == "timing":
            if password_field:
                raise ValueError("timing enumeration runs only on reset forms; a login would send "
                                 "repeated wrong-password attempts to the test account")
            if not getattr(self, "_timing_enumeration_allowed", False):
                raise PermissionError("timing enumeration needs the operator's "
                                      "timing_enumeration_allowed policy flag")
            self._class_claim_timing(TIMING_REQUESTS)
            proof = await asyncio.to_thread(
                probe_account_enum_timing, url, kind=kind, fields=fields,
                username_field=user_field, password_field=password_field,
                test_username=test_username, allowed_origin=allowed,
                nonce=secrets.token_hex(8),
                interval=float(getattr(self, "_class_timing_interval", TIMING_INTERVAL_S)),
            )
            proof["template_artifact_id"] = template_id
            return proof
        self._scoped_claim_posts(6)
        proof = await asyncio.to_thread(
            probe_account_enum, url, kind=kind, fields=fields, username_field=user_field,
            password_field=password_field, test_username=test_username,
            allowed_origin=allowed, nonce=secrets.token_hex(8),
        )
        proof["template_artifact_id"] = template_id
        return proof

    async def scoped_account_enum_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, identity: str,
        username_field: str = "", mode: str = "differential", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Compare an operator test account with random accounts on a login/reset POST."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "auth")
        if error:
            return error
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_enum_run(url, str(identity or ""), str(username_field or ""),
                                               str(mode or "differential"))
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="account_enumeration",
                                         coverage_cell_id=coverage_cell_id)
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_account_enum",
                           "Account enumeration differential requires independent verification")
        out = {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
               "proof_confirmed": proof["proof_confirmed"], "stopped": proof["stopped"],
               "mode": proof.get("mode", "differential"), "requests_sent": proof["requests_sent"]}
        if proof.get("mode") == "timing":
            out.update(timing_stable=proof["timing_stable"], runs=proof["runs"])
        else:
            out["differential"] = proof["differential"]
        return out

    # ------------------------------------------------------------ OAuth redirect_uri

    def _class_oauth_observed(self, url: str, identity: str) -> str:
        from app.services.agent.evidence_store import origin
        from app.services.agent.scoped_assessment.class_probes import oauth_observed_valid

        path = urlsplit(url).path or "/"
        for candidate in reversed(self._class_observed_urls(identity)):
            try:
                if (origin(candidate) == origin(url)
                        and (urlsplit(candidate).path or "/") == path):
                    oauth_observed_valid(candidate)
                    return candidate
            except ValueError:
                continue
        raise ValueError("No observed authorization request with client_id and response_type")

    async def _class_oauth_run(self, url: str, identity: str) -> dict:
        from app.services.agent.scoped_assessment.class_probes import probe_oauth_redirect

        allowed = self._scoped_origin(url)
        observed = self._class_oauth_observed(url, identity)
        self._scoped_claim_gets(3)
        return await asyncio.to_thread(
            probe_oauth_redirect, observed, allowed_origin=allowed,
            state=self._scoped_state(identity, url), nonce=secrets.token_hex(8),
        )

    async def scoped_oauth_redirect_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, identity: str = "", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Send an observed authorization request with a nonce prowl.invalid redirect_uri."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "oauth")
        if error:
            return error
        actor = str(identity or cell.get("identity") or "anonymous")
        if actor == "unspecified":
            actor = "anonymous"
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_oauth_run(url, actor)
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=actor, test_type="oauth",
                                         coverage_cell_id=coverage_cell_id)
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_oauth_redirect",
                           "Grant sent to a foreign redirect_uri requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "attempts": proof["attempts"],
                "requests_sent": proof["requests_sent"]}

    # ------------------------------------------------------------ CSWSH

    def _class_ws_frame(self, identity: str, url: str, sha: str = "") -> str:
        """First read-only client frame from the identity's own captured traffic on this socket."""
        from app.services.agent.evidence_store import origin
        from app.services.agent.scoped_assessment.class_probes import ws_frame_meta

        target = (origin(url), urlsplit(url).path or "/")
        for capture in (getattr(self, "_scoped_ws_client_frames", None) or {}).get(identity) or []:
            try:
                captured = str(capture.get("url") or "")
                if (origin(captured), urlsplit(captured).path or "/") != target:
                    continue
            except ValueError:
                continue
            for frame in capture.get("frames") or []:
                meta = ws_frame_meta(frame)
                if meta and (not sha or meta["sha256"] == sha):
                    return frame
        raise ValueError("No read-only client frame in this identity's captured WebSocket traffic")

    async def _class_cswsh_run(self, url: str, identity: str, subprotocol: str = "",
                               send_captured_frame: bool = False, frame_sha: str = "") -> dict:
        from app.services.agent.scoped_assessment.class_probes import probe_cswsh

        allowed = self._scoped_origin(url)
        if identity in {"", "anonymous", "legacy"}:
            raise ValueError("CSWSH proof needs a named authenticated identity")
        state = self._scoped_state(identity, url)
        if not (state or {}).get("cookies"):
            raise ValueError("CSWSH needs an identity with ambient cookies for this origin")
        if subprotocol and (len(subprotocol) > 64 or not all(
                c.isalnum() or c in "-_.," for c in subprotocol)):
            raise ValueError("Invalid subprotocol")
        other_state = None
        from app.services.agent.assessment_sessions import identity_registry

        for name in sorted(identity_registry(self).identities):
            if name == identity:
                continue
            try:
                candidate = self._scoped_state(name, url)
            except ValueError:
                continue
            if (candidate or {}).get("cookies"):
                other_state = candidate
                break
        frame = (self._class_ws_frame(identity, url, frame_sha)
                 if send_captured_frame or frame_sha else "")
        self._scoped_claim_gets(4 if other_state else 3)
        return await asyncio.to_thread(
            probe_cswsh, url, allowed_origin=allowed, identity_state=state,
            nonce=secrets.token_hex(8), subprotocol=subprotocol, other_state=other_state,
            client_frame=frame,
        )

    async def scoped_cswsh_probe(self, url: str, identity: str, subprotocol: str = "",
                                 send_captured_frame: bool = False,
                                 **_kwargs: Any) -> Dict[str, Any]:
        """CSWSH proof extending probe_websocket_origin with an identity-specific read."""
        from app.services.agent.ported_probes import ws_http_url

        try:
            raw = str(url or "").strip()
            target = ws_http_url(raw if "://" in raw else f"https://{raw}")
            parts = urlsplit(target)
            target = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
            proof = await self._class_cswsh_run(target, str(identity or ""), str(subprotocol or ""),
                                                send_captured_frame=bool(send_captured_frame))
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        proof["subprotocol"] = str(subprotocol or "")
        artifact_id = self._class_record(proof, url=target, identity=identity, test_type="cswsh")
        return {"success": True, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "sessions": proof["sessions"],
                "identity_values": len(proof["identity_value_digests"]),
                "client_frame_verb": (proof.get("client_frame") or {}).get("verb", ""),
                "requests_sent": proof["requests_sent"]}

    # ------------------------------------------------------------ server-side prototype pollution

    async def _class_pp_run(self, url: str, identity: str, capture_id: str, readback_url: str,
                            exclude: Optional[int] = None, gadget: str = "json_spaces") -> dict:
        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.class_probes import (
            pp_spaces, pp_status_code, probe_pp_json_spaces, probe_pp_status,
        )

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if not self._class_approved_post(path):
            raise PermissionError("JSON POST path is not in body_replay_paths")
        if gadget == "status_code":
            parts = urlsplit(readback_url)
            if (self._scoped_origin(readback_url) != allowed or parts.query or parts.fragment
                    or readback_url != allowed + (parts.path or "/")):
                raise ValueError("readback_url must be an exact same-origin URL without query")
            if not self._class_approved_post(parts.path or "/"):
                raise PermissionError("status-gadget error readback path is not in body_replay_paths")
            document, private = self._class_capture(capture_id, identity, path)
            if not isinstance(document, dict) or not document:
                raise ValueError("The captured body must be a JSON object")
            self._scoped_claim_posts(7)
            return await asyncio.to_thread(
                probe_pp_status, url, document=document, error_url=readback_url,
                allowed_origin=allowed, state=self._scoped_state(identity, url),
                nonce=secrets.token_hex(8), code=pp_status_code([exclude]),
                headers=body_probe.safe_replay_headers(private),
            )
        if gadget != "json_spaces":
            raise ValueError("gadget must be json_spaces or status_code")
        if (self._scoped_origin(readback_url) != allowed
                or readback_url not in self._class_observed_urls(identity)
                and readback_url not in self._class_observed_urls("anonymous")):
            raise ValueError("readback_url must be an observed same-origin GET")
        document, private = self._class_capture(capture_id, identity, path)
        if not isinstance(document, dict) or not document:
            raise ValueError("The captured body must be a JSON object")
        self._scoped_claim_posts(3)
        self._scoped_claim_gets(4)
        return await asyncio.to_thread(
            probe_pp_json_spaces, url, document=document, readback_url=readback_url,
            allowed_origin=allowed, state=self._scoped_state(identity, url),
            nonce=secrets.token_hex(8), spaces=pp_spaces([exclude]),
            headers=body_probe.safe_replay_headers(private),
        )

    async def scoped_server_pp_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, readback_url: str,
        gadget: str = "json_spaces", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """JSON-spaces or status-code pollution gadget with control and reset (one marker
        per endpoint per run, whichever gadget)."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        gadget = str(gadget or "json_spaces")
        done = getattr(self, "_class_pp_paths", None)
        if done is None:
            done = self._class_pp_paths = set()
        known = next((row for row in brain.coverage_cells if row.get("id") == coverage_cell_id), None)
        if known and known.get("path") in done:
            return {"success": False, "error": "already_probed",
                    "reason": "One bounded pollution marker per endpoint per run"}
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id,
                                              "prototype_pollution")
        if error:
            return error
        identity = str(cell.get("identity") or "anonymous")
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_pp_run(url, identity, str(cell.get("capture_id") or ""),
                                             str(readback_url or ""), gadget=gadget)
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        done.add(cell["path"])
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="server_prototype_pollution",
                                         coverage_cell_id=coverage_cell_id,
                                         capture_id=str(cell.get("capture_id") or ""))
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_server_pp",
                           "Prototype pollution gadget requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "gadget": proof["gadget"],
                "steps": proof["steps"], "reset_restored": proof["reset_restored"],
                "persistence_note": proof["persistence_note"]}

    # ------------------------------------------------------------ LLM canary

    async def _class_llm_run(self, url: str, identity: str, capture_id: str, field: str) -> dict:
        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.class_probes import (
            detect_message_field, probe_llm_canary,
        )

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if not self._class_approved_post(path):
            raise PermissionError("chat POST path is not in body_replay_paths")
        document, private = self._class_capture(capture_id, identity, path)
        field = field or detect_message_field(document)
        self._scoped_claim_posts(2)
        return await asyncio.to_thread(
            probe_llm_canary, url, document=document, field=field, allowed_origin=allowed,
            state=self._scoped_state(identity, url), nonce=secrets.token_hex(8),
            headers=body_probe.safe_replay_headers(private),
        )

    async def scoped_llm_canary_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, field: str = "", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Embedded-instruction canary on an observed chat/AI JSON POST."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "llm_ai")
        if error:
            return error
        identity = str(cell.get("identity") or "anonymous")
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_llm_run(url, identity, str(cell.get("capture_id") or ""),
                                              str(field or ""))
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="prompt_injection",
                                         coverage_cell_id=coverage_cell_id,
                                         capture_id=str(cell.get("capture_id") or ""))
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_llm_canary",
                           "Prompt-injection canary requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "control": proof["control"],
                "probe": proof["probe"], "field": proof["field"]}

    # ------------------------------------------------------------ LLM out-of-band fetch

    async def _class_llm_oob_run(self, url: str, identity: str, capture_id: str, field: str) -> dict:
        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.class_probes import (
            OOB_POLL_SLEEP_S, detect_message_field, probe_llm_oob,
        )

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if not self._class_approved_post(path):
            raise PermissionError("chat POST path is not in body_replay_paths")
        register, poll, stop = self._class_oob()
        document, private = self._class_capture(capture_id, identity, path)
        field = field or detect_message_field(document)
        self._scoped_claim_posts(2)
        return await asyncio.to_thread(
            probe_llm_oob, url, document=document, field=field, allowed_origin=allowed,
            state=self._scoped_state(identity, url), nonce=secrets.token_hex(8),
            register=register, poll=poll, stop=stop,
            headers=body_probe.safe_replay_headers(private),
            pause=float(getattr(self, "_class_oob_pause", OOB_POLL_SLEEP_S)),
        )

    async def scoped_llm_oob_fetch_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, field: str = "", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Embedded instruction to fetch a fresh collector host; proof is the correlated callback."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "llm_ai")
        if error:
            return error
        identity = str(cell.get("identity") or "anonymous")
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_llm_oob_run(url, identity, str(cell.get("capture_id") or ""),
                                                  str(field or ""))
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="prompt_injection",
                                         coverage_cell_id=coverage_cell_id,
                                         capture_id=str(cell.get("capture_id") or ""))
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_llm_oob_fetch",
                           "Prompt-injection outbound fetch requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "control": proof["control"],
                "probe": proof["probe"], "field": proof["field"], "claim": proof["claim"]}

    # ------------------------------------------------------------ indirect LLM injection

    def _class_llm_indirect_plan(self, allowed: str, identity: str, entry: dict,
                                 state: Optional[dict], cell_id: str, nonce: str,
                                 cleanup_url_template: str) -> Tuple[str, Any, Any]:
        """(write mode, plant, cleanup) for one approved llm_indirect_fields entry."""
        from app.services.agent.scoped_assessment import body_probe, intent_request
        from app.services.agent.scoped_assessment.class_probes import (
            http_request, own_record_body, set_path,
        )
        from app.services.agent.scoped_assessment.test_records import (
            NONCE, OwnRecordWriter, TestRecordAborted,
        )

        write_path, field = entry["write_path"], entry["field"]
        if "{id}" in write_path:
            endpoint = next((row for row in self._scoped_test_record_endpoints or []
                             if row["record_path"] == write_path), None)
            if not endpoint:
                raise PermissionError("write_path is not an approved test_record_endpoints record_path")
            method = "PUT" if "PUT" in endpoint["write_methods"] else "PATCH"
            if method not in endpoint["write_methods"]:
                raise PermissionError("the test record endpoint allows neither PUT nor PATCH")
            content_type = ("application/json" if endpoint["content_type"] == "json"
                            else "application/x-www-form-urlencoded")
            writers: Dict[str, Any] = {}
            sent = {"n": 0}

            def counted(req, *, allowed_origin):
                sent["n"] += 1
                return intent_request._open(req, allowed_origin=allowed_origin)

            def plant(label: str, text: str) -> dict:
                before = sent["n"]
                writer = OwnRecordWriter(self, endpoint, method=method, identity=identity,
                                         state=state, scoped_origin=allowed,
                                         coverage_cell_id=cell_id, send=counted)
                writers[label] = writer
                try:
                    row = writer._create()
                except TestRecordAborted:
                    created = any(row.get("state") != "create_failed" for row in writer.records)
                    return {"ok": False, "created": created, "status": None,
                            "requests": sent["n"] - before}
                body = own_record_body(endpoint, writer.nonce, field, text)
                status, _location, _data = writer._request(method, row["path"], body, content_type)
                return {"ok": 200 <= status < 300, "created": True, "status": status,
                        "requests": sent["n"] - before}

            def cleanup(label: str, _planted: dict) -> dict:
                writer = writers.get(label)
                before = sent["n"]
                if writer is None:
                    return {"success": True, "requests": 0}
                writer.finish()
                pending = [row for row in writer.records
                           if row.get("state") in {"active", "cleanup_pending"}]
                return {"success": not pending, "requests": sent["n"] - before,
                        "leftover": "; ".join(f"{row.get('path') or row.get('create_path')} "
                                              f"({row.get('reason') or 'not removed'})"
                                              for row in pending)}

            return "own_record", plant, cleanup
        document, private = self._class_find_capture(identity, write_path)
        set_path(document, field, "x")  # the approved field must be text in the capture
        headers = {**body_probe.safe_replay_headers(private), "Content-Type": "application/json"}
        if cleanup_url_template:
            probe_url = cleanup_url_template.replace(NONCE, "x")
            if (NONCE not in cleanup_url_template or self._scoped_origin(probe_url) != allowed
                    or (urlsplit(probe_url).path or "/") not in
                    (getattr(self, "_scoped_stored_xss_cleanup_paths", None) or set())):
                raise PermissionError("cleanup path is not an approved stored_xss_cleanup_paths "
                                      "entry with __PROWL_NONCE__")

        def plant(label: str, text: str) -> dict:
            body = json.dumps(set_path(document, field, text)).encode()
            response = http_request("POST", allowed + write_path, allowed_origin=allowed,
                                    state=state, headers=headers, body=body)
            ok = 200 <= int(response.get("status") or 0) < 300
            return {"ok": ok, "created": ok, "status": response.get("status"), "requests": 1}

        def cleanup(label: str, _planted: dict) -> dict:
            from app.services.agent.scoped_assessment.class_probes import llm_note_marker

            marker = llm_note_marker(nonce, label)
            leftover = f"{write_path} document carrying {marker}"
            if not cleanup_url_template:
                return {"success": False, "requests": 0, "leftover": leftover}
            try:
                response = http_request("DELETE", cleanup_url_template.replace(NONCE, marker),
                                        allowed_origin=allowed, state=state)
            except (ValueError, OSError):
                return {"success": False, "requests": 1, "leftover": leftover}
            return {"success": 200 <= int(response.get("status") or 0) < 300, "requests": 1,
                    "leftover": leftover}

        return "post", plant, cleanup

    async def _class_llm_indirect_run(self, url: str, identity: str, capture_id: str,
                                      write_path: str, cleanup_url_template: str = "",
                                      oob: bool = False, cell_id: str = "") -> dict:
        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.class_probes import (
            OOB_POLL_SLEEP_S, http_request, llm_token, probe_llm_indirect,
        )

        allowed = self._scoped_origin(url)
        read_path = urlsplit(url).path or "/"
        entry = next((row for row in getattr(self, "_scoped_llm_indirect_fields", None) or []
                      if row["write_path"] == write_path and row["read_path"] == read_path), None)
        if not entry:
            raise PermissionError("write_path/read_path is not an approved llm_indirect_fields entry")
        register = poll = stop = None
        if oob:
            register, poll, stop = self._class_oob()
        chat_document, chat_private = self._class_capture(capture_id, identity, read_path)
        chat_body = json.dumps(chat_document).encode()
        chat_headers = {**body_probe.safe_replay_headers(chat_private),
                        "Content-Type": "application/json"}
        state = self._scoped_state(identity, url)
        nonce = secrets.token_hex(8)
        if llm_token(nonce).encode() in chat_body.lower():
            raise ValueError("The chat request must not contain the assembled token")
        mode, plant, cleanup = self._class_llm_indirect_plan(
            allowed, identity, entry, state, cell_id, nonce, cleanup_url_template)
        # Chat asks; POST-mode document writes and cleanups (own-record writes
        # are charged by OwnRecordWriter as they are sent).
        self._scoped_claim_posts(2 + (0 if mode == "own_record" else
                                      2 + (2 if cleanup_url_template else 0)))

        def ask() -> dict:
            return http_request("POST", url, allowed_origin=allowed, state=state,
                                headers=chat_headers, body=chat_body, timeout=60)

        proof = await asyncio.to_thread(
            probe_llm_indirect, nonce=nonce,
            instruction="oob_fetch" if oob else "canary_word",
            plant=plant, ask=ask, cleanup=cleanup, write_path=write_path,
            field=entry["field"], read_path=read_path, write_mode=mode,
            register=register, poll=poll, stop=stop,
            pause=float(getattr(self, "_class_oob_pause", OOB_POLL_SLEEP_S)),
        )
        proof["cleanup_url_template"] = cleanup_url_template
        return proof

    async def scoped_llm_indirect_canary_assigned(
        self, coverage_cell_id: str, coverage_lease_id: str, write_path: str,
        cleanup_url_template: str = "", oob: bool = False, **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Plant a split-word (or fetch) instruction in one approved document field and read
        the model's answer on the leased chat cell."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "llm_ai")
        if error:
            return error
        identity = str(cell.get("identity") or "anonymous")
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_llm_indirect_run(
                url, identity, str(cell.get("capture_id") or ""), str(write_path or ""),
                str(cleanup_url_template or ""), bool(oob), coverage_cell_id)
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="prompt_injection",
                                         coverage_cell_id=coverage_cell_id,
                                         capture_id=str(cell.get("capture_id") or ""))
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"],
                           "scoped_llm_indirect_canary",
                           "Indirect prompt-injection canary requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "instruction": proof["instruction"],
                "write_mode": proof["write_mode"], "control": proof["control"],
                "probe": proof["probe"], "plants": proof["plants"],
                "leftovers": proof["leftovers"], "requests_sent": proof["requests_sent"]}

    # ------------------------------------------------------------ verifier replay

    async def replay_class_probe(self, cand: Any, hunter: dict) -> str:
        """Fresh-nonce replay of a hunter class receipt; returns the new artifact id.

        Runs the same approval, scope and budget checks as the hunter tool and
        derives the request inputs from the candidate's cell, not from the
        hunter's claims. Must run inside a verification run.
        """
        from app.services.agent.evidence_store import verification_run

        if verification_run.get() is None:
            raise ValueError("Class replay runs only inside a verification run")
        payload = hunter.get("payload") or {}
        test_type = payload.get("test_type")
        identity = str(hunter.get("identity") or "anonymous")
        url = str(cand.target)
        cell_id = ""
        capture_id = ""
        if test_type == "cswsh":
            proof = await self._class_cswsh_run(
                url, identity, str(payload.get("subprotocol") or ""),
                frame_sha=str(payload.get("client_frame_sha256") or ""))
            proof["subprotocol"] = str(payload.get("subprotocol") or "")
        else:
            cell_type = {"file_upload": "file_upload", "account_enumeration": "auth",
                         "oauth": "oauth", "server_prototype_pollution": "prototype_pollution",
                         "prompt_injection": "llm_ai"}.get(test_type)
            cell = self._class_cell_for_candidate(cand, cell_type) if cell_type else None
            if not cell:
                raise ValueError("The candidate's coverage cell is required")
            cell_id = cell["id"]
            if url != self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]:
                raise ValueError("Candidate target is not the cell endpoint")
            if test_type == "file_upload":
                proof = await self._class_upload_run(
                    url, identity, file_field=str(payload.get("file_field") or "file"),
                    served_url_template=str(payload.get("served_url_template") or ""),
                    cleanup_url_template=str(payload.get("cleanup_url_template") or ""))
                proof.update(served_url_template=payload.get("served_url_template") or "",
                             cleanup_url_template=payload.get("cleanup_url_template") or "")
            elif test_type == "account_enumeration":
                proof = await self._class_enum_run(url, identity,
                                                   str(payload.get("username_field") or ""),
                                                   str(payload.get("mode") or "differential"))
            elif test_type == "oauth":
                proof = await self._class_oauth_run(url, identity)
            elif test_type == "server_prototype_pollution":
                capture_id = str(cell.get("capture_id") or "")
                gadget = str(payload.get("gadget") or "json_spaces")
                proof = await self._class_pp_run(
                    url, identity, capture_id, str(payload.get("readback_url") or ""),
                    exclude=payload.get("code" if gadget == "status_code" else "spaces"),
                    gadget=gadget)
            else:
                capture_id = str(cell.get("capture_id") or "")
                instruction = str(payload.get("instruction") or "canary_word")
                if payload.get("channel") == "indirect_document":
                    proof = await self._class_llm_indirect_run(
                        url, identity, capture_id, str(payload.get("write_path") or ""),
                        str(payload.get("cleanup_url_template") or ""),
                        oob=instruction == "oob_fetch", cell_id=cell_id)
                elif instruction == "oob_fetch":
                    proof = await self._class_llm_oob_run(url, identity, capture_id,
                                                          str(payload.get("field") or ""))
                else:
                    proof = await self._class_llm_run(url, identity, capture_id,
                                                      str(payload.get("field") or ""))
        return self._class_record(proof, url=url, identity=identity, test_type=str(test_type),
                                  coverage_cell_id=cell_id, capture_id=capture_id)





CLASS_PROOF_SECTION = "Class Proof Probes (receipt-backed; the verifier repeats them)"
TOOL_SECTION_NOTES = {
    CLASS_PROOF_SECTION: (
        "Each records a scoped_class_probe receipt. proof_confirmed=true is a candidate: submit "
        "it with submit_finding_candidate(vulnerability_class=<class>, evidence_ids=[evidence_id]); "
        "the independent verifier repeats the plan with a fresh nonce. POSTs need the operator's "
        "body_replay_paths (enumeration also accepts auth_login_path; indirect LLM writes and "
        "chat asks need an llm_indirect_fields entry); cleanup DELETE only on "
        "stored_xss_cleanup_paths or Prowl-owned test records. Out-of-band variants need "
        "oob_callbacks_allowed. Bounded request counts; nothing here follows redirects. "
    ),
}

TOOL_SPECS = (
    write_tool(
        "scoped_upload_probe_assigned",
        (
            "file_upload proof on one leased file_upload POST cell. Args: coverage_cell_id, "
            "coverage_lease_id, file_field (multipart field, default file), served_url_template "
            "(optional same-origin URL with __PROWL_FILE__ when the response does not name the "
            "stored file), cleanup_url_template (optional, __PROWL_FILE__, path must be in "
            "stored_xss_cleanup_paths). Uploads a benign script-free HTML, then SVG, carrying "
            "prowl-upload-<nonce>, and fetches it back. Confirms only when the target's own origin "
            "serves the marker with 200 and an active type (text/html, image/svg+xml, JavaScript), "
            "no attachment disposition and no CSP sandbox. Reports leftovers it could not clean up. "
            "vulnerability_class=file_upload; script execution in a browser is upload_xss under xss."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_account_enum_assigned",
        (
            "account_enumeration proof on one leased auth POST cell (login or reset; never "
            "registration). Args: coverage_cell_id, coverage_lease_id, identity (an operator-"
            "registered test identity whose own login/reset request the operator captured), "
            "username_field (optional), mode (differential|timing, default differential). The "
            "test account name comes only from that operator capture, never from a guess; other "
            "accounts are fresh random nonexistent names. differential: 6 POSTs (test account and "
            "two random accounts, twice, one wrong nonce password); confirms only a stable "
            "normalized difference (status, redirect path, body with nonces/timestamps/CSRF "
            "values removed). timing: for identical responses; 40 paced POSTs (two runs of 10 "
            "test-account and 10 fresh random-account samples, interleaved ABBA); confirms only "
            "when each run passes the 10-sample 2-sigma rule with effect size >= 2.5 and a median "
            "gap >= 25 ms, in the same direction both runs. Timing mode runs only on a reset form "
            "(never a login) and only with the operator's timing_enumeration_allowed policy flag. "
            "Both modes stop on 429 or lockout text."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_oauth_redirect_assigned",
        (
            "OAuth redirect_uri proof on one leased oauth GET cell. Args: coverage_cell_id, "
            "coverage_lease_id, identity (optional; a logged-in identity is usually needed for a "
            "grant). Replays an observed authorization request (client_id, response_type) with "
            "redirect_uri set to https://<nonce>.prowl.invalid/cb, then suffix-host and userinfo "
            "variants of the registered URI (max 3 GETs, no redirects followed). Confirms only "
            "when a 3xx Location (or a page link) to that host carries code, access_token or "
            "id_token. Grant values are never recorded. vulnerability_class=oauth."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_cswsh_probe",
        (
            "CSWSH proof extending probe_websocket_origin. Args: **url** (ws, wss, http or https), "
            "**identity** (named, with session cookies), subprotocol, send_captured_frame (default "
            "false). Three handshakes: identity + same Origin, identity + foreign "
            "https://<nonce>.cswsh.prowl.invalid, anonymous + foreign Origin (plus a second "
            "identity when registered). Reads up to 4 server-pushed text frames for 3 s each. "
            "send_captured_frame=true, for sockets that push only after a client message: sends "
            "exactly one text frame per session, copied from this identity's own operator-captured "
            "WebSocket traffic and only if read-only (subscribe/hello/init/join/listen/ping/get/"
            "list/query style verb; refused if its verb or keys name a write, send, message or "
            "auth action, or it carries a token, session, password, JWT, long secret or GraphQL "
            "mutation). Never invents a frame. Confirms only when the foreign-Origin identity "
            "handshake gets 101 with a valid accept key and a value the same-origin identity "
            "session also gets and an accepted comparison session (anonymous, or a second "
            "registered identity) does not; values are stored as digests. "
            "vulnerability_class=cswsh."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_server_pp_assigned",
        (
            "Server-side prototype pollution proof extending probe_server_prototype_pollution, on "
            "one leased prototype_pollution JSON POST cell with a browser capture. Args: "
            "coverage_cell_id, coverage_lease_id, **readback_url**, gadget (json_spaces|"
            "status_code, default json_spaces). json_spaces: readback_url is an observed "
            "same-origin JSON GET on another path; GET control, POST the captured body plus a "
            "plain \"json spaces\" property (control), GET, POST with __proto__.\"json spaces\"=n "
            "(3-9), GET, POST reset to 0, GET; confirms only when the unrelated response's "
            "indentation becomes exactly n after the gadget and not after the control. "
            "status_code: readback_url is another body_replay_paths URL that gets a malformed "
            "JSON body (never parsed, so no handler runs); 7 POSTs: error control, nested plain "
            "control, error, __proto__.status=c (541-589), error, reset __proto__.status=0, "
            "error; confirms only when the unrelated error status becomes exactly c after the "
            "gadget, not after the control, and returns to the control status after the reset. "
            "One marker per endpoint per run, whichever gadget; a vulnerable process keeps the property "
            "until restart (the reset only restores behavior). "
            "vulnerability_class=server_prototype_pollution."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_llm_canary_assigned",
        (
            "Prompt-injection canary on one leased llm_ai JSON POST cell with a browser capture. "
            "Args: coverage_cell_id, coverage_lease_id, field (dotted path of the message text, "
            "e.g. message or messages.-1.content; detected when omitted). Two POSTs: a control "
            "with a benign note, then the same note carrying an embedded instruction to output a "
            "word joined from three parts. Confirms only when the joined word (absent from the "
            "input) is in the probe output and not the control. This shows the model obeys "
            "instructions inside data; impact (exfiltration, tool abuse) needs its own proof. "
            "vulnerability_class=prompt_injection."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_llm_oob_fetch_assigned",
        (
            "Prompt-injection outbound-fetch proof on one leased llm_ai JSON POST cell with a "
            "browser capture; needs oob_callbacks_allowed. Args: coverage_cell_id, "
            "coverage_lease_id, field (as scoped_llm_canary_assigned). Registers two fresh "
            "collector hosts; a control note names one as inert data, the probe note instructs "
            "the model to open https://<nonce>.<probe collector>/. Two POSTs. Confirms only on a "
            "correlated HTTP callback for the probe host and no callback at all for the control "
            "host. Shows the model follows instructions in data and can reach out; it is not "
            "data exfiltration. vulnerability_class=prompt_injection."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_llm_indirect_canary_assigned",
        (
            "Indirect prompt-injection proof: the leased llm_ai cell is the chat path where the "
            "model's answer is read (its captured request is replayed unchanged), and **write_path** "
            "names an operator llm_indirect_fields entry {write_path, field, read_path} for this "
            "chat path. Args: coverage_cell_id, coverage_lease_id, write_path, "
            "cleanup_url_template (optional, POST write_path only: same-origin, __PROWL_NONCE__ "
            "is replaced by the planted note marker, path must be in stored_xss_cleanup_paths), "
            "oob (default false; needs oob_callbacks_allowed). A write_path without {id} gets one "
            "POST of this identity's captured JSON body with the approved field replaced; a "
            "record_path with {id} writes only a Prowl-owned test record (create, ownership "
            "readback, PUT/PATCH, cleanup). Plants a control note, asks, cleans up; then the probe "
            "note with the split-word instruction (or, with oob, a fetch instruction for a fresh "
            "collector host), asks, cleans up. Confirms as scoped_llm_canary_assigned (or "
            "scoped_llm_oob_fetch_assigned). Reports documents it could not remove under "
            "leftovers. vulnerability_class=prompt_injection."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
)
