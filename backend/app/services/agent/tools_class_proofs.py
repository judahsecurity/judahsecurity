"""Leased, receipt-backed proofs for classes that used to be lead-only.

Mixin for ASMToolsManager; declared with tool specs (tool_specs.py). Request
plans and verdicts live in ``scoped_assessment/class_probes.py``. Every tool
here checks the lease (where the class has coverage cells), the assessment
scope, operator approvals for any POST/DELETE, and the scoped request budget,
then records one ``scoped_class_probe`` receipt. A positive receipt is a
candidate, never a finding: the independent verifier repeats the same plan
with a fresh nonce (``replay_class_probe``) before publication.

Approvals reused (no new method approvals):
- POST upload, JSON gadget and LLM requests: ``body_replay_paths``.
- Login/reset enumeration POST: ``body_replay_paths`` or ``auth_login_path``.
- Upload cleanup DELETE: only an operator ``stored_xss_cleanup_paths`` entry.
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

    async def _class_enum_run(self, url: str, identity: str, username_field: str = "") -> dict:
        from app.services.agent.assessment_sessions import identity_registry
        from app.services.agent.scoped_assessment.class_probes import (
            REGISTRATION_PATH, enum_fields, probe_account_enum,
        )

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
        username_field: str = "", **_kwargs: Any,
    ) -> Dict[str, Any]:
        """Compare an operator test account with two random accounts on a login/reset POST."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
        cell, error = self._class_leased_cell(brain, coverage_cell_id, coverage_lease_id, "auth")
        if error:
            return error
        try:
            url = self._class_scoped_origin(str(cell.get("host") or "")) + cell["path"]
            proof = await self._class_enum_run(url, str(identity or ""), str(username_field or ""))
        except PermissionError as exc:
            return {"success": False, "error": "operator_approval_required", "reason": str(exc)}
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        artifact_id = self._class_record(proof, url=url, identity=identity,
                                         test_type="account_enumeration",
                                         coverage_cell_id=coverage_cell_id)
        self._class_settle(brain, cell, artifact_id, proof["proof_confirmed"], "scoped_account_enum",
                           "Account enumeration differential requires independent verification")
        return {"success": True, "coverage_cell_id": coverage_cell_id, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "stopped": proof["stopped"],
                "differential": proof["differential"], "requests_sent": proof["requests_sent"]}

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

    async def _class_cswsh_run(self, url: str, identity: str, subprotocol: str = "") -> dict:
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
        self._scoped_claim_gets(4 if other_state else 3)
        return await asyncio.to_thread(
            probe_cswsh, url, allowed_origin=allowed, identity_state=state,
            nonce=secrets.token_hex(8), subprotocol=subprotocol, other_state=other_state,
        )

    async def scoped_cswsh_probe(self, url: str, identity: str, subprotocol: str = "",
                                 **_kwargs: Any) -> Dict[str, Any]:
        """CSWSH proof extending probe_websocket_origin with an identity-specific read."""
        from app.services.agent.ported_probes import ws_http_url

        try:
            raw = str(url or "").strip()
            target = ws_http_url(raw if "://" in raw else f"https://{raw}")
            parts = urlsplit(target)
            target = f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"
            proof = await self._class_cswsh_run(target, str(identity or ""), str(subprotocol or ""))
        except (ValueError, OSError) as exc:
            return self._class_error(exc)
        proof["subprotocol"] = str(subprotocol or "")
        artifact_id = self._class_record(proof, url=target, identity=identity, test_type="cswsh")
        return {"success": True, "evidence_id": artifact_id,
                "proof_confirmed": proof["proof_confirmed"], "sessions": proof["sessions"],
                "identity_values": len(proof["identity_value_digests"]),
                "requests_sent": proof["requests_sent"]}

    # ------------------------------------------------------------ server-side prototype pollution

    async def _class_pp_run(self, url: str, identity: str, capture_id: str, readback_url: str,
                            exclude: Optional[int] = None) -> dict:
        from app.services.agent.scoped_assessment import body_probe
        from app.services.agent.scoped_assessment.class_probes import (
            pp_spaces, probe_pp_json_spaces,
        )

        allowed = self._scoped_origin(url)
        path = urlsplit(url).path or "/"
        if not self._class_approved_post(path):
            raise PermissionError("JSON POST path is not in body_replay_paths")
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
        self, coverage_cell_id: str, coverage_lease_id: str, readback_url: str, **_kwargs: Any,
    ) -> Dict[str, Any]:
        """JSON-spaces prototype pollution gadget with control and reset (one per endpoint)."""
        from app.services.agent.engagement_brain import engagement_brain_from_dict

        brain = engagement_brain_from_dict(getattr(self, "_engagement_brain", None))
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
                                             str(readback_url or ""))
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
                "proof_confirmed": proof["proof_confirmed"], "steps": proof["steps"],
                "reset_restored": proof["reset_restored"],
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
            proof = await self._class_cswsh_run(url, identity, str(payload.get("subprotocol") or ""))
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
                                                   str(payload.get("username_field") or ""))
            elif test_type == "oauth":
                proof = await self._class_oauth_run(url, identity)
            elif test_type == "server_prototype_pollution":
                capture_id = str(cell.get("capture_id") or "")
                proof = await self._class_pp_run(
                    url, identity, capture_id, str(payload.get("readback_url") or ""),
                    exclude=payload.get("spaces"))
            else:
                capture_id = str(cell.get("capture_id") or "")
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
        "body_replay_paths (enumeration also accepts auth_login_path); upload cleanup DELETE only "
        "on stored_xss_cleanup_paths. Bounded request counts; nothing here follows redirects. "
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
            "username_field (optional). The test account name comes only from that operator "
            "capture, never from a guess. Sends 6 POSTs: test account and two fresh random "
            "nonexistent accounts, twice, with one wrong nonce password; stops on 429 or lockout "
            "text. Confirms only a stable normalized difference (status, redirect path, body with "
            "nonces/timestamps/CSRF values removed). Timing is reported as a lead only."
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
            "**identity** (named, with session cookies), subprotocol. Three handshakes: identity + "
            "same Origin, identity + foreign https://<nonce>.cswsh.prowl.invalid, anonymous + "
            "foreign Origin. Sends no frames; reads up to 4 server-pushed text frames for 3 s each. "
            "Confirms only when the foreign-Origin identity handshake gets 101 with a valid accept "
            "key and a value the same-origin identity session also gets and an accepted comparison "
            "session (anonymous, or a second registered identity when one exists) does not; values "
            "are stored as digests. If the anonymous handshake is rejected and there is no second "
            "identity, or the server pushes nothing until a client message, it stays a lead. "
            "vulnerability_class=cswsh."
        ),
        phases=ACTIVE_PHASES, section=CLASS_PROOF_SECTION,
    ),
    write_tool(
        "scoped_server_pp_assigned",
        (
            "Server-side prototype pollution proof extending probe_server_prototype_pollution, on "
            "one leased prototype_pollution JSON POST cell with a browser capture. Args: "
            "coverage_cell_id, coverage_lease_id, **readback_url** (an observed same-origin JSON "
            "GET on another path). GET control, POST the captured body plus a plain \"json spaces\" "
            "property (control), GET, POST with __proto__.\"json spaces\"=n (3-9), GET, POST reset "
            "to 0, GET. Confirms only when the unrelated response's indentation becomes exactly n "
            "after the gadget and not after the control. One marker per endpoint per run; a "
            "vulnerable process keeps the property until restart. "
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
)
