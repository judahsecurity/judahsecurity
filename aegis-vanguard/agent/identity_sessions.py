"""Persistent, label-addressed HTTP sessions for authorized test identities.

Secrets remain inside this module.  Agents receive only identity labels and
sanitized session status, then reference a label when making a guarded tool
call.  Requests still flow through ``scanners.run_send_http_request`` so scope
controls, tracing, and the shared request ledger remain intact.
"""

from __future__ import annotations

import json
import hashlib
import re
import threading
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, List, Optional, Sequence
from urllib.parse import urlencode, urljoin, urlparse

from agent.authz_probe import _authz_verdict


Transport = Callable[[str, str, Dict[str, str], str, bool], Dict[str, Any]]
_SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
_SAFE_RETRY_METHODS = {"GET", "HEAD", "OPTIONS"}
_AUTH_PATH_RE = re.compile(
    r"(?:login|sign[ -]?in|session|authenticate|account|oauth|sso)", re.I
)
_CSRF_NAME_RE = re.compile(
    r"(?:csrf|xsrf|authenticity|requestverificationtoken|verificationtoken)", re.I
)
_LOGIN_FAILURE_RE = re.compile(
    r"(?:invalid (?:user|email|password|credential)|incorrect password|login failed|"
    r"authentication failed|unable to sign in)", re.I
)


def _origin(url: str) -> tuple:
    parsed = urlparse(str(url or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("identity session URLs must be absolute HTTP(S) URLs")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return parsed.scheme.lower(), parsed.hostname.lower(), port


def _same_origin(a: str, b: str) -> bool:
    try:
        return _origin(a) == _origin(b)
    except ValueError:
        return False


def _default_transport(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: str,
    follow_redirects: bool,
) -> Dict[str, Any]:
    import scanners

    return scanners.run_send_http_request(
        method=method,
        url=url,
        headers_json=json.dumps(headers),
        body=body,
        follow_redirects=follow_redirects,
        bridge=None,
    )


def _response_headers(response: Dict[str, Any]) -> Dict[str, str]:
    headers = response.get("headers")
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    parsed: Dict[str, str] = {}
    raw = str(response.get("raw_headers") or "")
    for line in raw.splitlines()[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip().lower()] = value.strip()
    return parsed


def _set_cookie_values(response: Dict[str, Any]) -> List[str]:
    values: List[str] = []
    headers = response.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() == "set-cookie":
                values.append(str(value))
    raw = str(response.get("raw_headers") or "")
    for line in raw.splitlines():
        if line.lower().startswith("set-cookie:"):
            values.append(line.split(":", 1)[1].strip())
    return values


def _cookie_pairs(value: str) -> Dict[str, str]:
    cookie = SimpleCookie()
    try:
        cookie.load(value or "")
    except Exception:
        return {}
    return {name: morsel.value for name, morsel in cookie.items()}


def _safe_headers(response: Dict[str, Any]) -> Dict[str, str]:
    return {
        key: "[REDACTED]" if key.lower() in _SENSITIVE_HEADERS else value
        for key, value in _response_headers(response).items()
    }


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: List[dict] = []
        self._current: Optional[dict] = None

    def handle_starttag(self, tag: str, attrs) -> None:
        values = {str(k).lower(): str(v or "") for k, v in attrs}
        if tag.lower() == "form":
            self._current = {
                "action": values.get("action", ""),
                "method": values.get("method", "POST").upper(),
                "enctype": values.get(
                    "enctype", "application/x-www-form-urlencoded"
                ),
                "inputs": [],
            }
            self.forms.append(self._current)
        elif tag.lower() == "input" and self._current is not None:
            self._current["inputs"].append({
                "name": values.get("name", ""),
                "type": values.get("type", "text").lower(),
                "value": values.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current = None


def _forms(html: str) -> List[dict]:
    parser = _FormParser()
    try:
        parser.feed(html or "")
    except Exception:
        return []
    return parser.forms


def _login_form(html: str) -> Optional[dict]:
    forms = _forms(html)
    return next(
        (
            form for form in forms
            if any(item.get("type") == "password" for item in form["inputs"])
        ),
        None,
    )


def _csrf_value(html: str) -> tuple[str, str]:
    for form in _forms(html):
        for item in form["inputs"]:
            name = str(item.get("name") or "")
            value = str(item.get("value") or "")
            if name and value and _CSRF_NAME_RE.search(name):
                return name, value
    return "", ""


def _json_value(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


@dataclass
class _IdentityRuntime:
    label: str
    username: str
    password: str
    role: str
    tenant: str
    base_headers: Dict[str, str]
    login: Dict[str, Any]
    state: str = "configured"
    evidence: str = ""
    error: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    csrf_name: str = ""
    csrf_value: str = ""
    last_status: Optional[int] = None
    last_url: str = ""
    lock: threading.RLock = field(default_factory=threading.RLock)


class IdentitySessionManager:
    """Owns persistent cookie/header state for one assessment."""

    def __init__(self, transport: Optional[Transport] = None):
        self._transport = transport or _default_transport
        self._target_url = ""
        self._identities: Dict[str, _IdentityRuntime] = {}
        self._lock = threading.RLock()

    def configure(
        self,
        identities: Sequence[dict],
        target_url: str,
        input_surface: Optional[dict] = None,
    ) -> None:
        _origin(target_url)
        login_candidate = self._login_candidate(input_surface or {})
        configured: Dict[str, _IdentityRuntime] = {}
        for item in identities or []:
            label = str(item.get("label") or "").strip()
            if not label:
                continue
            headers = {str(k): str(v) for k, v in (item.get("headers") or {}).items()}
            cookies: Dict[str, str] = {}
            for key in list(headers):
                if key.lower() == "cookie":
                    cookies.update(_cookie_pairs(headers.pop(key)))
            login = dict(item.get("login") or {})
            if not login.get("url") and login_candidate:
                login["url"] = login_candidate.get("source_url") or login_candidate.get("action_url")
                login["action_url"] = (
                    login.get("action_url") or login_candidate.get("action_url") or ""
                )
                login["method"] = login.get("method") or login_candidate.get("method") or "POST"
                login["content_type"] = (
                    login.get("content_type") or login_candidate.get("content_type") or ""
                )
            configured[label] = _IdentityRuntime(
                label=label,
                username=str(item.get("username") or ""),
                password=str(item.get("password") or ""),
                role=str(item.get("role") or "unknown"),
                tenant=str(item.get("tenant") or "default"),
                base_headers=headers,
                login=login,
                cookies=cookies,
            )
        with self._lock:
            self._target_url = target_url
            self._identities = configured

    @staticmethod
    def _login_candidate(surface: dict) -> dict:
        for form in surface.get("forms") or []:
            if not isinstance(form, dict):
                continue
            controls = form.get("controls") or []
            has_password = any(
                isinstance(item, dict) and item.get("type") == "password"
                for item in controls
            )
            urls = f"{form.get('source_url', '')} {form.get('action_url', '')}"
            if has_password or _AUTH_PATH_RE.search(urls):
                return form
        return {}

    def _runtime(self, label: str) -> _IdentityRuntime:
        with self._lock:
            runtime = self._identities.get(str(label))
        if runtime is None:
            raise ValueError(f"unknown identity label: {label}")
        return runtime

    def _validate_url(self, url: str) -> None:
        if not self._target_url:
            raise ValueError("identity sessions are not configured")
        if not _same_origin(self._target_url, url):
            raise ValueError("identity session request must preserve the target origin")

    @staticmethod
    def _has_session_header(runtime: _IdentityRuntime) -> bool:
        return bool(runtime.cookies) or any(
            key.lower() in {"authorization", "proxy-authorization", "x-api-key", "x-auth-token"}
            for key in runtime.base_headers
        )

    def _send_locked(
        self,
        runtime: _IdentityRuntime,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
    ) -> Dict[str, Any]:
        self._validate_url(url)
        merged = dict(runtime.base_headers)
        merged.update(headers or {})
        if runtime.cookies:
            merged["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(runtime.cookies.items())
            )
        response = self._transport(method.upper(), url, merged, body, False)
        request_id = response.get("request_id")
        if request_id:
            try:
                from agent.request_ledger import get_request_ledger

                get_request_ledger().tag_identity(str(request_id), runtime.label)
            except Exception:
                pass
        for value in _set_cookie_values(response):
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except Exception:
                continue
            for name, morsel in parsed.items():
                if morsel["max-age"] == "0" or not morsel.value:
                    runtime.cookies.pop(name, None)
                else:
                    runtime.cookies[name] = morsel.value
        runtime.last_status = response.get("status")
        runtime.last_url = url
        csrf_name, csrf_value = _csrf_value(str(response.get("body") or ""))
        if csrf_value:
            runtime.csrf_name, runtime.csrf_value = csrf_name, csrf_value
        return response

    def _follow_same_origin_redirect(
        self,
        runtime: _IdentityRuntime,
        response: Dict[str, Any],
        current_url: str,
    ) -> tuple[Dict[str, Any], str, bool]:
        location = _response_headers(response).get("location", "")
        if not location or not isinstance(response.get("status"), int):
            return response, current_url, False
        if not (300 <= response["status"] < 400):
            return response, current_url, False
        next_url = urljoin(current_url, location)
        if not _same_origin(self._target_url, next_url):
            return response, current_url, False
        return self._send_locked(runtime, "GET", next_url), next_url, True

    def establish(self, identity_label: str, force: bool = False) -> dict:
        runtime = self._runtime(identity_label)
        with runtime.lock:
            if runtime.state == "authenticated" and not force:
                return self._public_status(runtime)
            runtime.state = "authenticating"
            runtime.error = ""
            login = runtime.login
            session_header = self._has_session_header(runtime)

            if session_header and not (
                runtime.username and runtime.password and login.get("url")
            ):
                verify_url = str(login.get("verify_url") or self._target_url)
                try:
                    response = self._send_locked(runtime, "GET", verify_url)
                except Exception as exc:
                    runtime.state, runtime.error = "error", str(exc)
                    return self._public_status(runtime)
                marker = str(login.get("success_marker") or "")
                body = str(response.get("body") or "")
                if response.get("status") in {401, 403}:
                    runtime.state = "rejected"
                    runtime.error = f"verification returned HTTP {response.get('status')}"
                elif marker and marker not in body:
                    runtime.state = "rejected"
                    runtime.error = "configured success marker was not present"
                elif marker:
                    runtime.state, runtime.evidence = "authenticated", "success_marker"
                else:
                    runtime.state = "ready_unverified"
                    runtime.evidence = "session headers accepted; no private marker configured"
                return self._public_status(runtime)

            login_url = str(login.get("url") or "")
            if not login_url:
                runtime.state = "error"
                runtime.error = "no login URL discovered or configured"
                return self._public_status(runtime)
            try:
                self._validate_url(login_url)
                page = self._send_locked(runtime, "GET", login_url)
                page, page_url, _ = self._follow_same_origin_redirect(
                    runtime, page, login_url
                )
                form = _login_form(str(page.get("body") or ""))
                username_field = str(login.get("username_field") or "")
                password_field = str(login.get("password_field") or "")
                if form:
                    username_field = username_field or next((
                        item["name"] for item in form["inputs"]
                        if item.get("name") and item.get("type") in {
                            "text", "email", "username", "tel"
                        }
                    ), "username")
                    password_field = password_field or next((
                        item["name"] for item in form["inputs"]
                        if item.get("name") and item.get("type") == "password"
                    ), "password")
                if not username_field or not password_field:
                    raise ValueError("could not determine login username/password fields")

                fields = {
                    item["name"]: item.get("value", "")
                    for item in (form or {}).get("inputs", [])
                    if item.get("name") and item.get("type") == "hidden"
                }
                fields.update({
                    str(k): str(v)
                    for k, v in (login.get("extra_fields") or {}).items()
                })
                fields[username_field] = runtime.username
                fields[password_field] = runtime.password
                action = str(login.get("action_url") or "")
                action_url = urljoin(page_url, action or (form or {}).get("action") or page_url)
                self._validate_url(action_url)
                method = str(login.get("method") or (form or {}).get("method") or "POST").upper()
                content_type = str(
                    login.get("content_type") or (form or {}).get("enctype")
                    or "application/x-www-form-urlencoded"
                )
                headers = {"Content-Type": content_type}
                body = (
                    json.dumps(fields, separators=(",", ":"))
                    if "json" in content_type.lower()
                    else urlencode(fields)
                )
                cookies_before = dict(runtime.cookies)
                response = self._send_locked(runtime, method, action_url, headers, body)

                token_field = str(login.get("token_field") or "")
                token = None
                try:
                    parsed_body = json.loads(str(response.get("body") or ""))
                except (json.JSONDecodeError, TypeError, ValueError):
                    parsed_body = None
                for path in filter(None, [token_field, "access_token", "accessToken"]):
                    token = _json_value(parsed_body, path) if parsed_body is not None else None
                    if token:
                        runtime.base_headers["Authorization"] = f"Bearer {token}"
                        break

                final, final_url, redirected = self._follow_same_origin_redirect(
                    runtime, response, action_url
                )
                final_body = str(final.get("body") or "")
                failure_marker = str(login.get("failure_marker") or "")
                success_marker = str(login.get("success_marker") or "")
                failed = bool(
                    (failure_marker and failure_marker in final_body)
                    or _LOGIN_FAILURE_RE.search(final_body)
                    or not isinstance(final.get("status"), int)
                    or final.get("status") >= 400
                )
                cookie_changed = runtime.cookies != cookies_before
                still_login = _login_form(final_body) is not None
                redirect_location = _response_headers(response).get("location", "")
                external_redirect = bool(
                    redirect_location
                    and not _same_origin(self._target_url, urljoin(action_url, redirect_location))
                )
                if failed:
                    runtime.state = "rejected"
                    runtime.error = "login response indicates authentication failure"
                elif success_marker and success_marker not in final_body:
                    runtime.state = "rejected"
                    runtime.error = "configured success marker was not present"
                elif token:
                    runtime.state, runtime.evidence = "authenticated", "bearer_token"
                elif success_marker:
                    runtime.state, runtime.evidence = "authenticated", "success_marker"
                elif cookie_changed and not still_login and not external_redirect:
                    runtime.state = "authenticated"
                    runtime.evidence = "session_cookie+redirect" if redirected else "session_cookie"
                else:
                    runtime.state = "ready_unverified"
                    runtime.evidence = (
                        "cross-origin login continuation was not followed"
                        if external_redirect else
                        f"login submitted to {final_url}; no private success marker configured"
                    )
            except Exception as exc:
                runtime.state, runtime.error = "error", str(exc)
            return self._public_status(runtime)

    def _refresh_csrf(self, runtime: _IdentityRuntime, url: str) -> None:
        response = self._send_locked(runtime, "GET", url)
        name, value = _csrf_value(str(response.get("body") or ""))
        if not value:
            raise ValueError("no CSRF token found on refresh page")
        runtime.csrf_name, runtime.csrf_value = name, value

    def request(
        self,
        identity_label: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        csrf_url: str = "",
        refresh_on_auth_failure: bool = True,
    ) -> dict:
        runtime = self._runtime(identity_label)
        method = method.upper()
        forbidden = [
            key for key in (headers or {}) if key.lower() in _SENSITIVE_HEADERS
        ]
        if forbidden:
            return {"error": "identity requests cannot override session headers"}
        with runtime.lock:
            if runtime.state not in {"authenticated", "ready_unverified"}:
                return {
                    "error": f"identity session is not ready ({runtime.state})",
                    "identity": runtime.label,
                }
            request_headers = dict(headers or {})
            if "{{csrf}}" in body or any("{{csrf}}" in value for value in request_headers.values()):
                if csrf_url:
                    self._validate_url(csrf_url)
                    self._refresh_csrf(runtime, csrf_url)
                elif not runtime.csrf_value:
                    self._refresh_csrf(runtime, url)
                body = body.replace("{{csrf}}", runtime.csrf_value)
                request_headers = {
                    key: value.replace("{{csrf}}", runtime.csrf_value)
                    for key, value in request_headers.items()
                }
            response = self._send_locked(runtime, method, url, request_headers, body)
            refreshed = False
            if (
                refresh_on_auth_failure
                and method in _SAFE_RETRY_METHODS
                and response.get("status") in {401, 403}
                and runtime.username
            ):
                self.establish(runtime.label, force=True)
                if runtime.state == "authenticated":
                    response = self._send_locked(runtime, method, url, request_headers, body)
                    refreshed = True
            result = self._public_response(runtime, response, url, method)
            result.update({
                "probe": "identity_request",
                "identity": runtime.label,
                "identity_state": runtime.state,
                "session_refreshed": refreshed,
                "candidates": [],
            })
            return result

    def authz_diff(
        self,
        owner_label: str,
        other_label: str,
        target_url: str,
        method: str = "GET",
        body: str = "",
        headers: Optional[Dict[str, str]] = None,
        test_unauth: bool = True,
    ) -> dict:
        owner = self.request(
            owner_label, method, target_url, headers=headers, body=body
        )
        if owner.get("error"):
            return {"probe": "authz", "target": target_url, "candidates": [],
                    "error": f"owner request failed: {owner['error']}"}
        other = self.request(
            other_label, method, target_url, headers=headers, body=body
        )
        if other.get("error"):
            return {"probe": "authz", "target": target_url, "candidates": [],
                    "error": f"other-identity request failed: {other['error']}"}
        unauth = None
        if test_unauth:
            self._validate_url(target_url)
            unauth_raw = self._transport(
                method.upper(), target_url, dict(headers or {}), body, False
            )
            if unauth_raw.get("request_id"):
                try:
                    from agent.request_ledger import get_request_ledger

                    get_request_ledger().tag_identity(
                        str(unauth_raw["request_id"]), "anonymous"
                    )
                except Exception:
                    pass
            unauth = {
                **unauth_raw,
                "headers": _safe_headers(unauth_raw),
            }

        verdict = _authz_verdict(owner, other, unauth)
        candidates: List[dict] = []
        finding = verdict.get("finding")
        if finding:
            candidates.append({
                "title": (
                    "Insecure Direct Object Reference (BOLA)"
                    if finding == "idor"
                    else "Broken Access Control — unauthenticated object access"
                ),
                "vuln_type": finding,
                "severity": "high",
                "url": target_url,
                "method": method.upper(),
                "identity": other_label if finding == "idor" else "anonymous",
                "owner_identity": owner_label,
                "other_identity": other_label,
                "evidence": verdict.get("reason"),
                "similarity": verdict.get("similarity"),
                "response_evidence": self._brief(
                    other if finding == "idor" else unauth
                ),
                "confirmed": True,
            })
        candidate_identity = (
            other_label if finding == "idor"
            else "anonymous" if finding == "broken_access_control"
            else ""
        )
        coverage = [
            {"parameter_spec": "endpoint", "identity": owner_label,
             "status": "tested_negative", "signals": []},
            {"parameter_spec": "endpoint", "identity": other_label,
             "status": "candidate" if candidate_identity == other_label else "tested_negative",
             "signals": [finding] if candidate_identity == other_label else []},
        ]
        if test_unauth:
            coverage.append({
                "parameter_spec": "endpoint", "identity": "anonymous",
                "status": "candidate" if candidate_identity == "anonymous" else "tested_negative",
                "signals": [finding] if candidate_identity == "anonymous" else [],
            })
        return {
            "probe": "authz",
            "target": target_url,
            "method": method.upper(),
            "tested_identities": [owner_label, other_label]
                + (["anonymous"] if test_unauth else []),
            "owner": self._brief(owner),
            "other": self._brief(other),
            "unauth": self._brief(unauth) if unauth else None,
            "verdict": verdict,
            "coverage": coverage,
            "candidates": candidates,
        }

    @staticmethod
    def _brief(response: Optional[dict]) -> Optional[dict]:
        if response is None:
            return None
        from agent.request_ledger import redact_response_body

        body = str(response.get("body") or "")
        redacted = redact_response_body(body)
        return {
            "status": response.get("status"),
            "length": len(body),
            "request_id": response.get("request_id"),
            "body_sha256": hashlib.sha256(body.encode(errors="replace")).hexdigest(),
            "body_preview": redacted[:500],
            "error": response.get("error"),
        }

    @staticmethod
    def _public_response(
        runtime: _IdentityRuntime,
        response: Dict[str, Any],
        url: str,
        method: str,
    ) -> dict:
        from agent.request_ledger import redact_response_body

        return {
            "target": url,
            "url": url,
            "method": method,
            "status": response.get("status"),
            "headers": _safe_headers(response),
            "body": redact_response_body(str(response.get("body") or ""))
                .replace(runtime.csrf_value, "[REDACTED-CSRF]")[:8000]
                if runtime.csrf_value else
                redact_response_body(str(response.get("body") or ""))[:8000],
            "elapsed_ms": response.get("elapsed_ms"),
            "request_id": response.get("request_id"),
            "response_classes": response.get("response_classes") or [],
            "adaptive_hints": response.get("adaptive_hints") or [],
            "error": response.get("error"),
        }

    @staticmethod
    def _public_status(runtime: _IdentityRuntime) -> dict:
        return {
            "label": runtime.label,
            "role": runtime.role,
            "tenant": runtime.tenant,
            "state": runtime.state,
            "evidence": runtime.evidence,
            "error": runtime.error,
            "cookie_names": sorted(runtime.cookies),
            "has_authorization_header": any(
                key.lower() == "authorization" for key in runtime.base_headers
            ),
            "csrf_available": bool(runtime.csrf_value),
            "last_status": runtime.last_status,
            "last_url": runtime.last_url,
        }

    def status(self) -> List[dict]:
        with self._lock:
            runtimes = list(self._identities.values())
        statuses = []
        for runtime in runtimes:
            with runtime.lock:
                statuses.append(self._public_status(runtime))
        return statuses


_IDENTITY_SESSIONS = IdentitySessionManager()


def get_identity_sessions() -> IdentitySessionManager:
    return _IDENTITY_SESSIONS


def configure_identity_sessions(
    identities: Sequence[dict],
    target_url: str,
    input_surface: Optional[dict] = None,
) -> IdentitySessionManager:
    _IDENTITY_SESSIONS.configure(identities, target_url, input_surface)
    return _IDENTITY_SESSIONS


__all__ = [
    "IdentitySessionManager",
    "configure_identity_sessions",
    "get_identity_sessions",
]
