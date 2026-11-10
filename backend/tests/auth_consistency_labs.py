"""Synthetic labs for the auth-consistency invariant.

Each lab is an httpx handler reproducing how a real framework misroutes auth.
The probe only sees HTTP, so these are faithful to what it would observe on a
live target. Labs are deliberately varied (framework, verb, nouns, identifier
shape) so a passing suite shows the capability generalizes rather than
matching one engagement's paths.

Positive labs (must be flagged):
  express_get_only_auth  – router.get(auth, h) + router.post(h): POST bypass.
                           A model listing leaks names; the calculate route is
                           templated. Mirrors an ML/ICS analytics deployment.
  flask_put_branch       – decorator wraps only the GET branch; PUT returns the
                           export. Different nouns, UUID-ish ids, 401 not 403.
  override_after_auth    – auth checks the wire verb, router honours
                           X-HTTP-Method-Override afterwards.

Negative labs (must NOT be flagged):
  properly_protected     – every verb 401.
  spa_catch_all          – POST falls through to index.html (200).
  soft_deny_200          – POST 200 {"error":"Unauthorized"}.
  method_not_allowed     – POST 405.
  state_changing_path    – denied /delete path: probe must send no write verbs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

import httpx

SPA_SHELL = (
    "<!doctype html><html><head><title>App</title>"
    "<script src=\"/static/main.3f9a1c2b.js\"></script></head>"
    "<body><div id=\"root\"></div></body></html>"
)

_CSV_HEADER = "Sample,Flow_A,Flow_B,Tank_Level,Pressure,Actual,Predicted,R2,MAE"


def _csv(rows: int) -> str:
    lines = [_CSV_HEADER]
    for i in range(1, rows + 1):
        lines.append(f"{i},0.0,0.0,{60 + i % 3}.1,3.8,0.0,-0.67,0.775,8.09")
    return "\n".join(lines)


class Lab:
    """Records every request so tests can assert what the probe sent."""

    def __init__(self, name: str, handler: Callable[[httpx.Request], httpx.Response]):
        self.name = name
        self._handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)

    def sent(self, method: str, path_re: str = ".*") -> list[httpx.Request]:
        return [r for r in self.requests if r.method == method and re.search(path_re, r.url.path)]


def _json(status: int, payload) -> httpx.Response:
    return httpx.Response(status, json=payload)


def _shell() -> httpx.Response:
    return httpx.Response(200, text=SPA_SHELL, headers={"content-type": "text/html"})


def express_get_only_auth() -> Lab:
    models: dict[str, str] = {
        "plant7mixerline2": _csv(40),
        "sim_oven": _csv(12),
        "empty_model": "",
    }

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/api/models" and req.method == "GET":
            # Unauthenticated disclosure that seeds the chain.
            return _json(200, {"models": [{"name": n, "tags": 10} for n in models]})
        m = re.fullmatch(r"/api/predictions/calculate/([^/]+)", path)
        if m:
            if req.method == "GET":
                return _json(403, {"message": "Invalid auth"})
            if req.method == "POST":
                name = m.group(1)
                return _json(200, {"data": models.get(name, ""), "filename": f"{name}.csv"})
            return httpx.Response(404, text="Cannot " + req.method)
        return _shell()  # Express static catch-all for the SPA

    return Lab("express_get_only_auth", handler)


def flask_put_branch() -> Lab:
    reports = ["rpt-7f3a9c01", "rpt-11b2e4d9"]

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if path == "/v2/reports" and req.method == "GET":
            return _json(200, [{"report_id": r, "owner_name": "ops"} for r in reports])
        m = re.fullmatch(r"/v2/reports/([^/]+)/export", path)
        if m:
            if req.method == "GET":
                return _json(401, {"error": "authentication required"})
            if req.method == "PUT":
                return _json(200, {"report": m.group(1), "rows": [{"site": "A", "kwh": 42}]})
            return httpx.Response(405, text="Method Not Allowed")
        return httpx.Response(404, text="Not Found")

    return Lab("flask_put_branch", handler)


def override_after_auth() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/rest/admin/config":
            if req.method == "GET":
                return _json(403, {"detail": "Forbidden"})
            if req.method == "POST" and req.headers.get("x-http-method-override", "").upper() == "GET":
                return _json(200, {"smtp_host": "mail.internal", "debug": True})
            return httpx.Response(405)
        return httpx.Response(404)

    return Lab("override_after_auth", handler)


def properly_protected() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/api/"):
            return _json(401, {"message": "Unauthorized"})
        return _shell()

    return Lab("properly_protected", handler)


def spa_catch_all() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/admin/users" and req.method == "GET":
            return _json(403, {"message": "Forbidden"})
        return _shell()  # every other method/path → index.html 200

    return Lab("spa_catch_all", handler)


def soft_deny_200() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/billing/summary":
            if req.method == "GET":
                return _json(401, {"error": "Unauthorized"})
            return _json(200, {"error": "Unauthorized", "data": None})
        return httpx.Response(404)

    return Lab("soft_deny_200", handler)


def method_not_allowed() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/api/metrics":
            if req.method == "GET":
                return _json(403, {"message": "Forbidden"})
            return httpx.Response(405, text="Method Not Allowed")
        return httpx.Response(404)

    return Lab("method_not_allowed", handler)


def state_changing_path() -> Lab:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.startswith("/api/users/delete/"):
            if req.method == "GET":
                return _json(403, {"message": "Forbidden"})
            return _json(200, {"deleted": True})
        return httpx.Response(404)

    return Lab("state_changing_path", handler)


def body_json(request: httpx.Request):
    try:
        return json.loads(request.content or b"null")
    except Exception:
        return None
