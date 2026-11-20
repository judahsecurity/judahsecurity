"""Render a single-page app's signed-in shell without credentials.

Many applications keep most of their API surface behind a client-side login
gate: the page checks for a token, calls a "who am I" endpoint, loads menus
and permissions, and only then mounts the modules that call the real APIs.
Without a test account an anonymous crawl sees the login page and little else.

In shell-unlock mode the browser:

* seeds placeholder auth markers in storage before any page script runs, so a
  render gate that only checks "is there a token" lets the app continue;
* passes same-origin XHR/fetch GET requests to the server as usual, but when
  the server answers "not signed in" (401/403, or a JSON login error), hands
  the page a neutral success body instead, so the app keeps rendering and
  sends the next request;
* never sends state-changing XHR/fetch requests (anything other than GET,
  HEAD or OPTIONS): their shape is recorded and the page gets a placeholder
  success, so a mounted module cannot change server data;
* walks client-side routes with ``history.pushState`` so each module mounts.

Nothing here authenticates. The placeholder token has an invalid signature,
so the server sees ordinary unauthenticated traffic. The value is the list of
requests the app makes, and which of them the server guards ("auth_gated"):
those are the targets for authorization testing. Rewritten and withheld
responses are fake, so they are never kept as replayable evidence.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import urlsplit

PLACEHOLDER = "prowl-shell-unlock-placeholder"
MAX_ROUTES = 12
MAX_ROUTE_CHARS = 200
MAX_BODY_BYTES = 1_000_000
ROUTE_SETTLE_MS = 1200
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_AUTH_STATUSES = frozenset({401, 403, 419, 440})


def _b64(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# JWT-shaped so apps that decode the token client-side (expiry, role) keep
# going. HS256 with a junk signature: no server should accept it, and it is
# deliberately not alg=none, which Prowl tests only through its own JWT probe.
PLACEHOLDER_JWT = ".".join([
    _b64({"alg": "HS256", "typ": "JWT"}),
    _b64({"sub": "prowl-shell-unlock", "name": "prowl", "exp": 4102444800,
          "role": "admin", "roles": ["admin"]}),
    base64.urlsafe_b64encode(PLACEHOLDER.encode()).rstrip(b"=").decode(),
])

_TOKEN_KEYS = (
    "token", "access_token", "accessToken", "authToken", "auth_token", "jwt",
    "id_token", "Authorization", "userToken", "Admin-Token", "x-token",
)
_FLAG_KEYS = ("isLogin", "isLoggedIn", "loggedIn", "isAuthenticated")

INIT_SCRIPT = """(() => {
  const jwt = %(jwt)s;
  const tokenKeys = %(token_keys)s;
  const flagKeys = %(flag_keys)s;
  for (const store of [window.localStorage, window.sessionStorage]) {
    try {
      for (const key of tokenKeys) if (!store.getItem(key)) store.setItem(key, jwt);
      for (const key of flagKeys) if (!store.getItem(key)) store.setItem(key, 'true');
    } catch (e) {}
  }
  try {
    if (!/(?:^|; )token=/.test(document.cookie)) document.cookie = 'token=' + jwt + '; path=/';
  } catch (e) {}
  Object.defineProperty(window, '__PROWL_SHELL_UNLOCK__', {value: true});
})();""" % {
    "jwt": json.dumps(PLACEHOLDER_JWT),
    "token_keys": json.dumps(list(_TOKEN_KEYS)),
    "flag_keys": json.dumps(list(_FLAG_KEYS)),
}

_BOOTSTRAP_PATH = re.compile(
    r"(?:^|/)(?:me|whoami|profile|account|session|current[-_]?user|user[-_/]?info|userinfo|"
    r"users?/(?:me|current|profile)|"
    r"getinfo|get[-_]?user[-_]?info|permissions?|perms|menus?|routers?|nav|roles?|auth/check|"
    r"auth/user|check[-_]?login|login[-_]?status)(?:/|$|\.json$)",
    re.I,
)
_LOGIN_TEXT = re.compile(
    r"not\s*(?:logged|signed)\s*in|please\s*(?:log|sign)\s*in|login\s*required|"
    r"unauthori[sz]ed|unauthenticated|token\s*(?:expired|invalid|missing)|"
    r"invalid\s*token|session\s*(?:expired|timeout)|未登录|请登录|登录过期|令牌",
    re.I,
)
_CODE_FIELDS = ("code", "status", "errno", "errcode", "error_code", "resultCode", "retCode")
_OK_CODES = {0, 200, "0", "200", "ok", "OK", "success", "SUCCESS", True}
_AUTH_CODES = {401, 403, "401", "403", 40100, 40300, "40100", "40300"}

_STUB_USER = {
    "id": 1, "userId": 1, "username": "prowl", "userName": "prowl", "name": "prowl",
    "nickname": "prowl", "email": "prowl@example.invalid",
    "role": "admin", "roles": ["admin"], "permissions": ["*:*:*"], "perms": ["*"],
    "authorities": ["admin"], "isAdmin": True, "admin": True, "menus": [], "routes": [],
}


def looks_unauthenticated(status: int, content_type: str, body: bytes) -> bool:
    """True when the server is saying "sign in first"."""
    if status in _AUTH_STATUSES:
        return True
    if status != 200 or "json" not in (content_type or "").lower() or not body:
        return False
    try:
        data = json.loads(body[:MAX_BODY_BYTES])
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    codes = [data.get(field) for field in _CODE_FIELDS if field in data]
    if any(isinstance(code, (int, str)) and code in _AUTH_CODES for code in codes):
        return True
    if codes and all(isinstance(code, (int, str, bool)) and code in _OK_CODES for code in codes):
        return False
    message = " ".join(str(data.get(key) or "")[:200] for key in ("msg", "message", "error", "detail"))
    return bool(_LOGIN_TEXT.search(message))


def is_bootstrap_path(path: str) -> bool:
    return bool(_BOOTSTRAP_PATH.search(path or ""))


def stub_body(path: str) -> bytes:
    """A neutral success envelope; a user object for identity/menu endpoints."""
    envelope: dict[str, Any] = {
        "code": 0, "status": 0, "success": True, "ok": True,
        "msg": "ok", "message": "ok", "data": {},
    }
    if is_bootstrap_path(path):
        envelope["data"] = dict(_STUB_USER)
        for key, value in _STUB_USER.items():
            envelope.setdefault(key, value)
    return json.dumps(envelope).encode()


def safe_method(method: str) -> bool:
    return (method or "").upper() in _SAFE_METHODS


def normalize_route(value: object) -> str:
    """A same-app client route: '/path' or '#/path', no query, bounded."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if not value or len(value) > MAX_ROUTE_CHARS or any(ch in value for ch in "\r\n\t <>\"'`\\"):
        return ""
    hashed = value.startswith("#/")
    path = value[1:] if hashed else value
    if not path.startswith("/") or path.startswith("//") or "?" in path or "#" in path:
        return ""
    # Fill route parameters (":id", "[id]", "*") with an inert value.
    path = re.sub(r":[A-Za-z_][A-Za-z0-9_]*\??", "1", path)
    path = re.sub(r"\[[^\]/]{1,40}\]", "1", path)
    path = path.replace("*", "")
    path = re.sub(r"/{2,}", "/", path) or "/"
    if len(path) > 1:
        path = path.rstrip("/")
    return ("#" + path) if hashed else path


_ROUTE_IN_SOURCE = re.compile(
    rb"""\bpath\s*:\s*["'](/[A-Za-z0-9_\-/:\[\].*]{1,120})["']""",
)


def routes_from_sources(sources: list[dict], *, limit: int = 40) -> list[str]:
    """Client route paths declared in router tables of loaded scripts."""
    found: list[str] = []
    for source in sources or []:
        data = source.get("data") if isinstance(source, dict) else None
        if not isinstance(data, (bytes, bytearray)):
            continue
        for match in _ROUTE_IN_SOURCE.finditer(bytes(data)[:5_000_000]):
            route = normalize_route(match.group(1).decode("ascii", "ignore"))
            if route and route not in found:
                found.append(route)
                if len(found) >= limit:
                    return found
    return found


# Read the router of a mounted Vue app, when there is one. Other frameworks
# fall back to links and router tables found in the scripts.
ROUTER_ROUTES_JS = """() => {
  const out = [];
  const add = (p) => { if (typeof p === 'string' && out.length < 60) out.push(p); };
  try {
    for (const el of document.querySelectorAll('[data-v-app], #app, #root, body > div')) {
      const app3 = el.__vue_app__;
      const router3 = app3 && app3.config && app3.config.globalProperties.$router;
      if (router3 && router3.getRoutes) router3.getRoutes().forEach(r => add(r.path));
      const vm2 = el.__vue__;
      const router2 = vm2 && vm2.$router;
      if (router2 && router2.options && router2.options.routes) {
        const walk = (routes, base) => routes.forEach(r => {
          const full = r.path.startsWith('/') ? r.path : (base.replace(/\\/$/, '') + '/' + r.path);
          add(full);
          if (r.children) walk(r.children, full);
        });
        walk(router2.options.routes, '');
      }
    }
  } catch (e) {}
  return out;
}"""

# Navigate client-side without a document load, as the app's own links would.
PUSH_ROUTE_JS = """(route) => {
  if (route.startsWith('#')) { window.location.hash = route.slice(1); return location.href; }
  history.pushState({}, '', route);
  window.dispatchEvent(new PopStateEvent('popstate', {state: {}}));
  return location.href;
}"""

_LOGIN_ROUTE = re.compile(r"(?:^|[/#])(?:login|signin|sign-in|auth/login|passport)(?:$|[/?#])", re.I)


def looks_like_login(url: str) -> bool:
    parts = urlsplit(url)
    return bool(_LOGIN_ROUTE.search((parts.path or "/") + ("#" + parts.fragment if parts.fragment else "")))


def choose_routes(candidates: list[object], *, allowed_path, limit: int = MAX_ROUTES) -> list[str]:
    """Ordered, de-duplicated routes that pass the discovery path policy."""
    out: list[str] = []
    for value in candidates:
        route = normalize_route(value)
        path = route[1:] if route.startswith("#") else route
        if not route or route in out or looks_like_login(path) or not allowed_path(path):
            continue
        out.append(route)
        if len(out) >= limit:
            break
    return out


class ShellUnlock:
    """Per-browser-run state for shell-unlock routing."""

    def __init__(self) -> None:
        self.outcomes: dict[object, tuple[str, int | None]] = {}
        self.counts = {"passed": 0, "rewritten": 0, "withheld": 0, "fetch_failed": 0}
        self.routes: list[dict] = []

    def is_faked(self, request: object) -> bool:
        outcome = self.outcomes.get(request)
        return bool(outcome and outcome[0] in {"rewritten", "withheld"})

    async def handle(self, route) -> None:
        """Route one same-origin XHR/fetch request in unlock mode."""
        request = route.request
        path = urlsplit(request.url).path or "/"
        if not safe_method(request.method):
            self.outcomes[request] = ("withheld", None)
            self.counts["withheld"] += 1
            await route.fulfill(status=200, content_type="application/json", body=stub_body(path))
            return
        try:
            response = await route.fetch(max_redirects=0, timeout=15_000)
        except Exception:
            self.counts["fetch_failed"] += 1
            await route.abort()
            return
        content_type = response.headers.get("content-type", "")
        body = b""
        if "json" in content_type.lower() or response.status in _AUTH_STATUSES:
            try:
                body = (await response.body())[:MAX_BODY_BYTES]
            except Exception:
                body = b""
        if looks_unauthenticated(response.status, content_type, body):
            self.outcomes[request] = ("rewritten", response.status)
            self.counts["rewritten"] += 1
            await route.fulfill(status=200, content_type="application/json", body=stub_body(path))
            return
        self.outcomes[request] = ("passed", response.status)
        self.counts["passed"] += 1
        await route.fulfill(response=response)

    def annotate(self, request_rows: dict) -> list[dict]:
        """Mark recorded request rows; return the server-guarded ones."""
        gated = []
        for request, row in request_rows.items():
            outcome = self.outcomes.get(request)
            if not outcome:
                continue
            kind, real_status = outcome
            row["shell_unlock"] = kind
            if real_status is not None:
                row["status"] = real_status
            else:
                row.pop("status", None)
                row.pop("content_type", None)
            if kind == "rewritten":
                row["auth_gated"] = True
                gated.append({"method": row.get("method"), "path": row.get("path"),
                              "status": real_status, "query_keys": row.get("query_keys", [])})
            if kind == "withheld":
                row["not_sent"] = True
        return gated

    def summary(self, gated: list[dict]) -> dict:
        return {
            "enabled": True,
            "counts": dict(self.counts),
            "auth_gated": gated[:60],
            "routes": self.routes[:MAX_ROUTES],
            "routes_reaching_login": sum(1 for row in self.routes if row.get("login_redirect")),
        }
