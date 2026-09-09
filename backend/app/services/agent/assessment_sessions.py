"""Named test identities and RFC-aware HTTP cookie transport."""

from __future__ import annotations

import time
from copy import deepcopy
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from urllib.parse import urlsplit

import httpx

from app.services.agent.evidence_store import origin


def cookie_jar(url: str, stored: list | None = None, explicit=None) -> httpx.Cookies:
    origin(url)
    host = urlsplit(url).hostname
    jar = CookieJar(
        policy=DefaultCookiePolicy(
            strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain
        )
    )
    entries = list(stored or [])
    if isinstance(explicit, dict):
        entries.extend({"name": k, "value": v} for k, v in explicit.items())
    elif isinstance(explicit, list):
        entries.extend(explicit)
    for item in entries:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        domain = str(item.get("domain") or host).lower()
        domain_cookie = domain.startswith(".")
        expires = item.get("expires")
        expires = (
            int(expires) if isinstance(expires, (float, int)) and expires > 0 else None
        )
        if expires is not None and expires <= time.time():
            continue
        jar.set_cookie(
            Cookie(
                version=0,
                name=str(item["name"]),
                value=str(item.get("value", "")),
                port=None,
                port_specified=False,
                domain=domain,
                domain_specified=domain_cookie,
                domain_initial_dot=domain_cookie,
                path=item.get("path") or "/",
                path_specified=True,
                secure=bool(item.get("secure")),
                expires=expires,
                discard=expires is None,
                comment=None,
                comment_url=None,
                rest={"HttpOnly": bool(item.get("httpOnly"))},
                rfc2109=False,
            )
        )
    return httpx.Cookies(jar)


class IdentityRegistry:
    def __init__(self):
        self.identities: dict[str, dict] = {}
        self._sessions: dict[tuple, dict] = {}

    def register(
        self,
        name: str,
        target: str,
        *,
        cookies=None,
        headers=None,
        storage_state=None,
        role: str = "",
        tenant: str = "",
    ) -> dict:
        if not name or name in ("anonymous", "legacy"):
            raise ValueError(
                "Use a unique identity name other than anonymous or legacy"
            )
        origin(target)
        # Identities may use existing engagement scope; they cannot expand it.
        from app.services.agent.assessment_scope import assert_url_in_scope

        assert_url_in_scope(self._manager, target)
        if headers and any(str(key).lower() == 'host' for key in headers):
            raise ValueError('Identity registration cannot override Host')
        if isinstance(cookies, dict):
            cookies = [dict(name=key, value=value) for key, value in cookies.items()]
        session = {
            'target': target, 'cookies': cookies or (storage_state or {}).get('cookies') or [],
            'headers': headers or {}, 'storage_state': storage_state or {},
            'role': role, 'tenant': tenant, 'authenticated': False,
        }
        session = deepcopy(session)
        # A registry entry owns only one exact origin, including browser storage.
        expected_origin = origin(target)
        session['storage_state']['origins'] = [o for o in session['storage_state'].get('origins', [])
                                               if origin(o.get('origin', '')) == expected_origin]
        self._sessions[(name, expected_origin)] = session
        self.identities[name] = session
        return self.describe(name, target)

    def resolve(self, name: str, url: str) -> dict:
        if name == 'anonymous':
            return {'cookies': [], 'headers': {}, 'authenticated': False}
        session = self._sessions.get((name, origin(url)))
        if session is None:
            raise ValueError(f"Unknown test identity: {name}")
        if origin(session["target"]) != origin(url):
            raise ValueError(f"Identity {name} is not registered for this origin")
        return session

    def describe(self, name: str, target: str = '') -> dict:
        item = self.resolve(name, target) if target else self.identities[name]
        return {'name': name, 'target': item['target'], 'role': item['role'],
                'tenant': item['tenant'], 'authenticated': item['authenticated']}

    def describe_all(self) -> list[dict]:
        return [self.describe(name, session['target']) for (name, _), session in self._sessions.items()]


def identity_registry(manager) -> IdentityRegistry:
    if getattr(manager, "_identity_registry", None) is None:
        manager._identity_registry = IdentityRegistry()
        manager._identity_registry._manager = manager
    return manager._identity_registry


def browser_storage_state(session: dict, target: str) -> dict:
    """Translate this origin's HTTP jar to a standalone browser identity context."""
    host = urlsplit(target).hostname
    cookies = []
    for cookie in cookie_jar(target, session.get('cookies', [])).jar:
        domain = cookie.domain.lstrip('.')
        if host != domain and not (cookie.domain_initial_dot and host.endswith('.' + domain)):
            continue
        cookies.append(dict(name=cookie.name, value=cookie.value, domain=host, path=cookie.path,
                            expires=cookie.expires if cookie.expires is not None else -1,
                            secure=cookie.secure, httpOnly=bool(cookie.get_nonstandard_attr('HttpOnly'))))
    return dict(cookies=cookies, origins=deepcopy(session.get('storage_state', {}).get('origins', [])))


async def configure_browser_origin(context, target: str) -> None:
    """Apply the same exact-origin boundary to browser and crawler contexts."""
    expected_origin = origin(target)
    async def scope_route(route):
        try:
            permitted = origin(route.request.url) == expected_origin
        except ValueError:
            permitted = False
        await route.continue_() if permitted else await route.abort()
    await context.route("**/*", scope_route)
    def scope_socket_route(socket):
        try:
            socket_url = socket.url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)
            permitted = origin(socket_url) == expected_origin
        except ValueError:
            permitted = False
        if permitted:
            socket.connect_to_server()
        else:
            socket.close()
    if not hasattr(context, "route_web_socket"):
        raise RuntimeError("Identity browser isolation requires Playwright 1.48 or newer")
    await context.route_web_socket("**/*", scope_socket_route)
