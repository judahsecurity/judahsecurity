"""Named test identities and RFC-aware HTTP cookie transport."""

from __future__ import annotations

import time
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
        self.identities[name] = {
            "target": target,
            "cookies": cookies or (storage_state or {}).get("cookies") or [],
            "headers": headers or {},
            "storage_state": storage_state or {},
            "role": role,
            "tenant": tenant,
            "authenticated": False,
        }
        return self.describe(name)

    def resolve(self, name: str, url: str) -> dict:
        if name == "anonymous":
            return {"cookies": [], "headers": {}, "authenticated": False}
        session = self.identities.get(name)
        if session is None:
            raise ValueError(f"Unknown test identity: {name}")
        if origin(session["target"]) != origin(url):
            raise ValueError(f"Identity {name} is not registered for this origin")
        return session

    def describe(self, name: str) -> dict:
        item = self.identities[name]
        return {
            "name": name,
            "target": item["target"],
            "role": item["role"],
            "tenant": item["tenant"],
            "authenticated": item["authenticated"],
        }


def identity_registry(manager) -> IdentityRegistry:
    if getattr(manager, "_identity_registry", None) is None:
        manager._identity_registry = IdentityRegistry()
    return manager._identity_registry
