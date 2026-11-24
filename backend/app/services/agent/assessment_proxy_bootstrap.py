"""Make the assessment proxy (Caido) ready before any traffic goes through it.

Caido only proxies traffic once a project is selected. A fresh or restarted
instance with no selected project answers with its own error page, which a
browser then records as the target's response. Strix avoids this by logging
in as a guest and selecting a project when each scan starts; this module does
the same for the shared ``caido-assessment`` service, then sends one request
through the proxy to the target so a broken proxy is reported clearly before
the agent spends actions on it.

Configuration:
  AEGIS_ASSESSMENT_PROXY_URL      the proxy listener (traffic)
  AEGIS_ASSESSMENT_PROXY_API_URL  the Caido UI/API listener (GraphQL); when
                                  unset, project bootstrap is skipped and only
                                  the reachability preflight runs.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time

logger = logging.getLogger(__name__)

PROJECT_NAME = "prowl-assessment"
_READY_TTL_SECONDS = 600
_ready_until: dict[str, float] = {}
_lock = asyncio.Lock()

_LOGIN = "mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"
_PROJECTS = "query Projects { projects { id name } }"
_CREATE = ("mutation CreateProject($input: CreateProjectInput!) { createProject(input: $input) "
           "{ project { id } error { __typename } } }")
_SELECT = ("mutation SelectProject($id: ID!) { selectProject(id: $id) "
           "{ currentProject { project { id } } error { __typename } } }")


class AssessmentProxyNotReady(RuntimeError):
    """The assessment proxy cannot carry traffic to the target."""


def proxy_api_url() -> str:
    return (os.environ.get("AEGIS_ASSESSMENT_PROXY_API_URL") or "").strip().rstrip("/")


async def _graphql(client, url: str, query: str, variables: dict | None = None,
                   token: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = await client.post(f"{url}/graphql", json={"query": query, "variables": variables or {}},
                                 headers=headers)
    response.raise_for_status()
    body = response.json()
    if body.get("errors"):
        raise AssessmentProxyNotReady(f"Caido API error: {str(body['errors'])[:200]}")
    return body.get("data") or {}


async def ensure_project(api_url: str, *, client=None) -> str:
    """Log in as guest and select (or create) the assessment project."""
    import httpx

    own = client is None
    client = client or httpx.AsyncClient(timeout=15, trust_env=False)
    try:
        last = ""
        for attempt in range(5):
            try:
                login = await _graphql(client, api_url, _LOGIN)
                break
            except Exception as exc:  # Caido may still be starting
                last = f"{type(exc).__name__}: {exc}"
                await asyncio.sleep(min(1.0 + attempt, 4.0))
        else:
            raise AssessmentProxyNotReady(
                "Caido guest login failed; start caido-assessment with --allow-guests "
                f"and --ui-domain for the API host ({last[:160]})")
        token = (((login.get("loginAsGuest") or {}).get("token") or {}).get("accessToken") or "")
        if not token:
            raise AssessmentProxyNotReady("Caido guest login returned no token")
        projects = (await _graphql(client, api_url, _PROJECTS, token=token)).get("projects") or []
        project_id = next((p["id"] for p in projects if p.get("name") == PROJECT_NAME), "")
        if not project_id:
            created = (await _graphql(client, api_url, _CREATE,
                                      {"input": {"name": PROJECT_NAME, "temporary": True}},
                                      token=token)).get("createProject") or {}
            if created.get("error"):
                raise AssessmentProxyNotReady(f"Caido project create failed: {created['error']}")
            project_id = (created.get("project") or {}).get("id") or ""
        selected = (await _graphql(client, api_url, _SELECT, {"id": project_id},
                                   token=token)).get("selectProject") or {}
        if selected.get("error") or not project_id:
            raise AssessmentProxyNotReady(f"Caido project select failed: {selected.get('error')}")
        return project_id
    finally:
        if own:
            await client.aclose()


async def preflight(target: str, *, client=None) -> None:
    """Send one GET through the proxy; fail if the proxy answers instead of the target."""
    import httpx

    from app.services.agent.assessment_proxy import assessment_httpx_options
    from app.services.agent.scoped_assessment.browser import proxy_error_message, proxy_error_page

    own = client is None
    client = client or httpx.AsyncClient(timeout=20, follow_redirects=False,
                                         **assessment_httpx_options())
    try:
        try:
            response = await client.get(target)
        except Exception as exc:
            raise AssessmentProxyNotReady(
                f"Request to {target} through the assessment proxy failed: {type(exc).__name__}") from exc
        title = ""
        if "html" in response.headers.get("content-type", ""):
            import re

            match = re.search(r"<title[^>]*>(.*?)</title>", response.text[:20000], re.I | re.S)
            title = (match.group(1).strip() if match else "")[:200]
        if proxy_error_page(response.status_code, title, dict(response.headers)):
            raise AssessmentProxyNotReady(proxy_error_message(response.status_code, target))
    finally:
        if own:
            await client.aclose()


async def ensure_assessment_proxy_ready(target: str) -> None:
    """Bootstrap the Caido project and preflight the target, cached per origin."""
    from urllib.parse import urlsplit

    from app.services.agent.assessment_proxy import assessment_proxy_url

    if not assessment_proxy_url():
        return
    parts = urlsplit(target)
    key = f"{parts.scheme}://{parts.netloc}"
    if _ready_until.get(key, 0) > time.monotonic():
        return
    async with _lock:
        if _ready_until.get(key, 0) > time.monotonic():
            return
        api = proxy_api_url()
        if api:
            await ensure_project(api)
        await preflight(f"{key}/")
        _ready_until[key] = time.monotonic() + _READY_TTL_SECONDS
        logger.info("assessment proxy ready for %s", key)


def invalidate(target: str) -> None:
    """Forget readiness for an origin, e.g. after Caido restarted.

    Caido drops a temporary project on restart and then answers every proxied
    request with its own error page, so a cached "ready" must not outlive it.
    """
    from urllib.parse import urlsplit

    parts = urlsplit(target)
    _ready_until.pop(f"{parts.scheme}://{parts.netloc}", None)


def reset_cache() -> None:
    _ready_until.clear()
