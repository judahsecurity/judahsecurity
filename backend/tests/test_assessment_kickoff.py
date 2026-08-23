"""Kickoff tech fingerprinting: local Wappalyzer + WhatRuns."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

from app.services.agent.assessment_kickoff import (
    merge_tech_labels,
    run_assessment_kickoff,
)
from app.services.wappalyzer_service import WappalyzerService


WP_HTML = """<!doctype html>
<html>
<head>
  <meta name="generator" content="WordPress 5.8.1">
  <title>Emulate3D</title>
  <link rel="https://api.w.org/" href="https://www.emulate3d.com/wp-json/" />
</head>
<body>
  <link rel="stylesheet" href="/wp-content/themes/demo/style.css">
  <script src="/wp-includes/js/jquery.min.js"></script>
</body>
</html>
"""


class _FakeCookies:
    jar = []


class _FakeResp:
    def __init__(self, url, status=200, text="", headers=None):
        self.url = url
        self.status_code = status
        self.text = text
        self.headers = headers or {"content-type": "text/html"}
        self.cookies = _FakeCookies()


class _FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, follow_redirects=True, timeout=8.0):
        u = str(url)
        if u.rstrip("/").endswith("emulate3d.com") or u.endswith("emulate3d.com/"):
            return _FakeResp(u, text=WP_HTML)
        if u.rstrip("/").endswith("wp-admin"):
            return _FakeResp(u, status=302, text="")
        if "robots.txt" in u:
            return _FakeResp(u, text="User-agent: *\nDisallow:")
        return _FakeResp(u, status=404, text="")


def test_wappalyzer_analyze_page_detects_wordpress_version():
    svc = WappalyzerService()
    found = svc.analyze_page(
        "https://www.emulate3d.com/",
        WP_HTML,
        headers={
            "content-type": "text/html",
            "link": '<https://www.emulate3d.com/wp-json/>; rel="https://api.w.org/"',
        },
    )
    names = {t.name.lower(): t for t in found}
    assert "wordpress" in names
    assert names["wordpress"].version == "5.8.1"


def test_merge_tech_labels_prefers_wappalyzer_version():
    wapp = [SimpleNamespace(name="WordPress", slug="wordpress", version="5.8.1")]
    wr = [
        SimpleNamespace(name="WordPress", slug="wordpress", version=None),
        SimpleNamespace(name="Contact Form 7", slug="contact-form-7", version=None),
    ]
    merged = merge_tech_labels(wapp, wr)
    assert "WordPress:5.8.1" in merged
    assert "Contact Form 7" in merged
    assert "WordPress" not in merged


def test_kickoff_merges_wappalyzer_and_whatruns(monkeypatch):
    wr = [SimpleNamespace(name="Contact Form 7", slug="contact-form-7", version=None)]

    async def fake_whatruns(base):
        return wr

    monkeypatch.setattr(
        "app.services.agent.assessment_kickoff._run_whatruns",
        fake_whatruns,
    )

    async def _run():
        with patch("httpx.AsyncClient", _FakeClient):
            return await run_assessment_kickoff("https://www.emulate3d.com/")

    result = asyncio.run(_run())

    assert result["success"] is True
    techs = " ".join(result["technologies"]).lower()
    assert "wordpress" in techs
    assert "5.8.1" in techs
    assert "contact form 7" in techs
    assert "Tech (wappalyzer)" in result["brief"]
    assert "Tech (whatruns)" in result["brief"]
    assert "CMS: WordPress" in result["brief"]
    assert result["tech_by_source"]["whatruns"]


def test_wordpress_hunt_note_sees_kickoff_technologies():
    from app.services.agent.orchestrator import AgentOrchestrator

    note = AgentOrchestrator._wordpress_hunt_note(
        None,
        {
            "target_info": {
                "technologies": ["WordPress:5.8.1", "PHP"],
                "primary_target": "https://www.emulate3d.com",
            },
            "execution_trace": [],
            "kickoff_brief": "Tech (wappalyzer): WordPress:5.8.1",
        },
    )
    assert "WordPress detected" in note
    assert "/wp-json/wp/v2/users" in note


def test_registry_hunt_note_sees_kickoff_host():
    from app.services.agent.orchestrator import AgentOrchestrator

    note = AgentOrchestrator._registry_hunt_note(
        None,
        {
            "target_info": {
                "technologies": ["Azure Container Registry"],
                "primary_target": "https://contoso.azurecr.io",
            },
            "execution_trace": [],
            "kickoff_brief": "Registry: *.azurecr.io — probe_registry_anonymous",
        },
    )
    assert "probe_registry_anonymous" in note
    assert "contoso.azurecr.io" in note


def test_wordpress_hunt_note_sees_wp_admin_path():
    from app.services.agent.orchestrator import AgentOrchestrator

    note = AgentOrchestrator._wordpress_hunt_note(
        None,
        {
            "target_info": {
                "technologies": [],
                "primary_target": "https://www.emulate3d.com",
            },
            "execution_trace": [],
            "kickoff_brief": "Notable paths: [302] /wp-admin",
        },
    )
    assert "WordPress detected" in note


def test_appsmith_spa_catchall_is_not_wordpress():
    """Same HTML 200 on /wp-json is an SPA shell, not WordPress."""
    spa = (
        '<!doctype html><html lang="en"><head><title>Appsmith</title></head>'
        "<body>loader</body></html>"
    )

    class _SpaClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, follow_redirects=True, timeout=8.0):
            headers = {
                "content-type": "text/html; charset=utf-8",
                "x-appsmith-request-id": "abc",
            }
            return _FakeResp(str(url), status=200, text=spa, headers=headers)

    async def fake_whatruns(base):
        return []

    async def fake_wapp(base, root):
        return []

    async def _run():
        with (
            patch("httpx.AsyncClient", _SpaClient),
            patch("app.services.agent.assessment_kickoff._run_wappalyzer", fake_wapp),
            patch("app.services.agent.assessment_kickoff._run_whatruns", fake_whatruns),
        ):
            return await run_assessment_kickoff("https://appsmith-dmpc.unifytwin.com/")

    result = asyncio.run(_run())
    assert result["success"] is True
    assert "CMS: WordPress" not in result["brief"]
    assert "SPA catch-all" in result["brief"]
    assert "Appsmith" in result["brief"]
    kind = (result.get("assessment") or {}).get("app_kind")
    assert kind != "wordpress"
    start = (result.get("assessment") or {}).get("start_here") or []
    specs = [r.get("specialist") for r in start]
    assert "injection" not in specs or not any(r.get("hunt") == "wordpress" for r in start)
    assert "credential_assault" in specs or "spa_client" in specs
    assert "ssrf" in specs
    assert "sqli" in specs


def test_kickoff_acr_probes_token_and_catalog_not_website_paths(monkeypatch):
    class _AcrClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, follow_redirects=True, timeout=8.0):
            u = str(url)
            if "/oauth2/token" in u:
                return _FakeResp(
                    u,
                    status=200,
                    text=json.dumps({"access_token": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}),
                    headers={"content-type": "application/json"},
                )
            if "/v2/_catalog" in u:
                return _FakeResp(
                    u,
                    status=200,
                    text=json.dumps({"repositories": ["app/web"]}),
                    headers={"content-type": "application/json"},
                )
            return _FakeResp(u, status=401, text="unauthorized")

    async def fake_whatruns(base):
        return []

    async def fake_wapp(base, root):
        return []

    monkeypatch.setattr(
        "app.services.agent.assessment_kickoff._run_whatruns",
        fake_whatruns,
    )

    async def _run():
        with (
            patch("httpx.AsyncClient", _AcrClient),
            patch("app.services.agent.assessment_kickoff._run_wappalyzer", fake_wapp),
        ):
            return await run_assessment_kickoff("https://contoso.azurecr.io")

    result = asyncio.run(_run())
    assert result["success"] is True
    assert result["needs_dir_brute"] is False
    assert "Azure Container Registry" in result["technologies"]
    paths = [str(h.get("path") or "") for h in result["hits"]]
    assert any("oauth2/token" in p for p in paths)
    assert any("_catalog" in p for p in paths)
    assert not any("wp-admin" in p for p in paths)
    assert "probe_registry_anonymous" in result["brief"]
    assert "docker pull" in result["brief"].lower() or "do not" in result["brief"].lower()


def test_kickoff_404_flags_dir_brute(monkeypatch):
    class _EmptyClient(_FakeClient):
        async def get(self, url, follow_redirects=True, timeout=8.0):
            return _FakeResp(str(url), status=404, text="Not Found")

    async def fake_whatruns(base):
        return []

    monkeypatch.setattr(
        "app.services.agent.assessment_kickoff._run_whatruns",
        fake_whatruns,
    )

    async def _run():
        with patch("httpx.AsyncClient", _EmptyClient):
            return await run_assessment_kickoff("https://empty.example.com/")

    result = asyncio.run(_run())
    assert result["needs_dir_brute"] is True
    assert result["root_status"] == 404
    assert "EMPTY/404" in result["brief"] or "directory brute" in result["brief"].lower()
