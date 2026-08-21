"""Kickoff tech fingerprinting: local Wappalyzer + WhatRuns."""

import asyncio
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
