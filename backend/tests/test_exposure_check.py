"""Unauthenticated exposure check: signatures, candidates, and pipeline position."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.services.agent import exposure_check, tester_loop
from app.services.agent.exposure_check import CHECKS, map_paths, run_exposure_checks
from app.services.agent.model_led import always_forced
from app.services.agent.proof_policy import validate_proof

SOFT_404 = "<!DOCTYPE html><html><body>Page not found: repositoryformatversion = 0</body></html>"
POSITIVE = {
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
    "/.env": "APP_ENV=production\nDATABASE_PASSWORD=hunter2\nSECRET=x\n",
    "/openapi.json": json.dumps({"openapi": "3.0.1", "paths": {"/users": {}}}),
    "/swagger.json": json.dumps({"swagger": "2.0", "paths": {}}),
    "/v2/api-docs": json.dumps({"swagger": "2.0", "paths": {}}),
    "/v3/api-docs": json.dumps({"openapi": "3.1.0", "paths": {}}),
    "/actuator/env": json.dumps({"activeProfiles": ["prod"], "propertySources": []}),
    "/actuator": json.dumps({"_links": {"self": {"href": "http://x/actuator"}}}),
    "/server-status": "<html><h1>Apache Server Status for shop.test (via 10.0.0.1)</h1>",
    "/phpinfo.php": "<html><title>phpinfo()</title><h1>PHP Version 8.1.2</h1>",
    "/.aws/credentials": "[default]\naws_access_key_id = AKIAEXAMPLE\n",
    "/debug/pprof/": "<html>Types of profiles available:</html>",
}


def test_every_check_has_a_positive_and_ignores_soft_404s():
    for check in CHECKS:
        marker = check.marker(POSITIVE[check.path])
        assert marker and len(marker) >= 12 and marker in POSITIVE[check.path], check.key
    for check in CHECKS:
        if check.key not in ("server_status", "phpinfo", "pprof"):
            assert check.marker(SOFT_404) is None, check.key


def test_env_marker_quotes_a_key_name_not_a_secret():
    marker = next(c for c in CHECKS if c.key == "dotenv").marker(POSITIVE["/.env"])
    assert marker == "DATABASE_PASSWORD=" and "hunter2" not in marker
    assert next(c for c in CHECKS if c.key == "dotenv").marker("ONLY_ONE=1\n") is None


def test_api_schema_needs_paths():
    check = next(c for c in CHECKS if c.key == "openapi")
    assert check.marker(json.dumps({"openapi": "3.0.1"})) is None


def test_discovered_map_paths_are_checked_too():
    cmap = {"discovered_links": [{"url": "https://shop.test/backup/.env.bak"},
                                 {"url": "https://shop.test/catalog"}],
            "pages_visited": ["https://shop.test/manage/actuator/health"],
            "api_endpoints": [{"path": "/api/swagger.json"}]}
    paths = map_paths(cmap)
    assert "/backup/.env.bak" in paths and "/manage/actuator/health" in paths
    assert "/api/swagger.json" in paths and "/catalog" not in paths


class FakeManager:
    def __init__(self, bodies, fail_on=None):
        self.bodies, self.fail_on = bodies, fail_on or {}
        self.requests, self.submissions = [], []

    async def _http_exchange(self, method, url, **kw):
        from urllib.parse import urlsplit

        assert method == "GET" and kw["use_auth_session"] is False
        assert kw["follow_redirects"] is False
        path = urlsplit(url).path
        self.requests.append(path)
        if path in self.fail_on:
            raise self.fail_on[path]
        body = self.bodies.get(path)
        status = 200 if body is not None else 404
        return {"response": {"status": status}, "_body_text": body or "",
                "evidence_id": f"ev-{len(self.requests)}"}

    async def submit_finding_candidate(self, **kw):
        self.submissions.append(kw)
        return json.dumps({"ok": True})


def test_hits_become_exposure_candidates_with_the_get_as_evidence():
    manager = FakeManager({"/.env": POSITIVE["/.env"], "/openapi.json": SOFT_404,
                           "/swagger.json": POSITIVE["/swagger.json"]})
    result = asyncio.run(run_exposure_checks(manager, "https://shop.test/catalog"))
    assert result["success"] and result["checked"] == len(CHECKS)
    keys = [h["key"] for h in result["hits"]]
    assert keys == ["dotenv", "swagger"]  # the soft-404 openapi page is not a hit
    sub = manager.submissions[0]
    assert sub["vulnerability_class"] == "exposure" and sub["target"] == "https://shop.test/.env"
    assert sub["evidence_ids"] == [result["hits"][0]["evidence_id"]]
    assert "hunter2" not in json.dumps(manager.submissions)
    assert "submitted" in exposure_check.format_result(result)


def test_budget_exhaustion_stops_the_sweep():
    manager = FakeManager({}, fail_on={"/.env": ValueError("Request ceiling reached (budget)")})
    result = asyncio.run(run_exposure_checks(manager, "https://shop.test"))
    assert manager.requests == ["/.git/config", "/.env"]
    assert result["hits"] == [] and "budget" in result["errors"][0]


@pytest.mark.parametrize("check", CHECKS, ids=lambda c: c.key)
def test_each_candidate_passes_the_response_match_proof_rule(check):
    """The submitted wording and evidence satisfy proof_policy's response_match."""
    body = POSITIVE[check.path]
    marker = check.marker(body)
    url = "https://shop.test" + check.path
    store = SimpleNamespace(records={"ev-1": {
        "kind": "http_exchange", "identity": "anonymous",
        "payload": {"request": {"method": "GET", "url": url, "headers": {"user-agent": "x"}},
                    "response": {"status": 200, "url": url, "body": body}}}})
    candidate = SimpleNamespace(
        title=f"{check.title}: {check.path}",
        description=(f"{check.impact} An anonymous GET with no cookies or credentials "
                     f"returned HTTP 200 and the response body contains \"{marker}\". "
                     "Proof kind: response_match."),
        vulnerability_class="exposure", target=url)
    ok, why = validate_proof(store, candidate,
                             {"kind": "response_match", "artifact_id": "ev-1", "contains": marker},
                             ["ev-1"])
    assert ok, why


def test_pipeline_runs_it_once_and_keeps_it_forced(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_EXPOSURE_CHECK", True, raising=False)
    step = tester_loop._exposure_check_step({"mode": "agent"}, [], "https://shop.test/")
    assert step["tool_name"] == "check_exposures" and always_forced(step)
    trace = [{"tool_name": "check_exposures", "tool_args": step["tool_args"]}]
    assert tester_loop._exposure_check_step({"mode": "agent"}, trace, "https://shop.test/") is None
    assert tester_loop._exposure_check_step({"mode": "pilot"}, [], "https://shop.test/") is None
    monkeypatch.setattr(settings, "AGENT_EXPOSURE_CHECK", False, raising=False)
    assert tester_loop._exposure_check_step({"mode": "agent"}, [], "https://shop.test/") is None


def test_pending_exposure_candidates_are_force_verified():
    state = {"engagement_brain": {"candidates": [{
        "id": "c1", "status": "pending", "vulnerability_class": "exposure"}]}}
    step = tester_loop._pending_candidate_verify_step(state, [])
    assert step and step["tool_name"] == "independent_verify"
