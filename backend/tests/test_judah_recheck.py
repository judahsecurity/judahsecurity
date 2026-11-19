"""Judah Recheck replays a finding's stored proof recipe against a live app."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_plus, urlsplit

import pytest

from app.services.agent.judah_recheck import (
    append_history, as_validation_verdict, classify, publishable, recheck, recipe_for_finding, remember,
)


class _App(BaseHTTPRequestHandler):
    vulnerable = True
    flaky = False
    calls = 0

    def do_GET(self):  # noqa: N802
        _App.calls += 1
        q = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        raw = unquote_plus((q.get("id") or [""])[0])
        body = "item 7"
        if _App.vulnerable and " AND " in raw:
            left, right = raw.split(" AND ", 1)[1].split("=")
            body = "item 7" if left == right else "no rows"
        if _App.flaky:
            body += f" {_App.calls}"
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture()
def app_url(monkeypatch):
    monkeypatch.setenv("AEGIS_ALLOW_INSECURE_TLS", "1")
    _App.vulnerable, _App.flaky, _App.calls = True, False, 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _App)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _recipe(base):
    return {"version": 1, "recipe": "numeric_and_boolean_v1", "baseline": f"{base}/item?id=7",
            "parameter": "id", "identity": "anonymous", "target": f"{base}/item"}


def test_only_safe_supported_anonymous_recipes_are_stored():
    good = _recipe("https://shop.test")
    assert publishable(good)["recipe"] == "numeric_and_boolean_v1"
    assert publishable({**good, "identity": "alice"}) is None
    assert publishable({**good, "recipe": "string_time_v1"}) is None
    assert publishable({**good, "baseline": "https://shop.test/item?id=7&token=ghp_" + "a" * 36}) is None
    tm = type("TM", (), {})()
    remember(tm, "ev1", {"proof_confirmed": True, "proof_recipe": "numeric_and_boolean_v1", "target": "t"},
             baseline=good["baseline"], parameter="id", identity="anonymous")
    remember(tm, "ev2", {"proof_confirmed": False, "proof_recipe": "numeric_and_boolean_v1"},
             baseline=good["baseline"], parameter="id", identity="anonymous")
    assert set(tm._recheck_recipes) == {"ev1"}
    assert recipe_for_finding(tm._recheck_recipes, ["other", "ev1"])["baseline"] == good["baseline"]


@pytest.mark.asyncio
async def test_still_vulnerable_app_is_still_reproducible(app_url):
    record = await recheck(_recipe(app_url), finding_id=42)
    assert record["outcome"] == "still_reproducible" and record["requests_sent"] == 6
    verdict = as_validation_verdict(record)
    assert verdict["verdict"] == "confirmed" and verdict["recheck_outcome"] == "still_reproducible"


@pytest.mark.asyncio
async def test_patched_app_is_fixed(app_url):
    _App.vulnerable = False
    record = await recheck(_recipe(app_url), finding_id=42)
    assert record["outcome"] == "fixed"
    assert as_validation_verdict(record)["verdict"] == "false_positive"


@pytest.mark.asyncio
async def test_unstable_app_cannot_be_confirmed(app_url):
    _App.vulnerable, _App.flaky = False, True
    assert (await recheck(_recipe(app_url)))["outcome"] == "cannot_confirm"


@pytest.mark.asyncio
async def test_missing_recipe_or_network_error_cannot_confirm():
    assert (await recheck(None))["outcome"] == "cannot_confirm"
    record = await recheck(_recipe("http://127.0.0.1:9"))
    assert record["outcome"] == "cannot_confirm" and "Replay could not run" in record["reason"]


def test_history_keeps_original_metadata():
    meta = {"verification": {"evidence": "original"}, "trace": {"candidate_id": "c1"}}
    out = append_history(meta, {"outcome": "fixed", "at": 1.0, "checks": {"big": 1}})
    assert out["verification"] == meta["verification"] and out["trace"] == meta["trace"]
    assert out["recheck_history"] == [{"outcome": "fixed", "at": 1.0}]
    assert "recheck_history" not in meta


def test_classify_requires_stable_successful_baseline():
    ok = {"status": 200, "redirected": False, "truncated": False, "body_sha256": "a" * 64}
    rows = {k: dict(ok) for k in ("baseline_first", "true_first", "baseline_last")}
    assert classify({"proof_confirmed": False, "checks": rows})[0] == "fixed"
    rows["true_first"]["status"] = 500
    assert classify({"proof_confirmed": False, "checks": rows})[0] == "cannot_confirm"
