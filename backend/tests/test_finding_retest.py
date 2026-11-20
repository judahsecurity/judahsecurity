"""Retest an existing finding: reproduced, fixed, or inconclusive."""

import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.models.vulnerability import VulnerabilityStatus
from app.services import finding_retest_service as retest
from app.services.agent.demonstrated_chain import parse_args
from app.services.agent.tools import ASMToolsManager

TARGET = "https://shop.example.test"


def _step(tool, **args):
    return {"tool": tool, "args": parse_args(args)}


def _finding(*steps):
    payload = {"id": 7, "organization_id": 1, "detected_by": "agent",
               "asset": "shop.example.test", "target": TARGET}
    metadata = {"agent_detection": {"chain": list(steps)}}
    return payload, metadata


def _control(monkeypatch, status=200, ok=True):
    def probe(url):
        return {"url": url, "ok": ok, "status": status,
                "normal": ok and status < 500 and status not in (401, 403, 407, 429)}

    monkeypatch.setattr(retest, "_control", lambda origin: probe(origin + "/"))
    # The proof page itself is re-observed first; keep it answering normally.
    monkeypatch.setattr(retest, "_control_url", lambda url: probe(url) | {"normal": True})


def _sqli(monkeypatch, *, confirmed=None, inconclusive=False, error=None):
    calls = []

    async def fake(self, url="", parameter="", identity="anonymous", artifact_id=""):
        calls.append({"url": url, "parameter": parameter, "identity": identity})
        if error:
            raise error
        data = {"proof_confirmed": confirmed, "requests_sent": 6, "evidence_id": "e" * 32}
        if inconclusive:
            data["inconclusive"] = True
        return json.dumps(data)

    monkeypatch.setattr(ASMToolsManager, "scoped_numeric_sqli", fake)
    return calls


def test_stored_arguments_round_trip():
    argv = parse_args({"url": f"{TARGET}/item?id=1", "parameter": "id"})
    assert retest.argv_to_kwargs(argv) == {"url": f"{TARGET}/item?id=1", "parameter": "id"}


def test_only_anonymous_url_proofs_are_replayable():
    steps, skipped = retest.replayable_steps({"chain": [
        _step("scoped_numeric_sqli", url=f"{TARGET}/item?id=1", parameter="id"),
        _step("scoped_numeric_sqli", artifact_id="a" * 32, parameter="id"),
        _step("scoped_string_sqli", url=f"{TARGET}/s?q=x", parameter="q", identity="alice"),
        _step("scoped_browser_assessment", operation="map", url=TARGET),
        _step("scoped_browser_assessment", operation="check_xss", url=f"{TARGET}/s?q=x"),
        _step("scoped_numeric_sqli", url="https://other.test/x?id=1", parameter="id"),
        _step("execute_curl", url=TARGET),
    ]}, asset_host="shop.example.test")
    assert [(s["tool"], s["kwargs"].get("operation")) for s in steps] == [
        ("scoped_numeric_sqli", None), ("scoped_browser_assessment", "check_xss"),
    ]
    assert len(skipped) == 3
    assert any("session-only capture" in reason for reason in skipped)
    assert any("'alice'" in reason for reason in skipped)
    assert any("other.test" in reason for reason in skipped)


@pytest.mark.asyncio
async def test_reproduced_when_the_proof_fires_again(monkeypatch):
    _control(monkeypatch)
    calls = _sqli(monkeypatch, confirmed=True)
    payload, metadata = _finding(
        _step("scoped_numeric_sqli", url=f"{TARGET}/item?id=1", parameter="id"))
    result = await retest.retest_finding(payload, metadata)
    assert result["retest_verdict"] == "reproduced"
    assert result["verdict"] == "confirmed" and result["still_open"] is True
    assert calls == [{"url": f"{TARGET}/item?id=1", "parameter": "id", "identity": "anonymous"}]


@pytest.mark.asyncio
async def test_fixed_needs_a_clean_negative_and_a_normal_control(monkeypatch):
    _control(monkeypatch, status=200)
    _sqli(monkeypatch, confirmed=False)
    payload, metadata = _finding(
        _step("scoped_numeric_sqli", url=f"{TARGET}/item?id=1", parameter="id"))
    result = await retest.retest_finding(payload, metadata)
    assert result["retest_verdict"] == "fixed"
    assert result["verdict"] == "fixed" and result["still_open"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("control_status,kwargs,reason", [
    (503, {"confirmed": False}, "control"),
    (403, {"confirmed": False}, "control"),
    (200, {"confirmed": False, "inconclusive": True}, "inconclusive"),
    (200, {"error": ValueError("page gone")}, "could not run"),
])
async def test_a_failed_trigger_alone_is_not_a_fix(monkeypatch, control_status, kwargs, reason):
    _control(monkeypatch, status=control_status)
    _sqli(monkeypatch, **kwargs)
    payload, metadata = _finding(
        _step("scoped_numeric_sqli", url=f"{TARGET}/item?id=1", parameter="id"))
    result = await retest.retest_finding(payload, metadata)
    assert result["retest_verdict"] == "inconclusive"
    assert reason in result["reasoning"]


@pytest.mark.asyncio
async def test_signed_in_proof_is_inconclusive_without_requests(monkeypatch):
    calls = _sqli(monkeypatch, confirmed=True)
    payload, metadata = _finding(
        _step("scoped_numeric_sqli", url=f"{TARGET}/item?id=1", parameter="id", identity="alice"))
    result = await retest.retest_finding(payload, metadata)
    assert result["retest_verdict"] == "inconclusive"
    assert calls == []


@pytest.mark.asyncio
async def test_port_findings_use_the_nmap_state(monkeypatch):
    async def fake_port(finding):
        return {"port_state": "closed", "method": "nmap_port_verify", "port": 9200,
                "reasoning": "closed", "evidence": "nmap_state=closed"}

    monkeypatch.setattr("app.services.finding_revalidation_service.revalidate_port_exposure",
                        fake_port)
    result = await retest.retest_finding(
        {"detected_by": "port_scanner", "asset": "db.example.test"}, {})
    assert result["retest_verdict"] == "fixed"
    assert result["port_check_method"] == "nmap_port_verify"


@pytest.mark.asyncio
async def test_no_replayable_proof_is_inconclusive():
    result = await retest.retest_finding({"detected_by": "manual", "asset": "x.test"}, {})
    assert result["retest_verdict"] == "inconclusive"
    assert result["method"] == "no_replayable_proof"


@pytest.mark.parametrize("verdict,before,after", [
    ("fixed", VulnerabilityStatus.OPEN, VulnerabilityStatus.RESOLVED),
    ("fixed", VulnerabilityStatus.ACCEPTED, VulnerabilityStatus.ACCEPTED),
    ("reproduced", VulnerabilityStatus.RESOLVED, VulnerabilityStatus.OPEN),
    ("reproduced", VulnerabilityStatus.OPEN, VulnerabilityStatus.OPEN),
    ("inconclusive", VulnerabilityStatus.OPEN, VulnerabilityStatus.OPEN),
    ("inconclusive", VulnerabilityStatus.RESOLVED, VulnerabilityStatus.RESOLVED),
])
def test_status_moves_only_on_a_decisive_retest(verdict, before, after):
    vuln = SimpleNamespace(status=before, resolved_at=None, metadata_={"keep": 1})
    retest.apply_retest_status(vuln, {"retest_verdict": verdict, "method": "m"},
                               validation_id=3, now=datetime(2026, 11, 20))
    assert vuln.status == after
    assert vuln.metadata_["keep"] == 1
    assert vuln.metadata_["last_retest"]["verdict"] == verdict
    assert vuln.metadata_["last_retest"]["status_after"] == after.value


# ---------------------------------------------------------------------------
# End to end: the real numeric SQLi proof against a local vulnerable / patched app
# ---------------------------------------------------------------------------


def _item_server(vulnerable: bool, waf: bool = False):
    import re
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, unquote, urlsplit

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            parts = urlsplit(self.path)
            raw = unquote(parse_qs(parts.query).get("id", [""])[0])
            match = re.fullmatch(r"(\d+)(?: AND (\d+)=(\d+))?", raw)
            if parts.path == "/":
                body, status = b"home", 200
            elif waf and " AND " in raw:
                body, status = b"blocked", 403
            elif not match:
                body, status = b"bad id", 400
            elif match.group(2) and not vulnerable:
                body, status = b"bad id", 400
            elif match.group(2) and match.group(2) != match.group(3):
                body, status = b"no such item", 200
            else:
                body, status = f"item {match.group(1)}".encode() * 20, 200
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,waf,expected", [
    (True, False, "reproduced"),
    (False, False, "fixed"),
    (True, True, "inconclusive"),  # a WAF in front is not a fix
])
async def test_real_numeric_sqli_replay(vulnerable, waf, expected):
    server = _item_server(vulnerable, waf)
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        payload = {"id": 9, "organization_id": 1, "detected_by": "agent",
                   "asset": "127.0.0.1", "target": base}
        metadata = {"agent_detection": {"chain": [
            _step("scoped_numeric_sqli", url=f"{base}/item?id=3", parameter="id"),
        ]}}
        result = await retest.retest_finding(payload, metadata)
    finally:
        server.shutdown()
    assert result["retest_verdict"] == expected, result["reasoning"]
