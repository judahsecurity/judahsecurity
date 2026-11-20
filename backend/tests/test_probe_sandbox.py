"""Custom-probe execution modes and the probe-egress scope checks."""

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.services.agent.custom_probe import custom_probe_mode, run_custom_probe_isolated

_EGRESS_PATH = Path(__file__).resolve().parents[1] / "probe_sandbox" / "egress.py"
_spec = importlib.util.spec_from_file_location("probe_egress", _EGRESS_PATH)
egress = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(egress)


def test_probe_mode_defaults_off_and_fails_closed(monkeypatch):
    assert settings.AGENT_CUSTOM_PROBE_MODE == "off"
    assert custom_probe_mode() == "off"
    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "sandbox-please")
    assert custom_probe_mode() == "off"
    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "Isolated")
    assert custom_probe_mode() == "isolated"


def test_disabled_tool_refuses_without_running(monkeypatch):
    from app.services.agent import custom_probe
    from app.services.agent.tools import ASMToolsManager

    def boom(*_args, **_kwargs):
        raise AssertionError("probe must not run while disabled")

    monkeypatch.setattr(custom_probe, "run_custom_probe_async", boom)
    monkeypatch.setattr(custom_probe, "run_custom_probe_isolated", boom)
    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._scoped_policy_applied = False
    out = json.loads(asyncio.run(manager.run_custom_probe("print(1)", allowed_hosts="example.com")))
    assert out["error"] == "custom_probe_disabled"


def test_isolated_client_requires_configuration(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_TOKEN", "")
    out = asyncio.run(run_custom_probe_isolated("print(1)", allowed_hosts=["example.com"]))
    assert out["ok"] is False and "not configured" in out["error"]


def test_isolated_client_still_applies_source_checks(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_TOKEN", "t" * 30)
    out = asyncio.run(run_custom_probe_isolated("import os", allowed_hosts=["example.com"]))
    assert out["error"] == "Sandbox rejected source"


def test_specialists_lose_probe_tools_when_off():
    from app.services.agent import fireteam_service

    source = Path(fireteam_service.__file__).read_text()
    assert 'if custom_probe_mode() == "off":' in source


@pytest.mark.parametrize("host,expected", [
    ("app.example.com", True),
    ("deep.app.example.com", True),
    ("APP.EXAMPLE.COM.", True),
    ("example.com", False),
    ("evil-app.example.com", False),
    ("abc.oast.fun", True),
    ("localhost", False),
    ("", False),
])
def test_egress_host_scope(host, expected):
    assert egress.host_in_scope(host, ["app.example.com"], ["oast.fun"]) is expected


def test_egress_blocks_private_and_unlisted_ips(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", False)
    assert egress.resolve_checked("10.0.0.5", 80, ["app.example.com"])[0] is None
    assert egress.resolve_checked("169.254.169.254", 80, ["169.254.169.254"])[0] is None
    assert egress.resolve_checked("127.0.0.1", 80, ["127.0.0.1"])[0] is None
    assert egress.resolve_checked("8.8.8.8", 443, ["8.8.8.8"]) == ("8.8.8.8", "")


def test_egress_rejects_names_resolving_only_private(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", False)
    monkeypatch.setattr(egress.socket, "getaddrinfo",
                        lambda *a, **k: [(2, 1, 6, "", ("192.168.1.10", 80))])
    ip, reason = egress.resolve_checked("app.example.com", 80, ["app.example.com"])
    assert ip is None and "non-public" in reason


def test_egress_job_credential_lookup():
    egress._jobs["tok123"] = {"allowed": ["a.example"], "oob": [], "log": []}
    try:
        import base64

        good = "Basic " + base64.b64encode(b"job:tok123").decode()
        bad = "Basic " + base64.b64encode(b"job:nope").decode()
        assert egress._job_for(good)[1] is egress._jobs["tok123"]
        assert egress._job_for(bad) == (None, None)
        assert egress._job_for(None) == (None, None)
    finally:
        egress._jobs.pop("tok123", None)


# --- recording proxy: parsing, CA, evidence -----------------------------------

import gzip
import io
import socket
import ssl
import threading


def _msg(raw: bytes, **kwargs):
    return egress.read_message(io.BufferedReader(io.BytesIO(raw)), **kwargs)


def test_parse_content_length_request():
    msg = _msg(b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
    assert msg.start == "POST /a HTTP/1.1" and msg.body == b"hello"


def test_parse_chunked_response_keeps_raw_and_decodes():
    raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"
    msg = _msg(raw, response=True)
    assert msg.body == b"abcde"
    assert msg.raw_body.startswith(b"3\r\nabc")


def test_parse_response_without_length_reads_to_eof():
    msg = _msg(b"HTTP/1.1 200 OK\r\n\r\nuntil-close", response=True)
    assert msg.body == b"until-close"


def test_parse_head_and_204_have_no_body():
    assert _msg(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n", response=True,
                request_method="HEAD").body == b""
    assert _msg(b"HTTP/1.1 204 No Content\r\n\r\n", response=True).body == b""


def test_parse_rejects_oversized_head():
    with pytest.raises(ValueError):
        _msg(b"GET / HTTP/1.1\r\nX: " + b"a" * (egress.MAX_HEAD_BYTES + 10) + b"\r\n\r\n")


def test_serialize_forces_connection_close_and_strips_proxy_headers():
    out = egress._serialize("GET / HTTP/1.1", [("Host", "x"), ("Proxy-Authorization", "Basic z"),
                                                ("Connection", "keep-alive")], b"")
    assert b"Proxy-Authorization" not in out and b"keep-alive" not in out
    assert out.endswith(b"Connection: close\r\n\r\n")


def test_gzip_bodies_are_recorded_decoded():
    body, note = egress._decoded(gzip.compress(b'{"error":"near ORDER BY"}'), "gzip")
    assert body == b'{"error":"near ORDER BY"}' and note == ""
    assert egress._decoded(b"x", "br")[1] == "stored still br-encoded"


def test_binary_bodies_are_not_stored_as_text():
    rec = egress._body_record(b"\x89PNG\r\n\x1a\n\xff\xfe", "image/png")
    assert rec["binary"] is True and rec["body"] == ""
    big = egress._body_record(b"a" * (egress.MAX_RECORDED_BODY + 1), "text/plain")
    assert big["truncated"] is True and len(big["body"]) == egress.MAX_RECORDED_BODY


def test_leaf_certificate_passes_strict_client_verification(tmp_path):
    ca = egress.CertificateAuthority()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text(ca.cert_pem)
    client_ctx = ssl.create_default_context(cafile=str(ca_file))
    client_ctx.verify_flags |= getattr(ssl, "VERIFY_X509_STRICT", 0)
    server_sock, client_sock = socket.socketpair()
    errors = []

    def serve():
        try:
            tls = ca.context_for("app.example.com").wrap_socket(server_sock, server_side=True)
            tls.sendall(b"ok")
            tls.close()
        except Exception as exc:  # surfaced through the client assertion
            errors.append(exc)

    thread = threading.Thread(target=serve)
    thread.start()
    tls = client_ctx.wrap_socket(client_sock, server_hostname="app.example.com")
    assert tls.recv(2) == b"ok"
    assert tls.selected_alpn_protocol() in (None, "http/1.1")
    tls.close()
    thread.join(5)
    assert not errors


def test_leaf_certificate_is_rejected_for_another_host(tmp_path):
    ca = egress.CertificateAuthority()
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text(ca.cert_pem)
    client_ctx = ssl.create_default_context(cafile=str(ca_file))
    server_sock, client_sock = socket.socketpair()
    thread = threading.Thread(target=lambda: _quiet_accept(ca, server_sock))
    thread.start()
    with pytest.raises(ssl.SSLCertVerificationError):
        client_ctx.wrap_socket(client_sock, server_hostname="other.example.com")
    client_sock.close()
    thread.join(5)


def _quiet_accept(ca, sock):
    try:
        ca.context_for("app.example.com").wrap_socket(sock, server_side=True)
    except (ssl.SSLError, OSError):
        pass


def test_probe_exchanges_become_redacted_evidence():
    from app.services.agent.evidence_store import evidence_store
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    index = manager._record_probe_exchanges([{
        "request": {"method": "GET", "url": "https://app.example.com/u/7",
                    "headers": {"Authorization": "Bearer abc.def.ghi"}, "body": "", "length": 0},
        "response": {"status": 200, "url": "https://app.example.com/u/7",
                     "headers": {"Content-Type": "application/json"},
                     "body": '{"user":"bob"}', "length": 14},
    }])
    assert index[0]["status"] == 200 and index[0]["url"].endswith("/u/7")
    record = evidence_store(manager).records[index[0]["evidence_id"]]
    assert record["kind"] == "http_exchange" and record["test_type"] == "custom_probe"
    assert record["payload"]["request"]["headers"]["Authorization"] == "[redacted]"
    assert '"bob"' in record["payload"]["response"]["body"]
