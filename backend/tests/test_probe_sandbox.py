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


# --- sandbox_shell ------------------------------------------------------------

from app.services.agent.custom_probe import shell_command_violations


@pytest.mark.parametrize("command,blocked", [
    ("curl -s https://app.example.com/api/me", False),
    ("ffuf -x \"$PROBE_PROXY\" -w /opt/wordlists/app-dirs-common.txt -u https://a/FUZZ", False),
    ("sqlmap -u 'https://a/x?id=1' --batch --proxy=\"$PROBE_PROXY\"", False),
    ("sqlmap -u 'https://a/x?id=1' --os-shell", True),
    ("sqlmap -u x --OS-PWN", True),
    ("sqlmap -u x --dump-all", True),
    ("sqlmap -u x --risk=3", True),
    ("sqlmap -u x --file-write=/tmp/a --file-dest=/var/www/a", True),
    ("hydra -l admin -P list https://a", True),
    ("", True),
])
def test_shell_guard(command, blocked):
    assert bool(shell_command_violations(command)) is blocked


def _shell_manager():
    from app.services.agent.tools import ASMToolsManager

    manager = ASMToolsManager.__new__(ASMToolsManager)
    manager._scoped_policy_applied = False
    manager._fallback_target = "https://app.example.com"
    manager._capability_map = {}
    return manager


def test_sandbox_shell_needs_isolated_mode_and_flag(monkeypatch):
    manager = _shell_manager()
    out = json.loads(asyncio.run(manager.sandbox_shell("curl -s https://app.example.com/")))
    assert out["error"] == "sandbox_shell_disabled"
    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "inprocess")
    monkeypatch.setattr(settings, "AGENT_SANDBOX_SHELL", True)
    out = json.loads(asyncio.run(manager.sandbox_shell("curl -s https://app.example.com/")))
    assert out["error"] == "sandbox_shell_disabled"


def test_sandbox_shell_posts_command_and_records_exchanges(monkeypatch):
    from app.services.agent import custom_probe
    from app.services.agent.evidence_store import evidence_store

    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "isolated")
    monkeypatch.setattr(settings, "AGENT_SANDBOX_SHELL", True)
    sent = {}

    async def fake_relay(job, hosts, timeout, **_policy):
        sent.update(job=job, hosts=hosts, timeout=timeout)
        return {"ok": True, "stdout": "200", "exchanges": [{
            "request": {"method": "GET", "url": "https://app.example.com/", "headers": {}},
            "response": {"status": 200, "headers": {}, "body": "hi", "length": 2},
        }]}

    monkeypatch.setattr(custom_probe, "_post_to_relay", fake_relay)
    manager = _shell_manager()
    out = json.loads(asyncio.run(manager.sandbox_shell("curl -s https://app.example.com/",
                                                        timeout_sec=999)))
    assert sent["job"] == {"command": "curl -s https://app.example.com/"}
    assert sent["hosts"] == ["app.example.com"] and sent["timeout"] == 120.0
    evidence_id = out["exchanges"][0]["evidence_id"]
    assert evidence_store(manager).records[evidence_id]["test_type"] == "custom_probe"


def test_sandbox_shell_refuses_guarded_command_before_network(monkeypatch):
    from app.services.agent import custom_probe

    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "isolated")
    monkeypatch.setattr(settings, "AGENT_SANDBOX_SHELL", True)

    async def boom(*_a, **_k):
        raise AssertionError("guarded command must not reach the relay")

    monkeypatch.setattr(custom_probe, "_post_to_relay", boom)
    out = json.loads(asyncio.run(_shell_manager().sandbox_shell("sqlmap -u x --os-shell")))
    assert out["error"] == "Sandbox rejected command"


# --- SOCKS5 lane for raw TCP ------------------------------------------------------

import struct


def _socks_connect(port, token, host, dest_port, user="job"):
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"\x05\x01\x02")
    assert sock.recv(2) == b"\x05\x02"
    sock.sendall(bytes([1, len(user)]) + user.encode() + bytes([len(token)]) + token.encode())
    if sock.recv(2) != b"\x01\x00":
        sock.close()
        return None, "auth"
    name = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", dest_port))
    reply = sock.recv(10)
    return sock, reply[1]


@pytest.fixture
def socks(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", True)
    server = egress._SocksServer(("127.0.0.1", 0), egress.SocksHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = socket.socket()
    target.bind(("127.0.0.1", 0))
    target.listen(4)

    def serve():
        while True:
            try:
                conn, _ = target.accept()
            except OSError:
                return
            conn.sendall(b"SSH-2.0-test\r\n")
            conn.close()

    threading.Thread(target=serve, daemon=True).start()
    job = {"allowed": ["127.0.0.1"], "oob": [], "log": [], "exchanges": [],
           "recorded_bytes": 0, "dropped": 0, "tcp": {}, "tcp_count": 0}
    egress._jobs["socks-token"] = job
    yield server.server_address[1], target.getsockname()[1], job
    egress._jobs.pop("socks-token", None)
    server.shutdown()
    target.close()


def test_socks_connects_in_scope_and_logs(socks):
    port, target_port, job = socks
    sock, code = _socks_connect(port, "socks-token", "127.0.0.1", target_port)
    assert code == 0
    assert sock.recv(64).startswith(b"SSH-2.0")
    sock.close()
    summary = egress._tcp_summary(job)
    assert summary["connections"] == 1
    assert summary["destinations"][0]["reason"] == "open"


def test_socks_refuses_out_of_scope_and_bad_token(socks):
    port, target_port, job = socks
    _sock, code = _socks_connect(port, "socks-token", "127.0.0.2", target_port)
    assert code == 2
    assert job["tcp"]["127.0.0.2:%d" % target_port]["reason"] == "host not in scope"
    assert _socks_connect(port, "wrong", "127.0.0.1", target_port) == (None, "auth")


def test_socks_connection_budget(socks, monkeypatch):
    port, target_port, job = socks
    monkeypatch.setattr(egress, "MAX_TCP_PER_JOB", 1)
    assert _socks_connect(port, "socks-token", "127.0.0.1", target_port)[1] == 0
    assert _socks_connect(port, "socks-token", "127.0.0.1", target_port)[1] == 2


@pytest.mark.parametrize("command,ok", [
    ("proxychains4 nmap -sT -Pn -sV -p 22,6379 app.example.com", True),
    ("proxychains4 nmap -sT -Pn --script=http-title app.example.com", True),
    ("nmap -sS app.example.com", False),
    ("nmap -sU -p 53 app.example.com", False),
    ("nmap -sT -O app.example.com", False),
    ("masscan -p1-65535 1.2.3.4", False),
    ("proxychains4 nmap -sT --script ssh-brute app.example.com", False),
])
def test_tcp_command_guard(command, ok):
    assert (not shell_command_violations(command)) is ok


def test_socks_resolves_in_scope_hostname(socks):
    port, target_port, job = socks
    job["allowed"].append("localhost")
    sock, code = _socks_connect(port, "socks-token", "localhost", target_port)
    assert code == 0 and sock.recv(64).startswith(b"SSH-2.0")
    sock.close()
    _sock, code = _socks_connect(port, "socks-token", "other.example.net", target_port)
    assert code == 2


def _dual_stack_resolver(name):
    """getaddrinfo that answers `name` IPv6-first, as glibc does for a
    dual-stack /etc/hosts entry (e.g. GitHub's Ubuntu runners for localhost)."""
    real = socket.getaddrinfo

    def fake(host, port, *args, **kwargs):
        if host == name:
            return [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", port, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            ]
        return real(host, port, *args, **kwargs)

    return fake


def test_egress_keeps_every_checked_address_in_resolver_order(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", True)
    monkeypatch.setattr(egress.socket, "getaddrinfo", _dual_stack_resolver("dual.test"))
    assert egress.resolve_checked_all("dual.test", 80, ["dual.test"]) == (["::1", "127.0.0.1"], "")
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", False)
    assert egress.resolve_checked_all("dual.test", 80, ["dual.test"])[0] == []


def test_socks_falls_back_to_ipv4_when_ipv6_is_closed(socks, monkeypatch):
    # The target listens on 127.0.0.1 only; the name resolves to ::1 first.
    port, target_port, job = socks
    monkeypatch.setattr(egress.socket, "getaddrinfo", _dual_stack_resolver("dual.test"))
    job["allowed"].append("dual.test")
    sock, code = _socks_connect(port, "socks-token", "dual.test", target_port)
    assert code == 0 and sock.recv(64).startswith(b"SSH-2.0")
    sock.close()
    assert job["tcp"]["dual.test:%d" % target_port]["reason"] == "open"


# --- operator method policy enforced by probe-egress ---------------------------

import base64 as _b64
from http.server import BaseHTTPRequestHandler as _BaseHandler
from http.server import ThreadingHTTPServer as _HTTPServer


def test_method_policy_parsing_and_decisions():
    assert egress.parse_method_policy(None) is None
    policy = egress.parse_method_policy({"approved_post_paths": ["/cart"],
                                         "approved_delete_paths": ["/cart/1"]})
    allowed = lambda m, t: egress.method_allowed(policy, m, t)[0]  # noqa: E731
    assert allowed("GET", "/anything?x=1") and allowed("HEAD", "/")
    assert allowed("POST", "/cart") and allowed("POST", "/cart?coupon=1")
    assert not allowed("POST", "/checkout")
    assert allowed("DELETE", "/cart/1") and not allowed("DELETE", "/cart")
    assert not allowed("PUT", "/cart") and not allowed("PATCH", "/cart")
    assert egress.method_allowed(None, "PUT", "/x") == (True, "")
    for bad in ({"approved_post_paths": "/cart"}, {"approved_post_paths": ["cart"]},
                {"approved_post_paths": ["/a?b"]}, "nope"):
        with pytest.raises(ValueError):
            egress.parse_method_policy(bad)


@pytest.fixture
def policy_proxy(monkeypatch):
    monkeypatch.setattr(egress, "ALLOW_PRIVATE", True)
    seen = []

    class Target(_BaseHandler):
        def log_message(self, *a):
            pass

        def _reply(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            seen.append((self.command, self.path))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        do_GET = do_POST = do_PUT = do_DELETE = _reply

    target = _HTTPServer(("127.0.0.1", 0), Target)
    proxy = _HTTPServer(("127.0.0.1", 0), egress.ProxyHandler)
    for server in (target, proxy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    job = {"allowed": ["127.0.0.1"], "oob": [], "log": [], "exchanges": [],
           "recorded_bytes": 0, "dropped": 0, "tcp": {}, "tcp_count": 0,
           "policy": egress.parse_method_policy({"approved_post_paths": ["/cart"]})}
    egress._jobs["policy-token"] = job
    yield proxy.server_address[1], target.server_address[1], job, seen
    egress._jobs.pop("policy-token", None)
    target.shutdown()
    proxy.shutdown()


def _via_proxy(proxy_port, target_port, method, path):
    auth = _b64.b64encode(b"job:policy-token").decode()
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    sock.sendall((f"{method} http://127.0.0.1:{target_port}{path} HTTP/1.1\r\n"
                  f"Host: 127.0.0.1:{target_port}\r\nProxy-Authorization: Basic {auth}\r\n"
                  "Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
    data = b""
    while chunk := sock.recv(4096):
        data += chunk
    sock.close()
    return int(data.split(b" ", 2)[1])


def test_egress_enforces_method_policy_end_to_end(policy_proxy):
    proxy_port, target_port, job, seen = policy_proxy
    assert _via_proxy(proxy_port, target_port, "GET", "/catalog?q=1") == 200
    assert _via_proxy(proxy_port, target_port, "POST", "/cart") == 200
    assert _via_proxy(proxy_port, target_port, "POST", "/checkout") == 403
    assert _via_proxy(proxy_port, target_port, "PUT", "/cart") == 403
    # Denied writes never reach the target.
    assert ("POST", "/checkout") not in seen and ("PUT", "/cart") not in seen
    denied = [e for e in job["log"] if e.get("allowed") is False]
    assert any("operator-approved" in e.get("reason", "") for e in denied)


def test_socks_lane_closed_under_method_policy(socks):
    port, target_port, job = socks
    job["policy"] = egress.parse_method_policy({})
    _sock, code = _socks_connect(port, "socks-token", "127.0.0.1", target_port)
    assert code == 2
    assert "method policy" in job["tcp"]["127.0.0.1:%d" % target_port]["reason"]


def test_sandbox_shell_runs_under_policy_and_sends_it(monkeypatch):
    from app.services.agent import custom_probe

    monkeypatch.setattr(settings, "AGENT_CUSTOM_PROBE_MODE", "isolated")
    monkeypatch.setattr(settings, "AGENT_SANDBOX_SHELL", True)
    sent = {}

    async def fake_relay(job, hosts, timeout_sec, *, method_policy=None, oob_allowed=True):
        sent.update(method_policy=method_policy, oob_allowed=oob_allowed)
        return {"ok": True, "stdout": "", "exchanges": []}

    monkeypatch.setattr(custom_probe, "_post_to_relay", fake_relay)
    manager = _shell_manager()
    manager._scoped_policy_applied = True
    manager._scoped_body_replay_paths = {"/cart"}
    manager._scoped_race_action_paths = set()
    manager._scoped_csrf_action_paths = set()
    manager._scoped_auth_login_path = ""
    manager._scoped_stored_xss_cleanup_paths = set()
    manager._scoped_race_cleanup_paths = set()
    manager._scoped_csrf_cleanup_paths = set()
    manager._oob_callbacks_allowed = False
    out = json.loads(asyncio.run(manager.sandbox_shell("curl -s https://app.example.com/")))
    assert "error" not in out, out
    assert sent["method_policy"] == {"approved_post_paths": ["/cart"], "approved_delete_paths": []}
    assert sent["oob_allowed"] is False


def test_runner_reports_an_immutable_toolbox_identity():
    """The runner builds a fingerprint over its image ref and executables, so a
    tool added mid-job would change it. See probe_sandbox/runner.py."""
    import importlib.util
    import os

    path = os.path.join(os.path.dirname(__file__), "..", "probe_sandbox", "runner.py")
    spec = importlib.util.spec_from_file_location("probe_runner_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    os.environ["PROBE_IMAGE_REF"] = "asm-probe-runner@sha256:test"
    os.environ.setdefault("PROBE_RUNNER_TOKEN", "x" * 24)
    spec.loader.exec_module(mod)

    identity = mod.RUNNER_IDENTITY
    assert identity["image_ref"] == "asm-probe-runner@sha256:test"
    assert len(identity["fingerprint"]) == 64
    assert "bash" in identity["tools"] and "python3" in identity["tools"]
    # Rebuilding with the same image yields the same fingerprint; a different
    # image reference changes it.
    assert mod._build_identity()["fingerprint"] == identity["fingerprint"]
    # IMAGE_REF is read once at startup (immutable for the process); a different
    # pinned image would produce a different fingerprint.
    mod.IMAGE_REF = "other"
    assert mod._build_identity()["fingerprint"] != identity["fingerprint"]


def test_egress_caps_each_job_at_its_reserved_requests(policy_proxy):
    """The backend reserves a block from the run ceiling; the relay sends at
    most that many requests and counts only those it actually sent."""
    proxy_port, target_port, job, seen = policy_proxy
    job.update(max_requests=2, sent=0)
    assert _via_proxy(proxy_port, target_port, "GET", "/a") == 200
    assert _via_proxy(proxy_port, target_port, "POST", "/checkout") == 403  # refused, not counted
    assert _via_proxy(proxy_port, target_port, "GET", "/b") == 200
    assert _via_proxy(proxy_port, target_port, "GET", "/c") == 429
    assert job["sent"] == 2 and ("GET", "/c") not in seen


def test_socks_connections_count_against_the_job_cap(socks):
    port, target_port, job = socks
    job.update(max_requests=1, sent=0)
    assert _socks_connect(port, "socks-token", "127.0.0.1", target_port)[1] == 0
    assert _socks_connect(port, "socks-token", "127.0.0.1", target_port)[1] == 2
    assert job["sent"] == 1


def test_relay_jobs_reserve_and_refund_the_run_budget(monkeypatch):
    import asyncio

    from app.services.agent import custom_probe
    from app.services.agent import request_budget as rb

    budget = rb.RequestBudget(limit=150, reserve=0)
    token = rb.current_request_budget.set(budget)
    sent_payloads = []

    async def fake_once(job, hosts, timeout_sec, **kw):
        sent_payloads.append(job)
        return {"ok": True, "requests_sent": 7}

    monkeypatch.setattr(custom_probe, "_post_to_relay_once", fake_once)
    try:
        first = asyncio.run(custom_probe._post_to_relay({"command": "id"}, ["t"], 10))
        assert sent_payloads[0]["max_requests"] == rb.SANDBOX_JOB_REQUESTS
        assert first["requests_metered"] == 7 and budget.used == 7
        # Only 143 left: the next job is capped at what remains.
        budget.used = 145
        asyncio.run(custom_probe._post_to_relay({"command": "id"}, ["t"], 10))
        # Granted 5; the relay claims 7 but can only have sent the 5 it was allowed.
        assert sent_payloads[1]["max_requests"] == 5 and budget.used == 150
        budget.used = 150
        refused = asyncio.run(custom_probe._post_to_relay({"command": "id"}, ["t"], 10))
        assert refused["error"] == "request_ceiling_reached" and len(sent_payloads) == 2
    finally:
        rb.current_request_budget.reset(token)


def test_relay_without_a_count_is_charged_in_full(monkeypatch):
    import asyncio

    from app.services.agent import custom_probe
    from app.services.agent import request_budget as rb

    budget = rb.RequestBudget(limit=500, reserve=0)
    token = rb.current_request_budget.set(budget)

    async def old_relay(job, hosts, timeout_sec, **kw):
        return {"ok": True, "requests_sent": None}

    monkeypatch.setattr(custom_probe, "_post_to_relay_once", old_relay)
    try:
        asyncio.run(custom_probe._post_to_relay({"command": "id"}, ["t"], 10))
        assert budget.used == rb.SANDBOX_JOB_REQUESTS
    finally:
        rb.current_request_budget.reset(token)
