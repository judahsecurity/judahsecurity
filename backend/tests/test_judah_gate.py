"""Judah Gate: per-run scope, pacing, backoff and request caps, over real sockets."""

import asyncio
import datetime as dt
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services.agent import action_ledger, judah_gate
from app.services.agent.judah_gate import HostPacer, JudahGate, Pace, cli_gate_tokens, registry


class _Handler(BaseHTTPRequestHandler):
    statuses: dict = {}
    hits: list = []

    def do_GET(self):  # noqa: N802
        _Handler.hits.append(self.path)
        status = _Handler.statuses.get(self.path, 200)
        body = f"hello {self.path}".encode()
        self.send_response(status)
        if status == 429:
            self.send_header("Retry-After", "7")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "up.pem", tmp_path / "up.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cert_path, key_path


@pytest.fixture()
def upstreams(tmp_path):
    _Handler.statuses, _Handler.hits = {}, []
    plain = _serve(ThreadingHTTPServer(("127.0.0.1", 0), _Handler))
    cert_path, key_path = _self_signed(tmp_path)
    tls = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    tls.socket = ctx.wrap_socket(tls.socket, server_side=True)
    _serve(tls)
    yield plain.server_address[1], tls.server_address[1], cert_path
    plain.shutdown()
    tls.shutdown()


@pytest_asyncio.fixture()
async def gate(tmp_path, upstreams, monkeypatch):
    monkeypatch.setenv("JUDAH_GATE_CA_DIR", str(tmp_path / "ca"))
    registry.reset()
    g = JudahGate(upstream_verify=str(upstreams[2]), ca_directory=tmp_path / "ca")
    host, port = await g.start("127.0.0.1", 0)
    judah_gate._RUNNING.update(server=g, address=(host, port))
    yield host, port
    judah_gate._RUNNING.clear()
    registry.reset()
    await g.close()


def _client(lease, port, verify=True):
    return httpx.AsyncClient(proxies=f"http://{lease.token}:x@127.0.0.1:{port}", verify=verify,
                             trust_env=False, timeout=10)


@pytest.mark.asyncio
async def test_requires_credentials_and_enforces_scope(gate, upstreams):
    _, port = gate
    plain_port = upstreams[0]
    async with httpx.AsyncClient(proxies=f"http://127.0.0.1:{port}", trust_env=False) as anon:
        r = await anon.get(f"http://127.0.0.1:{plain_port}/a")
        assert r.status_code == 407
    lease = registry.open("run-1", ["localhost"], pace=Pace(100, 100, 4), max_requests=0)
    async with _client(lease, port) as client:
        r = await client.get(f"http://127.0.0.1:{plain_port}/a")
        assert r.status_code == 403 and r.headers["x-judah-gate"] == "scope"
    assert _Handler.hits == [] and lease.denied_scope == 1


@pytest.mark.asyncio
async def test_plain_and_tls_requests_are_forwarded_and_counted(gate, upstreams, tmp_path):
    _, port = gate
    plain_port, tls_port, _ = upstreams
    lease = registry.open("run-2", ["localhost"], pace=Pace(100, 100, 4), max_requests=0)
    from app.services.agent.judah_gate_ca import ca_cert_path

    async with _client(lease, port, verify=str(ca_cert_path())) as client:
        r1 = await client.get(f"http://localhost:{plain_port}/plain")
        r2 = await client.get(f"https://localhost:{tls_port}/secure")
        r3 = await client.get(f"https://localhost:{tls_port}/again")  # keep-alive inside the tunnel
    assert (r1.status_code, r1.text) == (200, "hello /plain")
    assert (r2.status_code, r2.text) == (200, "hello /secure")
    assert r3.text == "hello /again"
    assert lease.requests == 3 and lease.by_host["localhost"] == 3


@pytest.mark.asyncio
async def test_https_connect_out_of_scope_is_refused(gate, upstreams):
    _, port = gate
    lease = registry.open("run-3", ["app.acme.test"], pace=Pace(100, 100, 4), max_requests=0)
    async with _client(lease, port) as client:
        with pytest.raises(httpx.ProxyError):
            await client.get(f"https://localhost:{upstreams[1]}/x")
    assert lease.denied_scope == 1 and _Handler.hits == []


@pytest.mark.asyncio
async def test_request_budget_and_target_backoff(gate, upstreams):
    _, port = gate
    plain_port = upstreams[0]
    _Handler.statuses["/slow"] = 429
    lease = registry.open("run-4", ["localhost"], pace=Pace(100, 100, 4), max_requests=2)
    async with _client(lease, port) as client:
        assert (await client.get(f"http://localhost:{plain_port}/slow")).status_code == 429
        pacer = lease.pacer("localhost")
        assert lease.backoffs == 1 and pacer.wait_needed() > 5  # Retry-After: 7 honoured
        pacer.backoff_until = 0
        assert (await client.get(f"http://localhost:{plain_port}/ok")).status_code == 200
        r = await client.get(f"http://localhost:{plain_port}/third")
        assert r.status_code == 429 and r.headers["x-judah-gate"] == "request-budget"
    assert _Handler.hits == ["/slow", "/ok"] and lease.budget_exhausted


@pytest.mark.asyncio
async def test_token_bucket_paces_and_gives_up_past_max_wait():
    now = [0.0]
    pacer = HostPacer(Pace(rps=2.0, burst=1, inflight=1), clock=lambda: now[0])
    assert (await pacer.acquire())[0]
    assert pacer.wait_needed() == pytest.approx(0.5)
    pacer.backoff_until = 100.0
    ok, waited = await pacer.acquire(max_wait=1.0)
    assert not ok and waited == 0
    assert pacer.note_status(503) > 0 and pacer.strikes == 1
    assert pacer.note_status(200) == 0 and pacer.strikes == 0


def test_cli_tools_get_the_run_lease_and_cannot_pick_their_own_proxy(tmp_path, monkeypatch):
    monkeypatch.setenv("JUDAH_GATE_CA_DIR", str(tmp_path / "ca"))
    registry.reset()
    judah_gate._RUNNING.update(server=object(), address=("127.0.0.1", 8899))
    lease = registry.open("run-cli", ["app.acme.test"])
    token = action_ledger.active_run_id.set("run-cli")
    try:
        tokens = cli_gate_tokens("execute_nuclei", ["-u", "https://app.acme.test"])
        assert tokens == ["-proxy", f"http://{lease.token}:x@127.0.0.1:8899"]
        assert "--cacert" in cli_gate_tokens("execute_curl", [])
        assert cli_gate_tokens("execute_nmap", []) == []
        with pytest.raises(judah_gate.GateConflict):
            cli_gate_tokens("execute_ffuf", ["-x", "http://evil:8080"])
    finally:
        action_ledger.active_run_id.reset(token)
        judah_gate._RUNNING.clear()
        registry.reset()


def test_assessment_proxy_helpers_follow_the_lease(tmp_path, monkeypatch):
    from app.services.agent import assessment_proxy

    monkeypatch.setenv("JUDAH_GATE_CA_DIR", str(tmp_path / "ca"))
    monkeypatch.delenv("AEGIS_ASSESSMENT_PROXY_URL", raising=False)
    assert assessment_proxy.assessment_proxy_url() is None
    registry.reset()
    judah_gate._RUNNING.update(server=object(), address=("127.0.0.1", 8899))
    lease = registry.open("run-px", ["app.acme.test"])
    token = action_ledger.active_run_id.set("run-px")
    try:
        assert lease.token in assessment_proxy.assessment_proxy_url()
        opts = assessment_proxy.assessment_httpx_options()
        assert opts["verify"].endswith("judah-gate-ca.pem")
        browser = assessment_proxy.assessment_browser_proxy()
        assert browser == {"server": "http://127.0.0.1:8899", "username": lease.token, "password": "x"}
    finally:
        action_ledger.active_run_id.reset(token)
        judah_gate._RUNNING.clear()
        registry.reset()
