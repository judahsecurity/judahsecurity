"""Receipt-backed proofs for upload, enumeration, OAuth, CSWSH, server PP and LLM canaries."""

import base64
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, urlsplit

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.assessment_sessions import identity_registry
from app.services.agent.coverage_cells import claim_coverage_cell_leases, seed_parameter_coverage_cells
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.external_candidates import COVERAGE_TO_PROOF
from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate
from app.services.agent.proof_policy import (
    CLASS_PROBE_KINDS, PROOFS_BY_CLASS, inferred_vulnerability_class, proof_kind_allowed,
    validate_proof,
)
from app.services.agent.scoped_assessment import class_probes as cp
from app.services.agent.tools import ASMToolsManager


# ---------------------------------------------------------------- local target

class App:
    def __init__(self):
        self.files = {}
        self.upload_mode = "active"
        self.oauth_mode = "vulnerable"
        self.enum_mode = "differential"
        self.chat_mode = "obeys"
        self.spaces = None  # simulated Object.prototype["json spaces"]
        self.requests = []
        self.lock = threading.Lock()


def _serve(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def _send(self, status, body=b"", headers=()):
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            return self.rfile.read(int(self.headers.get("Content-Length") or 0))

        def do_GET(self):
            parts = urlsplit(self.path)
            app.requests.append(("GET", self.path))
            if parts.path.startswith("/files/"):
                name = parts.path.rsplit("/", 1)[1]
                if name not in app.files:
                    return self._send(404, b"missing")
                content, ctype = app.files[name]
                headers = [("Content-Type", ctype)]
                if app.upload_mode == "attachment":
                    headers.append(("Content-Disposition", f'attachment; filename="{name}"'))
                if app.upload_mode == "plain":
                    headers = [("Content-Type", "text/plain")]
                return self._send(200, content, headers)
            if parts.path == "/oauth/authorize":
                query = dict(parse_qsl(parts.query))
                redirect = query.get("redirect_uri", "")
                if app.oauth_mode == "strict" and redirect != "http://app.local/cb":
                    return self._send(400, b"invalid redirect_uri")
                if app.oauth_mode == "error":
                    return self._send(302, b"", [("Location", redirect + "?error=access_denied")])
                return self._send(302, b"", [(
                    "Location", f"{redirect}?code=SUPERSECRETCODE123&state={query.get('state', '')}")])
            if parts.path == "/api/status":
                doc = {"ok": True, "items": [1, 2]}
                text = json.dumps(doc, indent=app.spaces) if app.spaces else json.dumps(doc, separators=(",", ":"))
                return self._send(200, text.encode(), [("Content-Type", "application/json")])
            return self._send(404, b"nope")

        def do_DELETE(self):
            parts = urlsplit(self.path)
            app.requests.append(("DELETE", self.path))
            name = dict(parse_qsl(parts.query)).get("name", "")
            if parts.path == "/files/delete" and name in app.files:
                del app.files[name]
                return self._send(204)
            return self._send(404)

        def do_POST(self):
            parts = urlsplit(self.path)
            body = self._body()
            app.requests.append(("POST", self.path))
            if parts.path == "/upload":
                match = re.search(rb'filename="([^"]+)"\r\nContent-Type: ([^\r]+)\r\n\r\n(.*)\r\n--', body, re.S)
                name, ctype, content = match.group(1).decode(), match.group(2).decode(), match.group(3)
                app.files[name] = (content, ctype)
                return self._send(201, json.dumps({"url": f"/files/{name}"}).encode(),
                                  [("Content-Type", "application/json")])
            if parts.path == "/login":
                fields = dict(parse_qsl(body.decode()))
                user = fields.get("email", "")
                token = secrets.token_hex(16)
                if user == "alice@example.test" and app.enum_mode == "differential":
                    text = f'<input name="csrf" value="{token}"><p>Wrong password for {user}</p>'
                elif app.enum_mode == "lockout":
                    return self._send(429, b"Too many attempts, try again later")
                else:
                    text = f'<input name="csrf" value="{token}"><p>No account for {user}</p>' \
                        if app.enum_mode == "differential" else \
                        f'<input name="csrf" value="{token}"><p>Invalid email or password</p>'
                return self._send(401, text.encode(), [("Content-Type", "text/html")])
            if parts.path == "/api/profile":
                doc = json.loads(body)
                proto = doc.get("__proto__")
                if isinstance(proto, dict) and "json spaces" in proto:
                    app.spaces = proto["json spaces"]
                return self._send(200, b'{"saved":true}', [("Content-Type", "application/json")])
            if parts.path == "/api/chat":
                message = json.loads(body).get("message", "")
                found = re.search(r"joining '([^']*)', '([^']*)' and '([^']*)'", message)
                if app.chat_mode == "echo":
                    reply = message
                elif found:
                    reply = "".join(found.groups())
                else:
                    reply = "The customer was satisfied."
                return self._send(200, json.dumps({"reply": reply}).encode(),
                                  [("Content-Type", "application/json")])
            return self._send(404, b"nope")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


@pytest.fixture
def target():
    app = App()
    server, base = _serve(app)
    yield app, base
    server.shutdown()
    server.server_close()


def _manager(base, rows=()):
    brain = EngagementBrain(target=base)
    host = urlsplit(base).netloc
    seed_parameter_coverage_cells(brain, [{"host": host, "testable": True, **row} for row in rows])
    manager = ASMToolsManager()
    manager._fallback_target = base
    manager._capability_map = {"target": base, "scope": base}
    manager._engagement_brain = brain.to_dict()
    register_scope(manager, urlsplit(base).hostname)
    manager.set_scoped_assessment_policy({
        "body_replay_paths": ["/upload", "/api/profile", "/api/chat", "/login"],
        "stored_xss_cleanup_paths": ["/files/delete"],
    })
    return manager


def _lease(manager, specialist, test_type):
    brain = engagement_brain_from_dict(manager._engagement_brain)
    lease = claim_coverage_cell_leases(
        brain, [specialist], allowed_test_types=frozenset({test_type}),
    )[specialist]
    manager._engagement_brain = brain.to_dict()
    return lease


async def _verify(manager, base, path, result, vclass, identity="anonymous", cell_id=""):
    brain = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        brain, title=f"{vclass} proof on {path}", target=base + path,
        vulnerability_class=vclass, identity=identity, coverage_cell_id=cell_id,
        evidence_ids=[result["evidence_id"]],
    )
    manager._engagement_brain = brain.to_dict()
    reports = await run_independent_verifiers([candidate], llm=None, tools_manager=manager,
                                              targets=[base + path])
    return reports[0]


def _capture(manager, base, path, document, identity="anonymous"):
    store = evidence_store(manager)
    private = json.dumps({
        "method": "POST", "url": base + path, "resource_type": "xhr",
        "request_content_type": "application/json",
        "request_body_base64": base64.b64encode(json.dumps(document).encode()).decode(),
        "replay_headers": {},
    }).encode()
    capture_id = store.record("scoped_browser_exchange", {"method": "POST", "path": path},
                              target=base + path, identity=identity)
    manager._scoped_browser_exchanges = {
        **(manager._scoped_browser_exchanges or {}),
        capture_id: {"identity": identity, "private": private, "verifier_run_id": None,
                     "public": {"method": "POST", "path": path}},
    }
    return capture_id


# ---------------------------------------------------------------- file upload

@pytest.mark.asyncio
async def test_upload_lane_confirms_served_active_and_verifier_replays(target):
    app, base = target
    manager = _manager(base, [{"method": "POST", "path": "/upload", "name": "file",
                               "location": "body_form", "value_type": "file",
                               "source": "browser_traffic", "identity": "anonymous"}])
    lease = _lease(manager, "file_upload", "file_upload")
    assert (await manager.scoped_upload_probe_assigned(lease.coverage_cell_id, "bad"))[
        "error"] == "invalid_coverage_lease"
    result = await manager.scoped_upload_probe_assigned(
        lease.coverage_cell_id, lease.id,
        cleanup_url_template=base + "/files/delete?name=__PROWL_FILE__")
    assert result["proof_confirmed"] is True, result
    assert result["served"]["mime"] == "text/html" and result["leftovers"] == []
    assert app.files == {}  # cleaned up through the approved cleanup path
    report = await _verify(manager, base, "/upload", result, "file_upload",
                           cell_id=lease.coverage_cell_id)
    assert report["status"] == "confirmed", report["verifier_summary"]


@pytest.mark.parametrize("mode", ("attachment", "plain"))
def test_upload_attachment_or_inert_type_is_not_proof(target, mode):
    app, base = target
    app.upload_mode = mode
    proof = cp.probe_upload(base + "/upload", file_field="file", served_url_template="",
                            cleanup_url_template="", allowed_origin=base, state=None,
                            nonce="abcdef123456")
    assert proof["proof_confirmed"] is False
    assert sorted(proof["leftovers"]) == ["prowl-abcdef123456.html", "prowl-abcdef123456.svg"]


@pytest.mark.asyncio
async def test_upload_needs_body_replay_approval(target):
    _app, base = target
    manager = _manager(base, [{"method": "POST", "path": "/upload", "name": "file",
                               "location": "body_form", "value_type": "file",
                               "source": "browser_traffic", "identity": "anonymous"}])
    manager.set_scoped_assessment_policy({})
    lease = _lease(manager, "file_upload", "file_upload")
    result = await manager.scoped_upload_probe_assigned(lease.coverage_cell_id, lease.id)
    assert result["error"] == "operator_approval_required"
    result = await manager.scoped_upload_probe_assigned(
        lease.coverage_cell_id, lease.id, cleanup_url_template=base + "/other?name=__PROWL_FILE__")
    assert result["error"] == "operator_approval_required"


# ---------------------------------------------------------------- account enumeration

def _operator_login_capture(manager, base, identity="alice"):
    identity_registry(manager).register(identity, base, cookies=[{"name": "sid", "value": "a"}])
    return evidence_store(manager).record("http_exchange", {
        "source": "operator_capture",
        "request": {"method": "POST", "url": base + "/login",
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": "email=alice%40example.test&password=hunter2"},
        "response": {"status": 302, "url": base + "/login"},
    }, target=base + "/login", identity=identity)


@pytest.mark.asyncio
async def test_account_enum_uses_operator_capture_and_verifier_replays(target):
    app, base = target
    manager = _manager(base, [{"method": "POST", "path": "/login", "name": "email",
                               "location": "body_form", "source": "browser_traffic",
                               "identity": "anonymous"}])
    _operator_login_capture(manager, base)
    lease = _lease(manager, "auth_logic", "auth")
    assert (await manager.scoped_account_enum_assigned(
        lease.coverage_cell_id, lease.id, identity="nobody"))["success"] is False
    result = await manager.scoped_account_enum_assigned(lease.coverage_cell_id, lease.id,
                                                        identity="alice")
    assert result["proof_confirmed"] is True, result
    assert result["requests_sent"] == 6
    record = evidence_store(manager).records[result["evidence_id"]]
    assert "alice@example.test" not in json.dumps(record["payload"])
    assert record["payload"]["credential_field"] == "password"
    report = await _verify(manager, base, "/login", result, "account_enumeration",
                           identity="alice", cell_id=lease.coverage_cell_id)
    assert report["status"] == "confirmed", report["verifier_summary"]


@pytest.mark.parametrize("mode,stopped", (("uniform", ""), ("lockout", "lockout_or_rate_limit")))
def test_account_enum_uniform_or_lockout_is_not_proof(target, mode, stopped):
    app, base = target
    app.enum_mode = mode
    proof = cp.probe_account_enum(
        base + "/login", kind="form", fields={"email": "alice@example.test", "password": "x"},
        username_field="email", password_field="password", test_username="alice@example.test",
        allowed_origin=base, nonce="abcdef123456")
    assert proof["proof_confirmed"] is False and proof["stopped"] == stopped
    if mode == "lockout":
        assert proof["requests_sent"] == 1


def test_account_enum_signature_strips_volatile_values():
    a = {"status": 401, "headers": {}, "body": '<input name="csrf" value="aaaa1111bbbb2222cccc">'
         'at 2026-01-01T10:00:00Z no account for prowl1234@x.test'}
    b = {"status": 401, "headers": {}, "body": '<input name="csrf" value="9999ffff0000eeee1234">'
         'at 2026-02-03T11:12:13Z no account for prowlabcd@x.test'}
    assert (cp.normalized_signature(a, ["prowl1234@x.test"])
            == cp.normalized_signature(b, ["prowlabcd@x.test"]))


@pytest.mark.asyncio
async def test_account_enum_refuses_registration_paths(target):
    _app, base = target
    manager = _manager(base)
    with pytest.raises(ValueError, match="Registration"):
        await manager._class_enum_run(base + "/register", "alice")


# ---------------------------------------------------------------- OAuth

@pytest.mark.asyncio
async def test_oauth_lane_confirms_grant_to_canary_and_redacts_code(target):
    _app, base = target
    manager = _manager(base, [{"method": "GET", "path": "/oauth/authorize", "name": "client_id",
                               "location": "query", "source": "browser_link",
                               "identity": "anonymous"}])
    manager._capability_map["pages_visited"] = [
        base + "/oauth/authorize?client_id=web&response_type=code&redirect_uri="
        + quote("http://app.local/cb", safe="")]
    lease = _lease(manager, "auth_logic", "oauth")
    result = await manager.scoped_oauth_redirect_assigned(lease.coverage_cell_id, lease.id)
    assert result["proof_confirmed"] is True, result
    assert result["attempts"][0]["redirect"]["grant_params"] == ["code"]
    record = evidence_store(manager).records[result["evidence_id"]]
    assert "SUPERSECRETCODE123" not in json.dumps(record["payload"])
    report = await _verify(manager, base, "/oauth/authorize", result, "oauth",
                           cell_id=lease.coverage_cell_id)
    assert report["status"] == "confirmed", report["verifier_summary"]


@pytest.mark.parametrize("mode", ("strict", "error"))
def test_oauth_strict_or_error_redirect_is_not_proof(target, mode):
    app, base = target
    app.oauth_mode = mode
    observed = base + "/oauth/authorize?client_id=web&response_type=code&redirect_uri=" + \
        quote("http://app.local/cb", safe="")
    proof = cp.probe_oauth_redirect(observed, allowed_origin=base, state=None, nonce="abcdef123456")
    assert proof["proof_confirmed"] is False
    assert proof["requests_sent"] == 3
    assert [a["variant"] for a in proof["attempts"]] == ["replace", "suffix_host", "userinfo"]


def test_oauth_variants_keep_canary_as_real_host():
    for label, uri in cp.oauth_variants("https://app.example/cb", "abcdef123456"):
        assert urlsplit(uri).hostname.endswith("abcdef123456.prowl.invalid"), label


# ---------------------------------------------------------------- server-side prototype pollution

@pytest.mark.asyncio
async def test_server_pp_gadget_with_control_and_reset(target):
    app, base = target
    manager = _manager(base)
    capture = _capture(manager, base, "/api/profile", {"name": "bob"})
    brain = engagement_brain_from_dict(manager._engagement_brain)
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "path": "/api/profile", "host": urlsplit(base).netloc, "name": "name",
        "location": "body_json", "source": "browser_traffic", "identity": "anonymous",
        "testable": True, "artifact_id": capture}])
    manager._engagement_brain = brain.to_dict()
    manager._capability_map["pages_visited"] = [base + "/api/status"]
    lease = _lease(manager, "injection", "prototype_pollution")
    result = await manager.scoped_server_pp_assigned(lease.coverage_cell_id, lease.id,
                                                     readback_url=base + "/api/status")
    assert result["proof_confirmed"] is True, result
    assert result["reset_restored"] is True and app.spaces == 0
    again = await manager.scoped_server_pp_assigned(lease.coverage_cell_id, lease.id,
                                                    readback_url=base + "/api/status")
    assert again["error"] == "already_probed"
    report = await _verify(manager, base, "/api/profile", result, "server_prototype_pollution",
                           cell_id=lease.coverage_cell_id)
    assert report["status"] == "confirmed", report["verifier_summary"]


def test_json_indent_detection():
    assert cp.json_indent('{"a":1}') == 0
    assert cp.json_indent('{\n     "a": 1\n}') == 5
    assert cp.json_indent("{}") is None
    assert cp.json_indent("<html>") is None


def test_server_pp_needs_unrelated_readback():
    with pytest.raises(ValueError, match="unrelated"):
        cp.probe_pp_json_spaces("https://a.test/api/x", document={"a": 1},
                                readback_url="https://a.test/api/x", allowed_origin="https://a.test",
                                state=None, nonce="abcdef123456", spaces=5)


# ---------------------------------------------------------------- LLM canary

@pytest.mark.asyncio
async def test_llm_canary_needs_assembled_word_not_echo(target):
    app, base = target
    manager = _manager(base)
    capture = _capture(manager, base, "/api/chat", {"message": "hello"})
    brain = engagement_brain_from_dict(manager._engagement_brain)
    seed_parameter_coverage_cells(brain, [{
        "method": "POST", "path": "/api/chat", "host": urlsplit(base).netloc, "name": "message",
        "location": "body_json", "source": "browser_traffic", "identity": "anonymous",
        "testable": True, "artifact_id": capture}])
    manager._engagement_brain = brain.to_dict()
    lease = _lease(manager, "agent_tools", "llm_ai")
    result = await manager.scoped_llm_canary_assigned(lease.coverage_cell_id, lease.id)
    assert result["proof_confirmed"] is True, result
    assert result["field"] == "message"
    report = await _verify(manager, base, "/api/chat", result, "prompt_injection",
                           cell_id=lease.coverage_cell_id)
    assert report["status"] == "confirmed", report["verifier_summary"]
    app.chat_mode = "echo"
    echo = cp.probe_llm_canary(base + "/api/chat", document={"message": "hi"}, field="message",
                               allowed_origin=base, state=None, nonce="abcdef123456")
    assert echo["proof_confirmed"] is False


def test_llm_message_field_paths():
    doc = {"messages": [{"role": "system", "content": "x"}, {"role": "user", "content": "hi"}]}
    assert cp.detect_message_field(doc) == "messages.-1.content"
    assert cp.set_path(doc, "messages.-1.content", "new")["messages"][1]["content"] == "new"
    with pytest.raises(ValueError):
        cp.set_path(doc, "messages.5.content", "x")


# ---------------------------------------------------------------- CSWSH

@pytest.fixture
def ws_target():
    from websockets.sync.server import serve

    mode = {"origin_check": False, "anon_reject": False}

    def handler(ws):
        cookie = ws.request.headers.get("Cookie") or ""
        if "sid=alice" in cookie:
            ws.send(json.dumps({"type": "hello", "user": "alice-7731", "balance": 4210,
                                "server": "socket-v1.2.3"}))
        elif "sid=bob" in cookie:
            ws.send(json.dumps({"type": "hello", "user": "bob-1180", "balance": 15,
                                "server": "socket-v1.2.3"}))
        else:
            ws.send(json.dumps({"type": "hello", "user": "guest"}))
        try:
            ws.recv(timeout=3)
        except Exception:
            pass

    def process_request(_connection, request):
        origin = request.headers.get("Origin") or ""
        if mode["origin_check"] and "prowl.invalid" in origin:
            return _connection.respond(403, "forbidden origin\n")
        if mode["anon_reject"] and "sid=" not in (request.headers.get("Cookie") or ""):
            return _connection.respond(401, "login required\n")
        return None

    server = serve(handler, "127.0.0.1", 0, process_request=process_request)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield mode, f"http://127.0.0.1:{server.socket.getsockname()[1]}"
    server.shutdown()


@pytest.mark.asyncio
async def test_cswsh_reads_identity_value_cross_origin_and_verifier_replays(ws_target):
    mode, base = ws_target
    manager = _manager(base)
    identity_registry(manager).register("alice", base, cookies=[{"name": "sid", "value": "alice"}])
    anonymous = await manager.scoped_cswsh_probe(url=base.replace("http", "ws") + "/ws",
                                                 identity="anonymous")
    assert anonymous["success"] is False
    result = await manager.scoped_cswsh_probe(url=base.replace("http", "ws") + "/ws",
                                              identity="alice")
    assert result["proof_confirmed"] is True, result
    record = evidence_store(manager).records[result["evidence_id"]]
    assert "alice-7731" not in json.dumps(record["payload"])
    report = await _verify(manager, base, "/ws", result, "cswsh", identity="alice")
    assert report["status"] == "confirmed", report["verifier_summary"]
    mode["origin_check"] = True
    blocked = await manager.scoped_cswsh_probe(url=base + "/ws", identity="alice")
    assert blocked["proof_confirmed"] is False


# ---------------------------------------------------------------- policy

class Store:
    def __init__(self, hunter, verifier):
        self.records = {"hunter": hunter, "verifier": verifier}


def _record(rid, payload, created):
    return {"id": rid, "kind": "scoped_class_probe", "target": "https://a.test/api/chat",
            "identity": "anonymous", "created_at": created, "payload": payload}


def _llm(nonce):
    return {"operation": "scoped_class_probe", "test_type": "prompt_injection", "nonce": nonce,
            "channel": "direct_embedded", "field": "message", "canary_word": cp.llm_token(nonce),
            "canary_in_input": False, "requests_sent": 2, "proof_confirmed": True,
            "control": {"status": 200, "canary_in_output": False},
            "probe": {"status": 200, "canary_in_output": True}}


def test_class_proof_pair_needs_fresh_nonce_same_input_and_class():
    hunter = _record("hunter", _llm("aaaa1111bbbb"), 1)
    verifier = _record("verifier", _llm("cccc2222dddd"), 2)
    store = Store(hunter, verifier)
    candidate = SimpleNamespace(target=hunter["target"], evidence_ids=["hunter"],
                                title="Prompt injection in support chat", description="",
                                vulnerability_class="prompt_injection")
    proof = {"kind": "scoped_llm_canary", "hunter_artifact_id": "hunter", "artifact_id": "verifier"}
    assert validate_proof(store, candidate, proof, ["verifier"]) == (True, "")
    verifier["payload"] = _llm("aaaa1111bbbb")
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = {**_llm("cccc2222dddd"), "field": "other"}
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = {**_llm("cccc2222dddd"),
                           "control": {"status": 200, "canary_in_output": True}}
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = _llm("cccc2222dddd")
    # Text alone (a receipt claiming proof_confirmed without observations) cannot confirm.
    verifier["payload"] = {"operation": "scoped_class_probe", "test_type": "prompt_injection",
                           "nonce": "cccc2222dddd", "proof_confirmed": True}
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]
    verifier["payload"] = _llm("cccc2222dddd")
    verifier["created_at"] = 0
    assert not validate_proof(store, candidate, proof, ["verifier"])[0]


def test_new_classes_have_proof_kinds_and_coverage_mapping():
    for kind, claim in CLASS_PROBE_KINDS.items():
        assert kind in PROOFS_BY_CLASS[claim]
    assert COVERAGE_TO_PROOF["file_upload"] == "file_upload"
    assert COVERAGE_TO_PROOF["oauth"] == "oauth"
    assert COVERAGE_TO_PROOF["prototype_pollution"] == "server_prototype_pollution"
    assert COVERAGE_TO_PROOF["llm_ai"] == "prompt_injection"
    # Business logic proves only as an authorization/workflow bypass.
    assert COVERAGE_TO_PROOF["business_logic"] == "authorization"
    assert {"workflow", "state_change"} <= PROOFS_BY_CLASS["authorization"]


@pytest.mark.parametrize("title,expected", (
    ("Unrestricted file upload serves HTML", "file_upload"),
    ("Stored XSS via SVG upload", "xss"),
    ("Username enumeration on login", "account_enumeration"),
    ("OAuth redirect_uri validation bypass leaks code", "oauth"),
    ("Open redirect via redirect_uri", "open_redirect"),
    ("CSWSH on /ws", "cswsh"),
    ("Cross-site WebSocket hijacking on chat socket", "cswsh"),
    ("Server-side prototype pollution in profile API", "server_prototype_pollution"),
    ("Client-side prototype pollution via hash", "client_prototype_pollution"),
    ("Prompt injection in support bot", "prompt_injection"),
    ("CSRF on email change", "csrf"),
))
def test_claim_patterns_infer_new_classes_without_conflicts(title, expected):
    assert inferred_vulnerability_class(SimpleNamespace(title=title, description="")) == expected


def test_class_kinds_only_confirm_their_class():
    candidate = SimpleNamespace(title="Prompt injection in bot", description="",
                                vulnerability_class="")
    assert proof_kind_allowed(candidate, "scoped_llm_canary")[0]
    assert not proof_kind_allowed(candidate, "scoped_upload_served_active")[0]
    sqli = SimpleNamespace(title="SQL injection in search", description="", vulnerability_class="")
    assert not proof_kind_allowed(sqli, "scoped_server_pp_gadget")[0]


def test_new_tools_are_declared_and_granted():
    from app.services.agent.fireteam_service import get_specialist
    from app.services.agent.tool_specs import get_spec

    for name, lane in (("scoped_upload_probe_assigned", "file_upload"),
                       ("scoped_account_enum_assigned", "auth_logic"),
                       ("scoped_oauth_redirect_assigned", "auth_logic"),
                       ("scoped_cswsh_probe", "api_authz"),
                       ("scoped_server_pp_assigned", "injection"),
                       ("scoped_llm_canary_assigned", "agent_tools")):
        spec = get_spec(name)
        assert spec and not spec.read_only, name
        assert name in get_specialist(lane).allowed_tools, (name, lane)


@pytest.mark.asyncio
async def test_cswsh_needs_an_accepted_comparison_session(ws_target):
    mode, base = ws_target
    mode["anon_reject"] = True
    manager = _manager(base)
    identity_registry(manager).register("alice", base, cookies=[{"name": "sid", "value": "alice"}])
    # Anonymous rejected and no second identity: a server banner cannot be told
    # apart from user data, so the run stays a lead.
    lead = await manager.scoped_cswsh_probe(url=base + "/ws", identity="alice")
    assert lead["proof_confirmed"] is False
    identity_registry(manager).register("bob", base, cookies=[{"name": "sid", "value": "bob"}])
    result = await manager.scoped_cswsh_probe(url=base + "/ws", identity="alice")
    assert result["proof_confirmed"] is True, result
    payload = evidence_store(manager).records[result["evidence_id"]]["payload"]
    assert payload["comparison_basis"] == ["same_origin_other_identity"]
    # The shared server banner is not counted as identity-specific.
    assert cp._digest("socket-v1.2.3") not in payload["identity_value_digests"]


def test_upload_escaped_preview_is_not_served_content():
    content = "<p>prowl-upload-abc</p>"
    escaped = {"status": 200, "headers": {"content-type": "text/html"},
               "body": "<pre>&lt;p&gt;prowl-upload-abc&lt;/p&gt;</pre>"}
    raw = {"status": 200, "headers": {"content-type": "text/html"}, "body": content}
    base = "https://a.test"
    assert not cp.served_active(cp.served_observation(escaped, content, base + "/v/x", base))
    assert cp.served_active(cp.served_observation(raw, content, base + "/v/x", base))
