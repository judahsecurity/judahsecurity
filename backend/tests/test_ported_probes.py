"""Probes ported from Aegis Vanguard into Prowl agent tools.

Ports the relevant cases from aegis-vanguard/tests/test_new_detectors.py
(prototype pollution, GraphQL, VCS dump) and adds cases for the new gRPC,
WebSocket, GitLab, mail and vendor logic. No network: drivers get fake
transports, and the tool-level tests use httpx.MockTransport.
"""

import json
import struct

import httpx
import pytest

from app.services.agent import ported_probes as pp
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


def fake_send(handler):
    calls = []

    async def send(method, url, headers, body, http2=False):
        calls.append({"method": method, "url": url, "headers": headers, "body": body, "http2": http2})
        out = handler(method, url, headers or {}, body or "")
        out.setdefault("evidence_id", f"ev{len(calls)}")
        return out

    send.calls = calls
    return send


# ---------------------------------------------------------------------------
# Prototype pollution (Vanguard ProtoPollutionTest)
# ---------------------------------------------------------------------------

def test_pp_hit_reflect_and_error():
    assert pp.pp_hit({"status": 200, "body": "x"}, {"status": 200, "body": "polluted1337"}, "polluted1337")
    assert pp.pp_hit({"status": 200, "body": "ok"}, {"status": 500, "body": "err"}, "polluted1337")
    assert pp.pp_hit({"status": 200, "body": "polluted1337"},
                     {"status": 200, "body": "polluted1337"}, "polluted1337") is None


@pytest.mark.asyncio
async def test_pp_driver_reflection_lead():
    key, val = pp.pp_marker("abc")

    def handler(method, url, headers, body):
        if "__proto__" in body or "constructor" in body:
            return {"status": 200, "body": f"echo: {val}"}
        return {"status": 200, "body": "clean"}

    res = await pp.run_prototype_pollution("https://t/api", fake_send(handler), "abc")
    assert res["verdict"] == "LEAD"
    assert res["leads"][0]["strength"] == "medium"
    assert res["leads"][0]["evidence_ids"]


@pytest.mark.asyncio
async def test_pp_echo_endpoint_is_not_a_lead():
    _, val = pp.pp_marker("abc")

    def handler(method, url, headers, body):
        # Echoes any input: the plain-property control reflects too.
        return {"status": 200, "body": "echo " + (body or url)} if (body or "?" in url) else {"status": 200, "body": "x"}

    send = fake_send(handler)
    res = await pp.run_prototype_pollution("https://t/api", send, "abc")
    assert res["verdict"] == "NO_SIGNAL"
    # Each pollution vector was paired with a plain-property control that echoed.
    controls = [c for c in send.calls if val in (c["body"] or c["url"])
                and "proto" not in (c["body"] or c["url"])]
    assert len(controls) == 3


@pytest.mark.asyncio
async def test_pp_persisted_marker_is_strong_and_posts_can_be_skipped():
    _, val = pp.pp_marker("n1")
    state = {"polluted": False}

    def handler(method, url, headers, body):
        if method == "POST":
            return {"skipped": "POST /api requires an exact operator-approved path"}
        if "__proto__" in url:
            state["polluted"] = True
            return {"status": 200, "body": "ok"}
        return {"status": 200, "body": f"cfg {val}" if state["polluted"] and "?" not in url else "ok"}

    res = await pp.run_prototype_pollution("https://t/api", fake_send(handler), "n1")
    assert res["leads"][0]["strength"] == "strong"
    assert len(res["skipped"]) == 2


# ---------------------------------------------------------------------------
# GraphQL (Vanguard GraphQLTest)
# ---------------------------------------------------------------------------

def test_graphql_verdict_helpers():
    assert pp.introspection_enabled('{"data":{"__schema":{"types":[{"name":"Q"}]}}}')
    assert not pp.introspection_enabled('{"errors":["disabled"]}')
    assert pp.batching_enabled('[{"data":{}},{"data":{}}]')
    assert not pp.batching_enabled('{"data":{}}')
    assert pp.suggestions_leak('{"errors":[{"message":"Did you mean \\"user\\"?"}]}')
    assert pp.schema_type_names('{"data":{"__schema":{"types":[{"name":"__Type"},{"name":"User"}]}}}') == ["User"]


@pytest.mark.asyncio
async def test_graphql_driver():
    def handler(method, url, headers, body):
        if "queryTypes" in body:  # misspelled field -> suggestion
            return {"status": 400, "body": '{"errors":[{"message":"Did you mean \\"queryType\\"?"}]}'}
        if "__schema" in body:
            return {"status": 200, "body": '{"data":{"__schema":{"types":[{"name":"Query"}]}}}'}
        if body.startswith("["):
            return {"status": 200, "body": '[{"data":{}},{"data":{}}]'}
        if method == "GET":
            return {"status": 200, "body": '{"data":{"__typename":"Query"}}'}
        return {"status": 200, "body": '{"errors":[{"message":"Did you mean \\"user\\"?"}]}'}

    res = await pp.run_graphql("https://t/graphql", fake_send(handler))
    signals = {lead["signal"] for lead in res["leads"]}
    assert {"graphql_introspection", "graphql_batching", "graphql_suggestions",
            "graphql_get_queries"} <= signals
    assert res["schema_types_sample"] == ["Query"]


@pytest.mark.asyncio
async def test_graphql_falls_back_to_get_introspection_when_post_not_approved():
    def handler(method, url, headers, body):
        if method == "POST":
            return {"skipped": "POST /graphql requires an exact operator-approved path"}
        if "__schema" in url:
            return {"status": 200, "body": '{"data":{"__schema":{"types":[{"name":"User"}]}}}'}
        return {"status": 400, "body": '{"errors":[{"message":"bad"}]}'}

    send = fake_send(handler)
    res = await pp.run_graphql("https://t/graphql", send)
    assert res["leads"][0]["signal"] == "graphql_introspection"
    assert len(res["skipped"]) == 3
    assert any(c["method"] == "GET" and "__schema" in c["url"] for c in send.calls)


# ---------------------------------------------------------------------------
# VCS dump (Vanguard VCSDumpTest), with redaction
# ---------------------------------------------------------------------------

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
[remote "origin"]
\turl = https://deploy:hunter2-s3cret@github.com/acme/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[http "https://github.com/"]
\textraheader = AUTHORIZATION: basic eC1hY2Nlc3MtdG9rZW46Z2hzX3NlY3JldA==
"""


def test_extract_git_config_fingerprints_credentials():
    got = pp.extract_git_config(GIT_CONFIG)
    dumped = json.dumps(got)
    assert "hunter2-s3cret" not in dumped and "deploy" not in dumped
    assert "eC1hY2Nlc3MtdG9rZW46Z2hzX3NlY3JldA==" not in dumped
    assert got["remotes"][0]["has_credentials"] is True
    assert "github.com/acme/app.git" in got["remotes"][0]["url"]
    kinds = {c["kind"] for c in got["credentials"]}
    assert kinds == {"url_userinfo", "http_extraheader"}
    assert all(c["fingerprint"].startswith("sha256:") for c in got["credentials"])
    assert got["credentials"][1]["scheme"] == "basic"


def test_token_only_userinfo_and_benign_username():
    _, cred = pp.redact_url_userinfo("https://ghp_abcdefabcdef@github.com/x.git")
    assert cred["username"] == "[redacted]" and cred["has_password"] is False
    _, cred = pp.redact_url_userinfo("https://x-access-token:abc@github.com/x.git")
    assert cred["username"] == "x-access-token" and cred["has_password"] is True


def test_vcs_confirms_signatures():
    assert pp.vcs_confirms("/.git/HEAD", "ref: refs/heads/main\n")
    assert not pp.vcs_confirms("/.git/HEAD", "<html>404</html>")
    assert not pp.vcs_confirms("/.git/packed-refs", "<!doctype html><html>not found</html>")
    assert not pp.vcs_confirms("/.svn/entries", "<html><body>dir listing</body></html>")
    assert pp.vcs_confirms("/.git/index", "DIRC\x00\x00\x00\x02")


@pytest.mark.asyncio
async def test_vcs_dump_driver_flags_credentials():
    def handler(method, url, headers, body):
        if url.endswith("/.git/HEAD"):
            return {"status": 200, "body": "ref: refs/heads/main\n"}
        if url.endswith("/.git/config"):
            return {"status": 200, "body": "[core]\n[remote \"o\"]\n url = https://u:p@h/x.git\n"}
        if url.endswith("/.git/index"):
            data = b"DIRC" + struct.pack(">II", 2, 37)
            return {"status": 200, "body": data.decode("latin-1"), "body_bytes": data}
        if url.endswith("/.git/packed-refs"):
            return {"status": 200, "body": "a" * 40 + " refs/heads/release\n"}
        return {"status": 404, "body": "nope"}

    res = await pp.run_vcs_dump("https://t", fake_send(handler))
    assert res["verdict"] == "LEAD"
    assert res["leads"][0]["severity_hint"] == "critical"
    assert res["artifacts"]["index"] == {"version": 2, "tracked_files": 37}
    assert res["artifacts"]["refs"] == {"head": "refs/heads/main", "branches": ["release"], "tags": []}
    assert "u:p@" not in json.dumps(res)


@pytest.mark.asyncio
async def test_vcs_soft_404_is_no_signal():
    res = await pp.run_vcs_dump("https://t", fake_send(lambda *a: {"status": 200, "body": "<html>home</html>"}))
    assert res["verdict"] == "NO_SIGNAL" and res["accessible"] == []


# ---------------------------------------------------------------------------
# gRPC reflection
# ---------------------------------------------------------------------------

def _pb_bytes(field, payload: bytes) -> bytes:
    assert len(payload) < 128
    return bytes([(field << 3) | 2, len(payload)]) + payload


def _list_services_response(*names: str) -> bytes:
    services = b"".join(_pb_bytes(1, _pb_bytes(1, n.encode())) for n in names)
    return _pb_bytes(6, services)


def test_grpc_frame_and_parse_round_trip():
    frame = pp.grpc_frame(pp.reflection_list_services_request())
    assert frame == b"\x00\x00\x00\x00\x02\x3a\x00"
    body = pp.grpc_frame(_list_services_response("acme.Users", "grpc.health.v1.Health"))
    body += pp.grpc_frame(b"grpc-status: 0\r\ngrpc-message: \r\n", flags=0x80)
    messages, trailers = pp.parse_grpc_frames(body)
    assert trailers["grpc-status"] == "0"
    assert pp.parse_list_services(messages[0])["services"] == ["acme.Users", "grpc.health.v1.Health"]


def test_grpc_error_response_parse():
    err = _pb_bytes(7, bytes([0x08, 12]) + _pb_bytes(2, b"nope"))
    assert pp.parse_list_services(err)["error"] == {"code": 12, "message": "nope"}


@pytest.mark.asyncio
async def test_grpc_driver_lists_services_over_h2():
    body = pp.grpc_frame(_list_services_response("acme.Billing"))

    def handler(method, url, headers, req_body):
        assert req_body == "\x00\x00\x00\x00\x02\x3a\x00"
        if headers.get("Content-Type") == "application/grpc" and "v1alpha" in url:
            return {"status": 200, "headers": {"content-type": "application/grpc"},
                    "body": "", "body_bytes": body}
        return {"status": 200, "headers": {"grpc-status": "12"}, "body": "", "body_bytes": b""}

    send = fake_send(handler)
    res = await pp.run_grpc_reflection("https://grpc.t", send)
    assert res["verdict"] == "LEAD"
    assert res["leads"][0]["services"] == ["acme.Billing"]
    assert send.calls[0]["http2"] is True
    assert res["observations"][0]["grpc_status_name"] == "UNIMPLEMENTED"


@pytest.mark.asyncio
async def test_grpc_unauthenticated_is_no_signal():
    res = await pp.run_grpc_reflection("https://grpc.t", fake_send(
        lambda *a: {"status": 200, "headers": {"grpc-status": "16"}, "body": "", "body_bytes": b""}))
    assert res["verdict"] == "NO_SIGNAL"
    assert {o["grpc_status_name"] for o in res["observations"]} == {"UNAUTHENTICATED"}


# ---------------------------------------------------------------------------
# WebSocket Origin / CSWSH
# ---------------------------------------------------------------------------

def test_ws_accept_rfc6455_vector():
    assert pp.ws_accept_value("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    assert pp.ws_http_url("wss://a.t/socket?x=1") == "https://a.t/socket?x=1"


def _ws_server(allow_foreign: bool, cookie: bool = True):
    def handler(method, url, headers, body):
        origin = headers.get("Origin")
        if origin not in (None, "https://a.t") and not allow_foreign:
            return {"status": 403, "body": "bad origin", "cookie_sent": cookie}
        return {"status": 101, "headers": {
            "Sec-WebSocket-Accept": pp.ws_accept_value(headers["Sec-WebSocket-Key"])},
            "body": "", "cookie_sent": cookie}
    return handler


@pytest.mark.asyncio
async def test_ws_origin_enforced_vs_not():
    res = await pp.run_websocket_origin("wss://a.t/ws", fake_send(_ws_server(False)), "n")
    assert res["origin_policy"] == "enforced" and res["verdict"] == "NO_SIGNAL"
    res = await pp.run_websocket_origin("wss://a.t/ws", fake_send(_ws_server(True)), "n")
    assert res["origin_policy"] == "lead" and res["leads"][0]["strength"] == "medium"
    res = await pp.run_websocket_origin("wss://a.t/ws", fake_send(_ws_server(True, cookie=False)), "n")
    assert res["origin_policy"] == "weak"


@pytest.mark.asyncio
async def test_ws_wrong_accept_is_inconclusive():
    res = await pp.run_websocket_origin("wss://a.t/ws", fake_send(
        lambda *a: {"status": 101, "headers": {"Sec-WebSocket-Accept": "bogus"}, "body": ""}), "n")
    assert res["verdict"] == "INCONCLUSIVE"


# ---------------------------------------------------------------------------
# GitLab fingerprint
# ---------------------------------------------------------------------------

def test_gitlab_cve_2021_22205_ranges():
    risk = pp.gitlab_cve_2021_22205_risk
    assert risk("13.8.7") == "vulnerable" and risk("13.8.8") == "patched"
    assert risk("13.9.5") == "vulnerable" and risk("13.9.6") == "patched"
    assert risk("13.10.2") == "vulnerable" and risk("13.10.3") == "patched"
    assert risk("12.0.0") == "vulnerable" and risk("14.0.0") == "patched"
    assert risk("11.8.0") == "unknown" and risk("") == "unknown"


@pytest.mark.asyncio
async def test_gitlab_driver_matches_hash_db():
    css = b"body{color:red}"
    import hashlib

    db = {hashlib.sha256(css).hexdigest(): {"version": "13.9.1"}}
    help_html = ('<html>GitLab<link rel="stylesheet" href="/assets/application-1.css">'
                 '<link href="https://cdn.other/x.css" rel="stylesheet"></html>')

    def handler(method, url, headers, body):
        if url.endswith("/help"):
            return {"status": 200, "body": help_html}
        if "cdn.other" in url:
            return {"skipped": "Out-of-scope network destination blocked: cdn.other"}
        return {"status": 200, "body": css.decode(), "body_bytes": css}

    res = await pp.run_gitlab_fingerprint("https://gl.t", fake_send(handler), db)
    assert res["cve_2021_22205_risk"] == "vulnerable"
    assert res["versions"] == ["13.9.1"]
    assert res["leads"][0]["cve_id"] == "CVE-2021-22205"
    assert len(res["skipped"]) == 1


# ---------------------------------------------------------------------------
# Mail security intel
# ---------------------------------------------------------------------------

def test_spf_dmarc_parsers_and_score():
    spf = pp.parse_spf(['"v=spf1 include:_spf.google.com ~all"', '"google-site-verification=x"'])
    assert spf["present"] and spf["all"] == "softfail" and spf["count"] == 1
    assert pp.parse_spf(['"v=spf1 +all"'])["all"] == "pass"
    dmarc = pp.parse_dmarc(['"v=DMARC1; p=none; rua=mailto:d@t.com"'])
    assert dmarc["policy"] == "none" and dmarc["reporting"]
    assert pp.email_risk_score({"spf": True, "dkim": True, "dmarc": True}) == 25
    assert pp.detect_mail_provider(["10 aspmx.l.google.com"]) == "Google Workspace"


@pytest.mark.asyncio
async def test_mail_intel_driver_with_fake_resolver():
    zone = {
        ("t.com", "MX"): ["10 t-com.mail.protection.outlook.com"],
        ("t.com", "TXT"): ['"v=spf1 include:spf.protection.outlook.com -all"'],
        ("_dmarc.t.com", "TXT"): ['"v=DMARC1; p=none"'],
        ("selector1._domainkey.t.com", "TXT"): ['"v=DKIM1; k=rsa; p=MIIB"'],
        ("_mta-sts.t.com", "TXT"): ['"v=STSv1; id=1"'],
    }

    async def resolve(name, rtype):
        if (name, rtype) not in zone:
            raise LookupError("NXDOMAIN")
        return zone[(name, rtype)]

    res = await pp.run_mail_intel("t.com", resolve)
    assert res["provider"] == "Microsoft 365"
    assert res["records"]["dkim_selectors"] == ["selector1"]
    assert res["records"]["mta_sts"] and not res["records"]["dane"]
    assert {w["issue"] for w in res["weaknesses"]} == {"dmarc_policy_none"}


# ---------------------------------------------------------------------------
# Third-party vendors
# ---------------------------------------------------------------------------

def test_vendor_report():
    body = ('<script src="https://js.stripe.com/v3/"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/x.js" integrity="sha384-abc"></script>'
            '<script src="https://evil-cdn.example/a.js"></script><script src="/local.js"></script>')
    report = pp.vendor_report("https://t.com/", body,
                              {"Content-Security-Policy": "script-src https://static.hotjar.com"})
    names = {v["name"]: v["source"] for v in report["vendors"]}
    assert names == {"Stripe": "body", "jsDelivr CDN": "body", "Hotjar": "csp"}
    assert report["external_scripts"] == 3
    assert report["external_scripts_without_sri"] == ["evil-cdn.example", "js.stripe.com"]
    assert report["unclassified_script_hosts"] == ["evil-cdn.example"]


# ---------------------------------------------------------------------------
# Tool level: registration, docs, scope, evidence redaction, method policy
# ---------------------------------------------------------------------------

PORTED_TOOLS = (
    "probe_server_prototype_pollution", "probe_graphql", "probe_vcs_exposure",
    "probe_grpc_reflection", "probe_websocket_origin", "fingerprint_gitlab",
    "query_mail_security", "detect_third_party_vendors",
)


@pytest.fixture
def manager():
    org = current_organization_id.set(98766)
    session = current_session_id.set("ported-probes-test")
    instance = ASMToolsManager()
    instance._assessment_scope.update({"app.test"})
    yield instance
    current_session_id.reset(session)
    current_organization_id.reset(org)


@pytest.fixture
def transport(monkeypatch):
    original = httpx.AsyncClient
    seen = []

    def install(handler):
        def wrapped(request):
            seen.append(request)
            return handler(request)

        monkeypatch.setattr(httpx, "AsyncClient",
                            lambda **kwargs: original(transport=httpx.MockTransport(wrapped), **kwargs))
        return seen

    return install


def test_tools_registered_documented_and_phased(manager):
    from app.services.agent.prompts import TOOL_PHASE_MAP, all_tool_docs

    docs = all_tool_docs()
    for name in PORTED_TOOLS:
        assert name in manager.tools
        assert name in docs
        assert TOOL_PHASE_MAP[name]


@pytest.mark.asyncio
async def test_describe_tools_covers_ported(manager):
    out = await manager.describe_tools(list(PORTED_TOOLS))
    assert "Unknown tools" not in out
    assert out.count("- **") == len(PORTED_TOOLS)


@pytest.mark.asyncio
async def test_out_of_scope_is_blocked_before_any_request(manager, transport):
    seen = transport(lambda request: httpx.Response(200, text="x"))
    for name in PORTED_TOOLS:
        arg = "domain" if name == "query_mail_security" else "url"
        out = json.loads(await manager.tools[name](**{arg: "https://elsewhere.test/"}))
        assert out["verdict"] == "BLOCKED", name
    assert seen == []


@pytest.mark.asyncio
async def test_vcs_tool_records_evidence_without_raw_credentials(manager, transport):
    from app.services.agent.evidence_store import evidence_store

    def handler(request):
        if request.url.path == "/.git/config":
            return httpx.Response(200, text=GIT_CONFIG)
        if request.url.path == "/.git/HEAD":
            return httpx.Response(200, text="ref: refs/heads/main\n")
        return httpx.Response(404, text="<html>not found</html>")

    seen = transport(handler)
    out = await manager.probe_vcs_exposure(url="https://app.test/")
    result = json.loads(out)
    assert result["verdict"] == "LEAD" and result["leads"][0]["severity_hint"] == "critical"
    assert all("cookie" not in {k.lower() for k in r.headers} for r in seen)
    for secret in ("hunter2-s3cret", "eC1hY2Nlc3MtdG9rZW46Z2hzX3NlY3JldA=="):
        assert secret not in out
        for evidence_id in result["evidence_ids"]:
            assert secret not in evidence_store(manager).read(evidence_id, limit=12000)["content"]


@pytest.mark.asyncio
async def test_post_vectors_respect_scoped_method_policy(manager, transport):
    seen = transport(lambda request: httpx.Response(200, text='{"ok":true}'))
    manager.set_scoped_assessment_policy({})
    result = json.loads(await manager.probe_server_prototype_pollution(url="https://app.test/api"))
    assert len(result["skipped"]) == 2
    assert {r.method for r in seen} == {"GET"}


@pytest.mark.asyncio
async def test_websocket_tool_over_mock_transport(manager, transport):
    def handler(request):
        if request.headers.get("origin") != "https://app.test":
            return httpx.Response(403, text="origin")
        accept = pp.ws_accept_value(request.headers["sec-websocket-key"])
        return httpx.Response(101, headers={"Sec-WebSocket-Accept": accept, "Upgrade": "websocket"})

    transport(handler)
    result = json.loads(await manager.probe_websocket_origin(url="wss://app.test/ws"))
    assert result["origin_policy"] == "enforced"
    assert result["requests_sent"] == 4


@pytest.mark.asyncio
async def test_grpc_tool_sends_binary_frame_over_http2(manager, transport):
    reply = pp.grpc_frame(_list_services_response("acme.Users"))

    def handler(request):
        assert request.content == b"\x00\x00\x00\x00\x02\x3a\x00"
        return httpx.Response(200, headers={"content-type": "application/grpc"}, content=reply)

    transport(handler)
    result = json.loads(await manager.probe_grpc_reflection(url="https://app.test"))
    assert result["leads"][0]["services"] == ["acme.Users"]


@pytest.mark.asyncio
async def test_mail_tool_uses_resolver_and_records_evidence(manager, monkeypatch):
    from app.services.agent import tools_ported_probes

    async def resolve(name, rtype):
        raise LookupError("NXDOMAIN")

    monkeypatch.setattr(tools_ported_probes, "_dns_resolve", resolve)
    result = json.loads(await manager.query_mail_security(domain="app.test"))
    assert result["risk_score"] == 100
    assert result["evidence_ids"]


def test_evidence_redaction_covers_url_userinfo_and_basic_auth():
    from app.services.agent.observability import redact_string

    text = "url = https://u:pw@h/x.git\nextraheader = AUTHORIZATION: basic Zm9vOmJhcg==\n"
    out = redact_string(text)
    assert "u:pw" not in out and "Zm9vOmJhcg==" not in out
    assert redact_string("https://h/p?email=a@b.c") == "https://h/p?email=a@b.c"
