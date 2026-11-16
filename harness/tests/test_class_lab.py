import json
import base64
import re
import urllib.parse
from io import BytesIO
from types import SimpleNamespace

from local_harness.benchmark.class_lab import _b64url, handler_for
from local_harness.benchmark.class_lab_manifest import KNOWN_GAPS, build_identities, build_manifest


class MemorySocket:
    def __init__(self, request):
        self.input = BytesIO(request)
        self.output = BytesIO()

    def makefile(self, mode, *_args, **_kwargs):
        return self.input if "r" in mode else self.output

    def sendall(self, data):
        self.output.write(data)

    def close(self):
        pass


def request(handler, path, *, method="GET", body=None, identity=None, form=None, headers=None,
            full=False):
    if form is not None:
        payload = urllib.parse.urlencode(form).encode()
        content_type = "application/x-www-form-urlencoded"
    else:
        payload = json.dumps(body).encode() if body is not None else b""
        content_type = "application/json"
    extra = headers
    headers = [f"{method} {path} HTTP/1.1", "Host: localhost"]
    if identity:
        headers.append(f"X-Lab-Identity: {identity}")
    headers.extend(f"{key}: {value}" for key, value in (extra or {}).items())
    if body is not None or form is not None:
        headers.extend([f"Content-Type: {content_type}", f"Content-Length: {len(payload)}"])
    socket = MemorySocket(("\r\n".join(headers) + "\r\n\r\n").encode() + payload)
    handler(socket, ("127.0.0.1", 12345), SimpleNamespace())
    raw = socket.output.getvalue()
    header, response_body = raw.split(b"\r\n\r\n", 1)
    if full:
        return int(header.split()[1]), header.decode(), response_body.decode()
    return int(header.split()[1]), response_body.decode()


def test_positive_and_negative_sql_and_graphql_boundaries():
    for vulnerable in (True, False):
        sql = handler_for("sqli", vulnerable, "")
        status, body = request(sql, "/search?q=" + urllib.parse.quote("' OR 1=1--"))
        assert status == 200
        assert ("aegis-lab-private-record" in body) is vulnerable

        encoded = handler_for("sqli_encoded", vulnerable, "")
        category = urllib.parse.quote(base64.b64encode(b"public' OR 1=1-- ").decode())
        status, body = request(encoded, "/catalog?category=" + category)
        assert status == 200
        assert ("aegis-lab-private-record" in body) is vulnerable
        graphql = handler_for("graphql_authz", vulnerable, "")
        status, body = request(graphql, "/graphql", method="POST", identity="B", body={
            "query": "query($id: ID!) { node(id: $id) { ownerId secret } }",
            "variables": {"id": "1"},
        })
        assert status == 200
        assert ("aegis-lab-private-record" in body) is vulnerable


def test_upload_and_csrf_negatives_reject_active_or_forged_content():
    for vulnerable in (True, False):
        upload = handler_for("unsafe_file_upload", vulnerable, "")
        status, body = request(upload, "/api/uploads", method="POST", body={
            "filename": "canary.html", "content_type": "text/html",
            "content": "<script>alert('aegis-verify-test')</script>",
        })
        assert (status == 201) is vulnerable
        if vulnerable:
            item_id = json.loads(body)["id"]
            assert "<script>" in request(upload, "/api/uploads/" + item_id)[1]
        csrf = handler_for("csrf", vulnerable, "")
        status, _ = request(csrf, "/profile", method="POST", identity="A",
                            body={"display_name": "aegis-verify-test"})
        assert (status == 200) is vulnerable
        assert ("aegis-verify-test" in request(csrf, "/profile", identity="A")[1]) is vulnerable


def test_manifest_has_positive_and_negative_cases_for_each_class():
    cases = build_manifest("http://127.0.0.1:8765")["cases"]
    assert len(cases) == 30
    by_id = {case["id"]: case for case in cases}
    assert by_id["ssti-positive"]["specialist"] == "server_injection"
    assert by_id["command_injection-positive"]["expected_findings"][0]["category"] == "rce"
    assert by_id["path_traversal-positive"]["expected_findings"][0]["category"] == "lfi"
    assert "known_gap" not in by_id["jwt-positive"] and "known_gap" not in by_id["jwt-negative"]
    assert by_id["jwt-positive"]["specialist"] == "auth_logic"
    assert by_id["jwt-positive"]["identities"] == "class_lab_jwt_identities.json"
    assert "known_gap" not in by_id["csrf-positive"]
    for bug_class in {case["bug_class"] for case in cases}:
        assert {case["polarity"] for case in cases if case["bug_class"] == bug_class} == {
            "positive", "negative"
        }


def test_dom_xss_fixture_has_executable_sink_only_in_positive_case():
    for vulnerable in (True, False):
        handler = handler_for("xss_dom", vulnerable, "")
        status, body = request(handler, "/blog?search=hello")
        assert status == 200
        assert ('getElementById("results").innerHTML=value' in body) is vulnerable
        assert ('getElementById("results").textContent=value' in body) is not vulnerable


def test_post_blind_sql_fixture_has_vulnerable_and_patched_responses():
    for vulnerable in (True, False):
        handler = handler_for("sqli_post_blind", vulnerable, "")
        baseline = request(handler, "/api/filter", method="POST", body={
            "template": "botox", "page": 2,
        })
        true = request(handler, "/api/filter", method="POST", body={
            "template": "botox' OR '12345'='12345'-- ", "page": 2,
        })
        false = request(handler, "/api/filter", method="POST", body={
            "template": "botox' OR '12345'='12346'-- ", "page": 2,
        })
        assert all(status == 200 for status, _ in (baseline, true, false))
        assert json.loads(baseline[1])["results"] == json.loads(false[1])["results"] == []
        assert bool(json.loads(true[1])["results"]) is vulnerable


def test_post_xhr_xss_fixture_rotates_token_and_escapes_patched_response():
    payload = '<img src=x onerror=alert("lab")>'
    for vulnerable in (True, False):
        handler = handler_for("xss_post_xhr", vulnerable, "")
        status, page = request(handler, "/")
        assert status == 200 and 'role="tab"' in page
        token = re.search(r'csrf_token:"([0-9a-f]{16})"', page).group(1)
        status, body = request(handler, "/api/render", method="POST", body={
            "message": payload, "csrf_token": token,
        })
        assert status == 200
        assert (payload in body) is vulnerable
        assert ("&lt;img" in body) is not vulnerable
        assert request(handler, "/api/render", method="POST", body={
            "message": payload, "csrf_token": token,
        })[0] == 403


def test_index_links_new_class_surfaces_for_crawler_discovery():
    expected = {
        "ssti": "/greeting?message=", "command_injection": "/tools/ping?host=",
        "path_traversal": "/download?file=", "jwt": "/api/documents/1",
    }
    for bug_class, link in expected.items():
        for vulnerable in (True, False):
            status, page = request(handler_for(bug_class, vulnerable, ""), "/")
            assert status == 200 and link in page


def test_ssti_evaluates_template_arithmetic_only_in_positive():
    for payload, product in (("{{1337*7331}}", "9801547"), ("${41*43}", "1763"),
                             ("#{19*23}", "437"), ("<%= 17*29 %>", "493")):
        for vulnerable in (True, False):
            handler = handler_for("ssti", vulnerable, "")
            status, body = request(handler, "/greeting?message=" + urllib.parse.quote("hi " + payload))
            assert status == 200
            assert (product in body) is vulnerable
            if not vulnerable:
                assert html_escaped(payload) in body
    status, body = request(handler_for("ssti", True, ""), "/greeting?message=Hello")
    assert status == 200 and "Hello" in body


def html_escaped(value):
    import html
    return html.escape(value, quote=True)


def test_command_injection_is_simulated_and_only_positive_evaluates():
    payloads = (
        "127.0.0.1; expr 1337 \\* 7331", "127.0.0.1|expr 1337 '*' 7331",
        "127.0.0.1 && echo $((1337*7331))", "127.0.0.1$(expr 1337 \\* 7331)",
        "127.0.0.1`expr 1337 \\* 7331`", "127.0.0.1\necho $((1337*7331))",
    )
    for payload in payloads:
        for vulnerable in (True, False):
            handler = handler_for("command_injection", vulnerable, "")
            status, body = request(handler, "/tools/ping?host=" + urllib.parse.quote(payload))
            assert ("9801547" in body) is vulnerable, payload
            assert status == (200 if vulnerable else 400)
    for vulnerable in (True, False):
        status, body = request(handler_for("command_injection", vulnerable, ""),
                               "/tools/ping?host=127.0.0.1")
        assert status == 200 and "PING 127.0.0.1" in body


def test_path_traversal_reads_fake_passwd_only_in_positive():
    marker = "root:x:0:0:root:/root:/bin/bash"
    for payload in ("../../../../etc/passwd", "../../../../../../../../etc/passwd",
                    "/etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd"):
        for vulnerable in (True, False):
            handler = handler_for("path_traversal", vulnerable, "")
            query = payload if "%" in payload else urllib.parse.quote(payload)
            status, body = request(handler, "/download?file=" + query)
            assert (marker in body) is vulnerable, payload
            assert status == (200 if vulnerable else 404)
    for vulnerable in (True, False):
        status, body = request(handler_for("path_traversal", vulnerable, ""), "/download?file=report.txt")
        assert status == 200 and "Quarterly report" in body


def test_path_traversal_never_touches_real_filesystem(monkeypatch):
    import builtins
    def refuse(*_args, **_kwargs):
        raise AssertionError("lab must not open real files")
    handler = handler_for("path_traversal", True, "")
    monkeypatch.setattr(builtins, "open", refuse)
    status, body = request(handler, "/download?file=" + urllib.parse.quote("../../../../etc/hostname"))
    assert status == 200 and body == "aegis-class-lab\n"


def test_jwt_alg_none_grants_peer_object_only_in_positive():
    for vulnerable in (True, False):
        handler = handler_for("jwt", vulnerable, "")
        assert request(handler, "/api/token")[0] == 401
        status, body = request(handler, "/api/token", identity="B")
        assert status == 200
        token_b = json.loads(body)["token"]
        auth = lambda token: {"Authorization": "Bearer " + token}
        assert request(handler, "/api/documents/2", headers=auth(token_b))[0] == 200
        assert request(handler, "/api/documents/1", headers=auth(token_b))[0] == 403
        assert request(handler, "/api/documents/1")[0] == 401
        token_a = json.loads(request(handler, "/api/token", identity="A")[1])["token"]
        status, body = request(handler, "/api/documents/1", headers=auth(token_a))
        assert status == 200 and "aegis-lab-private-record" in body

        forged = ".".join([_b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode()),
                           _b64url(json.dumps({"sub": "A"}).encode()), ""])
        status, body = request(handler, "/api/documents/1", headers=auth(forged))
        assert ("aegis-lab-private-record" in body) is vulnerable
        assert status == (200 if vulnerable else 401)
        header, _payload, signature = token_b.split(".")
        resigned = ".".join([header, _b64url(json.dumps({"sub": "A"}).encode()), signature])
        assert request(handler, "/api/documents/1", headers=auth(resigned))[0] == 401


def test_csrf_positive_supports_scoped_state_change_proof():
    """Cookie session, cross-site form POST without token, readback, anonymous control, reset."""
    for vulnerable in (True, False):
        handler = handler_for("csrf", vulnerable, "")
        status, header, _ = request(handler, "/login", method="POST",
                                    form={"username": "A", "password": "lab-pass"}, full=True)
        assert status == 200 and "Set-Cookie: lab_session=A" in header
        cookie = {"Cookie": "lab_session=A"}
        cross_site = {**cookie, "Origin": "https://attacker.example"}
        status, _ = request(handler, "/profile", method="POST", headers=cross_site,
                            form={"display_name": "aegis-csrf-canary"})
        assert (status == 200) is vulnerable
        assert ("aegis-csrf-canary" in request(handler, "/profile", headers=cookie)[1]) is vulnerable
        assert request(handler, "/profile", method="POST", headers={"Origin": "https://attacker.example"},
                       form={"display_name": "anonymous-canary"})[0] == 401
        assert "anonymous-canary" not in request(handler, "/profile", headers=cookie)[1]
        assert request(handler, "/profile", method="DELETE", headers=cookie)[0] == 200
        assert json.loads(request(handler, "/profile", headers=cookie)[1])["display_name"] == "initial"


def _bearer(token):
    return {"Authorization": "Bearer " + token}


def _jwt_identity_token(name):
    identities = {row["name"]: row for row in build_identities("http://127.0.0.1:8765", "jwt")}
    header = identities[name]["headers"]["Authorization"]
    assert header.startswith("Bearer ")
    return header[len("Bearer "):]


def test_jwt_identities_carry_lab_bearer_token_and_jwt_is_not_a_known_gap():
    assert "jwt" not in KNOWN_GAPS
    shared = build_identities("http://127.0.0.1:8765")
    assert all("Authorization" not in row["headers"] for row in shared)
    jwt_rows = build_identities("http://127.0.0.1:8765", "jwt")
    assert [row["name"] for row in jwt_rows] == ["A", "B"]
    for row in jwt_rows:
        assert row["headers"]["X-Lab-Identity"] == row["name"]
        assert row["check"]["url"].endswith("/whoami")
        token = _jwt_identity_token(row["name"])
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        assert payload == {"sub": row["name"]}
    # The token minted at identity-build time matches what a fresh lab issues.
    for vulnerable in (True, False):
        handler = handler_for("jwt", vulnerable, "")
        issued = json.loads(request(handler, "/api/token", identity="A")[1])["token"]
        assert issued == _jwt_identity_token("A")


def test_manifest_cli_writes_jwt_bearer_identities(tmp_path):
    from local_harness.benchmark import class_lab_manifest

    class_lab_manifest.main(["--out", str(tmp_path / "corpus.json")])
    rows = json.loads((tmp_path / "class_lab_jwt_identities.json").read_text())
    assert rows[0]["name"] == "A"
    assert rows[0]["headers"]["Authorization"] == "Bearer " + _jwt_identity_token("A")
    shared = json.loads((tmp_path / "class_lab_identities.json").read_text())
    assert all("Authorization" not in row["headers"] for row in shared)


def test_jwt_documents_gate_and_forged_token_by_polarity():
    token_a = _jwt_identity_token("A")
    header_b64, _payload, _signature = token_a.split(".")
    forged_payload = _b64url(json.dumps({"sub": "A", "prowl_nonce": "abcdef1234"}).encode())
    alg_none = ".".join([_b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode()),
                         forged_payload, ""])
    for vulnerable in (True, False):
        handler = handler_for("jwt", vulnerable, "")
        no_token = request(handler, "/api/documents/1")
        malformed = request(handler, "/api/documents/1", headers=_bearer("prowl.abcdef1234.invalid"))
        valid = request(handler, "/api/documents/1", headers=_bearer(token_a))
        forged = request(handler, "/api/documents/1", headers=_bearer(alg_none))
        assert no_token[0] == 401 and malformed[0] == 401
        assert valid[0] == 200 and "aegis-lab-private-record" in valid[1]
        if vulnerable:
            assert forged == valid
        else:
            assert forged[0] == 401 and "aegis-lab-private-record" not in forged[1]


def test_backend_probe_jwt_confirms_only_on_positive():
    import pytest

    jwt_probe = pytest.importorskip("app.services.agent.scoped_assessment.jwt_probe")
    target = "http://127.0.0.1:8765"
    identity = next(row for row in build_identities(target, "jwt") if row["name"] == "A")
    session = {"target": target, "headers": identity["headers"],
               "cookies": [{"name": k, "value": v} for k, v in identity["cookies"].items()]}
    for vulnerable in (True, False):
        handler = handler_for("jwt", vulnerable, "")

        def send(url, *, allowed_origin, session, where, name, token):
            assert where == "header" and url.startswith(allowed_origin)
            headers = {k: v for k, v in session["headers"].items() if k.lower() != "authorization"}
            if token is not None:
                headers[name] = "Bearer " + token
            status, body = request(handler, urllib.parse.urlsplit(url).path, headers=headers)
            return status, body.encode()

        proof = jwt_probe.probe_jwt(target + "/api/documents/1", allowed_origin=target,
                                    session=session, nonce="abcdef1234", send=send)
        assert proof["credential_location"] == "header"
        assert proof["auth_enforced"] is True
        assert proof["proof_confirmed"] is vulnerable
        assert jwt_probe.jwt_proof_valid({**proof, "nonce": "abcdef1234"}) is vulnerable
        if vulnerable:
            assert proof["recipe"] == "alg_none"
        else:
            assert proof["probes"] and all(p["status"] == 401 for p in proof["probes"])
