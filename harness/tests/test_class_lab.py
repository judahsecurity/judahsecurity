import json
import base64
import re
import urllib.parse
from io import BytesIO
from types import SimpleNamespace

from local_harness.benchmark.class_lab import handler_for
from local_harness.benchmark.class_lab_manifest import build_manifest


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


def request(handler, path, *, method="GET", body=None, identity=None):
    payload = json.dumps(body).encode() if body is not None else b""
    headers = [f"{method} {path} HTTP/1.1", "Host: localhost"]
    if identity:
        headers.append(f"X-Lab-Identity: {identity}")
    if body is not None:
        headers.extend(["Content-Type: application/json", f"Content-Length: {len(payload)}"])
    socket = MemorySocket(("\r\n".join(headers) + "\r\n\r\n").encode() + payload)
    handler(socket, ("127.0.0.1", 12345), SimpleNamespace())
    raw = socket.output.getvalue()
    header, response_body = raw.split(b"\r\n\r\n", 1)
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
    assert len(cases) == 22
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
