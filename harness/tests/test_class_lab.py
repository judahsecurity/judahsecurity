import json
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
    assert len(cases) == 14
    for bug_class in {case["bug_class"] for case in cases}:
        assert {case["polarity"] for case in cases if case["bug_class"] == bug_class} == {
            "positive", "negative"
        }
