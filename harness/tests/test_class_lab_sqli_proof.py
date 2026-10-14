"""Exercise the real HTTP JSON SQLi fixture through the scoped proof gate."""

from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
import json
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.evidence_store import EvidenceStore, VerificationRun, verification_run
from app.services.agent.proof_policy import validate_proof
from app.services.agent.scoped_assessment.sqli_string import (
    plan_string_boolean, probe_string_boolean, string_sql_proof_valid,
)
from local_harness.benchmark.class_lab import handler_for


@contextmanager
def local_server(handler):
    handler.log_message = lambda *_args: None
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    worker = Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=1)


def probe(origin):
    baseline, variants, nonce = plan_string_boolean(
        origin + "/search?q=public", parameter="q", allowed_origins=[origin],
    )
    return probe_string_boolean(
        baseline, variants, nonce, parameter="q", allowed_origins=[origin],
        storage_state=None, before_request=lambda: None,
    )


@pytest.mark.parametrize("vulnerable", [True, False])
def test_small_json_sql_injection_is_confirmed_only_in_vulnerable_lab(vulnerable):
    with local_server(handler_for("sqli", vulnerable, "")) as origin:
        result = probe(origin)
    assert result["proof_confirmed"] is vulnerable
    assert result["requests_sent"] == 8
    if vulnerable:
        assert result["proof_recipe"] == "string_or_json_rows_v1"
        assert result["checks"]["true_first"]["json_array_lengths"]["results"] == 2
        assert result["checks"]["false_first"]["json_array_lengths"]["results"] == 1
    assert "aegis-lab-private-record" not in json.dumps(result)


def test_json_reflection_and_payload_filter_are_not_sql_proof():
    class Lookalike(BaseHTTPRequestHandler):
        def do_GET(self):
            value = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            if value == "public'":
                status, body = 400, {"error": "invalid input"}
            else:
                status, body = 200, {"results": [{"echo": value}]}
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    with local_server(Lookalike) as origin:
        result = probe(origin)
    assert result["proof_confirmed"] is False
    assert not string_sql_proof_valid(result)


def test_json_sql_proof_needs_fresh_matching_verifier(monkeypatch):
    from app.services.agent.scoped_assessment import sqli_string

    nonces = iter((2345, 57890))
    monkeypatch.setattr(sqli_string.secrets, "randbelow", lambda _: next(nonces))
    with local_server(handler_for("sqli", True, "")) as origin:
        target = origin + "/search"
        store = EvidenceStore()
        hunter = store.record("scoped_string_sqli", probe(origin), target=target,
                              identity="anonymous")
        token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
        try:
            verifier_result = probe(origin)
            verifier = store.record("scoped_string_sqli", verifier_result, target=target,
                                    identity="anonymous")
            changed_counts = deepcopy(verifier_result)
            for key in ("true_first", "true_second"):
                changed_counts["checks"][key]["json_array_lengths"]["results"] = 3
            mismatched = store.record("scoped_string_sqli", changed_counts,
                                      target=target, identity="anonymous")
        finally:
            verification_run.reset(token)
    candidate = SimpleNamespace(target=target, evidence_ids=[hunter],
                                title="SQL injection in search")
    proof = {"kind": "string_boolean_sqli", "hunter_artifact_id": hunter,
             "artifact_id": verifier}
    assert validate_proof(store, candidate, proof, [verifier])[0]
    assert not validate_proof(store, candidate, proof, [hunter])[0]
    proof["artifact_id"] = mismatched
    assert not validate_proof(store, candidate, proof, [mismatched])[0]
