"""An upload claim requires the same canary across write, read, execution, cleanup."""

from types import SimpleNamespace

from app.services.agent.proof_policy import validate_proof


def _http(method, url, body, response, timestamp):
    return {
        "kind": "http_exchange", "created_at": timestamp,
        "payload": {
            "request": {"method": method, "url": url, "body": body},
            "response": {"status": 200, "body": response},
        },
    }


def test_upload_xss_needs_execution_and_cleanup_of_same_object():
    marker = "aegis-verify-123"
    upload = _http("POST", "https://app.test/api/uploads", marker, '{"url":"/uploads/1"}', 1)
    read = _http("GET", "https://app.test/uploads/1", "", f"<script>alert('{marker}')</script>", 2)
    browser = {
        "kind": "browser_xss", "created_at": 3,
        "payload": {"url": "https://app.test/uploads/1", "alert_text": marker,
                    "dialog_triggered": True},
    }
    cleanup = _http("DELETE", "https://app.test/uploads/1", "", "", 4)
    store = SimpleNamespace(records={
        "upload": upload, "read": read, "browser": browser, "cleanup": cleanup,
    })
    proof = {"kind": "upload_xss", "upload_id": "upload", "read_id": "read",
             "browser_id": "browser", "cleanup_id": "cleanup"}
    candidate = SimpleNamespace(nonce="123", title="Unsafe file upload stored XSS", description="")
    ids = list(store.records)
    assert validate_proof(store, candidate, proof, ids)[0]

    browser["payload"]["dialog_triggered"] = False
    assert not validate_proof(store, candidate, proof, ids)[0]
    browser["payload"]["dialog_triggered"] = True
    cleanup["payload"]["request"]["url"] = "https://app.test/uploads/other"
    assert not validate_proof(store, candidate, proof, ids)[0]
