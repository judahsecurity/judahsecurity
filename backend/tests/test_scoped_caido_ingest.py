"""Caido proxy exchanges ingest as scoped replay sources under the same rules.

Operator-captured Caido traffic is treated exactly like an execution-owned
browser capture: it must be in the assessment origin, credential headers are
dropped (replay auth comes only from a named identity), the full URL/bodies stay
private, and the returned capture is replayable by the scoped lanes.
"""

import base64
import json

import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.evidence_store import evidence_store
from app.services.agent.tools import ASMToolsManager

ORIGIN = "https://app.example.test"
URL = ORIGIN + "/api/search?category=gin"


def _manager():
    manager = ASMToolsManager()
    manager._fallback_target = ORIGIN
    register_scope(manager, "app.example.test")
    return manager


@pytest.mark.asyncio
async def test_ingested_caido_get_becomes_a_replayable_capture():
    manager = _manager()
    out = json.loads(await manager.scoped_ingest_caido_exchange(
        method="GET", url=URL, response_status=200,
        response_content_type="application/json",
        response_body_base64=base64.b64encode(b'{"results":[]}').decode(),
        resource_type="xhr", identity="anonymous",
    ))
    artifact_id = out["artifact_id"]
    assert out["source"] == "caido" and out["method"] == "GET"
    assert out["path"] == "/api/search" and "category" in out["query_keys"]

    # The capture is listed and its private bytes round-trip for replay.
    listed = json.loads(await manager.list_scoped_browser_exchanges())
    assert any(row["artifact_id"] == artifact_id for row in listed["exchanges"])
    private = json.loads(manager._scoped_exchange(artifact_id, "anonymous"))
    assert private["url"] == URL and private["method"] == "GET"


@pytest.mark.asyncio
async def test_ingest_drops_credential_headers():
    manager = _manager()
    out = json.loads(await manager.scoped_ingest_caido_exchange(
        method="GET", url=URL, response_status=200,
        response_content_type="application/json",
        request_headers={
            "Cookie": "session=secret", "Authorization": "Bearer t",
            "Accept": "application/json", "X-Requested-With": "XMLHttpRequest",
        },
        resource_type="xhr", identity="anonymous",
    ))
    private = json.loads(manager._scoped_exchange(out["artifact_id"], "anonymous"))
    replay_headers = {k.lower() for k in private.get("replay_headers", {})}
    assert "cookie" not in replay_headers and "authorization" not in replay_headers
    # Credential header names never surface in the public shape either.
    assert not any(name.lower() in {"cookie", "authorization"}
                   for name in out.get("replay_header_names", []))


@pytest.mark.asyncio
async def test_ingest_rejects_out_of_scope_origin():
    manager = _manager()
    with pytest.raises(ValueError):
        await manager.scoped_ingest_caido_exchange(
            method="GET", url="https://evil.test/api/search?category=gin",
            response_status=200, resource_type="xhr", identity="anonymous",
        )


@pytest.mark.asyncio
async def test_ingest_rejects_bad_resource_type_and_base64():
    manager = _manager()
    with pytest.raises(ValueError):
        await manager.scoped_ingest_caido_exchange(
            method="GET", url=URL, response_status=200,
            resource_type="stylesheet", identity="anonymous",
        )
    with pytest.raises(ValueError):
        await manager.scoped_ingest_caido_exchange(
            method="POST", url=ORIGIN + "/api/search", response_status=200,
            request_body_base64="not!base64!", resource_type="fetch",
            identity="anonymous",
        )


@pytest.mark.asyncio
async def test_ingested_capture_is_recorded_as_scoped_browser_exchange():
    manager = _manager()
    out = json.loads(await manager.scoped_ingest_caido_exchange(
        method="GET", url=URL, response_status=200,
        response_content_type="application/json", resource_type="xhr",
        identity="anonymous",
    ))
    record = evidence_store(manager).records.get(out["artifact_id"])
    assert record is not None and record["kind"] == "scoped_browser_exchange"
    assert record["identity"] == "anonymous"
