"""Vulnerable/patched multi-user fixtures for the cell→proof escalation path."""

import json

import httpx
import pytest

from app.services.agent.assessment_scope import register_scope
from app.services.agent.coverage_cells import migrate_coverage_cells
from app.services.agent.engagement_brain import (
    coverage_progress,
    denominator_surfaces,
    engagement_brain_from_dict,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("patched", [False, True], ids=["vulnerable", "patched"])
async def test_two_verified_users_route_only_vulnerable_match_to_proof(
    monkeypatch, patched
):
    original = httpx.AsyncClient
    calls = []

    def handler(request):
        user = request.headers.get("x-test-user", "anonymous")
        calls.append((request.url.path, user))
        if request.url.path == "/me":
            return httpx.Response(200, json={"id": user})
        if request.url.path == "/orders/order-a":
            if patched and user == "B":
                return httpx.Response(403, json={"error": "denied"})
            return httpx.Response(
                200,
                json={
                    "order_id": "order-a",
                    "owner_id": "A",
                    "private_marker": "owner-controlled",
                },
            )
        return httpx.Response(404, json={"error": "missing"})

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        lambda **kwargs: original(transport=httpx.MockTransport(handler), **kwargs),
    )
    org_token = current_organization_id.set(91001 if patched else 91000)
    session_token = current_session_id.set(
        "multi-user-patched" if patched else "multi-user-vulnerable"
    )
    try:
        manager = ASMToolsManager()
        register_scope(manager, "app.test")
        for identity in ("A", "B"):
            await manager.register_test_identity(
                identity,
                "https://app.test",
                headers={"x-test-user": identity},
                role="user",
                tenant="tenant-1",
            )
            check = json.loads(
                await manager.check_test_identity(
                    identity,
                    "https://app.test/me",
                    "id",
                    identity,
                )
            )
            assert check["authenticated"] is True

        await manager.map_application_traffic(
            [
                {
                    "method": "GET",
                    "url": "https://app.test/orders/order-a",
                }
            ],
            identity="A",
            source="multi_user_fixture",
        )
        operation = manager._engagement_brain["application_operations"][0]
        await manager.generate_authorization_matrix(
            [
                {
                    "operation_id": operation["id"],
                    "identity": "B",
                    "expected": "deny",
                }
            ],
            operation_ids=[operation["id"]],
            identity_names=["B"],
        )
        brain = engagement_brain_from_dict(manager._engagement_brain)
        matrix = next(
            row
            for row in brain.authorization_matrix
            if row["operation_id"] == operation["id"] and row["identity"] == "B"
        )
        migrate_coverage_cells(brain, denominator=denominator_surfaces(brain))
        cell = next(
            row
            for row in brain.coverage_cells
            if row["source"] == "authorization_matrix"
            and row["operation_id"] == operation["id"]
            and row["identity"] == "B"
        )
        manager._engagement_brain = brain.to_dict()

        result = json.loads(
            await manager.test_authorization_boundary(
                "https://app.test/orders/order-a",
                "A",
                "B",
                "owner_id",
                matrix["hypothesis_id"],
                cell["id"],
            )
        )
        assert result["baseline"]["request"]["identity"] == "A"
        assert result["mutant"]["request"]["identity"] == "B"
        assert result["baseline"]["trace"].get("coverage_cell_id") == ""
        assert result["mutant"]["trace"]["coverage_cell_id"] == cell["id"]

        resumed = engagement_brain_from_dict(manager._engagement_brain)
        if patched:
            assert result["verdict"] == "MUTANT_DENIED"
            assert "proof_escalation" not in result
            assert resumed.proof_escalations == []
        else:
            assert result["verdict"] == "LIKELY_IMPACT"
            assert "verified_cross_identity_object_match" in result["signals"]
            escalation = result["proof_escalation"]
            assert escalation["specialist"] == "api_authz"
            assert escalation["coverage_cell_id"] == cell["id"]
            traced_cell = next(
                row for row in resumed.coverage_cells if row["id"] == cell["id"]
            )
            assert traced_cell["proof_escalation_id"] == escalation["id"]
            assert traced_cell["status"] == "in_focus"
            progress = coverage_progress(resumed)
            assert progress["pending_proof_escalation_count"] == 1
            assert progress["ready_to_complete_coverage"] is False

        assert ("/orders/order-a", "A") in calls
        assert ("/orders/order-a", "B") in calls
    finally:
        current_session_id.reset(session_token)
        current_organization_id.reset(org_token)
