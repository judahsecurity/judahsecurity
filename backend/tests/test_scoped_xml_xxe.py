"""The XML specialist may adapt within one observed capture and proof gate."""

import json
import time

import pytest

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain, engagement_brain_from_dict
from app.services.agent.evidence_store import evidence_store
from app.services.agent.independent_verify import run_independent_verifiers, submit_candidate
from app.services.agent.parameter_inventory import collect_parameter_inventory
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.scoped_assessment.browser_traffic import package_exchange
from app.services.agent.scoped_assessment.xml_entity import plan_xml_entity_probe
from app.services.agent.tools import ASMToolsManager


ORIGIN = "https://app.example.test"
TARGET = ORIGIN + "/catalog/product/stock"
BODY = b"<stockCheck><productId>1</productId><storeId>2</storeId></stockCheck>"


def _observed_xml_manager():
    manager = ASMToolsManager()
    manager._fallback_target = ORIGIN
    public, private = package_exchange(
        url=TARGET, expected_origin=ORIGIN, action_ref="stock-button",
        method="POST", resource_type="xhr", status=200,
        content_type="application/json", request_body=BODY,
        response_body=b'{"stock":9}', request_content_type="application/xml",
        page_url=ORIGIN + "/catalog/product/1",
    )
    capture_id = evidence_store(manager).record(
        "scoped_browser_exchange", public, target=TARGET, identity="anonymous",
    )
    manager._scoped_browser_exchanges = {capture_id: {
        "identity": "anonymous", "private": private, "public": public,
        "verifier_run_id": None,
    }}
    cmap = {"target": ORIGIN, "scope": ORIGIN, "parameter_inventory": [{
        "url": TARGET, "method": "POST", "name": "document",
        "location": "body_xml", "source": "browser_traffic",
        "identity": "anonymous", "artifact_id": capture_id,
    }]}
    manager._capability_map = cmap
    brain = EngagementBrain(target=ORIGIN)
    seed_parameter_coverage_cells(brain, collect_parameter_inventory(cmap))
    lease = claim_coverage_cell_leases(
        brain, ["injection"], allowed_test_types=frozenset({"xxe"}),
    )["injection"]
    manager._engagement_brain = brain.to_dict()
    return manager, lease, capture_id


def test_xml_plan_preserves_capture_and_rejects_unsafe_shapes():
    assert is_tool_allowed_in_phase("scoped_xml_entity_assigned", "exploitation")
    manager, _, capture_id = _observed_xml_manager()
    private = manager._scoped_exchange(capture_id, "anonymous")
    plan = plan_xml_entity_probe(private, allowed_origin=ORIGIN,
                                 expected_path="/catalog/product/stock")
    assert plan["url"] == TARGET
    assert "<!ENTITY prowl SYSTEM \"{{callback_url}}\">" in plan["callback_body"]
    assert "<productId>&prowl;</productId>" in plan["callback_body"]
    assert "<!ENTITY prowl \"1\">" in plan["control_body"]
    assert BODY.decode() not in plan["callback_body"]
    with pytest.raises(ValueError, match="assigned endpoint"):
        plan_xml_entity_probe(private, allowed_origin=ORIGIN, expected_path="/other")
    unsafe = json.loads(private)
    unsafe["request_body_base64"] = "PCFET0NUWVBFIGEgWzwhRU5USVRZIGIgc1lTVEVNICJmaWxlOi8vL2V0Yy9wYXNzd2QiPl0+PGE+JmI7PC9hPg=="
    with pytest.raises(ValueError, match="contains a DTD"):
        plan_xml_entity_probe(json.dumps(unsafe).encode(), allowed_origin=ORIGIN,
                              expected_path="/catalog/product/stock")


@pytest.mark.asyncio
async def test_xml_callback_summary_keeps_proof_with_large_request(monkeypatch):
    from app.services.agent import oob_callback_workflow

    async def fake_workflow(manager, **kwargs):
        return {
            "success": True, "callback_observed": True,
            "evidence_ids": ["register", "plant", "poll"],
            "proof": {"kind": "oob_callback", "register_id": "register",
                      "plant_id": "plant", "poll_id": "poll"},
            "request": {"body": "x" * 20_000},
        }

    monkeypatch.setattr(oob_callback_workflow, "run_callback_workflow", fake_workflow)
    manager = ASMToolsManager()
    raw = await manager.run_oob_callback_workflow(url=TARGET, summary_only=True)
    result = json.loads(raw)
    assert result["evidence_ids"] == ["register", "plant", "poll"]
    assert result["proof"]["poll_id"] == "poll"
    assert "request" not in result


@pytest.mark.asyncio
async def test_xml_parser_control_is_bounded_and_stays_a_lead(monkeypatch):
    manager, lease, _ = _observed_xml_manager()
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/catalog/product/stock"]})

    async def fake_http_exchange(**kwargs):
        assert kwargs["method"] == "POST" and kwargs["url"] == TARGET
        assert kwargs["follow_redirects"] is False
        assert '<!ENTITY prowl "1">' in kwargs["body"]
        assert "SYSTEM" not in kwargs["body"]
        return {"evidence_id": "control-exchange", "response": {"status": 200}}

    monkeypatch.setattr(manager, "_http_exchange", fake_http_exchange)
    result = await manager.scoped_xml_entity_assigned(
        lease.coverage_cell_id, lease.id, "parser_control",
    )
    assert result["success"] is True and result["proof_confirmed"] is False
    assert manager._scoped_post_count == 1
    repeated = await manager.scoped_xml_entity_assigned(
        lease.coverage_cell_id, lease.id, "parser_control",
    )
    assert repeated["error"] == "technique_already_attempted"


@pytest.mark.asyncio
@pytest.mark.parametrize("verifier_has_entity", [True, False])
async def test_captured_xml_callback_requires_approval_and_fresh_verifier(
    monkeypatch, verifier_has_entity,
):
    manager, lease, capture_id = _observed_xml_manager()
    denied = await manager.scoped_xml_entity_assigned(
        lease.coverage_cell_id, lease.id, "external_callback",
    )
    assert denied["error"] == "operator_approval_required"
    manager.set_scoped_assessment_policy({"body_replay_paths": ["/catalog/product/stock"]})
    denied = await manager.scoped_xml_entity_assigned(
        lease.coverage_cell_id, lease.id, "external_callback",
    )
    assert denied["error"] == "oob_callbacks_not_authorized"
    manager._oob_callbacks_allowed = True
    store = evidence_store(manager)
    calls = []

    async def fake_execute(name, args):
        assert name == "run_oob_callback_workflow"
        assert args["url"] == TARGET and args["method"] == "POST"
        assert args["location"] == "raw" and args["identity"] == "anonymous"
        assert args["headers"]["Content-Type"] == "application/xml"
        number = len(calls) + 1
        domain = f"probe{number}.oast.test"
        body = args["body"].replace("{{callback_url}}", "https://" + domain)
        assert "<productId>&prowl;</productId>" in body
        if number == 2 and not verifier_has_entity:
            body = f"<stockCheck><productId>https://{domain}</productId></stockCheck>"
        session_id = f"session-{number}"
        register_id = store.record("oob_register", {
            "payload_domain": domain, "session_id": session_id, "reused": False,
        }, target=TARGET)
        time.sleep(0.001)
        plant_id = store.record("http_exchange", {
            "request": {"method": "POST", "url": TARGET, "identity": "anonymous",
                        "headers": args["headers"], "body": body},
            "response": {"status": 200, "url": TARGET, "body": "ok"},
        }, target=TARGET, identity="anonymous")
        time.sleep(0.001)
        poll_id = store.record("oob_poll", {
            "session_id": session_id,
            "interactions": [{"protocol": "dns", "unique_id": f"probe{number}"}],
        }, target=TARGET)
        calls.append(domain)
        return {"success": True, "output": json.dumps({
            "success": True, "callback_observed": True, "poll_attempts": 1,
            "evidence_ids": [register_id, plant_id, poll_id],
            "proof": {"kind": "oob_callback", "register_id": register_id,
                      "plant_id": plant_id, "poll_id": poll_id},
        })}

    monkeypatch.setattr(manager, "_execute_impl", fake_execute)
    hunter = await manager.scoped_xml_entity_assigned(
        lease.coverage_cell_id, lease.id, "external_callback",
    )
    assert hunter["proof_confirmed"] is True
    assert len(calls) == 1 and hunter["evidence_id"] in store.records
    cell = next(row for row in engagement_brain_from_dict(manager._engagement_brain).coverage_cells
                if row["id"] == lease.coverage_cell_id)
    assert cell["status"] == "in_focus"
    assert cell["xxe_probe_attempts"][0]["technique"] == "external_callback"
    brain = engagement_brain_from_dict(manager._engagement_brain)
    candidate = submit_candidate(
        brain, title="XXE in stock check", target=TARGET,
        vulnerability_class="xxe", identity="anonymous",
        parameter="body_xml:document", capture_id=capture_id,
        evidence_ids=[hunter["evidence_id"]],
        coverage_cell_id=lease.coverage_cell_id,
    )
    manager._engagement_brain = brain.to_dict()
    reports = await run_independent_verifiers(
        [candidate], llm=None, tools_manager=manager, targets=[TARGET],
    )
    assert reports[0]["status"] == (
        "confirmed" if verifier_has_entity else "inconclusive"
    ), reports
    assert calls == ["probe1.oast.test", "probe2.oast.test"]
