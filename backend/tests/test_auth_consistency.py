"""Auth-consistency invariant: pure logic + end-to-end against synthetic labs."""

import json

import auth_consistency_labs as labs
import httpx
import pytest
from app.services.agent import auth_consistency as ac
from app.services.agent.engagement_brain import (
    EngagementBrain,
    engagement_brain_from_dict,
)
from app.services.agent.tools import (
    ASMToolsManager,
    current_organization_id,
    current_session_id,
)

# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------


def test_plan_never_sends_delete_and_skips_state_changing_paths():
    variants, skipped = ac.plan_variants("/api/predictions/calculate/x", methods=["POST", "DELETE"])
    assert [v.method for v in variants if v.label.startswith("verb:")] == ["POST"]
    assert all(v.method != "DELETE" for v in variants)
    assert any("DELETE" in s for s in skipped)
    assert all(v.body == "{}" for v in variants)

    variants, skipped = ac.plan_variants("/api/users/delete/7")
    assert variants == [] and skipped
    variants, _ = ac.plan_variants("/api/users/delete/7", allow_state_changing=True)
    assert {v.method for v in variants} == {"POST", "PUT", "PATCH"}


@pytest.mark.parametrize(
    "variant_status,body,headers,expected",
    [
        (200, '{"data":"a,b\\n1,2\\n3,4","filename":"x.csv"}', {"content-type": "application/json"}, "bypass"),
        (200, '{"data":"","filename":"Dryer.csv"}', {"content-type": "application/json"}, "bypass"),
        (200, "", {}, "handler_reached"),
        (422, '{"detail":"field required"}', {}, "handler_reached"),
        (403, '{"message":"Invalid auth"}', {}, "consistent"),
        (302, "", {}, "consistent"),
        (405, "", {}, "not_routed"),
        (200, labs.SPA_SHELL, {"content-type": "text/html"}, "spa_fallback"),
        (200, '{"error":"Unauthorized","data":null}', {}, "soft_deny"),
        (200, '{"message":"Invalid auth"}', {}, "soft_deny"),
    ],
)
def test_classify_variant(variant_status, body, headers, expected):
    result = ac.classify_variant(
        baseline_status=403, baseline_body='{"message":"Invalid auth"}',
        variant_status=variant_status, variant_body=body, variant_headers=headers,
        shell_fingerprints={ac.body_fingerprint(labs.SPA_SHELL)},
    )
    assert result["outcome"] == expected, result


def test_classify_requires_denied_baseline():
    result = ac.classify_variant(
        baseline_status=200, baseline_body="{}", variant_status=200, variant_body='{"a":1}',
    )
    assert result["outcome"] == "not_applicable"


def test_data_shape_reports_embedded_csv_without_values():
    shape = ac.data_shape(json.dumps({"data": labs._csv(5), "filename": "m.csv"}), "application/json")
    assert shape["embedded_csv"] == {"rows": 5, "columns": 9}
    assert "Flow_A" not in json.dumps(shape)


def test_harvest_identifiers_from_listings():
    assert ac.harvest_identifiers({"models": [{"name": "Dryer"}, {"name": "Sim2"}]}) == ["Dryer", "Sim2"]
    assert ac.harvest_identifiers([{"report_id": "rpt-1", "owner_name": "ops"}]) == ["rpt-1", "ops"]
    assert ac.harvest_identifiers(["Dryer", "test2", True, "../etc"]) == ["Dryer", "test2"]
    # secret-looking keys and hash blobs are never used as path input
    leaked = {"items": [{"id": "a1", "api_key": "sk_live_x", "salt": "abc"}], "sha": "f" * 64}
    assert ac.harvest_identifiers(leaked) == ["a1"]
    assert ac.harvest_identifiers("not json") == []


@pytest.mark.parametrize(
    "template",
    [
        "https://t/api/predictions/calculate/{model_name}",
        "https://t/api/predictions/calculate/:model",
        "https://t/api/predictions/calculate/${modelName}",
        "https://t/api/predictions/calculate/<string:model>",
        "https://t/api/predictions/calculate/EXPR",
    ],
)
def test_expand_template_slot_styles(template):
    assert ac.expand_template(template, ["Dryer", "a b"]) == [
        "https://t/api/predictions/calculate/Dryer",
    ]


def test_expand_template_refuses_multi_slot():
    assert ac.expand_template("/orgs/{org}/models/{model}", ["a"]) == []


def test_seed_cells_one_per_alternate_method_and_routes_to_auth_logic():
    brain = EngagementBrain(target="https://t")
    obs = ac.deny_observation("GET", "https://t/api/predictions/calculate/m1", 403)
    ac.seed_auth_consistency_cells(brain, [obs, obs])
    cells = [c for c in brain.coverage_cells if c["test_type"] == ac.TEST_TYPE]
    assert sorted(c["parameter"] for c in cells) == ["method:PATCH", "method:POST", "method:PUT"]
    assert all(c["status"] == "untested" and c["priority_rank"] == 0 for c in cells)
    assert all(c["specialist"] == "auth_logic" for c in cells)

    ac.seed_auth_consistency_cells(brain, [ac.deny_observation("GET", "https://t/api/x/delete/1", 403)])
    blocked = [c for c in brain.coverage_cells if c["path"] == "/api/x/delete/1"]
    assert len(blocked) == 1 and blocked[0]["status"] == "blocked"
    assert ac.deny_observation("GET", "https://t/a", 200) is None


# ---------------------------------------------------------------------------
# End-to-end against labs (real tool, real scope + evidence plumbing)
# ---------------------------------------------------------------------------


@pytest.fixture
def run_lab(monkeypatch):
    original = httpx.AsyncClient
    org_token = current_organization_id.set(424242)
    session_token = current_session_id.set("auth-consistency-labs")

    async def _run(lab, **kwargs):
        monkeypatch.setattr(
            httpx, "AsyncClient",
            lambda **kw: original(transport=httpx.MockTransport(lab), **kw),
        )
        manager = ASMToolsManager()
        manager._assessment_scope.add("lab.test")
        manager._engagement_brain = EngagementBrain(target="https://lab.test").to_dict()
        out = json.loads(await manager.test_auth_consistency(**kwargs))
        return out, manager

    yield _run
    current_session_id.reset(session_token)
    current_organization_id.reset(org_token)


@pytest.mark.asyncio
async def test_lab_express_chain_from_leaked_model_names(run_lab):
    """No product knowledge: a listing leak + a templated route is enough."""
    lab = labs.express_get_only_auth()
    out, manager = await run_lab(
        lab,
        url="https://lab.test/api/predictions/calculate/{model}",
        identifier_source_url="https://lab.test/api/models",
    )
    assert out["harvested_identifiers"] == ["plant7mixerline2", "sim_oven", "empty_model"]
    assert out["verdict"] == "MUTANT_BYPASS_CANDIDATE"
    assert out["severity_hint"] == "high"
    bypassed = {b["url"].rsplit("/", 1)[-1] for b in out["bypasses"] if b["outcome"] == "bypass"}
    # Even the model with no data proves the handler ran (Praetorian's "Dryer" case).
    assert bypassed == {"plant7mixerline2", "sim_oven", "empty_model"}
    big = next(b for b in out["bypasses"] if b["url"].endswith("plant7mixerline2") and b["variant"] == "verb:POST")
    assert big["data_shape"]["embedded_csv"]["rows"] == 40
    assert all(len(b["evidence_ids"]) == 2 and all(b["evidence_ids"]) for b in out["bypasses"])
    assert out["proof_escalations"]
    assert not lab.sent("DELETE")
    # Output carries a bounded excerpt, never the dataset
    assert "Sample,Flow_A" in json.dumps(out) and ",40," not in json.dumps(out)

    brain = engagement_brain_from_dict(manager._engagement_brain)
    findings = [c for c in brain.coverage_cells
                if c["test_type"] == ac.TEST_TYPE and c["status"] == "finding"]
    assert {c["parameter"] for c in findings} >= {"method:POST"}
    assert brain.proof_escalations[0]["strategy"] == "independent_lane_replay"


@pytest.mark.asyncio
async def test_lab_flask_put_variant_generalizes(run_lab):
    """Different framework, verb, deny code, nouns and id shape."""
    lab = labs.flask_put_branch()
    out, _ = await run_lab(
        lab,
        url="https://lab.test/v2/reports/<report_id>/export",
        identifier_source_url="https://lab.test/v2/reports",
        max_targets=2,
    )
    assert out["verdict"] == "MUTANT_BYPASS_CANDIDATE"
    variants = {b["variant"] for b in out["bypasses"] if b["outcome"] == "bypass"}
    assert variants == {"verb:PUT"}
    assert {b["baseline_status"] for b in out["bypasses"]} == {401}


@pytest.mark.asyncio
async def test_lab_method_override_after_auth(run_lab):
    out, _ = await run_lab(labs.override_after_auth(), url="https://lab.test/rest/admin/config")
    assert out["verdict"] == "MUTANT_BYPASS_CANDIDATE"
    assert [b["variant"] for b in out["bypasses"]] == ["override:X-HTTP-Method-Override"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "factory,url",
    [
        (labs.properly_protected, "https://lab.test/api/predictions/calculate/m"),
        (labs.spa_catch_all, "https://lab.test/api/admin/users"),
        (labs.soft_deny_200, "https://lab.test/api/billing/summary"),
        (labs.method_not_allowed, "https://lab.test/api/metrics"),
    ],
)
async def test_negative_labs_are_not_flagged(run_lab, factory, url):
    out, manager = await run_lab(factory(), url=url)
    assert out["verdict"] == "CONSISTENT", out
    assert out["bypasses"] == []
    brain = engagement_brain_from_dict(manager._engagement_brain)
    tested = [c for c in brain.coverage_cells if c["test_type"] == ac.TEST_TYPE and c["path"] in url]
    assert tested and all(c["status"] == "tested_clean" for c in tested)


@pytest.mark.asyncio
async def test_state_changing_path_sends_no_write_verbs(run_lab):
    lab = labs.state_changing_path()
    out, _ = await run_lab(lab, url="https://lab.test/api/users/delete/7")
    assert out["bypasses"] == []
    assert out["targets"][0]["skipped"]
    assert not [r for r in lab.requests if r.method != "GET"]


@pytest.mark.asyncio
async def test_templated_url_without_identifiers_asks_for_them(run_lab):
    out, _ = await run_lab(labs.express_get_only_auth(), url="https://lab.test/api/predictions/calculate/:model")
    assert out["error"] == "Templated URL needs identifiers"


@pytest.mark.asyncio
async def test_any_anonymous_deny_opens_coverage_cells(run_lab, monkeypatch):
    """Passive half: a 403 seen by any tool queues the invariant without a hint."""
    lab = labs.express_get_only_auth()
    original = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda **kw: original(transport=httpx.MockTransport(lab), **kw))
    manager = ASMToolsManager()
    manager._assessment_scope.add("lab.test")
    manager._engagement_brain = EngagementBrain(target="https://lab.test").to_dict()
    await manager._http_exchange("GET", "https://lab.test/api/predictions/calculate/sim_oven",
                                 use_auth_session=False)
    brain = engagement_brain_from_dict(manager._engagement_brain)
    open_cells = [c for c in brain.coverage_cells
                  if c["test_type"] == ac.TEST_TYPE and c["status"] == "untested"]
    assert {c["parameter"] for c in open_cells} == {"method:POST", "method:PUT", "method:PATCH"}


def test_tool_is_registered_for_authz_specialists():
    from app.services.agent.fireteam_service import _tool_contract, get_specialist

    manager = ASMToolsManager()
    assert callable(manager.get_tool("test_auth_consistency"))
    assert _tool_contract(manager, "test_auth_consistency").startswith("  - test_auth_consistency(url")
    for name in ("auth_logic", "api_authz"):
        assert "test_auth_consistency" in get_specialist(name).allowed_tools
