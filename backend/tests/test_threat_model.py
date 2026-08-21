"""Threat-model bootstrap, brain seeding, and skill/playbook wiring."""

from pathlib import Path

from app.services.agent.capability_map import build_capability_map_from_crawl
from app.services.agent.engagement_brain import (
    engagement_brain_from_dict,
    seed_hypotheses_from_capability_map,
    specialists_from_open_hypotheses,
)
from app.services.agent.playbooks import get_playbook, list_playbooks
from app.services.agent.skills_service import get_skill, parse_skill_prefix
from app.services.agent.threat_model import (
    apply_threat_patch,
    bootstrap_from_code,
    bootstrap_from_url,
    format_threat_model_for_prompt,
    to_markdown,
    threat_model_from_dict,
)
from types import SimpleNamespace


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://tenant-a.app.example.com/login",
            },
            {
                "method": "POST",
                "action": "/search",
                "inputs": ["q"],
                "page": "https://tenant-a.app.example.com/search",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {"GET /api/users?id=1", "GET /api/orders/100"},
            "tenant-b.app.example.com": {"GET /api/users?id=2"},
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items"},
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_url_bootstrap_ranks_authz_and_partitions_focus_areas():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    assert brain.threat_model
    ids = {t["id"] for t in brain.threat_model["threats"]}
    assert "T-object-authz" in ids
    assert "T-tenant-isolation" in ids
    assert "T-auth-boundary" in ids
    assert any(h.source == "threat_model" for h in brain.hypotheses)
    assert brain.focus_areas
    specs = {fa["specialist"] for fa in brain.focus_areas}
    assert "api_authz" in specs or "host_tenant" in specs
    md = to_markdown(threat_model_from_dict(brain.threat_model))
    assert "## 4. Threats" in md
    assert "T-object-authz" in md
    prompt = format_threat_model_for_prompt(brain.threat_model)
    assert "Ranked threats" in prompt
    names = specialists_from_open_hypotheses(brain)
    assert names[0] == "app_mapper"
    assert any(n in names for n in ("host_tenant", "api_authz", "auth_logic", "injection"))


def test_bare_url_bootstrap_before_crawl():
    model = bootstrap_from_url("https://app.example.com/login", technologies=["Next.js"])
    assert model.mode == "url"
    assert any(t.id == "T-auth-boundary" for t in model.threats)
    assert "next" in " ".join(model.frameworks).lower() or model.open_questions


def test_code_bootstrap_inventories_checkout(tmp_path: Path):
    (tmp_path / "package.json").write_text('{"dependencies":{"next":"14.0.0"}}', encoding="utf-8")
    (tmp_path / "auth.ts").write_text("export function login() {}", encoding="utf-8")
    model = bootstrap_from_code(str(tmp_path))
    assert model.mode == "code"
    assert "javascript" in model.languages or "next" in model.frameworks
    ids = {t.id for t in model.threats}
    assert "T-code-injection" in ids
    assert "T-code-authz" in ids
    assert any(t.specialist == "code_sast" for t in model.threats)
    assert any(fa.specialist == "code_sast" for fa in model.focus_areas)


def test_update_threat_deprioritize():
    model = bootstrap_from_url("https://app.example.com/api/users")
    patched = apply_threat_patch(
        model,
        "T-object-authz",
        deprioritize_reason="out of scope — no tenant data in ROE",
    )
    assert patched is not None
    assert patched.status == "risk_accepted"
    assert model.deprioritized


def test_playbook_and_skill_registered():
    assert get_playbook("threat_model")
    assert get_playbook("code_assessment")
    ids = {p["id"] for p in list_playbooks()}
    assert "threat_model" in ids
    assert "code_assessment" in ids
    skill = get_skill("threat-model")
    assert skill and skill.playbook_id == "threat_model"
    code = get_skill("code-scan")
    assert code and code.playbook_id == "code_assessment"
    parsed, args, rest = parse_skill_prefix("/threat-model target=https://app.example.com")
    assert parsed and parsed.id == "threat-model"
    assert args.get("target") == "https://app.example.com"
    assert rest == ""
    api = get_skill("api-test")
    assert api and api.playbook_id == "api_test"
    assert get_playbook("api_test")
