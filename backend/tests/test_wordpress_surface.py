"""WordPress surface: fingerprint → mandatory probes, even on thin maps."""

from app.services.agent.capability_map import (
    build_capability_map_from_crawl,
    select_specialists_for_map,
)
from app.services.agent.methodology_catalog import methodologies_from_capability_map
from app.services.agent.skills_service import get_skill, parse_skill_prefix, resolve
from app.services.agent.tester_loop import complete_blocked_reason, forced_next_step
from app.services.agent.wordpress_surface import (
    stamp_stack_on_map,
    wordpress_detected,
    wordpress_forced_step,
    wordpress_from_map,
    wordpress_hunt_note,
    wordpress_missing_probes,
    wordpress_probe_status,
)


def _fake_crawl(**overrides):
    from types import SimpleNamespace

    base = dict(
        target="https://www.emulate3d.com",
        scope="emulate3d.com",
        authenticated=False,
        pages_visited=["https://www.emulate3d.com/"],
        forms=[],
        api_calls={},
        js_files={"https://www.emulate3d.com/wp-content/themes/demo/style.css"},
        endpoints_from_js=set(),
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_thin_wordpress_map_is_attack_ready_and_hunts():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    assert wordpress_from_map(cmap) is True
    assert "wordpress" in cmap.capabilities
    assert cmap.ready_for_attack is True
    ids = {m.id for m in methodologies_from_capability_map(cmap)}
    assert "wp_rest_user_enum" in ids
    assert "wp_ajax_tax_query_sqli" in ids
    assert "wp_plugin_cves" in ids
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "wordpress" in hunts
    names = select_specialists_for_map(cmap)
    assert "injection" in names


def test_stamp_kickoff_tech_onto_empty_paths():
    state = {
        "target_info": {
            "technologies": ["WordPress:5.8.1"],
            "primary_target": "https://www.emulate3d.com",
        },
        "kickoff_brief": "Tech (wappalyzer): WordPress:5.8.1",
        "execution_trace": [],
    }
    stamped = stamp_stack_on_map({"target": "https://www.emulate3d.com", "notes": []}, state)
    assert wordpress_from_map(stamped)
    assert stamped.get("ready_for_attack") is True
    ids = {m["id"] for m in (stamped.get("methodologies") or [])}
    assert "wp_rest_user_enum" in ids


def test_forced_wp_probes_after_crawl():
    url = "https://www.emulate3d.com"
    state = {
        "original_objective": url,
        "target_info": {
            "primary_target": url,
            "technologies": ["WordPress:5.8.1"],
        },
        "kickoff_brief": "CMS: WordPress is in-play now",
        "execution_trace": [{"tool_name": "execute_deep_crawl", "success": True}],
    }
    assert wordpress_detected(state)
    step = forced_next_step(state)
    assert step and step["tool_name"] == "check_cve_applicability"
    assert "emulate3d.com" in (step.get("tool_args") or {}).get("url", "")

    after_cves = {
        **state,
        "execution_trace": state["execution_trace"] + [
            {
                "tool_name": "check_cve_applicability",
                "tool_args": {"url": url},
                "success": True,
            }
        ],
    }
    step = wordpress_forced_step(after_cves)
    assert step and step["tool_name"] == "execute_curl"
    assert "wp-json/wp/v2/users" in (step.get("tool_args") or {}).get("args", "")

    after_users = {
        **after_cves,
        "execution_trace": after_cves["execution_trace"] + [
            {
                "tool_name": "execute_curl",
                "tool_args": {"args": f"-sS -D- {url}/wp-json/wp/v2/users?per_page=100"},
                "success": True,
            }
        ],
    }
    step = wordpress_forced_step(after_users)
    assert step and step["tool_name"] == "compare_requests"
    mutant = (step.get("tool_args") or {}).get("mutant") or {}
    assert "admin-ajax.php" in str(mutant.get("url") or "")
    assert "SLEEP(2)" in str(mutant.get("body") or "")


def test_complete_blocked_until_wp_probes():
    url = "https://www.emulate3d.com"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url, "technologies": ["WordPress"]},
        "kickoff_brief": "WordPress 5.8.1",
        "execution_trace": [
            {"tool_name": "execute_interceptor", "success": True},
            {"tool_name": "recon_worker:ferox_dirs", "success": True},
            {"tool_name": "fingerprint_api", "success": True},
            {"tool_name": "fetch_lazy_chunks", "success": True},
            {"tool_name": "extract_js_endpoints", "success": True},
            {"tool_name": "sync_engagement_brain", "success": True},
            {"tool_name": "fireteam_dispatch", "success": True},
        ],
        "engagement_brain": {"hypotheses": [{"id": "h1"}]},
        "capability_map": {"target": url, "pages_visited": ["/"]},
    }
    reason = complete_blocked_reason(state)
    assert reason
    assert "wp_users_enum" in reason or "REST user enum" in reason or "plugin" in reason.lower()
    missing = wordpress_missing_probes(state)
    assert {m["id"] for m in missing} >= {"wp_users_enum", "wp_ajax_sqli", "wp_plugin_cves"}


def test_wp_probes_unlock_complete():
    url = "https://www.emulate3d.com"
    state = {
        "original_objective": url,
        "target_info": {"primary_target": url, "technologies": ["WordPress"]},
        "execution_trace": [
            {"tool_name": "execute_interceptor", "success": True},
            {"tool_name": "recon_worker:ferox_dirs", "success": True},
            {"tool_name": "fingerprint_api", "success": True},
            {"tool_name": "fetch_lazy_chunks", "success": True},
            {"tool_name": "extract_js_endpoints", "success": True},
            {"tool_name": "sync_engagement_brain", "success": True},
            {"tool_name": "fireteam_dispatch", "success": True},
            {
                "tool_name": "check_cve_applicability",
                "tool_args": {"url": url},
                "success": True,
            },
            {
                "tool_name": "execute_curl",
                "tool_args": {"args": f"-sS {url}/wp-json/wp/v2/users"},
                "success": True,
            },
            {
                "tool_name": "compare_requests",
                "tool_args": {
                    "baseline": {"url": f"{url}/wp-admin/admin-ajax.php", "body": "action=loadmore"},
                    "mutant": {"url": f"{url}/wp-admin/admin-ajax.php", "body": "SLEEP(2)"},
                },
                "success": True,
            },
        ],
        "engagement_brain": {"hypotheses": [{"id": "h1"}]},
        "capability_map": {"target": url, "pages_visited": ["/"]},
    }
    assert wordpress_probe_status(state)["users_enum"] is True
    assert wordpress_probe_status(state)["ajax_sqli"] is True
    assert wordpress_missing_probes(state) == []
    assert complete_blocked_reason(state) is None


def test_wordpress_skill_and_pack():
    from app.services.agent.playbooks import get_playbook
    from app.services.agent.skill_md import list_skill_packs, skill_body
    from app.services.agent.specialist_skills import skill_pack_for

    skill = get_skill("wordpress")
    assert skill and skill.playbook_id == "wordpress_stack"
    parsed, args, _rest = parse_skill_prefix("/wordpress https://www.emulate3d.com")
    assert parsed and parsed.id == "wordpress"
    assert args.get("target") == "https://www.emulate3d.com"
    hit = resolve("/skill wordpress target=https://www.emulate3d.com")
    assert hit["matched"] is True
    assert "wp-json" in hit["system_context"]
    assert "wordpress" in list_skill_packs()
    assert "admin-ajax" in skill_body("wordpress")
    assert get_playbook("wordpress_stack")
    inj = skill_pack_for("injection")
    assert "wp-json" in inj.lower()
    assert "tax_query" in inj.lower() or "admin-ajax" in inj.lower()


def test_hunt_note_still_sees_kickoff_tech():
    note = wordpress_hunt_note({
        "target_info": {
            "technologies": ["WordPress:5.8.1", "PHP"],
            "primary_target": "https://www.emulate3d.com",
        },
        "execution_trace": [],
        "kickoff_brief": "Tech (wappalyzer): WordPress:5.8.1",
    })
    assert "WordPress detected" in note
    assert "/wp-json/wp/v2/users" in note
