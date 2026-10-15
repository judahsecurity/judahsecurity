from pathlib import Path

from agent.web_security_playbooks import (
    format_hunter_playbooks,
    relevant_playbooks,
    topic_playbooks,
)
from agent.owasp_hunters import create_hunters_for_engagement


def test_academy_catalog_is_complete_and_in_sync_with_platform():
    rows = topic_playbooks()
    assert len(rows) == 31
    assert len({row["id"] for row in rows}) == len(rows)
    vanguard = Path(__file__).parents[1] / "agent" / "web_security_topics.json"
    platform = Path(__file__).parents[2] / "backend" / "app" / "services" / "agent" / "methodology_procedures" / "web_security_topics.json"
    assert vanguard.read_bytes() == platform.read_bytes()


def test_observed_feature_selects_relevant_cards():
    ids = {row["id"] for row in relevant_playbooks(
        "cache_poison_hunter", "Authenticated account page; CDN X-Cache: HIT"
    )}
    assert {"web_cache_deception", "web_cache_poisoning", "web_essential_skills"} <= ids
    assert "web_llm_attacks" not in ids
    assert "web_websockets" in format_hunter_playbooks("websocket_hunter", "wss://example.test/chat")


def test_selected_hunters_receive_topic_instructions():
    hunters = create_hunters_for_engagement(
        max_turns=15,
        recon_brief="Observed /api/items?user_id=1, a chatbot, and a login form",
        include_api_framework=False,
        include_enterprise=False,
    )
    by_name = {hunter.name: hunter.instructions for hunter in hunters}
    assert "web_api_testing" in by_name["authz_hunter"]
    assert "web_llm_attacks" in by_name["llm_ai_hunter"]
    assert "web_sqli" in by_name["injection_hunter"]
