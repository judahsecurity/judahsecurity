import pytest
from fastapi import HTTPException

from aegis_praetorium.config import PraetoriumConfig, get_config, set_config
from aegis_praetorium.denylist import (
    DenyPolicy,
    DenyRule,
    StaticDenyPolicyProvider,
    evaluate,
    extract_hosts,
    get_deny_policy_provider,
    host_matches,
    set_deny_policy_provider,
)
from aegis_praetorium.lictor import HookContext, Lictor
from app.services import agent_denylist

ACCEPTED = {"document_text": "signed RoE", "document_hash": "abc"}


@pytest.fixture(autouse=True)
def _restore_globals():
    cfg, provider = get_config(), get_deny_policy_provider()
    yield
    set_config(cfg)
    set_deny_policy_provider(provider)
    agent_denylist.invalidate()


def _use(policy: DenyPolicy) -> None:
    set_deny_policy_provider(StaticDenyPolicyProvider(policy))


def test_extracts_hosts_from_positional_args_urls_and_json():
    text = 'nmap -sV portal.agency.gov\n{"url": "https://API.Example.com/v1"} 10.0.0.5'
    hosts = extract_hosts(text)
    assert "portal.agency.gov" in hosts
    assert "api.example.com" in hosts
    assert "10.0.0.5" in hosts


def test_host_matching_covers_suffix_wildcard_ip_and_cidr():
    assert host_matches("a.b.example.com", "example.com")
    assert host_matches("a.example.com", "*.example.com")
    assert not host_matches("notexample.com", "example.com")
    assert host_matches("10.1.2.3", "10.0.0.0/8")
    assert host_matches("10.1.2.3", "10.1.2.3")
    assert not host_matches("10.1.2.4", "10.1.2.3")


def test_government_domains_are_blocked_by_default():
    _use(DenyPolicy())
    verdict = evaluate(["-u https://portal.agency.gov/login"])
    assert verdict.blocked
    assert verdict.rule.source == "default"
    assert "portal.agency.gov" in verdict.reason
    assert not evaluate(["-u https://shop.example.com"]).blocked


def test_written_scope_in_lifts_a_default_but_a_bare_suffix_does_not():
    specific = agent_denylist.policy_from_roe({**ACCEPTED, "scope_in": ["agency.gov"]})
    assert not evaluate(["https://portal.agency.gov"], policy=specific).blocked
    assert evaluate(["https://other.gov"], policy=specific).blocked

    broad = agent_denylist.policy_from_roe({**ACCEPTED, "scope_in": ["*.gov", "gov"]})
    assert evaluate(["https://portal.agency.gov"], policy=broad).blocked

    unsigned = agent_denylist.policy_from_roe({"scope_in": ["agency.gov"]})
    assert evaluate(["https://portal.agency.gov"], policy=unsigned).blocked


def test_scope_out_and_patterns_block_even_when_roe_is_disabled():
    policy = agent_denylist.policy_from_roe({
        "enabled": False,
        "scope_out": ["payments.example.com", "192.168.0.0/16"],
        "deny_patterns": [r"/admin/delete"],
    })
    assert evaluate(["GET https://payments.example.com/x"], policy=policy).blocked
    assert evaluate(["curl http://192.168.4.4/"], policy=policy).blocked
    hit = evaluate(["https://app.example.com/ADMIN/delete?id=1"], policy=policy)
    assert hit.blocked and hit.rule.kind == "regex"
    assert not evaluate(["https://app.example.com/admin/view"], policy=policy).blocked


def test_org_scope_out_cannot_be_lifted_by_scope_in():
    policy = agent_denylist.policy_from_roe({
        **ACCEPTED, "scope_in": ["example.com"], "scope_out": ["vendor.example.com"],
    })
    assert evaluate(["https://vendor.example.com"], policy=policy).blocked


def test_org_dry_run_logs_org_rules_but_keeps_defaults():
    policy = agent_denylist.policy_from_roe({"scope_out": ["example.com"], "deny_dry_run": True})
    org_hit = evaluate(["https://example.com"], policy=policy)
    assert not org_hit.blocked and org_hit.would_block
    assert evaluate(["https://x.mil"], policy=policy).blocked


def test_global_dry_run_and_disable_switches():
    _use(DenyPolicy())
    set_config(PraetoriumConfig(denylist_dry_run=True))
    verdict = evaluate(["https://x.gov"])
    assert not verdict.blocked and verdict.would_block
    set_config(PraetoriumConfig(denylist_enabled=False))
    assert not evaluate(["https://x.gov"]).would_block


def test_failing_provider_keeps_default_rules():
    class Broken:
        def policy_for(self, org_id):
            raise RuntimeError("db down")

    set_deny_policy_provider(Broken())
    assert evaluate(["https://x.gov"], org_id=7).blocked


def test_lictor_hook_inspects_structured_argument_text():
    _use(DenyPolicy(rules=(DenyRule(kind="host", pattern="secret.example.com"),)))
    ctx = HookContext(
        tool_name="execute_nuclei", args="", parsed_args=[], command=["nuclei"],
        metadata={"argument_text": "target=https://secret.example.com"},
    )
    result = Lictor().run_pre(ctx)
    assert not result.allowed
    assert "secret.example.com" in result.reason


def test_read_only_tools_are_exempt_and_new_tools_are_checked():
    _use(DenyPolicy())
    assert agent_denylist.is_exempt("save_note")
    assert agent_denylist.is_exempt("nuclei_help")
    assert not agent_denylist.check_tool_call("save_note", {"text": "saw x.gov"}, 1).blocked
    blocked = agent_denylist.check_tool_call(
        "brand_new_http_tool", {"request": {"url": "https://x.gov/a"}}, 1,
    )
    assert blocked.blocked


def test_tool_manager_refuses_before_running_the_tool():
    from app.services.agent.tools import ASMToolsManager

    _use(DenyPolicy())
    manager = ASMToolsManager.__new__(ASMToolsManager)
    refusal = manager._denylist_refusal("scoped_http_get", {"url": "https://x.gov/"}, None)
    assert refusal and refusal["denylist_blocked"] and refusal["success"] is False
    assert manager._denylist_refusal("scoped_http_get", {"url": "https://ok.example"}, None) is None


def test_preview_uses_candidate_rules_without_touching_the_live_provider():
    live = StaticDenyPolicyProvider(DenyPolicy())
    set_deny_policy_provider(live)
    out = agent_denylist.preview(["https://a.example.com", "https://b.example.com"],
                                 {"scope_out": ["a.example.com"]})
    assert [r["blocked"] for r in out["results"]] == [True, False]
    assert get_deny_policy_provider() is live


def test_route_rejects_invalid_regex():
    from app.api.routes.roe import _validate_patterns

    with pytest.raises(HTTPException) as exc:
        _validate_patterns(["(unclosed"])
    assert exc.value.status_code == 400
    assert _validate_patterns([" a ", "a", ""]) == ["a"]
