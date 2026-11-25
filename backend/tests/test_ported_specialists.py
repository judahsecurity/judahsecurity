"""Stack and perimeter specialists ported from the Vanguard hunters.

Covers profile resolution, tool allowlists against the live registry, proof
discipline in the prompts, and fingerprint-driven selection (ported from
aegis-vanguard/tests/test_hunter_selection.py and the Vanguard surface-signal
tables).
"""

from __future__ import annotations

import re

import pytest

from app.services.agent.capability_map import (
    build_capability_map_from_dict,
    select_specialists_for_map,
)
from app.services.agent.engagement_brain import (
    EngagementBrain,
    seed_hypotheses_from_capability_map,
    specialists_from_open_hypotheses,
)
from app.services.agent.fireteam_service import get_specialist
from app.services.agent.proof_policy import PROOFS_BY_CLASS
from app.services.agent.run_permissions import permitted_specialists
from app.services.agent.specialist_skills import skill_pack_for
from app.services.agent.surface_hunters import (
    PORTED_SPECIALISTS,
    SURFACE_HUNTERS,
    detect_surface_hunters,
)

NEW_SPECIALISTS = (
    "grpc_api", "nodejs_express", "deserialization", "m365_entra", "okta_idp",
    "sharepoint", "enterprise_vpn", "vcenter", "spring_boot", "laravel", "nextjs",
    "aspnet_iis",
)
FORBIDDEN_TOOLS = {"create_finding", "test_credential_spray", "execute_hydra", "execute_brutus"}


@pytest.fixture(scope="module")
def registry() -> set[str]:
    from app.services.agent.tools import ASMToolsManager

    return set(ASMToolsManager().tools)


def test_ported_names_match_surface_table():
    assert set(PORTED_SPECIALISTS) == set(NEW_SPECIALISTS)


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_profile_resolves_with_epithet_and_skill_pack(name):
    from app.services.agent.aegis_pantheon import PANTHEON

    profile = get_specialist(name)
    assert profile is not None and profile.name == name
    assert name in PANTHEON and profile.epithet == PANTHEON[name][0]
    assert profile.system_prompt_suffix
    assert skill_pack_for(name).startswith("SKILL PACK")


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_allowed_tools_exist_in_registry(name, registry):
    tools = get_specialist(name).allowed_tools
    missing = [tool for tool in tools if tool not in registry]
    assert not missing, f"{name} lists unregistered tools {missing}"
    assert len(tools) == len(set(tools))


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_no_direct_publish_or_credential_tools(name):
    assert not FORBIDDEN_TOOLS & set(get_specialist(name).allowed_tools)


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_named_classes_have_proof_policy_entries(name):
    text = get_specialist(name).system_prompt_suffix + skill_pack_for(name)
    classes = re.findall(r"vulnerability_class=\s*'([a-z_]+)'", text)
    for cls in classes:
        assert cls in PROOFS_BY_CLASS, f"{name} names unknown class {cls}"
    # Every lane states that some outcomes remain leads.
    assert "lead" in text.lower()


@pytest.mark.parametrize("name", ("enterprise_vpn", "vcenter", "sharepoint"))
def test_cve_lanes_are_kev_gated_and_known_cve_is_lead_only(name):
    text = get_specialist(name).system_prompt_suffix
    assert "search_vulnx" in get_specialist(name).allowed_tools
    assert "KEV" in text
    assert "known_cve" in text and "lead" in text
    assert PROOFS_BY_CLASS["known_cve"] == frozenset()


@pytest.mark.parametrize("name", ("m365_entra", "okta_idp"))
def test_identity_lanes_never_spray(name):
    profile = get_specialist(name)
    text = profile.system_prompt_suffix.lower()
    assert "no password spraying" in text
    assert "credential_assault" in text and "grants credential testing" in text
    assert PROOFS_BY_CLASS["account_enumeration"] == frozenset()


@pytest.mark.parametrize("name", ("deserialization", "nextjs"))
def test_oob_lanes_use_existing_workflow_only_when_authorized(name):
    profile = get_specialist(name)
    assert "execute_interactsh" in profile.allowed_tools  # stripped when OOB is off
    text = profile.system_prompt_suffix
    assert "run_oob_callback_workflow" in text
    assert "only when this run authorizes OOB" in text
    assert "oob_callback" in PROOFS_BY_CLASS["ssrf"]


def test_lead_only_lanes_are_not_dropped_by_permissions():
    chosen = ["credential_assault", *NEW_SPECIALISTS]
    assert permitted_specialists(chosen, allow_credential_testing=False) == list(NEW_SPECIALISTS)


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def _map(target="https://app.example.com", pages=(), apis=(), js=(), forms=(), third=(),
         samples=(), websockets=()):
    return {
        "target": target,
        "pages_visited": list(pages) or [target + "/"],
        "api_endpoints": [
            {"method": m, "path": p, "host": target.split("//", 1)[-1]} for m, p in apis
        ],
        "js_files": list(js),
        "forms": list(forms),
        "third_party": list(third),
        "api_samples": list(samples),
        "websockets": list(websockets),
    }


REPRESENTATIVE = {
    "grpc_api": _map(apis=[("POST", "/helloworld.Greeter/SayHello")]),
    "nodejs_express": _map(samples=[{"method": "GET", "url": "https://app.example.com/api/me",
                                     "response_headers": {"x-powered-by": "Express"}}]),
    "deserialization": _map(apis=[("POST", "/invoker/JMXInvokerServlet")]),
    "m365_entra": _map(third=["https://login.microsoftonline.com/common/oauth2/authorize"]),
    "okta_idp": _map(third=["https://example.okta.com/oauth2/default/v1/authorize"]),
    "sharepoint": _map(target="https://portal.example.com",
                       pages=["https://portal.example.com/_layouts/15/start.aspx"]),
    "enterprise_vpn": _map(target="https://vpn.example.com",
                           pages=["https://vpn.example.com/remote/login?lang=en"],
                           forms=[{"action": "/remote/logincheck", "inputs": ["username", "credential"]}]),
    "vcenter": _map(target="https://vc.example.com", pages=["https://vc.example.com/websso/SAML2/SSO"]),
    "spring_boot": _map(apis=[("GET", "/actuator/health")]),
    "laravel": _map(samples=[{"method": "GET", "url": "https://app.example.com/",
                              "set_cookie": "laravel_session"}]),
    "nextjs": _map(js=["https://app.example.com/_next/static/chunks/main-abc.js"]),
    "aspnet_iis": _map(pages=["https://app.example.com/Default.aspx"]),
}

# A storefront with search and a login form: the minimal web baseline.
UNRELATED = _map(
    pages=["https://shop.example.com/", "https://shop.example.com/search?q=shoes",
           "https://shop.example.com/login"],
    target="https://shop.example.com",
    apis=[("GET", "/api/products?page=1"), ("GET", "/api/cart")],
    js=["https://shop.example.com/static/app.js"],
    forms=[{"action": "/search", "inputs": ["q"]}, {"action": "/login", "inputs": ["email", "password"]}],
    third=["https://www.googletagmanager.com/gtm.js"],
)


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_signal_selects_specialist(name):
    data = REPRESENTATIVE[name]
    assert name in detect_surface_hunters(data)
    cmap = build_capability_map_from_dict(data)
    chosen = select_specialists_for_map(cmap)
    assert name in chosen, chosen
    assert len(chosen) <= 8


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_signal_seeds_hypothesis_for_specialist(name):
    cmap = build_capability_map_from_dict(REPRESENTATIVE[name])
    brain = seed_hypotheses_from_capability_map(EngagementBrain(), cmap.to_dict())
    hyps = [h for h in brain.hypotheses if h.specialist == name]
    assert hyps and hyps[0].methodology_id == f"surface_{name}"
    assert name in specialists_from_open_hypotheses(brain, max_specialists=40)


def test_unrelated_surface_selects_no_ported_specialist():
    # Ported from test_minimal_input_surface_uses_small_core_baseline.
    assert detect_surface_hunters(UNRELATED) == {}
    chosen = select_specialists_for_map(build_capability_map_from_dict(UNRELATED))
    assert not set(chosen) & set(NEW_SPECIALISTS)


@pytest.mark.parametrize("name", NEW_SPECIALISTS)
def test_other_fingerprints_do_not_cross_trigger(name):
    detected = set(detect_surface_hunters(REPRESENTATIVE[name])) & set(NEW_SPECIALISTS)
    assert detected == {name}


def test_product_fingerprint_needs_first_party_evidence():
    # A marketing link to a vendor is not an appliance on the target.
    data = _map(third=["https://www.fortinet.com/products/fortigate", "https://www.vmware.com/"])
    assert not {"enterprise_vpn", "vcenter"} & set(detect_surface_hunters(data))


def test_sharepoint_online_is_not_an_on_prem_farm():
    data = _map(target="https://contoso.sharepoint.com",
                pages=["https://contoso.sharepoint.com/_layouts/15/viewlsts.aspx"])
    assert "sharepoint" not in detect_surface_hunters(data)


def test_grpc_path_pattern_is_case_sensitive():
    assert "grpc_api" not in detect_surface_hunters(_map(apis=[("GET", "/api/settings/save")]))
    assert "grpc_api" not in detect_surface_hunters(
        _map(target="https://vpn.example.com", pages=["https://vpn.example.com/remote/login"])
    )


def test_many_fingerprints_respect_cap_and_forced_limit():
    data = _map(
        target="https://edge.example.com",
        pages=[
            "https://edge.example.com/", "https://edge.example.com/login",
            "https://edge.example.com/Default.aspx", "https://edge.example.com/account",
        ],
        apis=[("GET", "/actuator/env"), ("GET", "/telescope/requests"),
              ("POST", "/helloworld.Greeter/SayHello"), ("GET", "/api/users/1")],
        js=["https://edge.example.com/_next/static/chunks/main.js"],
        forms=[{"action": "/login", "inputs": ["email", "password"]}],
    )
    cmap = build_capability_map_from_dict(data)
    assert cmap.ready_for_attack
    chosen = select_specialists_for_map(cmap)
    assert len(chosen) <= 8
    assert chosen[-1] == "finding_judge"
    assert 1 <= len(set(chosen) & set(NEW_SPECIALISTS)) <= 8


def test_websocket_surface_adds_cswsh_card_for_api_authz():
    from app.services.agent.methodology_catalog import methodologies_from_capability_map

    data = _map(websockets=["wss://app.example.com/ws"])
    cards = {m.id: m for m in methodologies_from_capability_map(data)}
    assert cards["websocket_cswsh"].specialist == "api_authz"
    assert "CSWSH" in skill_pack_for("api_authz")


def test_thin_lanes_extended_in_existing_packs():
    assert "pull_request_target" in skill_pack_for("code_sast")
    assert "AKIA" in skill_pack_for("cloud_audit") and "ASIA" in skill_pack_for("cloud_audit")
    assert "never by using it" in skill_pack_for("cloud_audit")
    assert "cloud_audit" in skill_pack_for("secrets_hunter")
    cloud = next(h for h in SURFACE_HUNTERS if h.specialist == "cloud_audit")
    assert not cloud.first_party_only
    data = _map(third=["https://acme-assets.s3.amazonaws.com/logo.png"])
    assert "cloud_audit" in detect_surface_hunters(data)


def test_ported_probe_tools_are_granted_to_their_lanes():
    from app.services.agent.fireteam_service import (
        DEFAULT_SPECIALISTS, _PORTED_TOOL_GRANTS, get_specialist,
    )
    from app.services.agent.tools import ASMToolsManager

    registry = ASMToolsManager().tools
    for name, tools in _PORTED_TOOL_GRANTS.items():
        profile = get_specialist(name)
        assert profile is not None, name
        for tool in tools:
            assert tool in profile.allowed_tools and tool in registry, (name, tool)
    injection = get_specialist("injection")
    assert "record_defense_profile" in injection.allowed_tools
    assert "record_defense_profile" in registry
    comparers = [p for p in DEFAULT_SPECIALISTS if "compare_requests" in p.allowed_tools]
    assert comparers and all("diff_stored_exchanges" in p.allowed_tools for p in comparers)
    assert "diff_stored_exchanges" in registry
