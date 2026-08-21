"""Specialist skill packs + fireteam allowlist hygiene (offline-friendly)."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

_AGENT_DIR = Path(__file__).resolve().parents[1] / "app" / "services" / "agent"


def _load_specialist_skills():
    path = _AGENT_DIR / "specialist_skills.py"
    spec = importlib.util.spec_from_file_location("specialist_skills_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def _specialist_allowlists_from_ast() -> dict[str, list[str]]:
    """Parse DEFAULT_SPECIALISTS allowlists without importing langchain."""
    src = (_AGENT_DIR / "fireteam_service.py").read_text()
    tree = ast.parse(src)
    allowlists: dict[str, list[str]] = {}

    for node in tree.body:
        value = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.target.id == "DEFAULT_SPECIALISTS":
                value = node.value
        elif isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "DEFAULT_SPECIALISTS" for t in node.targets):
                value = node.value
        if not isinstance(value, ast.List):
            continue
        for elt in value.elts:
            if not isinstance(elt, ast.Call):
                continue
            kwargs = {kw.arg: kw.value for kw in elt.keywords if kw.arg}
            name_node = kwargs.get("name")
            tools_node = kwargs.get("allowed_tools")
            if not isinstance(name_node, ast.Constant) or not isinstance(tools_node, ast.List):
                continue
            tools = [
                t.value for t in tools_node.elts if isinstance(t, ast.Constant) and isinstance(t.value, str)
            ]
            allowlists[str(name_node.value)] = tools
    return allowlists


_FORBIDDEN = {
    "execute_trufflehog",
    "execute_prowler",
    "execute_scoutsuite",
    "execute_graphql_cop",
}


def test_every_default_specialist_has_skill_pack():
    ss = _load_specialist_skills()
    allowlists = _specialist_allowlists_from_ast()
    assert allowlists, "failed to parse DEFAULT_SPECIALISTS"
    for name in allowlists:
        pack = ss.skill_pack_for(name)
        assert pack, f"missing skill pack for {name}"


def test_no_stale_allowlist_tool_names():
    for name, tools in _specialist_allowlists_from_ast().items():
        bad = _FORBIDDEN.intersection(tools)
        assert not bad, f"{name} still lists {bad}"


def test_secrets_and_cloud_use_real_tools():
    allowlists = _specialist_allowlists_from_ast()
    assert "execute_hermes" in allowlists["secrets_hunter"]
    assert "execute_hermes" in allowlists["js_secrets"]
    assert "execute_themis" in allowlists["cloud_audit"]


def test_injection_and_auth_have_new_arsenal_tools():
    allowlists = _specialist_allowlists_from_ast()
    for name in ("execute_dalfox", "execute_commix", "execute_xsstrike", "execute_sqlmap", "execute_interactsh"):
        assert name in allowlists["injection"]
    assert "execute_hydra" in allowlists["auth_logic"]
    assert "test_credential_spray" in allowlists["auth_logic"]
    assert "execute_feroxbuster" in allowlists["web_recon"]
    assert "execute_feroxbuster" in allowlists["content_api"]
    assert "mutate_list" in allowlists["content_api"]
    assert "fingerprint_api" in allowlists["content_api"]
    assert "fingerprint_api" in allowlists["app_mapper"]
    assert "fetch_lazy_chunks" in allowlists["spa_client"]
    assert "run_custom_probe" in allowlists["injection"]
    assert "mutate_captured_request" in allowlists["injection"]
    assert "mutate_captured_request" in allowlists["api_authz"]



def test_credential_assault_and_finding_judge_exist():
    allowlists = _specialist_allowlists_from_ast()
    assert "credential_assault" in allowlists
    assert "finding_judge" in allowlists
    assert "execute_hydra" in allowlists["credential_assault"]
    assert "validate_finding" in allowlists["finding_judge"]
    assert "fireteam_dispatch" not in allowlists["credential_assault"]
    assert "fireteam_dispatch" not in allowlists["finding_judge"]


def test_pantheon_covers_specialists():
    path = _AGENT_DIR / "aegis_pantheon.py"
    spec = importlib.util.spec_from_file_location("pantheon_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    for name in _specialist_allowlists_from_ast():
        assert name in mod.PANTHEON, f"missing pantheon entry for {name}"
        assert mod.epithet_for(name)


def test_fireteam_injects_skill_pack_helper():
    src = (_AGENT_DIR / "fireteam_service.py").read_text()
    assert "skill_pack_for" in src
    assert "OperationDirective" in src or "directive" in src
    assert "finding_judge" in src
    assert "credential_assault" in src


def test_coverage_skill_pack_mentions_existing_prometheus_proxy():
    ss = _load_specialist_skills()
    coverage = ss.skill_pack_for("coverage")
    assert "admin/settings" in coverage
    assert "prometheus" in coverage.lower()
    assault = ss.skill_pack_for("credential_assault")
    assert "prom-operator" in assault
    assert "couchdb" in assault.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "foothold" in judge.lower() or "privileged" in judge.lower()
    assert "elasticsearch" in judge.lower() or "9200" in judge
    assert "authsession" in coverage.lower() or "_config" in coverage
    assert "aegis_test_index" in coverage
    assert "elasticsearch" in coverage.lower()
    assert "painless" in coverage.lower()
    assert "9264" in coverage
    assert "duckdb" in coverage.lower()
    fireteam_src = (_AGENT_DIR / "fireteam_service.py").read_text()
    assert "CVE-2024-9264" in fireteam_src
    assert "no such file or directory" in fireteam_src
    assert "do not install DuckDB" in fireteam_src
    judge = ss.skill_pack_for("finding_judge")
    assert "9264" in judge
    assert "duckdb" in judge.lower()
    assert "azurewebsites" in coverage.lower() or "tester" in coverage.lower()
    assert "azure_function_env_dump" in coverage
    judge = ss.skill_pack_for("finding_judge")
    assert "cosmos" in judge.lower() or "env dump" in judge.lower()
    cloud = ss.skill_pack_for("cloud_audit")
    assert "key vault" in cloud.lower() or "function" in cloud.lower()
    js = ss.skill_pack_for("js_secrets")
    assert "client_secret" in js
    assert "hostname-keyed" in js or "_next/static" in js
    assert "fetch_lazy_chunks" in js
    assert "extract_js_endpoints" in js
    assert "webpack" in js.lower() or "hash" in js.lower()
    assert "emailjs" in js.lower()
    assert "binary" in js.lower() or "firmware" in js.lower()
    auth = ss.skill_pack_for("auth_logic")
    assert "wiki" in auth.lower()
    assert "elogbook" in auth.lower() or "client-side" in auth.lower()
    assault = ss.skill_pack_for("credential_assault")
    assert "arangodb" in assault.lower()
    assert "emqx" in assault.lower()
    coverage = ss.skill_pack_for("coverage")
    assert "arangodb" in coverage.lower()
    assert "auth0" in coverage.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "wiki" in judge.lower()
    assert "binary" in judge.lower() or "strings" in judge.lower()
    api = ss.skill_pack_for("api_authz")
    assert "readOnly" in api or "readonly" in api.lower()
    assert "mass_assignment" in api or "mass assignment" in api.lower()
    assert "database" in api.lower() or "db is down" in api.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "mass assignment" in judge.lower() or "readonly" in judge.lower()
    api = ss.skill_pack_for("api_authz")
    assert "weborigins" in api.lower() or "keycloak" in api.lower()
    assert "canary" in api.lower() or "never-seen" in api.lower()
    sso = ss.skill_pack_for("saml_sso")
    assert "weborigins" in sso.lower() or "keycloak" in sso.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "cors" in judge.lower()
    assert "keycloak" in judge.lower() or "acao" in judge.lower()
    assault = ss.skill_pack_for("credential_assault")
    assert "admin-cli" in assault.lower()
    assert "invalid_grant" in assault.lower() or "password grant" in assault.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "admin-cli" in judge.lower() or "password grant" in judge.lower()
    api = ss.skill_pack_for("api_authz")
    assert "/api/auth/account" in api or "unauth_account_lookup" in api
    assert "401" in api and "500" in api
    assert "aegis-enum-canary@example.invalid" in api or "do not spray" in api.lower()
    judge = ss.skill_pack_for("finding_judge")
    assert "account lookup" in judge.lower() or "/api/auth/account" in judge
    assert "401" in judge and "500" in judge


def test_js_secrets_allowlist_can_prove_live_api():
    allowlists = _specialist_allowlists_from_ast()
    tools = allowlists["js_secrets"]
    assert "execute_curl" in tools
    assert "execute_browser" in tools
    assert "execute_interactsh" in tools
    assert "fetch_lazy_chunks" in tools
    assert "extract_js_endpoints" in tools
    assert "ingest_urls_into_map" in tools
    assert "queue_finding_followups" in tools
    assert "validate_finding" in tools
    assert "add_engagement_credential" in tools
