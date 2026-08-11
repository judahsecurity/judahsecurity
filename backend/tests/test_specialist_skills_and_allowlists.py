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
    for name in ("execute_dalfox", "execute_commix", "execute_xsstrike", "execute_sqlmap"):
        assert name in allowlists["injection"]
    assert "execute_hydra" in allowlists["auth_logic"]
    assert "test_credential_spray" in allowlists["auth_logic"]
    assert "execute_feroxbuster" in allowlists["web_recon"]
    assert "execute_feroxbuster" in allowlists["content_api"]


def test_fireteam_injects_skill_pack_helper():
    src = (_AGENT_DIR / "fireteam_service.py").read_text()
    assert "skill_pack_for" in src
