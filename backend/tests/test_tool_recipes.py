import asyncio

import pytest

from app.services import tool_recipes
from app.services.tool_recipes import RecipeError, load_recipes, parse_recipe

BASE = {"name": "execute_demo", "binary": "demo", "description": "Demo tool."}


def test_bundled_recipes_load_without_errors():
    recipes, errors = load_recipes()
    assert errors == []
    assert {"execute_tlsx", "execute_assetfinder", "execute_dig"} <= set(recipes)


def test_bundled_recipes_do_not_shadow_built_in_tools():
    from app.services.agent.prompts import _BUILTIN_TOOL_NAMES

    for recipe in tool_recipes.get_recipes().values():
        assert recipe.name not in _BUILTIN_TOOL_NAMES
        assert recipe.help_name not in _BUILTIN_TOOL_NAMES


def test_defaults_and_derived_names():
    r = parse_recipe(BASE)
    assert r.phases == tool_recipes.PHASES
    assert r.help_name == "demo_help"
    assert not r.auto_approve and not r.shareable
    assert parse_recipe({**BASE, "help_args": None}).help_name is None


@pytest.mark.parametrize("patch, message", [
    ({"name": "run_demo"}, "name"),
    ({"binary": "/usr/bin/demo"}, "binary"),
    ({"binary": "demo; rm"}, "binary"),
    ({"description": ""}, "description"),
    ({"phases": ["recon"]}, "phases"),
    ({"timeout_seconds": 0}, "timeout"),
    ({"timeout_seconds": 99999}, "timeout"),
    ({"fixed_args": ["-o out; id"]}, "fixed_args"),
    ({"deny_flags": "--brute"}, "deny_flags"),
    ({"auto_approve": "yes"}, "auto_approve"),
    ({"success_exit_codes": [True]}, "success_exit_codes"),
    ({"extra": 1}, "unknown keys"),
])
def test_invalid_recipes_are_rejected_with_a_reason(patch, message):
    with pytest.raises(RecipeError, match=message):
        parse_recipe({**BASE, **patch})


def test_bad_and_duplicate_files_are_skipped_not_fatal(tmp_path):
    (tmp_path / "a.yaml").write_text("name: execute_demo\nbinary: demo\ndescription: ok\n")
    (tmp_path / "b.yaml").write_text("name: execute_demo\nbinary: demo2\ndescription: dup\n")
    (tmp_path / "c.yml").write_text("name: [unclosed\n")
    (tmp_path / "d.yaml").write_text("name: execute_other\nbinary: x\n")
    recipes, errors = load_recipes(tmp_path)
    assert list(recipes) == ["execute_demo"]
    assert recipes["execute_demo"].binary == "demo"
    assert len(errors) == 3


def test_recipes_reach_every_registration_point():
    from app.services.agent.prompts import TOOL_PHASE_MAP, get_phase_tools
    from app.services.agent.tools import ASMToolsManager
    from app.services.mcp.server import MCPServer

    assert TOOL_PHASE_MAP["execute_dig"] == list(tool_recipes.PHASES)
    assert "dig_help" in TOOL_PHASE_MAP

    server = MCPServer()
    assert server.registry.get("execute_dig") is not None
    assert server.registry.get("dig_help") is not None
    assert server._HANDLER_BINARY["execute_dig"] == "dig"

    manager = ASMToolsManager.__new__(ASMToolsManager)
    names = ASMToolsManager._register_tools(manager)
    assert "execute_tlsx" in names and "tlsx_help" in names

    text = get_phase_tools("informational")
    dig = tool_recipes.get_recipes()["execute_dig"]
    assert ("**execute_dig**" in text) == dig.available()


def test_recipe_flags_feed_confirmation_and_single_flight():
    assert tool_recipes.is_auto_approved("execute_dig")
    assert tool_recipes.is_auto_approved("dig_help")
    assert tool_recipes.is_shareable("execute_tlsx")
    assert not tool_recipes.is_auto_approved("execute_sqlmap")


def test_recipe_calls_still_pass_through_lictor(monkeypatch):
    from aegis_praetorium.lictor import _SAFE_DEFAULTS
    from app.services.mcp.server import MCPServer

    server = MCPServer()
    assert "+time=5" in _SAFE_DEFAULTS["dig"]

    ran = []

    async def fake_run(cmd, **kwargs):
        ran.append(cmd)
        return {"success": True, "output": "ok", "error": None, "exit_code": 0}

    monkeypatch.setattr(server, "_run_command", fake_run)
    server._tool_availability_cache = {"execute_dig": True}

    blocked = asyncio.run(server.call_tool("execute_dig", {"args": "@169.254.169.254 example.com"}))
    assert blocked["success"] is False and not ran

    allowed = asyncio.run(server.call_tool("execute_dig", {"args": "example.com TXT"}))
    assert allowed["success"] is True
    assert ran[-1][:3] == ["dig", "example.com", "TXT"]
    assert "+time=5" in ran[-1]


def test_missing_binary_fails_fast_and_is_listed_unavailable():
    from app.services.mcp.server import MCPServer

    server = MCPServer()
    server._tool_availability_cache = {"execute_dig": False}
    result = asyncio.run(server.call_tool("execute_dig", {"args": "example.com"}))
    assert result.get("tool_unavailable") is True
    assert "execute_dig" in server.unavailable_tools()
