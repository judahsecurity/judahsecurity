"""Declarative tool specs: validation, registry, phase map, docs, permissions."""

import asyncio

import pytest

from app.services.agent import prompts, tool_specs as ts
from app.services.agent.tools import ASMToolsManager


def test_spec_validation():
    with pytest.raises(ValueError):
        ts.write_tool("Bad-Name", "doc")
    with pytest.raises(ValueError):
        ts.write_tool("x_tool", "doc", phases=("recon",))
    with pytest.raises(ValueError):
        ts.ToolSpec(name="x_tool", doc="d", run="x", read_only=False, concurrent=True)
    with pytest.raises(ValueError):
        ts.read_tool("x_tool", "   ")
    spec = ts.read_tool("x_tool", "Look  something\n up.")
    assert spec.read_only and spec.concurrent and spec.run == "x_tool"
    assert spec.doc_line() == "- **x_tool**: Look something up."
    assert not ts.write_tool("y_tool", "Act.").concurrent


def test_every_spec_is_registered_phased_and_documented():
    manager = ASMToolsManager()
    specs = ts.all_specs()
    assert len({s.name for s in specs}) == len(specs) >= 10
    docs = prompts.all_tool_docs()
    for spec in specs:
        assert spec.name in manager.tools
        assert prompts.TOOL_PHASE_MAP[spec.name] == list(spec.phases)
        assert docs[spec.name] == spec.doc_line()
        for phase in ts.ALL_PHASES:
            listed = f"**{spec.name}**" in prompts.get_phase_tools(phase, True)
            assert listed is (phase in spec.phases), (spec.name, phase)


def test_section_notes_render_once_under_their_heading():
    block = prompts.get_phase_tools("exploitation", True)
    heading = "### Ported Probe & Recon Tools (leads only; never create findings)"
    assert block.count(heading) == 1
    assert block.split(heading, 1)[1].lstrip().startswith("Each returns verdict LEAD")


def test_read_only_metadata_covers_specs_and_legacy_tools():
    manager = ASMToolsManager()
    assert ts.is_read_only("query_mail_security") and not ts.is_read_only("probe_graphql")
    legacy = ts.legacy_spec(manager, "query_assets")
    assert legacy is not None and legacy.section == "legacy" and legacy.doc
    assert legacy.phases == tuple(prompts.TOOL_PHASE_MAP["query_assets"])
    assert ts.legacy_spec(manager, "no_such_tool") is None
    assert ts.legacy_spec(manager, "probe_graphql") is ts.get_spec("probe_graphql")


def test_permission_check_refuses_before_running(monkeypatch):
    calls = []

    class Manager:
        async def act(self, **kwargs):
            calls.append(kwargs)
            return "ran"

    spec = ts.write_tool("gated_tool", "Gated.", run="act",
                         permission=lambda m, args: "needs grant" if not args.get("ok") else None)
    monkeypatch.setattr(ts, "_CACHE", (spec,))
    bound = ts.bind_specs(Manager())["gated_tool"]
    denied = asyncio.run(bound(ok=False))
    assert denied == {"success": False, "error": "permission_denied", "output": "needs grant"}
    assert calls == []
    assert asyncio.run(bound(ok=True)) == "ran" and calls == [{"ok": True}]


def test_spec_cannot_shadow_a_hand_registered_tool(monkeypatch):
    monkeypatch.setattr(ts, "_CACHE", (ts.read_tool("query_assets", "Shadow.", run="query_assets"),))
    with pytest.raises(ValueError, match="shadow"):
        ASMToolsManager()


def test_missing_method_fails_loudly(monkeypatch):
    monkeypatch.setattr(ts, "_CACHE", (ts.read_tool("ghost_tool", "Ghost."),))
    with pytest.raises(AttributeError, match="ghost_tool"):
        ts.bind_specs(object())
