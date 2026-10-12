"""Specialists see the registered tool argument names before calling tools."""

from app.services.agent.fireteam_service import _tool_contract, get_specialist
from app.services.agent.tools import ASMToolsManager


def test_specialist_contracts_match_registered_tools():
    manager = ASMToolsManager()
    assert _tool_contract(manager, "get_parameter_inventory") == (
        "  - get_parameter_inventory(specialist?, offset?, limit?)"
    )
    assert _tool_contract(manager, "scan_assigned_js") == (
        "  - scan_assigned_js(coverage_cell_id, coverage_lease_id)"
    )
    assert _tool_contract(manager, "scan_js_urls_for_secrets") == (
        "  - scan_js_urls_for_secrets(urls, max_urls?)"
    )
    assert _tool_contract(manager, "read_evidence").startswith(
        "  - read_evidence(evidence_id"
    )
    assert _tool_contract(manager, "execute_curl") == "  - execute_curl(args?)"


def test_injection_specialists_can_record_evidence_backed_coverage():
    manager = ASMToolsManager()
    for specialist in ("xss", "sqli"):
        profile = get_specialist(specialist)
        assert "record_surface_coverage" in profile.allowed_tools
        assert callable(manager.get_tool("record_surface_coverage"))
        assert "record_surface_coverage(" in _tool_contract(
            manager, "record_surface_coverage"
        )
