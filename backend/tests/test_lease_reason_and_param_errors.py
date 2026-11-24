"""Failures a live run reported without enough detail to act on."""

import asyncio
import time
from types import SimpleNamespace

import pytest

from app.services.agent import tools as tools_module
from app.services.agent.tools import _lease_failure_reason


def _cell(**kw):
    base = {"status": "leased", "lease_id": "L1", "lease_deadline": time.time() + 86_400,
            "path": "/catalog"}
    return {**base, **kw}


@pytest.mark.parametrize("cell,lease,reason", [
    (None, "L1", "missing_cell"),
    (_cell(status="open"), "L1", "not_leased"),
    (_cell(), "L2", "lease_mismatch"),
    (_cell(lease_deadline=time.time() - 1), "L1", "lease_expired"),
    (_cell(path="/logout"), "L1", "unsafe_path"),
    (_cell(), "L1", "unsupported_input"),
])
def test_lease_failure_reason_names_the_condition(cell, lease, reason):
    assert _lease_failure_reason(cell, lease) == reason


def test_ledger_detail_keeps_the_lease_reason(monkeypatch):
    from app.services.agent import action_ledger
    from app.services.agent.tools import ASMToolsManager

    events = []
    monkeypatch.setattr(action_ledger, "append_action",
                        lambda run_id, action_id, event, tool, **kw: events.append((event, kw)))
    token = action_ledger.active_run_id.set("run-1")
    manager = ASMToolsManager.__new__(ASMToolsManager)

    async def impl(tool_name, tool_args):
        return {"success": False, "error": "invalid_coverage_lease", "reason": "lease_expired"}

    manager._execute_impl = impl
    try:
        asyncio.run(manager._execute_recorded("scoped_cors_probe_assigned", {}))
    finally:
        action_ledger.active_run_id.reset(token)
    failed = [kw for event, kw in events if event == "failed"]
    assert failed and failed[-1]["detail"] == "invalid_coverage_lease:lease_expired"


def test_unmapped_sqli_parameter_lists_mapped_ones(monkeypatch):
    from app.services.agent.scoped_assessment_tools import ScopedAssessmentTools

    rows = [
        {"method": "GET", "host": "app.test", "path": "/catalog", "location": "query",
         "name": "searchTerm", "identity": "anonymous", "testable": True},
        {"method": "GET", "host": "app.test", "path": "/catalog", "location": "query",
         "name": "category", "identity": "anonymous", "testable": True},
        {"method": "POST", "host": "app.test", "path": "/catalog", "location": "body_form",
         "name": "email", "identity": "anonymous", "testable": True},
    ]
    monkeypatch.setattr("app.services.agent.parameter_inventory.collect_parameter_inventory",
                        lambda cmap: rows)
    manager = SimpleNamespace(_capability_map={})
    error = ScopedAssessmentTools._unmapped_parameter_error(
        manager, "String SQLi", "https://app.test/catalog", "email", "anonymous")
    text = str(error)
    assert "'email' is not one" in text
    assert "category, searchTerm" in text

    empty = ScopedAssessmentTools._unmapped_parameter_error(
        manager, "String SQLi", "https://app.test/other", "id", "anonymous")
    assert "No GET query parameters are mapped on /other" in str(empty)


def test_tools_module_exposes_helper():
    assert callable(tools_module._lease_failure_reason)
