"""Monotonic coverage transitions and planner breadth (ported from Vanguard test_coverage)."""

import pytest

from app.services.agent.coverage_cells import (
    CELL_STATUSES,
    can_transition_cell_status,
    claim_coverage_cell_leases,
    record_coverage_cell,
    recover_expired_coverage_leases,
    release_coverage_cell_lease,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain, record_surface_coverage
from app.services.agent.external_candidates import COVERAGE_TO_PROOF, coverage_classes
from app.services.agent.vulnerability_catalog import (
    endpoint_test_classes,
    parameter_test_classes,
    specialist_for_class,
)


def _cell(brain, status, **extra):
    return record_coverage_cell(
        brain, method="GET", path="/search", host="app.test", status=status,
        identity="anonymous", parameter="query:q", test_type="sqli", **extra,
    )


def _status(brain, cell_id):
    return next(c for c in brain.coverage_cells if c["id"] == cell_id)["status"]


def test_finding_is_sticky_against_every_other_state():
    for new in CELL_STATUSES - {"finding"}:
        assert can_transition_cell_status("finding", new) is False, new
    assert can_transition_cell_status("finding", "finding") is True
    # Vanguard aliases fold onto Prowl states before the check.
    assert can_transition_cell_status("validated", "rejected") is False


def test_clean_only_moves_to_stronger_evidence():
    assert can_transition_cell_status("tested_clean", "finding")
    assert can_transition_cell_status("tested_clean", "in_focus")
    assert can_transition_cell_status("tested_clean", "candidate")
    for new in ("untested", "inconclusive", "skipped", "blocked", "error"):
        assert not can_transition_cell_status("tested_clean", new), new


def test_work_states_accept_any_result():
    for current in ("untested", "in_focus", "leased", "blocked", "inconclusive", "skipped"):
        for new in CELL_STATUSES:
            assert can_transition_cell_status(current, new), (current, new)


def test_record_refuses_to_reset_finding_but_keeps_evidence():
    brain = EngagementBrain(target="https://app.test")
    first = _cell(brain, "finding", evidence_id="ev-proof", reason="proved",
                  finding_id="f-1", candidate_id="cand-1")
    later = _cell(brain, "tested_clean", evidence_id="ev-later", reason="looked clean",
                  finding_id="f-other")
    assert later["transition_refused"] is True
    assert later["requested_status"] == "tested_clean"
    stored = next(c for c in brain.coverage_cells if c["id"] == first["id"])
    assert stored["status"] == "finding"
    assert stored["reason"] == "proved"
    assert stored["finding_id"] == "f-1"
    assert stored["candidate_id"] == "cand-1"
    assert {"ev-proof", "ev-later"} <= set(stored["evidence_ids"])
    assert stored["last_refused_transition"]["to"] == "tested_clean"
    assert "transition_refused" not in stored


def test_inconclusive_retest_cannot_reopen_clean_cell():
    brain = EngagementBrain(target="https://app.test")
    cell = _cell(brain, "tested_clean", evidence_id="ev-1")
    assert _cell(brain, "inconclusive", reason="timeout")["transition_refused"]
    assert _status(brain, cell["id"]) == "tested_clean"
    upgraded = _cell(brain, "finding", evidence_id="ev-2")
    assert "transition_refused" not in upgraded
    assert _status(brain, cell["id"]) == "finding"


def test_inconclusive_is_superseded_by_a_later_real_verdict():
    brain = EngagementBrain(target="https://app.test")
    cell = _cell(brain, "inconclusive", reason="timeout")
    assert _cell(brain, "tested_clean", evidence_id="ev-1")["status"] == "tested_clean"
    assert _status(brain, cell["id"]) == "tested_clean"


def test_inconclusive_stays_open_for_leasing():
    """Vanguard's pending() skipped inconclusive rows; Prowl must re-lease them."""
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "host": "app.test", "path": "/search", "method": "GET", "location": "query",
        "name": "q", "identity": "anonymous", "source": "browser_traffic", "testable": True,
    }])
    leases = claim_coverage_cell_leases(brain, ["sqli"], now=100.0)
    lease = leases["sqli"]
    recover_expired_coverage_leases(brain, now=100.0 + 10_000)
    assert _status(brain, lease.coverage_cell_id) == "inconclusive"
    again = claim_coverage_cell_leases(brain, ["sqli"], now=100.0 + 10_001)
    assert again["sqli"].coverage_cell_id == lease.coverage_cell_id


def test_lease_then_result_and_lease_release_still_work():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [{
        "host": "app.test", "path": "/search", "method": "GET", "location": "query",
        "name": "q", "identity": "anonymous", "source": "browser_traffic", "testable": True,
    }])
    lease = claim_coverage_cell_leases(brain, ["sqli"])["sqli"]
    cell = next(c for c in brain.coverage_cells if c["id"] == lease.coverage_cell_id)
    done = record_coverage_cell(
        brain, method=cell["method"], path=cell["path"], host=cell["host"],
        status="tested_clean", identity=cell["identity"], parameter=cell["parameter"],
        test_type=cell["test_type"], coverage_cell_id_value=cell["id"],
        coverage_lease_id=lease.id, evidence_id="ev-1",
    )
    assert done["status"] == "tested_clean" and done["lease_id"] == ""
    xss = claim_coverage_cell_leases(brain, ["xss"])["xss"]
    released = release_coverage_cell_lease(brain, xss, verdict="inconclusive")
    assert released["status"] == "inconclusive" and released["lease_id"] == ""


def test_cited_lease_is_still_enforced():
    brain = EngagementBrain(target="https://app.test")
    _cell(brain, "untested")
    with pytest.raises(ValueError):
        _cell(brain, "tested_clean", coverage_lease_id="not-the-lease")


def test_surface_row_keeps_finding_when_another_check_is_clean():
    brain = EngagementBrain(target="https://app.test")
    record_surface_coverage(brain, path="/search", host="app.test", status="finding",
                            test_type="sqli", parameter="query:q", identity="anonymous",
                            reason="create_finding")
    row = record_surface_coverage(brain, path="/search", host="app.test", status="tested_clean",
                                  test_type="xss", parameter="query:q", identity="anonymous",
                                  evidence_id="ev-x")
    assert row["status"] == "finding"
    assert row["coverage_cell"]["status"] == "tested_clean"  # a different, exact cell


def test_status_detail_keeps_candidate_and_rejected():
    brain = EngagementBrain(target="https://app.test")
    cell = _cell(brain, "candidate")
    assert cell["status"] == "in_focus" and cell["status_detail"] == "candidate"
    rejected = _cell(brain, "rejected", evidence_id="ev-1")
    assert rejected["status"] == "tested_clean" and rejected["status_detail"] == "rejected"
    clean = record_coverage_cell(
        brain, method="GET", path="/search", host="app.test", status="tested_clean",
        identity="anonymous", parameter="query:q", test_type="xss",
    )
    assert clean["status_detail"] == ""
    # Survives snapshot migration.
    from app.services.agent.coverage_cells import migrate_coverage_cells

    migrated = {c["id"]: c for c in migrate_coverage_cells(brain)}
    assert migrated[rejected["id"]]["status_detail"] == "rejected"


# --- planner -----------------------------------------------------------------

def test_auth_class_for_login_reset_session_and_jwt_endpoints():
    for path in ("/login", "/api/password/reset", "/session", "/auth/jwt", "/account/sign-in"):
        assert "auth" in endpoint_test_classes({"path": path, "method": "POST"}), path
    for path in ("/authors", "/oauth/authorize", "/catalog", "/tokenizer-docs"):
        assert "auth" not in endpoint_test_classes({"path": path, "method": "GET"}), path
    assert specialist_for_class("auth") == "auth_logic"
    assert "auth" in coverage_classes()
    assert COVERAGE_TO_PROOF["auth"] is None


def test_crlf_planned_beyond_get_query():
    assert "crlf" in parameter_test_classes({"location": "header", "name": "X-Tenant"})
    assert "sqli" in parameter_test_classes({"location": "header", "name": "X-Tenant"})
    assert parameter_test_classes({"location": "cookie", "name": "lang"}) == ("sqli",)
    post_redirect = parameter_test_classes(
        {"location": "body_form", "name": "returnUrl", "method": "POST", "path": "/settings"})
    assert {"crlf", "open_redirect"} <= set(post_redirect)
    post_file = parameter_test_classes(
        {"location": "body_json", "name": "filename", "method": "POST", "path": "/export"})
    assert {"crlf", "path_traversal"} <= set(post_file)
    plain_post = parameter_test_classes(
        {"location": "body_form", "name": "comment", "method": "POST", "path": "/reviews"})
    assert "crlf" not in plain_post


def test_redirect_and_file_signals_read_the_endpoint_path():
    on_redirect_path = parameter_test_classes(
        {"location": "query", "name": "u", "method": "GET", "path": "/redirect"})
    assert "open_redirect" in on_redirect_path
    on_download_path = parameter_test_classes(
        {"location": "query", "name": "id", "method": "GET", "path": "/download/report"})
    assert "path_traversal" in on_download_path
    # Substrings in unrelated segments do not fan out to every parameter.
    for path in ("/homepage", "/nextgen-store", "/filetype-guide", "/profile"):
        classes = parameter_test_classes(
            {"location": "query", "name": "id", "method": "GET", "path": path})
        assert "open_redirect" not in classes and "path_traversal" not in classes, path


def test_xxe_from_xml_content_type_or_soap_endpoint():
    assert "xxe" in endpoint_test_classes(
        {"path": "/services/soap", "method": "POST", "location": "query"})
    assert "xxe" in endpoint_test_classes(
        {"path": "/import.xml", "method": "POST", "location": "body_form"})
    assert "xxe" in endpoint_test_classes(
        {"path": "/api/upload", "method": "POST", "location": "query",
         "content_type": "application/xml"})
    # An observed XML body already plans body_xml:document.
    assert "xxe" not in endpoint_test_classes(
        {"path": "/soap", "method": "POST", "location": "body_xml"})
    assert "xxe" not in endpoint_test_classes({"path": "/sitemap.xml", "method": "GET"})


def test_csrf_needs_an_authenticated_identity():
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert "csrf" in endpoint_test_classes(
            {"path": "/api/profile", "method": method, "identity": "user_a"})
        assert "csrf" not in endpoint_test_classes(
            {"path": "/api/profile", "method": method, "identity": "anonymous"})


def test_planner_growth_stays_bounded():
    brain = EngagementBrain(target="https://app.test")
    inventory = [
        {"host": "app.test", "path": f"/page/{index}", "method": "GET", "location": "query",
         "name": "id", "identity": "anonymous", "source": "browser_traffic", "testable": True}
        for index in range(50)
    ]
    cells = seed_parameter_coverage_cells(brain, inventory)
    per_input = len(cells) / 50
    assert per_input <= 6, per_input
