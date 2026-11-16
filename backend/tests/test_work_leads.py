"""Evidence, not only names, decides which checks an observed input gets."""

import asyncio
import json
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases,
    lead_packet_for_cell,
    seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fireteam_service import SpecialistReport, _fill_summary_contract
from app.services.agent.parameter_inventory import classify_value_shape, collect_parameter_inventory
from app.services.agent.reflection_probe import (
    body_reflection_contexts,
    header_reflection_contexts,
    probe_reflections,
)
from app.services.agent.tester_loop import _unprobed_class_cells
from app.services.agent.vulnerability_catalog import (
    classes_from_reflection,
    lead_class_allowed,
    parameter_test_classes,
)
from app.services.agent.work_leads import (
    MAX_LEADS_PER_REPORT,
    apply_reflection_observations,
    apply_specialist_leads,
    normalize_leads,
)


def _row(name, *, path="/view", method="GET", location="query", value_type="",
         source="browser_traffic", artifact_id="capture-1"):
    return {
        "host": "app.test", "path": path, "method": method, "location": location,
        "name": name, "identity": "anonymous", "source": source,
        "value_type": value_type, "artifact_id": artifact_id, "testable": True,
    }


def _cells(brain, **match):
    return [cell for cell in brain.coverage_cells
            if all(cell.get(key) == value for key, value in match.items())]


# --- value shape -----------------------------------------------------------

@pytest.mark.parametrize("value,label", [
    ("42", "positive_integer"),
    ("-3.5", "number"),
    ("true", "boolean"),
    ("3f2504e0-4f89-11d3-9a0c-0305e82c3301", "uuid"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "jwt"),
    ("someone@example.test", "email"),
    ("https://cdn.example.test/a.png", "url"),
    ("//cdn.example.test/a.png", "url"),
    ('{"a": 1}', "json"),
    ("<?xml version='1.0'?><a/>", "xml"),
    ("Hello {{ name }}", "template"),
    ("<b>bold</b>", "markup"),
    ("../reports/q1.pdf", "path"),
    ("invoice.pdf", "path"),
    ("dGhpcyBpcyBhIGxvbmcgZW5jb2RlZCB2YWx1ZQ==", "encoded"),
    ("hello world", ""),
    ("", ""),
    (7, "positive_integer"),
    (False, "boolean"),
])
def test_value_shape_labels_form_never_content(value, label):
    assert classify_value_shape(value) == label


def test_observed_value_shape_reaches_inventory_without_the_value():
    rows = collect_parameter_inventory({
        "target": "https://app.test",
        "pages_visited": ["https://app.test/view?data=https://cdn.example.test/x&doc=a/b.txt"],
        "api_samples": [{
            "method": "POST", "url": "https://app.test/api/render",
            "body": json.dumps({"layout": "{{ title }}", "owner": 12}),
            "artifact_id": "capture-9",
        }],
    })
    shapes = {(row["name"], row["value_type"]) for row in rows}
    assert ("data", "url") in shapes
    assert ("doc", "path") in shapes
    assert ("/layout", "template") in shapes
    assert ("/owner", "positive_integer") in shapes
    assert "cdn.example.test" not in json.dumps(rows)
    assert "{{ title }}" not in json.dumps(rows)


def test_value_shape_adds_classes_a_name_would_miss():
    # Neither name matches the SSRF, traversal, or SSTI name rules.
    assert {"ssrf", "open_redirect"} <= set(parameter_test_classes(_row("data", value_type="url")))
    assert "ssrf" not in parameter_test_classes(_row("data"))
    assert "path_traversal" in parameter_test_classes(_row("x", value_type="path"))
    assert "ssti" in parameter_test_classes(_row("x", value_type="template"))
    assert "authz" in parameter_test_classes(_row("x", value_type="uuid"))
    assert "stored_xss" in parameter_test_classes(
        _row("x", method="POST", location="body_form", value_type="markup"))
    # REST identifiers in the path are object references.
    assert parameter_test_classes(_row("path[2]", location="path",
                                       value_type="positive_integer")) == ("authz", "sqli")
    assert parameter_test_classes(_row("path[2]", location="path")) == ("sqli",)


# --- reflection placement --------------------------------------------------

def test_body_reflection_contexts_use_the_browser_vocabulary():
    m = "aegis0123"
    html = (f"<p>{m}</p><a href='/go?{m}'>x</a><input value=\"{m}\">"
            f"<script>var a='{m}'</script><div onclick=\"f('{m}')\"></div>"
            f"<style>.x{{content:'{m}'}}</style>")
    assert body_reflection_contexts(html, m) == [
        "css", "html_attribute", "html_text", "javascript", "url_attribute",
    ]
    assert header_reflection_contexts({"Location": f"/next?{m}", "X-Echo": m, "A": "b"}, m) == [
        "location_header", "response_header",
    ]


def test_reflection_classes_follow_placement():
    assert classes_from_reflection(["location_header"]) == ("crlf", "open_redirect")
    assert classes_from_reflection(["url_attribute"]) == ("open_redirect", "xss")
    assert classes_from_reflection(["html_text"]) == ("ssti", "xss")
    assert classes_from_reflection(["unknown"]) == ()


def test_probe_records_redirect_echo_as_header_placement_not_html_reflection():
    class Response:
        def __init__(self, status, headers, body=b""):
            self.status, self.headers, self._body = status, headers, body

        async def body(self):
            return self._body

    class Request:
        async def get(self, url, **_kwargs):
            marker = parse_qs(urlsplit(url).query)
            name, values = next(iter(marker.items()))
            if name == "returnTo":
                return Response(302, {"location": "/home?r=" + values[0]})
            return Response(200, {"content-type": "text/html"},
                            f"<script>x='{values[0]}'</script>".encode())

    rows = [dict(_row("returnTo", source="observed_form"), testable=True),
            dict(_row("q", path="/search", source="observed_form"), testable=True)]
    found = asyncio.run(probe_reflections(SimpleNamespace(request=Request()), "https://app.test",
                                          rows, deadline=time.monotonic() + 10))
    by_name = {row["parameter"]: row for row in found}
    assert by_name["returnTo"]["reflected"] is False
    assert by_name["returnTo"]["reflection_contexts"] == ["location_header"]
    assert by_name["q"]["reflected"] is True
    assert by_name["q"]["reflection_contexts"] == ["javascript"]


def test_reflection_placement_creates_prioritized_unattempted_checks():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("r")])
    assert not _cells(brain, parameter="query:r", test_type="open_redirect")

    results = apply_reflection_observations(
        brain,
        [{"path": "/view", "parameter": "r", "reflection_contexts": ["location_header"]},
         {"path": "/unseen", "parameter": "z", "reflection_contexts": ["location_header"]}],
        host="app.test", evidence_ids=["ev-reflect", "ev-other"],
    )
    assert {row["test_type"]: row["outcome"] for row in results} == {
        "crlf": "prioritized", "open_redirect": "created",
    }
    cell = _cells(brain, parameter="query:r", test_type="open_redirect")[0]
    assert cell["status"] == "untested" and cell["priority_rank"] == 0
    assert cell["evidence_ids"] == []  # basis is not an execution receipt
    assert cell["lead_basis"][0]["evidence_ids"] == ["ev-reflect"]
    assert cell["capture_id"] == "capture-1"
    assert cell["specialist"] == "injection"
    # The same check is not created twice for the same evidence.
    apply_reflection_observations(
        brain, [{"path": "/view", "parameter": "r", "reflection_contexts": ["location_header"]}],
        host="app.test", evidence_ids=["ev-reflect"],
    )
    assert len(_cells(brain, parameter="query:r", test_type="open_redirect")) == 1
    assert len(cell["lead_basis"]) == 1
    # Nothing is created for an input the ledger never observed.
    assert not _cells(brain, path="/unseen")


def test_evidence_backed_check_is_scheduled_and_leased_first():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("r"), _row("next", path="/login")])
    apply_reflection_observations(
        brain, [{"path": "/view", "parameter": "r", "reflection_contexts": ["location_header"]}],
        host="app.test", evidence_ids=["ev-reflect"],
    )
    state = {"engagement_brain": brain.to_dict()}
    assert any(row["test_type"] == "open_redirect" and row["parameter"] == "query:r"
               for row in _unprobed_class_cells(state, "https://app.test"))
    leases = claim_coverage_cell_leases(
        brain, ["injection"],
        allowed_sources=frozenset({"parameter_inventory", "surface_applicability", "js_inventory"}),
        excluded_test_types=frozenset({"xss", "sqli"}), first_pass_only=True,
    )
    leased = next(cell for cell in brain.coverage_cells
                  if cell["id"] == leases["injection"].coverage_cell_id)
    # /login?next matched by name only; the observed redirect echo goes first.
    assert leased["parameter"] == "query:r" and leased["lead_basis"]
    packet = lead_packet_for_cell(leased)
    assert packet["lead_basis"][0]["origin"] == "observed_behavior"


# --- specialist leads ------------------------------------------------------

def test_specialist_lead_requires_its_own_evidence_and_an_observed_input():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("export", path="/api/export")])
    anchor = _cells(brain, parameter="query:export", test_type="sqli")[0]
    leads = [
        {"coverage_cell_id": anchor["id"], "test_type": "path_traversal",
         "evidence_ids": ["ev-own"], "reason": "../ changed body to a file listing"},
        {"coverage_cell_id": anchor["id"], "test_type": "ssrf",
         "evidence_ids": ["ev-invented"], "reason": "looked like a fetch"},
        {"method": "GET", "path": "/api/export", "parameter": "query:export",
         "test_type": "ssti", "evidence_ids": ["ev-own"], "reason": ""},
        {"method": "GET", "path": "/never-seen", "parameter": "query:x",
         "test_type": "ssti", "evidence_ids": ["ev-own"], "reason": "7*7 rendered 49"},
        {"coverage_cell_id": anchor["id"], "test_type": "made_up",
         "evidence_ids": ["ev-own"], "reason": "x"},
        {"coverage_cell_id": anchor["id"], "test_type": "sqli",
         "evidence_ids": [], "reason": "quote error"},
    ]
    results = apply_specialist_leads(brain, leads, specialist="sqli",
                                     allowed_evidence_ids=["ev-own"])
    assert [row["outcome"] for row in results] == [
        "created",
        "rejected:evidence_not_execution_owned",
        "rejected:no_reason",
        "rejected:input_not_observed",
        "rejected:unknown_test_type",
        "rejected:no_evidence",
    ]
    cell = _cells(brain, parameter="query:export", test_type="path_traversal")[0]
    assert cell["lead_created"] == "specialist_lead"
    assert cell["lead_basis"][0]["proposed_by"] == "sqli"
    assert cell["specialist"] == "injection" and cell["status"] == "untested"
    assert not _cells(brain, test_type="ssrf", parameter="query:export")


def test_lead_on_existing_check_prioritizes_open_and_never_reopens_terminal():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("callbackUrl", path="/api/preview")])
    ssrf = _cells(brain, test_type="ssrf")[0]
    redirect = _cells(brain, test_type="open_redirect", parameter="query:callbackUrl")
    assert not redirect
    xss = _cells(brain, test_type="xss")[0]
    xss["status"] = "tested_clean"
    results = apply_specialist_leads(brain, [
        {"coverage_cell_id": ssrf["id"], "test_type": "ssrf",
         "evidence_ids": ["ev-1"], "reason": "callback fetched by server"},
        {"coverage_cell_id": ssrf["id"], "test_type": "xss",
         "evidence_ids": ["ev-1"], "reason": "echoed"},
    ], specialist="injection", allowed_evidence_ids=["ev-1"])
    assert [row["outcome"] for row in results] == ["prioritized", "already_terminal"]
    assert ssrf["priority_rank"] == 0
    assert xss["status"] == "tested_clean"


def test_location_gate_rejects_classes_a_header_cannot_carry():
    assert lead_class_allowed("header", "crlf")
    assert not lead_class_allowed("header", "ssrf")
    assert not lead_class_allowed("cookie", "authz")
    assert lead_class_allowed("path", "path_traversal")
    assert lead_class_allowed("query", "csrf")  # endpoint classes are request-level
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("X-Tenant", location="header")])
    anchor = _cells(brain, parameter="header:X-Tenant")[0]
    results = apply_specialist_leads(brain, [{
        "coverage_cell_id": anchor["id"], "test_type": "ssrf",
        "evidence_ids": ["ev-1"], "reason": "tenant header looked like a host",
    }], specialist="sqli", allowed_evidence_ids=["ev-1"])
    assert results[0]["outcome"] == "rejected:class_not_applicable_to_location"


def test_endpoint_class_lead_creates_a_request_level_check():
    brain = EngagementBrain(target="https://app.test")
    seed_parameter_coverage_cells(brain, [_row("qty", path="/api/redeem", method="POST",
                                               location="body_json")])
    anchor = _cells(brain, parameter="body_json:qty")[0]
    results = apply_specialist_leads(brain, [{
        "coverage_cell_id": anchor["id"], "test_type": "race_condition",
        "evidence_ids": ["ev-2"], "reason": "coupon applied twice in parallel replay",
    }], specialist="business_logic", allowed_evidence_ids=["ev-2"])
    assert results[0]["outcome"] in {"created", "prioritized"}
    cell = _cells(brain, parameter="endpoint", test_type="race_condition")[0]
    assert cell["source"] == "surface_applicability"


def test_leads_are_normalized_and_bounded():
    raw = [{"cell_id": "cov-1", "test_class": "SSRF", "evidence_id": "ev", "reason": "r" * 900}
           for _ in range(20)] + ["junk", {"reason": "no class"}]
    leads = normalize_leads(raw)
    assert len(leads) == MAX_LEADS_PER_REPORT
    assert leads[0]["test_type"] == "ssrf"
    assert leads[0]["coverage_cell_id"] == "cov-1"
    assert leads[0]["evidence_ids"] == ["ev"]
    assert len(leads[0]["reason"]) == 300
    report = SpecialistReport(specialist="sqli", role="r", mission="m", summary="s")
    _fill_summary_contract(report, {"done": True, "leads": raw[:1]})
    assert report.leads and report.leads[0]["test_type"] == "ssrf"


@pytest.mark.asyncio
async def test_dispatch_turns_a_cited_lead_into_work_and_drops_a_forged_one(monkeypatch):
    from app.services.agent.fireteam_service import FireteamResult, ToolInvocation
    from app.services.agent.tools import ASMToolsManager

    target = "https://app.test"
    brain = EngagementBrain(target=target)
    seed_parameter_coverage_cells(brain, [_row("callbackUrl", path="/api/preview")])
    manager = ASMToolsManager()
    manager._capability_map = {"target": target, "scope": target}
    manager._engagement_brain = brain.to_dict()
    monkeypatch.setattr(manager, "_cheap_llm", lambda: object())

    async def fake_fireteam(*, mission, directives, **_kwargs):
        directive = directives["ssrf"]
        cell_id = directive.coverage_cell_id
        return FireteamResult(mission=mission, specialists_run=["ssrf"], reports=[SpecialistReport(
            specialist="ssrf", role="SSRF", mission=mission, summary="no fetch observed",
            verdict="inconclusive", coverage_cell_id=cell_id,
            coverage_lease_id=directive.coverage_lease_id,
            tool_calls=[ToolInvocation(tool="replay_http_request", args={}, success=True,
                                       summary="body listed files", evidence_ids=["ev-own"])],
            leads=normalize_leads([
                {"coverage_cell_id": cell_id, "test_type": "path_traversal",
                 "evidence_ids": ["ev-own"], "reason": "file:// value returned a directory listing"},
                {"coverage_cell_id": cell_id, "test_type": "ssti",
                 "evidence_ids": ["ev-forged"], "reason": "imagined"},
            ]),
        )])

    monkeypatch.setattr("app.services.agent.fireteam_service.run_fireteam", fake_fireteam)
    result = json.loads(await manager.fireteam_dispatch(
        mission="Probe observed URL input", targets=[target],
        specialists=["ssrf"], mode="coverage_followup",
    ))
    outcomes = {row["test_type"]: row["outcome"] for row in result["lead_cells"]}
    assert outcomes == {"path_traversal": "created",
                        "ssti": "rejected:evidence_not_execution_owned"}
    cells = manager._engagement_brain["coverage_cells"]
    created = [row for row in cells if row["test_type"] == "path_traversal"
               and row["parameter"] == "query:callbackUrl"]
    assert len(created) == 1 and created[0]["status"] == "untested"
    assert created[0]["lead_basis"][0]["evidence_ids"] == ["ev-own"]
    # The path name already plans SSTI; the forged lead must not attach to it.
    assert not any(row.get("lead_basis") for row in cells
                   if row["test_type"] == "ssti" and row["parameter"] == "query:callbackUrl")
