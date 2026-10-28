"""Observed injection leads receive distinct work without becoming findings."""

from types import SimpleNamespace

from app.services.agent.coverage_cells import (
    claim_coverage_cell_leases, seed_js_coverage_cells, seed_parameter_coverage_cells,
)
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.agent.parameter_inventory import collect_parameter_inventory
from app.services.agent.request_mutate import apply_one_mutation
from app.services.agent.js_sinks import scan_body, scan_dom_sources
from app.services.agent.scoped_assessment.javascript import analyze_javascript
from app.services.agent.tester_loop import _coverage_followup_wave


def test_observed_inputs_create_class_specific_work():
    cmap = {
        "target": "https://app.test",
        "forms": [{"method": "GET", "action": "/catalog",
                   "fields": [{"name": "searchTerm"}, {"name": "category"}]},
                  {"method": "POST", "action": "/blog/comment",
                   "fields": [{"name": "comment"}, {"name": "author"}]},
                  {"method": "POST", "action": "/api/stock",
                   "fields": [{"name": "sku"}]}],
        "api_samples": [{"method": "POST", "url": "https://app.test/api/check-stock",
                         "headers": {"content-type": "application/xml"},
                         "body": "<stock><sku>1</sku></stock>"}],
    }
    inventory = collect_parameter_inventory(cmap)
    brain = EngagementBrain(target="https://app.test")
    cells = seed_parameter_coverage_cells(brain, inventory)
    observed = {(cell["test_type"], cell["path"], cell["parameter"])
                for cell in cells if cell["source"] == "parameter_inventory"}
    assert ("sqli", "/catalog", "query:category") in observed
    assert ("xss", "/catalog", "query:searchTerm") in observed
    assert ("crlf", "/catalog", "query:searchTerm") in observed
    assert ("stored_xss", "/blog/comment", "body_form:comment") in observed
    assert ("command_injection", "/api/stock", "body_form:sku") in observed
    assert ("xxe", "/api/check-stock", "body_xml:document") in observed
    assert all(cell["status"] == "untested" for cell in cells
               if cell["test_type"] in {"stored_xss", "command_injection", "xxe"})
    profiles = {name: SimpleNamespace(role=name + " specialist.",
                                      allowed_tools=["mutate_captured_request", "compare_requests"],
                                      max_iterations=4)
                for name in ("xss", "sqli", "injection")}
    leases = claim_coverage_cell_leases(brain, profiles)
    directives = directives_from_hypotheses(
        brain=brain, profiles_by_name=profiles, specialists=profiles,
        default_target="https://app.test", coverage_leases=leases,
    )
    assert directives["xss"].parameter_work["name"] == "searchTerm"
    assert directives["sqli"].parameter_work["name"] == "category"
    assert directives["injection"].parameter_work["test_type"] == "command_injection"


def test_dom_work_requires_both_browser_source_and_sink():
    target = "https://app.test"
    risky = analyze_javascript(
        b"const value = decodeURIComponent(location.hash); document.body.innerHTML = value;",
        source_url=target + "/risky.js", expected_origin=target,
    )
    inert = analyze_javascript(
        b"const value = location.hash; console.log(value);",
        source_url=target + "/inert.js", expected_origin=target,
    )
    brain = EngagementBrain(target=target)
    cells = seed_js_coverage_cells(brain, {
        "target": target,
        "js_files": [target + "/risky.js", target + "/inert.js"],
        "js_sources": [
            {"url": target + "/risky.js", "source_leads": risky["source_leads"],
             "transform_leads": risky["transform_leads"],
             "sink_leads": risky["sink_leads"]},
            {"url": target + "/inert.js", "source_leads": inert["source_leads"],
             "sink_leads": inert["sink_leads"]},
        ],
    })
    dom = [cell for cell in cells if cell["test_type"] == "dom_xss"]
    assert [cell["path"] for cell in dom] == ["/risky.js"]
    assert dom[0]["status"] == "untested"
    assert dom[0]["specialist"] == "xss"
    assert dom[0]["transform_leads"][0]["kind"] == "uri_decode"

    source = target + "/risky.js"
    assert scan_dom_sources("const x = location.hash", source=source)[0]["source"] == source
    assert scan_body("document.body.innerHTML = x", source=source)[0]["source"] == source


def test_client_script_leads_become_distinct_scheduled_review_work():
    target = "https://app.test"
    analysis = analyze_javascript(
        b"const value = new URLSearchParams(location.search).get('next');\n"
        b"location.href = value; anchor.href = value; label.textContent = value;\n"
        b"fetch(value); Handlebars.compile(value); Object.assign(state, value);\n"
        b"panel.innerHTML = value;",
        source_url=target + "/client.js", expected_origin=target,
    )
    brain = EngagementBrain(target=target)
    cells = seed_js_coverage_cells(brain, {
        "target": target, "js_files": [target + "/client.js", target + "/angular_1-7-7.js"],
        "js_sources": [{"url": target + "/client.js", **analysis}],
    })
    kinds = {cell["test_type"] for cell in cells}
    assert {"dom_xss", "dom_open_redirect", "dom_link_manipulation",
            "dom_data_manipulation", "request_url_override",
            "client_template_injection", "client_prototype_pollution",
            "js_dependency_review"} <= kinds
    assert all(cell["status"] == "untested" for cell in cells)
    assert all(cell["specialist"] == "spa_client" for cell in cells
               if cell["test_type"].startswith("client_") or cell["test_type"] == "dom_open_redirect")
    step = _coverage_followup_wave({"engagement_brain": brain.to_dict()}, [], target)
    assert step is not None
    assert "spa_client" in step["tool_args"]["specialists"]
    assert "xss" in step["tool_args"]["specialists"]


def test_inert_script_and_navigation_sink_do_not_create_dom_xss_work():
    target = "https://app.test"
    inert = analyze_javascript(
        b"const value = location.hash; console.log(value);",
        source_url=target + "/inert.js", expected_origin=target,
    )
    navigation = analyze_javascript(
        b"const value = location.hash; location.href = value;",
        source_url=target + "/navigation.js", expected_origin=target,
    )
    brain = EngagementBrain(target=target)
    cells = seed_js_coverage_cells(brain, {
        "target": target, "js_files": [target + "/inert.js", target + "/navigation.js"],
        "js_sources": [{"url": target + "/inert.js", **inert},
                       {"url": target + "/navigation.js", **navigation}],
    })
    assert not any(cell["test_type"] == "dom_xss" for cell in cells)
    assert not any(cell["path"] == "/inert.js" and cell["specialist"] == "spa_client"
                   for cell in cells)


def test_xml_replay_preserves_observed_request_and_rejects_network_callbacks():
    sample = {"method": "POST", "url": "https://app.test/api/check-stock",
              "headers": {"Content-Type": "application/xml"},
              "body": "<stock><sku>1</sku></stock>"}
    baseline, mutant = apply_one_mutation(
        sample, location="body_xml", field="document",
        value="<stock><sku>2</sku></stock>",
    )
    assert baseline["url"] == mutant["url"]
    assert baseline["headers"] == mutant["headers"]
    assert mutant["body"] == "<stock><sku>2</sku></stock>"
    try:
        apply_one_mutation(sample, location="body_xml", field="document",
                           value='<stock href="https://callback.test/"/>')
    except ValueError as exc:
        assert "callback workflow" in str(exc)
    else:
        raise AssertionError("Unapproved XML callback was accepted")
