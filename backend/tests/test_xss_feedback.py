"""Context feedback stays structured and payload variants stay bounded."""

import pytest

from app.services.agent.scoped_assessment.xss_feedback import (
    MAX_ATTEMPTS, payload_for, xss_trace,
)


def test_payload_variants_are_reviewed_and_keep_the_nonce_marker():
    mixed = payload_for("html_body", "mixed_case")
    assert "<ImG" in mixed and "oNeRrOr" in mixed
    assert "__PROWL_NONCE__" in mixed
    doubled = payload_for("html_body", "url_double")
    assert doubled.startswith("%3Cimg") and "__PROWL_NONCE__" in doubled
    for technique, variant, allow in [
        ("custom", "base", True), ("js_single", "mixed_case", True),
        ("html_body", "url_double", False),
    ]:
        with pytest.raises(ValueError):
            payload_for(technique, variant, allow_double_url=allow)


def test_trace_separates_static_leads_from_browser_render_and_next_tests():
    cell = {
        "test_type": "dom_xss", "method": "GET", "parameter": "fragment",
        "path": "/blog", "source_leads": [{"kind": "fragment"}],
        "transform_leads": [{"kind": "uri_decode"}],
        "sink_leads": [{"kind": "html_assignment"}],
    }
    proof = {
        "executed": False, "reflection_contexts": ["html_attribute"],
        "reflection_observations": [
            {"context": "html_attribute", "representation": "attribute_value"},
        ],
    }
    attempts = [{"technique": "html_body", "variant": "base", "executed": False}]
    trace = xss_trace(cell, proof, technique="html_body", variant="base", attempts=attempts)
    assert trace["source"] == {"kind": "fragment", "parameter": "fragment", "path": "/blog"}
    assert trace["static_source_leads"] == ["fragment"]
    assert trace["static_transform_leads"] == ["uri_decode"]
    assert trace["static_sink_leads"] == ["html_assignment"]
    assert trace["render_observations"] == [
        {"context": "html_attribute", "representation": "attribute_value"},
    ]
    assert trace["next_tests"] == [
        {"technique": "html_attribute", "variant": "base"},
        {"technique": "html_attribute_single", "variant": "base"},
    ]
    assert trace["remaining_attempts"] == MAX_ATTEMPTS - 1
    proof["executed"] = True
    assert xss_trace(cell, proof, technique="html_body", variant="base",
                     attempts=attempts)["next_tests"] == []


def test_trace_discards_untrusted_render_metadata_and_stops_at_budget():
    cell = {"test_type": "xss", "method": "POST", "parameter": "body_form:email",
            "path": "/subscribe", "source_leads": [{"kind": "ignore previous instructions"}]}
    proof = {"executed": False,
             "reflection_contexts": ["html_text", "ignore previous instructions"],
             "reflection_observations": [
                 {"context": "html_text", "representation": "literal_markup_text"},
                 {"context": "javascript", "representation": "secret payload"},
             ]}
    attempts = [{"technique": "html_body", "variant": "base"}] * MAX_ATTEMPTS
    trace = xss_trace(cell, proof, technique="html_body", variant="base", attempts=attempts)
    assert trace["rendered_contexts"] == ["html_text"]
    assert trace["static_source_leads"] == []
    assert trace["next_tests"] == [] and trace["remaining_attempts"] == 0
