"""Glasswing-style CVE applicability: homepage fingerprint + version range."""

from app.services.agent.cve_applicability import (
    applicability_pending_finding,
    cve_applicability_forced_step,
    cve_check_ran,
    cve_ids_in_text,
    is_cve_applicability_question,
    match_cve_to_stack,
    parse_affected_range,
    products_match,
    version_cmp,
    version_in_range,
)
from app.services.agent.passive_stack import parse_passive_stack
from app.services.agent.prompts import is_tool_allowed_in_phase
from app.services.agent.tester_loop import complete_blocked_reason, forced_next_step


CLEARPATH_HTML = """<!doctype html>
<html>
<head>
  <meta name="generator" content="WordPress 6.7.7" />
  <title>Clearpath Robotics</title>
  <!-- This site is optimized with the Yoast SEO plugin v24.3 - https://yoast.com/wordpress/plugins/seo/ -->
  <link rel="https://api.w.org/" href="https://clearpathrobotics.com/wp-json/" />
</head>
<body>
  <script src="/wp-content/plugins/wordpress-seo/js/dist/frontend.min.js?ver=24.3"></script>
</body>
</html>
"""

CLEARPATH_HEADERS = {
    "Server": "Apache/2.4.41 (Ubuntu)",
    "Link": '<https://clearpathrobotics.com/wp-json/>; rel="https://api.w.org/"',
    "Content-Type": "text/html; charset=UTF-8",
}

CVE_1293_INTEL = (
    "CVE-2026-1293 is a stored XSS in the Yoast SEO WordPress plugin, via the "
    "yoast-schema block attribute, affecting all versions up to and including 26.8. "
    "It requires an authenticated attacker with Contributor-level access or above."
)


def test_passive_stack_extracts_yoast_and_wordpress():
    products = parse_passive_stack(CLEARPATH_HTML, CLEARPATH_HEADERS)
    by_name = {p["name"]: p for p in products}
    assert by_name["wordpress"]["version"] == "6.7.7"
    assert by_name["yoast seo"]["version"] == "24.3"
    assert by_name["apache"]["version"] == "2.4.41"
    assert "Yoast SEO plugin v24.3" in by_name["yoast seo"]["evidence"]


def test_version_range_yoast_24_3_is_in_26_8():
    spec = parse_affected_range(CVE_1293_INTEL)
    assert spec["op"] == "<="
    assert spec["version"] == "26.8"
    assert version_in_range("24.3", spec) is True
    assert version_in_range("26.8", spec) is True
    assert version_in_range("26.9", spec) is False
    assert version_cmp("24.3", "26.8") < 0


def test_cve_2026_1293_applicable_to_clearpath_fingerprint():
    products = parse_passive_stack(CLEARPATH_HTML, CLEARPATH_HEADERS)
    match = match_cve_to_stack(
        cve_id="CVE-2026-1293",
        intel_text=CVE_1293_INTEL,
        products=products,
        affected_products=[{"vendor": "yoast", "product": "wordpress-seo"}],
    )
    assert match["verdict"] == "applicable"
    assert match["product_present"] is True
    yoast = next(h for h in match["hits"] if h["product"] == "yoast seo")
    assert yoast["in_range"] is True
    assert yoast["version"] == "24.3"


def test_patched_yoast_is_not_applicable():
    html = CLEARPATH_HTML.replace("v24.3", "v27.0").replace("ver=24.3", "ver=27.0")
    products = parse_passive_stack(html, CLEARPATH_HEADERS)
    match = match_cve_to_stack(
        cve_id="CVE-2026-1293",
        intel_text=CVE_1293_INTEL,
        products=products,
    )
    assert match["verdict"] == "not_applicable"
    yoast = next(h for h in match["hits"] if h["product"] == "yoast seo")
    assert yoast["in_range"] is False


def test_products_match_aliases():
    assert products_match("wordpress-seo", "yoast seo")
    assert products_match("Yoast SEO WordPress plugin", "yoast seo")
    assert not products_match("grafana", "yoast seo")
    assert not products_match("wordpress-seo", "wordpress")
    assert products_match("wordpress", "wordpress")


def test_named_cve_question_forces_check_before_crawl():
    q = "can we check if CVE-2026-1293 is applicable to clearpathrobotics.com"
    assert cve_ids_in_text(q) == ["CVE-2026-1293"]
    state = {
        "original_objective": q,
        "objective": q,
        "target_info": {"primary_target": "https://clearpathrobotics.com"},
        "execution_trace": [],
    }
    assert is_cve_applicability_question(state)
    step = forced_next_step(state)
    assert step and step["tool_name"] == "check_cve_applicability"
    assert step["tool_args"]["cve_id"] == "CVE-2026-1293"
    assert "clearpathrobotics.com" in step["tool_args"]["url"]


def test_cve_question_does_not_block_complete_on_wp_probes():
    q = "can we check if CVE-2026-1293 is applicable to https://clearpathrobotics.com"
    state = {
        "original_objective": q,
        "objective": q,
        "target_info": {
            "primary_target": "https://clearpathrobotics.com",
            "technologies": ["WordPress:6.7.7"],
        },
        "kickoff_brief": "WordPress 6.7.7",
        "execution_trace": [
            {
                "tool_name": "check_cve_applicability",
                "success": True,
                "tool_output": "VERDICT: applicable\nYoast SEO 24.3 IN RANGE",
            }
        ],
    }
    assert cve_check_ran(state)
    assert applicability_pending_finding(state)
    # Let Joshua file the finding — do not hijack into Interceptor.
    assert forced_next_step(state) is None
    assert complete_blocked_reason(state) is None


def test_full_assessment_still_requires_tester_loop():
    q = (
        "Perform an authorized web application security assessment of "
        "https://clearpathrobotics.com. Also note CVE-2026-1293."
    )
    state = {
        "original_objective": q,
        "objective": q,
        "target_info": {"primary_target": "https://clearpathrobotics.com"},
        "execution_trace": [],
    }
    assert not is_cve_applicability_question(state)
    step = cve_applicability_forced_step(state)
    assert step and step["tool_name"] == "check_cve_applicability"


def test_search_vulnx_allowed_in_informational():
    assert is_tool_allowed_in_phase("search_vulnx", "informational")
    assert is_tool_allowed_in_phase("vulnx_query", "informational")
    assert is_tool_allowed_in_phase("check_cve_applicability", "informational")
    assert is_tool_allowed_in_phase("fingerprint_passive_stack", "informational")
