"""SQLi payload guidance must preserve observed-input proof workflows."""

from app.services.agent.injection_payloads import generate_payloads
from app.services.agent.tool_selector import ToolSelector


def test_default_sqli_payloads_are_low_impact_controls():
    result = generate_payloads("sqli")
    payloads = "\n".join(result["payloads"]).lower()
    assert result["payload_count"] > 0
    assert result["reference_url"].endswith("/SQL%20Injection")
    assert all(token not in payloads for token in (
        "drop table", "union select", "information_schema", "from users",
        "password", "sleep(", "waitfor", "benchmark(",
    ))
    stacked = generate_payloads("sqli", technique="stacked")
    assert all("drop" not in payload.lower() for payload in stacked["payloads"])


def test_parameter_name_recommends_observed_probe_instead_of_fabricated_sqlmap_url():
    selector = ToolSelector(
        target="https://app.test", target_info={}, execution_trace=[],
        current_phase="exploitation",
        parameters={"category": {"likely_vulnerable_to": ["sqli"]}},
    )
    recommendations = selector.get_recommendations()
    by_name = {row["tool_name"]: row for row in recommendations}
    assert by_name["probe_observed_input_batch"]["args_template"] == "max_checks=8"
    assert "execute_sqlmap" not in by_name
    assert "execute_interactsh" not in by_name
