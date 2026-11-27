"""SQLi work must reach every server-read input: cookies, headers, and path IDs.

Regression for an in-band UNION SQLi in a language-preference cookie
(``Cookie: site_Language_Preference=0 UNION SELECT ...``) that the query/body-only
inventory could never assign.
"""

import pytest

from app.services.agent.coverage_cells import seed_parameter_coverage_cells
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.injection_payloads import generate_payloads
from app.services.agent.parameter_inventory import (
    collect_parameter_inventory,
    cookie_names,
    is_credential_cookie,
    parameters_for_specialist,
)
from app.services.agent.prowl_service_bridge import capability_map_from_observation
from app.services.agent.request_mutate import apply_one_mutation, set_cookie_pair
from app.services.agent.scoped_assessment.browser import _cookie_inputs
from app.services.agent.vulnerability_catalog import parameter_test_classes

TARGET = "https://shop.test/"


def _shop_map() -> dict:
    return {
        "target": TARGET,
        "pages_visited": [TARGET, "https://shop.test/product/42", "https://shop.test/product/43"],
        "api_samples": [
            {
                "method": "GET", "url": "https://shop.test/",
                "headers": {
                    "Cookie": "site_Language_Preference=1; site_Country_Preference=249; "
                              "PHPSESSID=private-session; _ga=GA1.2.3",
                    "X-Tenant-Id": "7", "X-Api-Key": "private-key",
                },
                "response_headers": {
                    "Set-Cookie": "site_Branch_Preference=1; Path=/; HttpOnly",
                },
            },
            {
                # The same cookies on another page must not create new work.
                "method": "GET", "url": "https://shop.test/about",
                "headers": {"Cookie": "site_Language_Preference=1; PHPSESSID=private-session"},
            },
        ],
    }


def _by(rows, location):
    return {row["name"]: row for row in rows if row["location"] == location}


def test_cookies_become_value_free_injection_points_once_per_name():
    rows = collect_parameter_inventory(_shop_map())
    cookies = _by(rows, "cookie")
    assert set(cookies) == {
        "site_Language_Preference", "site_Country_Preference",
        "site_Branch_Preference", "PHPSESSID", "_ga",
    }
    assert cookies["site_Language_Preference"]["testable"] is True
    assert cookies["site_Branch_Preference"]["testable"] is True  # from Set-Cookie
    assert cookies["PHPSESSID"]["testable"] is False
    assert cookies["_ga"]["testable"] is False
    assert sum(1 for row in rows if row["name"] == "site_Language_Preference") == 1
    assert cookies["site_Language_Preference"]["path"] == "/"
    # Names only: no cookie or header value enters the inventory.
    for secret in ("private-session", "private-key", "GA1.2.3", "249"):
        assert secret not in str(rows)


def test_headers_and_path_ids_become_injection_points():
    rows = collect_parameter_inventory(_shop_map())
    headers = _by(rows, "header")
    assert {"User-Agent", "Referer", "X-Forwarded-For", "Accept-Language"} <= set(headers)
    assert headers["X-Tenant-Id"]["testable"] is True
    assert headers["X-Api-Key"]["testable"] is False
    paths = [row for row in rows if row["location"] == "path"]
    # /product/42 and /product/43 are one input.
    assert [(row["path"], row["name"]) for row in paths] == [("/product/42", "path[2]")]
    assert paths[0]["value_type"] == "positive_integer"


def test_static_assets_and_credential_names_are_not_injection_work():
    rows = collect_parameter_inventory({
        "target": TARGET,
        "pages_visited": ["https://shop.test/static/12/app.js"],
        "cookie_inputs": [{"name": "ASP.NET_SessionId"}, {"name": "__RequestVerificationToken"},
                          {"name": "remember_me"}, {"name": "currency"}],
    })
    assert not [row for row in rows if row["location"] == "path"]
    assert {name: row["testable"] for name, row in _by(rows, "cookie").items()} == {
        "ASP.NET_SessionId": False, "__RequestVerificationToken": False,
        "remember_me": False, "currency": True,
    }


def test_cookie_header_and_path_rows_seed_sqli_cells():
    rows = collect_parameter_inventory(_shop_map())
    brain = EngagementBrain(target=TARGET)
    seed_parameter_coverage_cells(brain, rows)
    sqli = {cell["parameter"] for cell in brain.coverage_cells if cell["test_type"] == "sqli"}
    assert {
        "cookie:site_Language_Preference", "cookie:site_Country_Preference",
        "cookie:site_Branch_Preference", "header:User-Agent", "header:X-Tenant-Id",
        "path:path[2]",
    } <= sqli
    assert not {"cookie:PHPSESSID", "cookie:_ga", "header:X-Api-Key"} & sqli
    assert parameter_test_classes({"location": "cookie", "name": "lang"}) == ("sqli", "xss")


def test_sqli_specialist_ranks_cookies_ahead_of_generic_headers():
    ordered = [f"{row['location']}:{row['name']}"
               for row in parameters_for_specialist(_shop_map(), "sqli")]
    assert ordered.index("cookie:site_Language_Preference") < ordered.index("header:User-Agent")


def test_browser_cookie_jar_names_reach_the_inventory():
    jar = [
        {"name": "site_Language_Preference", "value": "1", "domain": "shop.test", "path": "/"},
        {"name": "PHPSESSID", "value": "s", "domain": ".shop.test", "path": "/", "httpOnly": True},
        {"name": "tracker", "value": "x", "domain": "ads.example", "path": "/"},
    ]
    inputs = _cookie_inputs(jar, "https://shop.test")
    assert [row["name"] for row in inputs] == ["site_Language_Preference", "PHPSESSID"]
    assert "value" not in str(inputs).lower().replace("'http_only'", "")
    cmap = capability_map_from_observation({"signal": "browser_map", "result": {
        "final_origin": "https://shop.test", "final_path": "/", "status": 200,
        "cookie_inputs": inputs,
    }})
    cookies = _by(cmap["parameter_inventory"], "cookie")
    assert cookies["site_Language_Preference"]["testable"] is True
    assert cookies["site_Language_Preference"]["source"] == "browser_cookie"
    assert cookies["PHPSESSID"]["testable"] is False


def test_cookie_name_parsing_and_credential_detection():
    assert cookie_names("a=1; b=2", ["c=3; Path=/; HttpOnly", "d=4; Expires=Wed, 21 Oct 2026 07:28:00 GMT"]) \
        == ["a", "b", "c", "d"]
    for name in ("PHPSESSID", "JSESSIONID", "connect.sid", "laravel_session", "XSRF-TOKEN", "jwt"):
        assert is_credential_cookie(name), name
    for name in ("site_Language_Preference", "country", "currency", "cart_view"):
        assert not is_credential_cookie(name), name


def test_cookie_mutation_changes_one_cookie_and_keeps_the_session():
    sample = {"method": "GET", "url": "https://shop.test/",
              "headers": {"Cookie": "PHPSESSID=s; site_Language_Preference=1"}}
    payload = "0 UNION SELECT 0x5b5b5b-- -"
    baseline, mutant = apply_one_mutation(sample, location="cookie",
                                          field="site_Language_Preference", value=payload)
    assert baseline["headers"]["Cookie"] == "PHPSESSID=s; site_Language_Preference=1"
    assert mutant["headers"]["Cookie"] == f"PHPSESSID=s; site_Language_Preference={payload}"
    assert mutant["cookies"] == {"site_Language_Preference": payload}
    # Without a captured Cookie header the value travels as an explicit cookie.
    _, bare = apply_one_mutation({"method": "GET", "url": "https://shop.test/"},
                                 location="cookie", field="lang", value="1 AND 1=2")
    assert bare["cookies"] == {"lang": "1 AND 1=2"}
    with pytest.raises(ValueError):
        apply_one_mutation(sample, location="cookie", field="lang", value="1; admin=1")
    assert set_cookie_pair("a=1", "b", "2") == "a=1; b=2"


def test_path_segment_mutation_targets_the_inventory_index():
    sample = {"method": "GET", "url": "https://shop.test/product/42?view=full"}
    _, mutant = apply_one_mutation(sample, location="path", field="path[2]", value="42 AND 1=2")
    assert mutant["url"] == "https://shop.test/product/42%20AND%201%3D2?view=full"
    with pytest.raises(ValueError):
        apply_one_mutation(sample, location="path", field="path[5]", value="1")


def test_numeric_context_union_payloads_are_available():
    union = generate_payloads("sqli", technique="union_based")
    probes = generate_payloads("sqli", technique="context_probe")
    text = str(union) + str(probes)
    assert "0 UNION SELECT 0x5b5b5b4145474953-- -" in text
    assert "2-1" in text and "1'" in text
