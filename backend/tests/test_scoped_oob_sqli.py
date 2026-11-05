"""Out-of-band SQLi reuses the correlated OAST workflow with server-owned payloads.

The model supplies no SQL bytes; it selects a mapped observed input and a family.
The payload template embeds a {{callback_host}} placeholder the workflow fills
with a freshly registered collaborator, preserves the observed value and the
other query fields, and is planted into the candidate endpoint. Proof is the
existing class-agnostic register->plant->poll correlation, now permitted to
confirm sql_injection.
"""

from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from app.services.agent.oob_callback_workflow import (
    CALLBACK_HOST_PLACEHOLDER,
    CALLBACK_PLACEHOLDER,
    _inject_callback,
)
from app.services.agent.proof_policy import PROOFS_BY_CLASS, proof_kind_allowed
from app.services.agent.scoped_assessment import sqli_oob

URL = "https://app.example.test/catalog?other=1&category=gin"


# ── server-owned payloads ────────────────────────────────────────────────────

@pytest.mark.parametrize("family", sqli_oob.OOB_FAMILIES)
def test_template_is_server_owned_and_preserves_observed_value(family):
    field, template = sqli_oob.plan_oob_sqli(URL, parameter="category", family=family)
    assert field == "category"
    assert template.startswith("gin'")          # observed value preserved, then break-out
    assert CALLBACK_HOST_PLACEHOLDER in template  # collaborator filled by the workflow
    assert template.rstrip().endswith("--")       # tail commented out


def test_plan_rejects_unknown_family_and_non_observed_value():
    with pytest.raises(ValueError):
        sqli_oob.plan_oob_sqli(URL, parameter="category", family="db2")
    with pytest.raises(ValueError):
        sqli_oob.plan_oob_sqli("https://app.example.test/c?category=a'b",
                               parameter="category", family="mysql")
    with pytest.raises(ValueError):  # parameter must occur exactly once
        sqli_oob.plan_oob_sqli("https://app.example.test/c?category=a&category=b",
                               parameter="category", family="mysql")


# ── query_template injection ─────────────────────────────────────────────────

def test_query_template_embeds_host_and_preserves_other_fields():
    _, template = sqli_oob.plan_oob_sqli(URL, parameter="category", family="mysql")
    url, _headers, body = _inject_callback(
        url=URL, payload_url="http://abc.oast.site/", payload_host="abc.oast.site",
        location="query_template", field="category", headers={}, body=template,
    )
    q = parse_qs(urlsplit(url).query)
    injected = unquote(q["category"][0])
    assert "abc.oast.site" in injected          # domain rides in the request text
    assert CALLBACK_HOST_PLACEHOLDER not in url  # placeholder fully substituted
    assert q["other"] == ["1"]                  # untouched sibling field
    assert body is None                          # GET carries no body


def test_query_template_requires_a_placeholder():
    with pytest.raises(ValueError):
        _inject_callback(url=URL, payload_url="http://x/", payload_host="x",
                         location="query_template", field="category",
                         headers={}, body="gin' AND 1=1-- ")


def test_raw_location_still_supports_host_placeholder():
    _url, _headers, body = _inject_callback(
        url="https://app.example.test/x", payload_url="http://abc.oast.site/",
        payload_host="abc.oast.site", location="raw", field="",
        headers={}, body="<x>" + CALLBACK_HOST_PLACEHOLDER + "</x>",
    )
    assert body == "<x>abc.oast.site</x>"


def test_raw_location_rejects_missing_placeholder():
    with pytest.raises(ValueError):
        _inject_callback(url="https://app.example.test/x", payload_url="http://x/",
                         payload_host="x", location="raw", field="",
                         headers={}, body="<x>no placeholder</x>")


# ── proof classing ───────────────────────────────────────────────────────────

def test_oob_callback_registered_and_allowed_for_sql_injection():
    assert "oob_callback" in PROOFS_BY_CLASS["sql_injection"]
    cand = SimpleNamespace(vulnerability_class="sql_injection",
                           title="Out-of-band SQL injection in category",
                           description="blind sqli via dns callback")
    ok, _ = proof_kind_allowed(cand, "oob_callback")
    assert ok is True


def test_callback_placeholder_constant_unchanged():
    # Existing SSRF/XXE raw flows depend on this exact token.
    assert CALLBACK_PLACEHOLDER == "{{callback_url}}"
