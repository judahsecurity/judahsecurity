"""Praetorian-style sitemap storage: classify, templatize, cluster URLs."""

from app.services.sitemap_service import (
    KIND_API,
    KIND_EXTERNAL,
    KIND_SITEMAP,
    classify_flags,
    classify_kind,
    parse_discovered_url,
    path_key,
    templatize_query,
)


def test_templatize_query_collapses_values():
    assert templatize_query("id=abc123&src=LEGACY&cond=1") == "id=EXPR&src=EXPR&cond=EXPR"


def test_parse_path_on_asset_host():
    parsed = parse_discovered_url("/enquiry", default_host="www.lektronix.it")
    assert parsed is not None
    assert parsed["host"] == "www.lektronix.it"
    assert parsed["path"] == "/enquiry"
    assert parsed["url"] == "https://www.lektronix.it/enquiry"


def test_parse_query_becomes_expr():
    parsed = parse_discovered_url(
        "https://www.lektronix.it/quick-contact.php?foo=secret-token"
    )
    assert parsed is not None
    assert parsed["path"] == "/quick-contact.php?foo=EXPR"
    assert "secret-token" not in parsed["url"]


def test_same_host_is_sitemap_other_host_is_external():
    assert classify_kind("www.lektronix.it", "/about", "www.lektronix.it") == KIND_SITEMAP
    assert classify_kind("lektronix.it", "/", "www.lektronix.it") == KIND_EXTERNAL
    assert classify_kind("cdn.cookielaw.org", "/consent", "www.lektronix.it") == KIND_EXTERNAL


def test_api_paths_classified():
    assert classify_kind("www.lektronix.it", "/api/v1/users", "www.lektronix.it") == KIND_API
    assert classify_kind("www.lektronix.it", "/graphql", "www.lektronix.it") == KIND_API


def test_login_and_sso_flags():
    login = classify_flags("/job-tracking-login")
    assert login["has_login"] is True
    sso = classify_flags("/oauth/authorize")
    assert sso["has_sso"] is True
    secrets = classify_flags("/.env")
    assert secrets["has_secrets"] is True


def test_bare_third_party_hostname():
    parsed = parse_discovered_url("cdn.cookielaw.org", default_host="www.lektronix.it")
    assert parsed is not None
    assert parsed["host"] == "cdn.cookielaw.org"
    assert classify_kind(parsed["host"], parsed["path"], "www.lektronix.it") == KIND_EXTERNAL


def test_path_key_stable_and_distinct():
    a = path_key(KIND_SITEMAP, "www.lektronix.it", "GET", "/about")
    b = path_key(KIND_SITEMAP, "www.lektronix.it", "GET", "/about")
    c = path_key(KIND_API, "www.lektronix.it", "GET", "/about")
    assert a == b
    assert a != c
