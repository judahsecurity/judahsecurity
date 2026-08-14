"""Tests for native Interceptor spider argv + output parsing."""

from app.services.interceptor_recon import (
    ReconResult,
    _build_spider_argv,
    _parse_spider_output,
)


def test_build_spider_argv_skill_flags():
    argv = _build_spider_argv(
        "https://www.emulate3d.com/",
        {
            "depth": 3,
            "max_clicks": 80,
            "include_subdomains": True,
            "robots": True,
            "sitemap": True,
            "probe_text": "hello",
        },
        max_pages=25,
    )
    assert argv[0] == "spider"
    assert argv[1] == "https://www.emulate3d.com/"
    assert "--max-pages" in argv and "25" in argv
    assert "--depth" in argv and "3" in argv
    assert "--max-clicks" in argv and "80" in argv
    assert "--include-subdomains" in argv
    assert "--robots" in argv
    assert "--sitemap" in argv
    assert "--probe-text" in argv and "hello" in argv


def test_parse_spider_output_coverage_and_urls():
    result = ReconResult(target="https://www.emulate3d.com/", scope="emulate3d.com")
    out = """
    Site spider complete
    coverage: PARTIAL leftover=12
    visited: https://www.emulate3d.com/
    visited: https://www.emulate3d.com/wp-admin/
    GET https://www.emulate3d.com/wp-json/wp/v2/posts
    https://www.emulate3d.com/wp-content/themes/x/app.js
    "/api/v1/demo"
    """
    _parse_spider_output(out, result)
    assert result.coverage == "PARTIAL"
    assert "https://www.emulate3d.com/" in result.pages_visited
    assert any("wp-json" in k for keys in result.api_calls.values() for k in keys) or result.js_files
    assert any(j.endswith(".js") for j in result.js_files)
