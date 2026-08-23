"""Lazy-chunk reconstruction, JS endpoint triage, captured-traffic API fingerprint."""

from __future__ import annotations

from app.services.agent.api_fingerprint import fingerprint_from_samples
from app.services.agent.js_endpoints import extract_from_body, triage_endpoints
from app.services.agent.lazy_chunks import (
    discover_chunk_paths,
    in_scope,
    resolve_chunk_urls,
)


WEBPACK = """
__webpack_require__.p = "/_next/";
__webpack_require__.u = function(e) { return "static/chunks/" + e + ".js"; };
var a = "/_next/static/chunks/app-abc123.js";
var b = "/_next/static/chunks/pages/admin.js";
"""

VITE = """
const m = __vite__mapDeps(["assets/index-abc.js", "assets/Action-def.js", "assets/foo.css"]);
"""


def test_discover_next_and_webpack_public_path():
    d = discover_chunk_paths(WEBPACK)
    assert "/_next/" in d["public_paths"]
    assert any("app-abc123.js" in p for p in d["chunk_paths"])
    assert any("admin.js" in p for p in d["chunk_paths"])


def test_discover_vite_map_deps():
    d = discover_chunk_paths(VITE)
    assert any("Action-def.js" in p for p in d["chunk_paths"])
    urls = resolve_chunk_urls(
        base_url="https://app.example.com/",
        public_paths=d["public_paths"],
        chunk_paths=d["chunk_paths"],
    )
    assert any(u.startswith("https://app.example.com/") and "Action-def.js" in u for u in urls)


def test_chunk_scope_rejects_off_host():
    assert in_scope("https://app.example.com/static/a.js", "example.com")
    assert not in_scope("https://evil.tld/static/a.js", "example.com")


def test_triage_idor_ssrf_and_api():
    body = """
    fetch("/api/v1/users?id=12");
    axios.get("https://app.example.com/api/actions/execute?url=http://inner");
    $.post("/graphql");
    const noise = "/logo.png";
    const API_BASE = "/api/v1";
    """
    groups = triage_endpoints(extract_from_body(body), origin_host="app.example.com")
    assert any("/api/v1/users" in p for p in groups["api_routes"] + groups["idor_candidates"])
    assert groups["ssrf_redirect_candidates"]
    assert not any(p.endswith(".png") for p in groups["fetch_targets"])
    assert any(p.rstrip("/") == "/api/v1" or "/api/v1" in p for p in groups["api_routes"] + groups["fetch_targets"])


def test_fingerprint_appsmith_from_samples():
    samples = [
        {"method": "POST", "url": "https://appsmith-dmpc.unifytwin.com/api/v1/actions/execute"},
        {"method": "GET", "url": "https://appsmith-dmpc.unifytwin.com/api/v1/users/me"},
    ]
    fp = fingerprint_from_samples(samples, target="https://appsmith-dmpc.unifytwin.com")
    techs = {i["tech"] for i in fp["technology_indicators"]}
    assert "appsmith" in techs
    assert fp["api_host_candidates"][0]["host"] == "appsmith-dmpc.unifytwin.com"
    assert fp["api_host_candidates"][0]["score"] >= 3
    assert any("mutate_captured_request" in n for n in fp["next_checks"])
    assert fp["coverage"]["external_corroboration"].startswith("out-of-scope")
    assert fp["recommended_active_probes"]["executed"] is False
    assert fp["blocked"] is False


def test_webpack_hash_map_expansion():
    """Port of fetch_lazy_chunks.js: template + {id:hash}[e] must expand."""
    src = (
        '__webpack_require__.p = "/";\n'
        '__webpack_require__.u = e => "static/js/" + e + "." + '
        '{143:"a1b2c3",99:"deadbeef"}[e] + ".chunk.js";\n'
    )
    d = discover_chunk_paths(src)
    assert "static/js/143.a1b2c3.chunk.js" in d["chunk_paths"]
    assert "static/js/99.deadbeef.chunk.js" in d["chunk_paths"]
    assert "/" in d["public_paths"] or d["public_paths"] == ["/"]


def test_next_bracketed_dynamic_route_chunk():
    src = 'const x = "static/chunks/app/[accountId]/page.js";'
    d = discover_chunk_paths(src)
    assert any("[accountId]" in p for p in d["chunk_paths"])


def test_skill_md_packs_load():
    from app.services.agent.skill_md import list_skill_packs, load_skill_md, skill_body

    names = list_skill_packs()
    assert "lazy_chunk_downloader" in names
    assert "js_analysis" in names
    assert "interceptor" in names
    assert "api_fingerprint" in names
    assert "api_test" in names
    assert "jshero" in names
    assert "wordpress" in names
    lazy = load_skill_md("lazy_chunk_downloader")
    assert lazy and "webpack" in lazy["body"].lower()
    assert "fetch_lazy_chunks" in skill_body("lazy_chunk_downloader")
    inter = load_skill_md("interceptor")
    assert inter and "macos" in inter["body"].lower()
    assert "ChatGPT" in inter["body"] or "chatgpt" in inter["body"].lower()


def test_fingerprint_cookie_and_banner():
    samples = [
        {
            "method": "GET",
            "url": "https://app.example.com/api/v1/me",
            "headers": {"cookie": "PHPSESSID=abc; other=1"},
            "response_headers": {"server": "nginx/1.24", "content-type": "application/json"},
            "status": 200,
        }
    ]
    fp = fingerprint_from_samples(samples, target="https://app.example.com")
    techs = {i["tech"] for i in fp["technology_indicators"]}
    assert "PHP" in techs
    assert "server" in techs
    assert fp["coverage"]["cookie_parameters"] == "covered"


def test_fingerprint_empty_is_ok_not_improvised():
    fp = fingerprint_from_samples([], target="https://example.com")
    assert fp["ok"] is True
    assert fp["blocked"] is True
    assert fp["sample_count"] == 0
    assert "not-covered" in fp["coverage"]["malformed_http_requests"]
    assert fp["recommended_active_probes"]["executed"] is False


def test_api_test_slash_command_positional_target():
    from app.services.agent.api_test_pipeline import STEPS, next_step
    from app.services.agent.skills_service import get_skill, parse_skill_prefix, resolve

    skill = get_skill("api-test")
    assert skill and skill.playbook_id == "api_test"
    parsed, args, rest = parse_skill_prefix("/api-test https://appsmith-dmpc.unifytwin.com")
    assert parsed and parsed.id == "api-test"
    assert args.get("target") == "https://appsmith-dmpc.unifytwin.com"
    assert rest == ""
    hit = resolve("/api-test https://example.com")
    assert hit["matched"] is True
    assert "execute_interceptor" in hit["system_context"]
    assert "fetch_lazy_chunks" in hit["system_context"]
    assert "fingerprint_api" in hit["system_context"]
    assert "Caido" in hit["system_context"] or "caido" in hit["system_context"].lower()

    assert STEPS[0]["tools"] == ["execute_interceptor"]
    assert STEPS[1]["parallel"] is True
    assert set(STEPS[1]["tools"]) == {"fetch_lazy_chunks", "fingerprint_api"}
    assert next_step([])["id"] == "visit"
    assert next_step(["execute_interceptor"])["id"] == "chunks_and_fingerprint"
    assert next_step(["execute_interceptor", "fetch_lazy_chunks"])["id"] == "chunks_and_fingerprint"
    assert next_step(["execute_interceptor", "fetch_lazy_chunks", "fingerprint_api"])["id"] == "extract"
    assert next_step(["execute_interceptor", "fetch_lazy_chunks", "fingerprint_api", "extract_js_endpoints"]) is None


def test_jshero_methods_params_and_template_routes():
    from app.services.agent.js_endpoints import extract_from_body, extract_methods_and_params

    body = """
    xhr.open("POST", "/api/v1/actions/execute");
    axios.post("/api/v1/users", { data: { url: inner, user_id: x } });
    const path = `${base}/users/${id}/profile`;
    """
    extra = extract_methods_and_params(body)
    methods = {m["method"] + " " + m["url"] for m in extra["methods"]}
    assert any(m.startswith("POST ") and "actions/execute" in m for m in methods)
    assert "url" in extra["params"] or "user_id" in extra["params"]
    found = extract_from_body(body)
    assert any("actions/execute" in p for p in found)
    assert any("EXPR" in p and "users" in p for p in found)


def test_jshero_sink_scan_high_signal_only():
    from app.services.agent.js_sinks import scan_body

    hits = scan_body("eval(user); el.innerHTML = q; fetch('/api'); document.cookie = 1;")
    types = {h["type"] for h in hits}
    assert "eval" in types
    assert "innerHTML" in types
    assert "fetch" not in types
    assert "cookie" not in types


def test_jshero_skill_slash_command():
    from app.services.agent.skill_md import list_skill_packs, skill_body
    from app.services.agent.skills_service import get_skill, parse_skill_prefix, resolve

    assert "jshero" in list_skill_packs()
    assert "fetch_lazy_chunks" in skill_body("jshero")
    assert "VPS" in skill_body("jshero") or "waymore" in skill_body("jshero").lower()
    skill = get_skill("jshero")
    assert skill and skill.playbook_id == "jshero"
    parsed, args, rest = parse_skill_prefix("/jshero https://appsmith-dmpc.unifytwin.com")
    assert parsed and parsed.id == "jshero"
    assert args.get("target") == "https://appsmith-dmpc.unifytwin.com"
    hit = resolve("/jshero https://example.com")
    assert hit["matched"] is True
    assert "scan_js_sinks" in hit["system_context"]
