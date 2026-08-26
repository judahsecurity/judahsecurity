"""Tests for observation → methodology catalog and engagement seeding."""

from types import SimpleNamespace
from unittest.mock import patch

from app.services.agent.capability_map import (
    build_capability_map_from_crawl,
    ingest_passive_urls,
)
from app.services.agent.engagement_brain import (
    boost_methodologies_for_cwes,
    engagement_brain_from_dict,
    format_engagement_brain_for_prompt,
    methodology_progress,
    seed_hypotheses_from_capability_map,
    update_hypothesis,
)
from app.services.agent.methodology_catalog import (
    methodologies_from_capability_map,
)
from app.services.agent.operation_directive import directives_from_hypotheses
from app.services.vuln_intel_enrichment import build_cwe_intel, enrich_cve_catalog


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-a.app.example.com/forgot-password",
            "https://tenant-a.app.example.com/signup",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
            "https://tenant-a.app.example.com/search?q=test",
            "https://tenant-a.app.example.com/swagger/index.html",
        ],
        forms=[
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://tenant-a.app.example.com/login",
            },
            {
                "method": "POST",
                "action": "/forgot-password",
                "inputs": ["email"],
                "page": "https://tenant-a.app.example.com/forgot-password",
            },
            {
                "method": "GET",
                "action": "/search",
                "inputs": ["q"],
                "page": "https://tenant-a.app.example.com/search",
            },
            {
                "method": "POST",
                "action": "/checkout",
                "inputs": ["quantity", "price"],
                "page": "https://tenant-a.app.example.com/checkout",
            },
            {
                "method": "POST",
                "action": "/upload",
                "inputs": ["file", "title"],
                "page": "https://tenant-a.app.example.com/upload",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {
                "GET /api/users?id=1",
                "GET /api/orders/100",
                "POST /api/webhooks?url=https://example.com",
            },
            "tenant-b.app.example.com": {
                "GET /api/users?id=2",
            },
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items", "/api/v1/api_key/status"},
        websockets={"wss://tenant-a.app.example.com/ws"},
        sse=set(),
        source_maps=set(),
        third_party=set(),
        api_samples=[{"url": "/api/webhooks?url=https://example.com", "method": "POST"}],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_methodologies_from_rich_crawl():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "default_weak_creds" in ids
    assert "login_injection" in ids
    login_sqli = next(m for m in methods if m.id == "login_injection")
    assert login_sqli.specialist == "sqli"
    assert "compare_requests" in login_sqli.test
    assert "CWE-89" in login_sqli.cwe_ids
    assert "password_reset_abuse" in ids
    assert "api_idor_bola" in ids
    assert "host_tenant_isolation" in ids
    assert "reflected_xss" in ids
    assert "unsafe_file_upload" in ids
    assert "ssrf_url_fetch" in ids
    assert "path_directory_context" in ids
    assert "path_parameter_mining" in ids
    assert "realtime_channel_auth" in ids
    assert "js_client_hmac_signing" in ids
    assert "admin_surface_exposure" in ids
    assert "coverage_known_vulns" in ids
    assert "registration_invite_abuse" in ids
    assert "openapi_schema_authz" in ids
    assert "openapi_mass_assignment" in ids
    assert "openapi_unauth_account_lookup" in ids
    assert "owasp_api_astf" in ids
    astf = next(m for m in methods if m.id == "owasp_api_astf")
    assert "execute_astf" in astf.test
    assert "compare_requests" in astf.test
    ma = next(m for m in methods if m.id == "openapi_mass_assignment")
    assert "CWE-915" in ma.cwe_ids
    assert "readOnly" in ma.test or "readonly" in ma.test.lower()
    assert "database" in ma.kill_criteria.lower()
    assert "js_apikey_exposure" in ids
    xss = next(m for m in methods if m.id == "reflected_xss")
    assert "CWE-79" in xss.cwe_ids
    assert xss.capec_ids
    assert cmap.methodologies
    assert any(h.get("methodology_id") for h in cmap.ranked_hunt_queue)
    assert any(h.get("hunt") == "unauth_account_lookup" for h in cmap.ranked_hunt_queue)


def test_action_execute_path_seeds_ssrf_card():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            pages_visited=["https://appsmith.example.com/"],
            api_calls={"appsmith.example.com": {"POST /api/v1/actions/execute"}},
            api_samples=[{"url": "/api/v1/actions/execute", "method": "POST"}],
            forms=[],
        )
    )
    ids = {m.id for m in methodologies_from_capability_map(cmap)}
    assert "ssrf_url_fetch" in ids
    assert "path_parameter_mining" in ids


def test_seed_hypotheses_uses_methodology_cards():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    method_hyps = [h for h in brain.hypotheses if h.source == "methodology"]
    assert method_hyps
    assert any(h.methodology_id == "reflected_xss" for h in method_hyps)
    assert any("CWE-79" in h.cwe_ids for h in method_hyps)
    text = format_engagement_brain_for_prompt(brain.to_dict())
    assert "CWE=" in text or "method=" in text
    assert "Methodology" in text or "ready_to_complete" in text


def test_methodology_progress_blocks_complete_until_high_pri_resolved():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    progress = methodology_progress(brain, cmap=cmap.to_dict())
    assert progress["seeded"] is True
    assert progress["blocking_high_priority"] > 0
    assert progress["ready_to_complete"] is False

    for h in list(brain.hypotheses):
        if h.priority in ("critical", "high") and h.specialist != "coverage":
            update_hypothesis(brain, h.id, status="killed", evidence="tested clean")
    progress2 = methodology_progress(brain, cmap=cmap.to_dict())
    assert progress2["ready_to_complete_methods"] is True
    from app.services.agent.engagement_brain import record_surface_coverage
    leftover = list((progress2.get("coverage") or {}).get("untested") or [])
    for _ in range(3):
        if not leftover:
            break
        for row in leftover:
            record_surface_coverage(
                brain,
                method=row.get("method") or "GET",
                path=row.get("path") or "/",
                host=row.get("host") or "",
                status="tested_clean",
                reason="killed high-priority cards",
            )
        progress2 = methodology_progress(brain, cmap=cmap.to_dict())
        leftover = list((progress2.get("coverage") or {}).get("untested") or [])
    assert progress2["ready_to_complete"] is True, (
        f"{progress2.get('summary')} leftover={leftover}"
    )
    assert progress2["ready_for_coverage_spray"] is True


def test_cve_cwe_loopback_boosts_related_cards():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    xss = next(h for h in brain.hypotheses if h.methodology_id == "reflected_xss")
    boosted = boost_methodologies_for_cwes(
        brain, ["CWE-79"], cve_id="CVE-2024-0001", evidence="nuclei hit"
    )
    assert any(h.methodology_id == "reflected_xss" for h in boosted)
    assert "CVE-2024-0001" in (xss.evidence or "")


def test_ingest_passive_urls_enriches_map():
    cmap = build_capability_map_from_crawl(_fake_crawl(pages_visited=["https://app.example.com/"]))
    merged = ingest_passive_urls(
        cmap.to_dict(),
        [
            "https://app.example.com/api/users?id=9",
            "https://app.example.com/swagger.json",
            "https://app.example.com/static/vendor.js",
            "https://app.example.com/forgot-password",
        ],
        source="katana",
        target="https://app.example.com",
    )
    blob = " ".join(merged.get("pages_visited") or []) + " ".join(
        e.get("path") or "" for e in (merged.get("api_endpoints") or [])
    )
    assert "swagger" in blob.lower() or "forgot-password" in blob.lower() or "users" in blob.lower()
    ids = {m.get("id") for m in merged.get("methodologies") or []}
    assert ids & {
        "openapi_schema_authz",
        "openapi_mass_assignment",
        "api_idor_bola",
        "password_reset_abuse",
        "js_secrets_retire",
    }


def test_operation_directive_includes_cwe_and_methodologies():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )

    class _P:
        def __init__(self, name):
            self.name = name
            self.epithet = name
            self.role = f"{name} specialist."
            self.allowed_tools = ["compare_requests", "execute_curl"]
            self.max_iterations = 6

    profiles = {
        "xss": _P("xss"),
        "api_authz": _P("api_authz"),
        "app_mapper": _P("app_mapper"),
    }
    directives = directives_from_hypotheses(
        brain=brain,
        profiles_by_name=profiles,
        specialists=["xss", "api_authz"],
        default_target=cmap.target,
    )
    xss = directives["xss"]
    assert xss.methodology_ids
    assert xss.cwe_ids
    block = xss.to_prompt_block()
    assert "Methodologies:" in block
    assert "CWE:" in block


def test_build_cwe_intel_from_nvd_cwes():
    intel = build_cwe_intel(["CWE-502", "CWE-79"])
    ids = {row["cwe_id"] for row in intel}
    assert "CWE-502" in ids
    assert "CWE-79" in ids
    xss = next(r for r in intel if r["cwe_id"] == "CWE-79")
    assert xss["capec"]
    assert any(c["id"].startswith("CAPEC-") for c in xss["capec"])
    assert xss["name"]


def test_grafana_hostname_seeds_kube_prometheus_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://grafana.qa.example.com",
            pages_visited=[
                "https://grafana.qa.example.com/",
                "https://grafana.qa.example.com/login",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "grafana_kube_prometheus_defaults" in ids
    grafana = next(m for m in methods if m.id == "grafana_kube_prometheus_defaults")
    assert "CWE-1393" in grafana.cwe_ids
    assert "prom-operator" in grafana.test
    weak = next(m for m in methods if m.id == "default_weak_creds")
    assert "CWE-1393" in weak.cwe_ids
    assert "grafana_cve_9264_sql_expressions" in ids
    sql = next(m for m in methods if m.id == "grafana_cve_9264_sql_expressions")
    assert "Viewer" in sql.test or "Viewer" in sql.assumption
    assert "no such file" in sql.test.lower() or "fork" in sql.test.lower()
    assert "CWE-89" in sql.cwe_ids
    assert "CWE-94" in sql.cwe_ids
    assert "CWE-863" in sql.cwe_ids


def test_elasticsearch_port_seeds_unauth_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="http://es.example.com:9200",
            pages_visited=[
                "http://es.example.com:9200/",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "elasticsearch_unauth_exposure" in ids
    es = next(m for m in methods if m.id == "elasticsearch_unauth_exposure")
    assert "CWE-306" in es.cwe_ids
    assert "aegis_test_index" in es.test
    assert "painless" in es.test.lower()


def test_arangodb_port_seeds_root_empty_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="http://db.example.com:8529",
            pages_visited=["http://db.example.com:8529/_db/_system/_admin/aardvark/"],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "arangodb_root_empty" in ids
    assert "CWE-1393" in next(m for m in methods if m.id == "arangodb_root_empty").cwe_ids


def test_wiki_signup_seeds_open_registration_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://wiki.example.com",
            pages_visited=[
                "https://wiki.example.com/wiki/Main_Page",
                "https://wiki.example.com/wiki/Special:CreateAccount",
                "https://wiki.example.com/signup",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "wiki_open_self_registration" in ids


def test_exe_download_seeds_binary_hardcoded_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://dl.example.com",
            pages_visited=["https://dl.example.com/firmware/setup.exe"],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "binary_hardcoded_credentials" in ids


def test_azure_function_host_seeds_anonymous_env_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ra-teamplanner-fa.azurewebsites.net",
            pages_visited=[
                "https://ra-teamplanner-fa.azurewebsites.net/api/Tester",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "azure_function_anonymous_env" in ids
    az = next(m for m in methods if m.id == "azure_function_anonymous_env")
    assert "CWE-526" in az.cwe_ids
    assert "Tester" in az.test or "authLevel" in az.assumption
    assert "azure_function_env_dump" in az.test
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "azure_function" in hunts


def test_acr_host_seeds_anonymous_pull_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://digipdevelopment.azurecr.io",
            pages_visited=[
                "https://digipdevelopment.azurecr.io/v2/",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "acr_anonymous_pull" in ids
    acr = next(m for m in methods if m.id == "acr_anonymous_pull")
    assert "CWE-306" in acr.cwe_ids
    assert "oauth2" in acr.test.lower() or "catalog" in acr.test.lower()
    assert "do not push" in acr.test.lower() or "do not pull the whole catalog" in acr.test.lower()
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "docker_registry" in hunts


def test_couchdb_hostname_seeds_default_admin_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://db.example.com:5984",
            pages_visited=[
                "https://db.example.com:5984/",
                "https://db.example.com:5984/_utils",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "couchdb_default_admin" in ids
    couch = next(m for m in methods if m.id == "couchdb_default_admin")
    assert "CWE-1393" in couch.cwe_ids
    assert "AuthSession" in couch.title or "authsession" in couch.test.lower() or "_config" in couch.test


def test_next_admin_js_seeds_hostname_keyed_cred_methodology():
    cmap = {
        "target": "https://sandbox-admin.example.com",
        "has_admin": True,
        "has_login_form": False,
        "pages_visited": ["https://sandbox-admin.example.com/admin"],
        "forms": [],
        "api_endpoints": [],
        "js_files": [
            "https://sandbox-admin.example.com/admin/_next/static/chunks/app.js",
        ],
        "js_endpoints": [],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "param_rich_paths": [],
        "api_samples": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "js_hostname_keyed_api_creds" in ids
    card = next(m for m in methods if m.id == "js_hostname_keyed_api_creds")
    assert "CWE-312" in card.cwe_ids
    assert "client_secret" in card.test
    assert "one" in card.test.lower()


def test_emailjs_js_surface_seeds_send_methodology():
    cmap = {
        "target": "https://app.example.com",
        "has_admin": False,
        "has_login_form": False,
        "pages_visited": ["https://app.example.com/"],
        "forms": [],
        "api_endpoints": [],
        "js_files": ["https://app.example.com/static/main.abc123.js"],
        "js_endpoints": ["https://api.emailjs.com/api/v1.0/email/send"],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "param_rich_paths": [],
        "api_samples": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "js_emailjs_client_send" in ids
    card = next(m for m in methods if m.id == "js_emailjs_client_send")
    assert "CWE-798" in card.cwe_ids
    assert "execute_interactsh" in card.test.lower()
    assert "payload_domain" in card.test.lower()
    assert "browser" in card.test.lower()


def test_js_files_seed_encryption_key_methodology():
    cmap = {
        "target": "https://estart.example.com",
        "has_admin": False,
        "has_login_form": False,
        "pages_visited": ["https://estart.example.com/"],
        "forms": [],
        "api_endpoints": [],
        "js_files": ["https://estart.example.com/main.09c599d56209cec4.js"],
        "js_endpoints": [],
        "websockets": [],
        "sse": [],
        "source_maps": [],
        "param_rich_paths": [],
        "api_samples": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "js_client_encryption_key" in ids
    card = next(m for m in methods if m.id == "js_client_encryption_key")
    assert "CWE-321" in card.cwe_ids
    assert "emailjs" in card.test.lower()


def test_enrich_cve_catalog_exposes_cwes():
    nvd = {
        "source": "nvd",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "description": "Log4Shell",
        "cwes": ["CWE-502"],
        "references": [],
    }
    with patch("app.services.vuln_intel_enrichment._fetch_nvd", return_value=nvd), \
         patch("app.services.vuln_intel_enrichment._fetch_osv", return_value=None), \
         patch("app.services.vuln_intel_enrichment._fetch_ghsa", return_value=[]), \
         patch("app.services.vuln_intel_enrichment._fetch_poc_github", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_trickest", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_github_repos", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_exploitdb", return_value={"found": False}), \
         patch("app.services.vuln_intel_enrichment._fetch_cxsecurity", return_value={"found": False}):
        out = enrich_cve_catalog("CVE-2021-44228", use_cache=False)

    assert out["cwes"] == ["CWE-502"]
    assert out["cwe_intel"]
    assert out["cwe_intel"][0]["cwe_id"] == "CWE-502"
    assert out["cwe_intel"][0]["capec"]


def test_api_schema_path_seeds_mass_assignment_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ics.example.com",
            pages_visited=[
                "https://ics.example.com/",
                "https://ics.example.com/api/schema/",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "openapi_mass_assignment" in ids
    ma = next(m for m in methods if m.id == "openapi_mass_assignment")
    assert "CWE-915" in ma.cwe_ids
    assert "CWE-639" in ma.cwe_ids
    assert "do not kill" in ma.kill_criteria.lower() or "unavailable" in ma.kill_criteria.lower()
    assert "/api/schema" in ma.test or "readOnly" in ma.test
    assert "openapi_unauth_account_lookup" in ids
    acct = next(m for m in methods if m.id == "openapi_unauth_account_lookup")
    assert acct.hunt == "unauth_account_lookup"
    assert "CWE-204" in acct.cwe_ids
    assert "do not kill" in acct.kill_criteria.lower() or "unavailable" in acct.kill_criteria.lower()
    assert "401" in acct.test and "500" in acct.test
    assert "404" in acct.test
    assert "aegis-enum-canary@example.invalid" in acct.test
    assert "critical" in acct.test.lower() or acct.priority == "critical"
    assert any(h.get("hunt") == "unauth_account_lookup" for h in cmap.ranked_hunt_queue)


def test_auth_account_path_seeds_unauth_lookup_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ics.example.com",
            pages_visited=[
                "https://ics.example.com/",
                "https://ics.example.com/api/auth/account/",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "openapi_unauth_account_lookup" in ids
    acct = next(m for m in methods if m.id == "openapi_unauth_account_lookup")
    assert "CWE-204" in acct.cwe_ids
    assert "CWE-862" in acct.cwe_ids
    assert "do not kill" in acct.kill_criteria.lower() or "unavailable" in acct.kill_criteria.lower()
    assert "do not spray" in acct.test.lower() or "one canary" in acct.test.lower()
    assert acct.hunt == "unauth_account_lookup"
    assert any(h.get("hunt") == "unauth_account_lookup" for h in cmap.ranked_hunt_queue)


def test_settings_save_path_seeds_unauth_settings_write_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://doccentrum-sensia.azurewebsites.net",
            pages_visited=[
                "https://doccentrum-sensia.azurewebsites.net/",
            ],
            forms=[],
            api_calls={
                "doccentrum-sensia.azurewebsites.net": {
                    "POST /api/Settings/SaveSettings",
                    "GET /api/Settings/GetSettings",
                    "POST /api/TaskAdmin/UpdateTask",
                }
            },
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "aspnet_unauth_settings_write" in ids
    card = next(m for m in methods if m.id == "aspnet_unauth_settings_write")
    assert card.hunt == "unauth_settings_write"
    assert "CWE-306" in card.cwe_ids
    assert "CWE-862" in card.cwe_ids
    assert "401" in card.test and "200" in card.test
    assert "canary" in card.test.lower()
    assert "do not kill" in card.kill_criteria.lower() or "GetSettings" in card.kill_criteria
    assert any(h.get("hunt") == "unauth_settings_write" for h in cmap.ranked_hunt_queue)


def test_azure_function_tester_does_not_require_settings_write_card():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ra-teamplanner-fa.azurewebsites.net",
            pages_visited=[
                "https://ra-teamplanner-fa.azurewebsites.net/api/Tester",
            ],
            forms=[],
            api_calls={
                "ra-teamplanner-fa.azurewebsites.net": {"GET /api/Tester"},
            },
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "azure_function_anonymous_env" in ids
    assert "aspnet_unauth_settings_write" not in ids


def test_keycloak_hostname_seeds_cors_web_origins_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://idp.example.com:8880",
            pages_visited=[
                "https://idp.example.com:8880/",
                "https://idp.example.com:8880/auth/realms/Security/.well-known/openid-configuration",
            ],
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "keycloak_cors_web_origins" in ids
    assert "cors_acao_credentials" in ids
    assert "keycloak_admin_cli_password_grant" in ids
    grant = next(m for m in methods if m.id == "keycloak_admin_cli_password_grant")
    assert "CWE-307" in grant.cwe_ids
    assert "admin-cli" in grant.test.lower() or "admin-cli" in grant.assumption.lower()
    assert "do not kill" in grant.kill_criteria.lower() or "guessed" in grant.kill_criteria.lower()
    assert "8" in grant.test or "hydra" in grant.test.lower()
    kc = next(m for m in methods if m.id == "keycloak_cors_web_origins")
    assert "CWE-942" in kc.cwe_ids
    assert "weborigins" in kc.test.lower() or "webOrigins" in kc.test
    assert "victim" in kc.kill_criteria.lower() or "jwks" in kc.kill_criteria.lower()
    cors = next(m for m in methods if m.id == "cors_acao_credentials")
    assert "credentials" in cors.pass_criteria.lower()
    assert "victim" in cors.kill_criteria.lower() or "session" in cors.kill_criteria.lower()


def test_reset_email_path_seeds_email_change_ato_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://guardianaicoe.azurewebsites.net",
            pages_visited=["https://guardianaicoe.azurewebsites.net/api/schema/"],
            forms=[],
            api_calls={
                "guardianaicoe.azurewebsites.net": {
                    "POST /api/auth/users/reset_email/",
                    "POST /api/auth/users/reset_email_confirm/",
                    "POST /api/auth/users/set_password/",
                }
            },
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "email_change_ato" in ids
    card = next(m for m in methods if m.id == "email_change_ato")
    assert card.hunt == "email_change_ato"
    assert "CWE-306" in card.cwe_ids
    assert "CWE-640" in card.cwe_ids
    assert "set_password" in card.test
    assert "canary" in card.test.lower()
    assert "do not" in card.test.lower()
    assert any(h.get("hunt") == "email_change_ato" for h in cmap.ranked_hunt_queue)


def test_jwt_api_seeds_auth_header_bypass_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://ofmdockerapi.azurewebsites.net",
            pages_visited=["https://ofmdockerapi.azurewebsites.net/"],
            forms=[],
            api_calls={
                "ofmdockerapi.azurewebsites.net": {
                    "GET /GetMenu",
                    "POST /GetEntitiesById",
                    "POST /Notes",
                }
            },
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "auth_header_bypass" in ids
    card = next(m for m in methods if m.id == "auth_header_bypass")
    assert card.hunt == "auth_header_bypass"
    assert "CWE-287" in card.cwe_ids
    assert "aegis-invalid" in card.test
    assert "400" in card.kill_criteria or "400" in card.test
    assert any(h.get("hunt") == "auth_header_bypass" for h in cmap.ranked_hunt_queue)


def test_socketio_path_seeds_stream_idor_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://vstream.glensserver.com",
            pages_visited=["https://vstream.glensserver.com/"],
            forms=[],
            api_calls={},
            websockets={"wss://vstream.glensserver.com/socket.io/?EIO=3&transport=websocket"},
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "socketio_unauth_stream_idor" in ids
    card = next(m for m in methods if m.id == "socketio_unauth_stream_idor")
    assert card.hunt == "socketio_idor"
    assert "CWE-639" in card.cwe_ids
    assert "url_key" in card.test.lower() or "get_stream" in card.test
    assert "null" in card.test.lower()
    assert any(h.get("hunt") == "socketio_idor" for h in cmap.ranked_hunt_queue)


def test_ml_train_path_seeds_rbac_methodology():
    cmap = build_capability_map_from_crawl(
        _fake_crawl(
            target="https://webapp-djangotwin.azurewebsites.net",
            pages_visited=["https://webapp-djangotwin.azurewebsites.net/"],
            forms=[],
            api_calls={
                "webapp-djangotwin.azurewebsites.net": {
                    "POST /api/v1/train/",
                    "DELETE /api/v1/celery-task/",
                    "POST /api/token-pair/",
                }
            },
        )
    )
    methods = methodologies_from_capability_map(cmap.to_dict())
    ids = {m.id for m in methods}
    assert "ml_pipeline_missing_rbac" in ids
    card = next(m for m in methods if m.id == "ml_pipeline_missing_rbac")
    assert card.hunt == "ml_pipeline_rbac"
    assert "CWE-285" in card.cwe_ids
    assert "do not delete" in card.test.lower()
    assert any(h.get("hunt") == "ml_pipeline_rbac" for h in cmap.ranked_hunt_queue)


def test_login_form_seeds_injection_without_query_params():
    """Login POST body is an injection surface even with an empty param map."""
    cmap = {
        "target": "https://bank.example.com",
        "has_login_form": True,
        "has_auth": True,
        "pages_visited": ["https://bank.example.com/login"],
        "forms": [
            {
                "method": "POST",
                "action": "/login",
                "inputs": ["username", "password"],
                "page": "https://bank.example.com/login",
            }
        ],
        "param_rich_paths": [],
        "api_endpoints": [],
        "js_files": [],
        "api_samples": [],
    }
    methods = methodologies_from_capability_map(cmap)
    ids = {m.id for m in methods}
    assert "login_injection" in ids
    assert "param_injection" not in ids
    card = next(m for m in methods if m.id == "login_injection")
    assert card.specialist == "sqli"
    assert card.hunt == "sqli"
    assert "compare_requests" in card.test
    assert "time" in card.test.lower()
    assert "CWE-89" in card.cwe_ids


def test_json_login_api_seeds_login_injection():
    cmap = {
        "target": "https://app.example.com",
        "has_login_form": False,
        "has_auth": False,
        "pages_visited": ["https://app.example.com/"],
        "forms": [],
        "param_rich_paths": [],
        "api_endpoints": [
            {"method": "POST", "path": "/api/auth/login", "host": "app.example.com"},
        ],
        "js_files": [],
        "api_samples": [],
    }
    ids = {m.id for m in methodologies_from_capability_map(cmap)}
    assert "login_injection" in ids


def test_appsmith_skips_login_field_injection():
    cmap = {
        "target": "https://appsmith.example.com",
        "has_login_form": True,
        "has_auth": True,
        "pages_visited": ["https://appsmith.example.com/user/login"],
        "forms": [
            {
                "method": "POST",
                "action": "/user/login",
                "inputs": ["email", "password"],
            }
        ],
        "param_rich_paths": [],
        "api_endpoints": [],
        "js_files": [],
        "api_samples": [],
    }
    ids = {m.id for m in methodologies_from_capability_map(cmap)}
    assert "login_injection" not in ids
