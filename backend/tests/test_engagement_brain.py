"""Tests for tester-process engagement brain + hypothesis chaining."""

from app.services.agent.capability_map import build_capability_map_from_crawl
from app.services.agent.engagement_brain import (
    classify_finding_type,
    engagement_brain_from_dict,
    format_engagement_brain_for_prompt,
    queue_followups_for_finding,
    seed_hypotheses_from_capability_map,
    specialists_from_open_hypotheses,
    update_hypothesis,
    add_credential,
)
from types import SimpleNamespace


def _fake_crawl(**overrides):
    base = dict(
        target="https://tenant-a.app.example.com",
        scope="example.com",
        authenticated=True,
        pages_visited=[
            "https://tenant-a.app.example.com/",
            "https://tenant-a.app.example.com/login",
            "https://tenant-b.app.example.com/",
            "https://tenant-a.app.example.com/admin",
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
                "action": "/checkout",
                "inputs": ["quantity", "price"],
                "page": "https://tenant-a.app.example.com/checkout",
            },
        ],
        api_calls={
            "tenant-a.app.example.com": {
                "GET /api/users?id=1",
                "GET /api/orders/100",
            },
            "tenant-b.app.example.com": {
                "GET /api/users?id=2",
            },
        },
        js_files={"https://tenant-a.app.example.com/static/app.js"},
        endpoints_from_js={"/api/v1/items"},
        websockets=set(),
        sse=set(),
        source_maps=set(),
        third_party=set(),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_seed_hypotheses_includes_host_tenant_and_business_logic():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    hunts = {h.specialist for h in brain.hypotheses}
    titles = " ".join(h.title.lower() for h in brain.hypotheses)
    assert "host_tenant" in hunts
    assert "business_logic" in hunts or "business" in titles
    assert "api_authz" in hunts or "auth_logic" in hunts
    assert any(h.specialist == "coverage" for h in brain.hypotheses)
    assert brain.phase in ("map", "attack")
    assert "authenticated" in brain.identities


def test_specialists_from_open_hypotheses_priority():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    names = specialists_from_open_hypotheses(brain, max_specialists=6)
    assert names[0] == "app_mapper"
    assert "finding_judge" not in names
    assert "independent_verifier" not in names
    assert len(names) <= 6
    # Should prefer attack specialists over empty
    assert any(n in names for n in ("host_tenant", "api_authz", "auth_logic", "injection", "js_secrets"))


def test_default_login_queues_grafana_chain_and_credential():
    brain = engagement_brain_from_dict(None)
    brain.target = "https://grafana.qa.example.com"
    created = queue_followups_for_finding(
        brain,
        vuln_type="default_login",
        title="Grafana Default Login admin:prom-operator",
        target="https://grafana.qa.example.com",
        evidence="grafana_session cookie; Logged in",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert any("9264" in h.title or "Authenticated CVE" in h.title for h in created)
    assert any("ssrf" in h.title.lower() and "aks" in h.title.lower() for h in created)
    assert any("datasource" in h.test.lower() for h in created)
    assert "admin/settings" in tests or "serviceaccounts" in tests
    assert "grafana-admin-apis" in {h.title for h in created} or "service accounts" in titles
    assert "prometheus" in tests and "existing" in tests
    g9264 = next(h for h in created if "9264" in h.title)
    assert "duckdb absent" not in g9264.kill_criteria.lower()
    assert "no such file" in g9264.pass_criteria.lower() or "fork" in g9264.pass_criteria.lower()
    assert "viewer" in g9264.assumption.lower() or "viewer" in g9264.test.lower()
    assert "sqlexpressions" in g9264.test.lower() or "toggle" in g9264.test.lower()
    assert "do not kill" in g9264.kill_criteria.lower() or "absent" in g9264.kill_criteria.lower()
    assert not any("authsession" in h.title.lower() for h in created)
    assert not any("couch_httpd" in h.test.lower() for h in created)
    assert brain.credentials
    assert brain.credentials[0].username == "admin"
    assert brain.credentials[0].secret == "prom-operator"
    assert "authenticated" in brain.identities


def test_grafana_ssrf_aks_card_skipped_for_non_grafana():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="default_login",
        title="Jenkins default credentials admin:admin",
        target="https://jenkins.example.com",
        evidence="dashboard",
    )
    assert created  # generic auth-cve / admin-ssrf may still queue
    assert not any("aks" in h.title.lower() for h in created)
    assert not any("9264" in h.title for h in created)
    assert not any("service account" in h.title.lower() for h in created)
    assert not any("prometheus" in h.title.lower() for h in created)
    assert not any("authsession" in h.title.lower() for h in created)
    assert not any("_config" in h.title.lower() for h in created)


def test_default_login_queues_couchdb_authsession_chain_and_kevin_cred():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="default_login",
        title="CouchDB default login kevin:kevin",
        target="https://estart.example.com:3443",
        evidence='{"couchdb":"Welcome","version":"2.1.1"} GET /_session _admin',
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "couch_httpd_auth" in tests
    assert "authsession" in tests or "forgery" in titles
    assert "/_node/_local/_config" in tests
    assert "derived_key" in tests  # tell the agent NOT to use it
    assert "secret" in tests and "salt" in tests
    assert any("_all_dbs" in h.test.lower() for h in created)
    assert not any("prometheus" in h.title.lower() for h in created)
    assert not any("aks" in h.title.lower() for h in created)
    assert brain.credentials
    assert brain.credentials[0].username.lower() == "kevin"
    assert brain.credentials[0].secret == "kevin"


def test_classify_finding_type_couchdb_cookie_forgery():
    assert classify_finding_type(title="CouchDB AuthSession cookie forgery") == "default_login"
    assert classify_finding_type(title="couch_httpd_auth secret exposed") == "default_login"


def test_host_header_queues_tenant_bypass_card():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="host_header",
        title="Host header reflection",
        target="https://tenant-a.example.com",
    )
    assert any(h.specialist == "host_tenant" for h in created)
    assert any("tenant" in h.title.lower() for h in created)


def test_update_hypothesis_and_prompt_format():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    brain = seed_hypotheses_from_capability_map(
        engagement_brain_from_dict(None), cmap.to_dict()
    )
    hyp = brain.hypotheses[0]
    updated = update_hypothesis(
        brain, hyp.id, status="proven", evidence="compare_requests LIKELY_IMPACT"
    )
    assert updated is not None
    assert updated.status == "proven"
    text = format_engagement_brain_for_prompt(brain.to_dict())
    assert "Hypotheses:" in text
    assert "Proven:" in text
    assert "compare_requests" in text
    assert "/api/auth/account" in text or "401" in text
    assert "down database is not a kill" in text.lower() or "500/app error vs sibling 401" in text.lower()


def test_classify_finding_type():
    assert classify_finding_type(title="Grafana Default Login") == "default_login"
    assert classify_finding_type(title="Weak credential (CWE-1393)") == "default_login"
    assert classify_finding_type(title="Host Header Injection") == "host_header"
    assert classify_finding_type(title="IDOR on /api/orders") == "idor"
    assert classify_finding_type(title="Random info") == "unknown"
    assert classify_finding_type(title="Hardcoded API credentials in JS bundle") == "js_secrets"
    assert classify_finding_type(title="client_secret in _next/static chunk") == "js_secrets"
    assert classify_finding_type(title="Hardcoded EmailJS service credentials") == "js_secrets"
    assert classify_finding_type(title="Unauthenticated Elasticsearch on :9200") == "elasticsearch_unauth"
    assert classify_finding_type(title="xpack.security disabled") == "elasticsearch_unauth"
    assert classify_finding_type(title="ArangoDB Default Root Credentials") == "arangodb_default"
    assert classify_finding_type(title="MongoDB - Anonymous Login Enabled") == "mongodb_unauth"
    assert classify_finding_type(title="Unauthenticated Auth0 Management API Token") == "auth0_mgmt_token"
    assert classify_finding_type(title="CORS Origin Reflection with Credentials") == "cors_credentials"
    assert classify_finding_type(
        title="Keycloak webOrigins wildcard on token endpoint"
    ) == "cors_credentials"
    assert classify_finding_type(
        title="Keycloak admin-cli public client password grant with no lockout"
    ) == "keycloak_password_grant"
    assert classify_finding_type(title="User-Supplied Admin Role in Public Portal") == "client_role_param"
    assert classify_finding_type(title="vendorJson API") == "vendorjson_unauth"
    assert classify_finding_type(title="Open Self-Registration Grants Wiki Write Access") == "wiki_open_reg"
    assert classify_finding_type(
        title="Hardcoded Production Credentials In A Publicly-downloadable Binary"
    ) == "binary_hardcoded_creds"
    assert classify_finding_type(
        title="Client-Side Only Authentication on Pharmaceutical eLogbook Admin Dashboard"
    ) == "client_side_auth"
    assert classify_finding_type(
        title="Additional Trivial Admin Credential (karen:karen) on Production CouchDB"
    ) == "default_login"
    assert classify_finding_type(title="EMQX Dashboard - Default Login Credentials") == "emqx_default"
    assert classify_finding_type(title="Exposed Docker Registry") == "docker_registry"
    assert classify_finding_type(title="Unauthenticated GitLab API") == "gitlab_unauth"
    assert classify_finding_type(
        title="DRF mass assignment — writable id on GroupRequest"
    ) == "mass_assignment"
    assert classify_finding_type(
        title="Broken object property-level authorization in /api/schema/"
    ) == "mass_assignment"
    assert classify_finding_type(
        title="Unauthenticated /api/auth/account/ lookup discloses role"
    ) == "unauth_account_lookup"
    assert classify_finding_type(
        title="Public user account statistics without authentication",
        description="OpenAPI security: {} returns is_staff and role for an email",
    ) == "unauth_account_lookup"


def test_guard_catalog_queues_arangodb_and_auth0():
    brain = engagement_brain_from_dict(None)
    arango = queue_followups_for_finding(
        brain,
        vuln_type="arangodb_default",
        title="ArangoDB Default Root Credentials With Empty Password",
        target="http://es.example.com:8529",
    )
    assert arango
    assert any("/_open/auth" in h.test or "root" in h.test.lower() for h in arango)
    auth0 = queue_followups_for_finding(
        engagement_brain_from_dict(None),
        vuln_type="auth0_mgmt_token",
        title="Unauthenticated Auth0 Management API Token Exposure",
        target="https://lwa-example.azurewebsites.net/",
        evidence="identitymigrate/api/token",
    )
    assert auth0
    assert any("per_page=1" in h.test for h in auth0)


def test_couchdb_default_login_queues_sibling_trivial_admins():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="default_login",
        title="CouchDB Admin Access via Weak Credentials (kevin:kevin)",
        target="https://estart.example.com:3443",
        evidence="kevin:kevin _admin",
    )
    tests = " ".join(h.test.lower() for h in created)
    titles = " ".join(h.title.lower() for h in created)
    assert "karen" in tests or "username=username" in tests or "sibling" in titles


def test_wiki_and_binary_queue_followups():
    wiki = queue_followups_for_finding(
        engagement_brain_from_dict(None),
        vuln_type="wiki_open_reg",
        title="Open Self-Registration Grants Wiki Write Access to Anonymous Users",
        target="https://wiki.example.com",
    )
    assert wiki
    assert any("sandbox" in h.test.lower() or "throwaway" in h.test.lower() for h in wiki)
    binary = queue_followups_for_finding(
        engagement_brain_from_dict(None),
        vuln_type="binary_hardcoded_creds",
        title="Hardcoded Production Credentials In A Publicly-downloadable Binary",
        target="https://dl.example.com/setup.exe",
    )
    assert binary
    assert any("strings" in h.test.lower() for h in binary)
    assert classify_finding_type(
        title="Anonymous Azure Function Tester env dump"
    ) == "azure_function_env_dump"
    assert classify_finding_type(
        title="authLevel anonymous on ra-teamplanner-fa.azurewebsites.net"
    ) == "azure_function_env_dump"


def test_azure_function_env_dump_queues_secret_chain():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="azure_function_env_dump",
        title="Anonymous Tester function dumps runtime env",
        target="https://ra-teamplanner-fa.azurewebsites.net/api/Tester",
        evidence="GET returned AzureWebJobsStorage, Cosmos key names, MACHINEKEY",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "cosmos" in titles
    assert "storage" in titles
    assert "-dev-" in tests or "peer" in titles
    assert "not_demonstrated" in tests or "do not" in tests
    assert "inject" in tests
    assert any("classify" in h.title.lower() or "secret" in h.title.lower() for h in created)
    other = queue_followups_for_finding(
        brain,
        vuln_type="idor",
        title="IDOR on /api/users",
        target="https://app.example.com",
    )
    assert not any("cosmos" in h.title.lower() for h in other)
    assert not any("function app" in h.title.lower() for h in other)


def test_elasticsearch_unauth_queues_read_write_chain():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="elasticsearch_unauth",
        title="Unauthenticated Elasticsearch 7.16.3",
        target="http://es.example.com:9200",
        evidence="GET / returned cluster_name without credentials",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "indices" in titles or "_cat/indices" in tests
    assert "aegis_test_index" in tests
    assert "painless" in tests
    assert any("write" in h.title.lower() or "test index" in h.title.lower() for h in created)
    # Product-specific ES cards should not leak onto unrelated findings
    other = queue_followups_for_finding(
        brain,
        vuln_type="idor",
        title="IDOR on /api/users",
        target="https://app.example.com",
    )
    assert not any("elasticsearch" in h.title.lower() for h in other)


def test_js_secrets_queues_live_api_and_stashes_oauth_client():
    brain = engagement_brain_from_dict(None)
    cid = "a" * 32
    secret = "b" * 32
    created = queue_followups_for_finding(
        brain,
        vuln_type="js_secrets",
        title="Hardcoded API credentials in Next.js chunk",
        target="https://sandbox-admin.example.com",
        evidence=f"client_id: {cid} / client_secret: {secret}",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "hostname-keyed" in titles or "client_id" in titles
    assert "live api" in titles
    assert "cross-environment" in titles or "sandbox" in titles
    assert "one read-only" in tests or "do not paginate" in tests
    assert brain.credentials
    assert brain.credentials[0].secret_type == "oauth_client"
    assert brain.credentials[0].username == cid
    assert brain.credentials[0].secret == secret


def test_emailjs_finding_queues_browser_canary_and_stashes_keys():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="emailjs",
        title="Hardcoded EmailJS service credentials in production JS",
        target="https://app.example.com",
        evidence=(
            "emailjs_serviceid: service_exampletest "
            "emailjs_userid: AbcdefghijkLMNOP "
            "emailjs_templateid: template_exampleone"
        ),
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    assert "emailjs" in titles
    assert "canary" in tests or "interactsh" in tests
    assert "never" in tests and ("employee" in tests or "arbitrary" in tests)
    assert "execute_browser" in tests or "browser" in tests
    # OAuth hostname-map cards may also queue; EmailJS cards must be present
    assert any("emailjs-keys" in (h.title.lower() + h.test.lower()) or "service_id" in h.test.lower() for h in created)
    assert brain.credentials
    rec = next(c for c in brain.credentials if c.secret_type == "emailjs")
    assert rec.username == "service_exampletest"
    assert rec.secret == "AbcdefghijkLMNOP"


def test_oauth_js_secrets_skips_emailjs_cards():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="js_secrets",
        title="Hardcoded API credentials in Next.js chunk",
        target="https://sandbox-admin.example.com",
        evidence="client_id: " + ("a" * 32) + " / client_secret: " + ("b" * 32),
    )
    assert not any("emailjs" in h.title.lower() for h in created)


def test_add_credential_dedupes():
    brain = engagement_brain_from_dict(None)
    add_credential(brain, username="admin", secret="x", valid_on=["a"])
    add_credential(brain, username="admin", secret="x", valid_on=["b"])
    assert len(brain.credentials) == 1
    assert set(brain.credentials[0].valid_on) == {"a", "b"}


def test_capability_map_hunt_queue_has_host_tenant():
    cmap = build_capability_map_from_crawl(_fake_crawl())
    hunts = [h["hunt"] for h in cmap.ranked_hunt_queue]
    assert "host_tenant" in hunts
    assert "coverage" in hunts


def test_mass_assignment_queues_schema_cards_and_does_not_kill_on_db_down():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="mass_assignment",
        title="Systemic mass assignment in DRF request serializers",
        target="https://ics.example.com",
        evidence="GET /api/schema/ GroupRequest writable id, created, user",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    kills = " ".join(h.kill_criteria.lower() for h in created)
    assert "readonly" in titles or "writable" in titles
    assert "/api/schema" in tests or "serializer" in tests
    assert "do not kill" in kills or "unavailable" in kills
    assert "all users" in titles or "shared" in titles
    # Azure Function cards must not enqueue just because a host could be azurewebsites
    assert not any("cosmos" in h.title.lower() for h in created)
    assert not any("tester" in h.title.lower() for h in created)


def test_cors_queues_acao_and_keycloak_idp_cards():
    brain = engagement_brain_from_dict(None)
    generic = queue_followups_for_finding(
        brain,
        vuln_type="cors_credentials",
        title="CORS Origin Reflection with Credentials",
        target="https://app.example.com",
        evidence="ACAO echoes Origin; credentials true",
    )
    assert generic
    titles = " ".join(h.title.lower() for h in generic)
    tests = " ".join(h.test.lower() for h in generic)
    kills = " ".join(h.kill_criteria.lower() for h in generic)
    assert "acao" in titles or "credentials" in titles
    assert "canary" in tests or "origin" in tests
    assert "html exploit" in tests or "victim" in kills
    assert not any("keycloak" in h.title.lower() for h in generic)
    assert not any("get_stream" in h.title.lower() or "socket" in h.title.lower() for h in generic)

    kc = queue_followups_for_finding(
        brain,
        vuln_type="cors_credentials",
        title="Keycloak CORS webOrigins=* on Security realm",
        target="https://idp.example.com:8880",
        evidence="openid-connect/token ACAO reflect + credentials; /auth/admin/realms",
    )
    assert any("keycloak" in h.title.lower() or "userinfo" in h.test.lower() for h in kc)
    assert any("admin-cli" in h.title.lower() or "password grant" in h.title.lower() for h in kc)
    kc_kills = " ".join(h.kill_criteria.lower() for h in kc)
    assert "weborigins" in kc_kills or "victim" in kc_kills or "jwks" in kc_kills
    assert "do not dump" in " ".join(h.test.lower() for h in kc) or "max=1" in " ".join(h.test.lower() for h in kc)


def test_keycloak_password_grant_queues_lockout_probe_not_hydra():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="keycloak_password_grant",
        title="admin-cli public password grant with no brute-force detection",
        target="https://idp.example.com:8880",
        evidence="POST token invalid_grant without client_secret on master",
    )
    assert created
    tests = " ".join(h.test.lower() for h in created)
    kills = " ".join(h.kill_criteria.lower() for h in created)
    titles = " ".join(h.title.lower() for h in created)
    assert "admin-cli" in titles or "password" in titles
    assert "invalid_grant" in tests or "client_secret" in tests
    assert "8" in tests or "lockout" in titles
    assert "do not kill" in kills or "not guessed" in kills or "password was wrong" in kills
    assert "rockyou" in tests or "do not hydra" in tests or "no hydra" in tests
    assert not any("cosmos" in h.title.lower() for h in created)


def test_unauth_account_lookup_queues_401_vs_500_and_does_not_spray():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="unauth_account_lookup",
        title="Unauthenticated account lookup discloses is_staff and role",
        target="https://ics.example.com",
        evidence="GET /api/auth/account/?email= canary; siblings 401; lookup 500",
    )
    assert created
    titles = " ".join(h.title.lower() for h in created)
    tests = " ".join(h.test.lower() for h in created)
    kills = " ".join(h.kill_criteria.lower() for h in created)
    assumptions = " ".join(h.assumption.lower() for h in created)
    blob = f"{titles} {tests} {kills} {assumptions}"
    assert "security" in blob or "is_staff" in blob or "role" in blob
    assert "401" in blob and "500" in blob
    assert "do not kill" in kills or "unavailable" in kills
    assert "canary" in tests
    assert "do not spray" in tests or "do not enumerate" in tests
    assert "aegis-enum-canary@example.invalid" in tests
    assert not any("hydra" in h.test.lower() for h in created)
    assert not any("cosmos" in h.title.lower() for h in created)
    assert not any("grafana" in h.title.lower() for h in created)


def test_mass_assignment_also_queues_unauth_account_lookup_followup():
    brain = engagement_brain_from_dict(None)
    created = queue_followups_for_finding(
        brain,
        vuln_type="mass_assignment",
        title="Systemic mass assignment in DRF request serializers",
        target="https://ics.example.com",
        evidence="GET /api/schema/ GroupRequest writable id, created, user",
    )
    tests = " ".join(h.test.lower() for h in created)
    titles = " ".join(h.title.lower() for h in created)
    assert "account" in titles or "email" in tests
    assert "401" in tests or "aegis-enum-canary@example.invalid" in tests
    assert "unauth_account_lookup" in tests