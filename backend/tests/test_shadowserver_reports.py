import hashlib
import hmac
import json
import urllib.error
from pathlib import Path

from app.services import shadowserver_reports as reports
from app.models.api_config import APIConfig


def test_signing_matches_exact_body_and_never_serializes_secret():
    body, headers = reports.build_signed_request("public-key", "super-secret", {"limit": 10})
    assert json.loads(body) == {"apikey": "public-key", "limit": 10}
    assert b"super-secret" not in body
    assert headers["HMAC2"] == hmac.new(b"super-secret", body, hashlib.sha256).hexdigest()


def test_shadowserver_secret_uses_existing_encrypted_storage(monkeypatch):
    monkeypatch.setenv("API_KEY_ENCRYPTION_KEY", "unit-test-encryption-key")
    config = APIConfig(organization_id=7, service_name="shadowserver")
    config.set_api_secret("super-secret")
    assert config.api_secret_encrypted != "super-secret"
    assert config.get_api_secret() == "super-secret"


def test_parser_aggregates_safe_cve_attempt_facts_and_redacts_raw_data():
    rows = [
        {"timestamp": "2026-09-12 01:00:00", "vulnerability_enum": "CVE",
         "vulnerability_id": "CVE-2026-1234", "session_tags": "pre-auth,rce",
         "target_vendor": "Vendor", "target_product": "Product",
         "src_ip": "192.0.2.1", "dst_ip": "198.51.100.2", "http_request": "GET /secret"},
        {"timestamp": "2026-09-13 01:00:00", "vulnerability_enum": "CVE",
         "vulnerability_id": "CVE-2026-1234", "session_tags": "rce"},
        {"timestamp": "2026-09-13 02:00:00", "vulnerability_enum": "URL",
         "vulnerability_id": "generic-scan", "src_ip": "203.0.113.1"},
    ]
    parsed = reports.parse_honeypot_http_rows(rows, retrieved_at="2026-09-13T03:00:00Z")
    item = parsed["CVE-2026-1234"]
    assert item["sighting_count"] == 2
    assert item["observation_days"] == 2
    assert item["successful_compromise"] is False
    assert item["telemetry_class"] == "observed_exploitation_attempt"
    rendered = json.dumps(parsed)
    assert "192.0.2.1" not in rendered
    assert "GET /secret" not in rendered
    assert "generic-scan" not in rendered


class _Config:
    is_valid = True
    last_error = None

    def increment_usage(self):
        return None


class _DB:
    def commit(self):
        return None


class _Response:
    def __init__(self, body):
        self.body = body

    def read(self, size=-1):
        return self.body if size < 0 else self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_refresh_selects_exact_report_type_and_persists_only_aggregates(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_INTEL_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(reports, "_credentials", lambda db, org: (_Config(), "key", "secret", reports.DEFAULT_API_URI))
    requests = []

    def opener(request, timeout):
        requests.append(request)
        if request.full_url.endswith("reports/list"):
            body = json.loads(request.data)
            assert body["type"] == reports.REPORT_TYPE
            assert body["limit"] == reports.MAX_REPORT_FILES
            return _Response(json.dumps([{"id": "safe-token", "type": reports.REPORT_TYPE}]).encode())
        assert request.full_url == "https://dl.shadowserver.org/safe-token"
        return _Response(
            b'timestamp,vulnerability_enum,vulnerability_id,session_tags,src_ip,http_request\n'
            b'2026-09-13 01:00:00,CVE,CVE-2026-1234,rce,192.0.2.1,GET /private\n'
        )

    result = reports.refresh_shadowserver_cache(_DB(), 11, days=2, limit=100, opener=opener)
    assert result["status"] == "ok"
    cache = reports._cache_path(11).read_text()
    assert "CVE-2026-1234" in cache
    assert "192.0.2.1" not in cache
    assert "GET /private" not in cache
    assert len(requests) == 2


def test_rate_limit_surfaces_health_without_invalidating_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_INTEL_CACHE_DIR", str(tmp_path))
    config = _Config()
    monkeypatch.setattr(reports, "_credentials", lambda db, org: (config, "key", "secret", reports.DEFAULT_API_URI))

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "rate limited", {}, None)

    result = reports.refresh_shadowserver_cache(_DB(), 11, opener=opener)
    assert result["status"] == "rate_limited"
    assert result["cached"] is False
    assert config.is_valid is True


def test_tenant_cache_isolation_and_stale_semantics(tmp_path, monkeypatch):
    monkeypatch.setenv("EXPLOIT_INTEL_CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(reports, "_credentials", lambda db, org: (_Config(), "key", "secret", reports.DEFAULT_API_URI))
    for organization_id, count in ((11, 2), (22, 7)):
        Path(reports._cache_path(organization_id)).write_text(json.dumps({
            "retrieved_at": "2026-09-13T00:00:00Z",
            "cves": {"CVE-2026-1234": {
                "cve_id": "CVE-2026-1234", "sighting_count": count,
                "telemetry_class": "observed_exploitation_attempt", "last_seen": "2026-09-13T00:00:00Z",
            }},
        }))
    assert reports.shadowserver_cve_signal(_DB(), 11, "CVE-2026-1234")["sighting_count"] == 2
    assert reports.shadowserver_cve_signal(_DB(), 22, "CVE-2026-1234")["sighting_count"] == 7
    assert reports._cache_path(11) != reports._cache_path(22)
