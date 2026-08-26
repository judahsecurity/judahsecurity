"""Unit tests for KEV feed helpers (no live network)."""

import io
import json
import zipfile

from app.api.routes.threat_intel import _euvd_cve_ids
from app.services.vuln_intel_feeds import (
    _map_vulncheck_row,
    _vulncheck_bootstrap_backup,
    _vulncheck_incremental,
    _vulncheck_next_cursor,
    _vulncheck_rows_from_backup_payload,
    fetch_vulncheck_kev,
)


def test_vulncheck_next_cursor_prefers_meta():
    payload = {"_meta": {"next_cursor": "abc123"}, "data": []}
    assert _vulncheck_next_cursor(payload) == "abc123"


def test_vulncheck_next_cursor_empty():
    assert _vulncheck_next_cursor({"_meta": {}, "data": []}) is None
    assert _vulncheck_next_cursor({"_meta": {"next_cursor": ""}, "data": []}) is None


def test_euvd_cve_ids_from_aliases():
    item = {
        "id": "EUVD-2024-1",
        "aliases": ["CVE-2024-1234", "GHSA-xxxx"],
        "description": "test",
    }
    assert _euvd_cve_ids(item) == ["CVE-2024-1234"]


def test_euvd_cve_ids_from_id_field():
    assert _euvd_cve_ids({"id": "CVE-2021-44228"}) == ["CVE-2021-44228"]


def test_map_vulncheck_row_community_schema():
    cve, rec = _map_vulncheck_row({
        "cve": ["CVE-2024-4577"],
        "vendorProject": "PHP Group",
        "product": "PHP",
        "vulnerabilityName": "PHP-CGI OS Command Injection",
        "shortDescription": "CGI argument injection",
        "knownRansomwareCampaignUse": "Known",
        "date_added": "2024-06-07T00:00:00Z",
    })
    assert cve == "CVE-2024-4577"
    assert rec["known_ransomware_use"] == "Known"
    assert rec["vendor_project"] == "PHP Group"


def test_backup_payload_accepts_vulnerabilities_key():
    rows = _vulncheck_rows_from_backup_payload({
        "vulnerabilities": [{"cve": ["CVE-2024-1"]}],
    })
    assert rows[0]["cve"] == ["CVE-2024-1"]


def test_incremental_stops_when_page_already_cached(monkeypatch):
    cached = {
        "CVE-2024-1": {"cve_id": "CVE-2024-1", "date_added": "2024-01-01"},
        "CVE-2024-2": {"cve_id": "CVE-2024-2", "date_added": "2024-01-02"},
    }
    calls = {"n": 0}

    def _page(_headers, *, cursor, page_limit, timeout):
        calls["n"] += 1
        return {
            "_meta": {"next_cursor": "page2"},
            "data": [
                {"cve": ["CVE-2024-2"], "date_added": "2024-01-02"},
                {"cve": ["CVE-2024-1"], "date_added": "2024-01-01"},
            ],
        }

    monkeypatch.setattr("app.services.vuln_intel_feeds._vulncheck_index_page", _page)
    mapped, added = _vulncheck_incremental({}, cached, max_pages=5, page_limit=100, timeout=5)
    assert added == 0
    assert calls["n"] == 1
    assert set(mapped) == {"CVE-2024-1", "CVE-2024-2"}


def test_incremental_merges_new_then_stops(monkeypatch):
    cached = {"CVE-2024-1": {"cve_id": "CVE-2024-1"}}
    pages = [
        {
            "_meta": {"next_cursor": "p2"},
            "data": [
                {"cve": ["CVE-2026-9"], "date_added": "2026-08-01", "vendorProject": "New"},
                {"cve": ["CVE-2024-1"], "date_added": "2024-01-01"},
            ],
        },
        {
            "_meta": {},
            "data": [
                {"cve": ["CVE-2024-1"], "date_added": "2024-01-01"},
            ],
        },
    ]

    def _page(_headers, *, cursor, page_limit, timeout):
        return pages.pop(0)

    monkeypatch.setattr("app.services.vuln_intel_feeds._vulncheck_index_page", _page)
    mapped, added = _vulncheck_incremental({}, cached, max_pages=5, page_limit=100, timeout=5)
    assert added == 1
    assert "CVE-2026-9" in mapped
    assert pages == []  # second page fetched, then stop


def test_bootstrap_backup_reads_zip(monkeypatch):
    inner = json.dumps({
        "vulnerabilities": [
            {"cve": ["CVE-2024-4577"], "vendorProject": "PHP Group", "date_added": "2024-06-07T00:00:00Z"},
        ]
    }).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("vulncheck_known_exploited_vulnerabilities.json", inner)
    zipped = buf.getvalue()

    monkeypatch.setattr(
        "app.services.vuln_intel_feeds._http_get_json",
        lambda *_a, **_k: {"data": [{"url": "https://example.invalid/kev.zip"}]},
    )
    monkeypatch.setattr(
        "app.services.vuln_intel_feeds._http_get_bytes",
        lambda *_a, **_k: zipped,
    )
    mapped = _vulncheck_bootstrap_backup({"Authorization": "Bearer x"}, timeout=5)
    assert "CVE-2024-4577" in mapped
    assert mapped["CVE-2024-4577"]["vendor_project"] == "PHP Group"


def test_fetch_warm_cache_does_not_rebootstrap(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    cache_path = tmp_path / "vulncheck_kev.json"
    cache_path.write_text(json.dumps({
        "entries": {"CVE-2024-1": {"cve_id": "CVE-2024-1", "date_added": "2024-01-01"}},
        "count": 1,
        "mode": "backup",
    }))

    def _boom(*_a, **_k):
        raise AssertionError("warm cache must not hit the backup endpoint")

    monkeypatch.setattr("app.services.vuln_intel_feeds._vulncheck_bootstrap_backup", _boom)

    def _page(_headers, *, cursor, page_limit, timeout):
        return {"data": [{"cve": ["CVE-2024-1"], "date_added": "2024-01-01"}], "_meta": {}}

    monkeypatch.setattr("app.services.vuln_intel_feeds._vulncheck_index_page", _page)
    mapped = fetch_vulncheck_kev("token")
    assert "CVE-2024-1" in mapped


def test_vulncheck_cache_only_skips_network(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))

    def _fail(*_args, **_kwargs):
        raise AssertionError("cache_only must not hit the network")

    monkeypatch.setattr("app.services.vuln_intel_feeds._http_get_json", _fail)
    assert fetch_vulncheck_kev("token", cache_only=True) == {}
