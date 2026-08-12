"""Unit tests for KEV feed helpers (no live network)."""

from app.services.vuln_intel_feeds import _vulncheck_next_cursor
from app.api.routes.threat_intel import _euvd_cve_ids


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
