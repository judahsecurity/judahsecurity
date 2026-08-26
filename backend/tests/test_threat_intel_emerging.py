"""Emerging-feed helpers: never let a slow source empty the list UI."""

import asyncio
from datetime import datetime, timezone

import pytest

from app.api.routes.threat_intel import _feed_or_empty
from app.services.vuln_intel_feeds import fetch_circl_kev_by_source, fetch_vulncheck_kev


@pytest.mark.asyncio
async def test_feed_or_empty_returns_empty_on_timeout():
    async def _hang():
        await asyncio.sleep(5)
        return [{"cve_id": "CVE-2024-1"}]

    result = await _feed_or_empty("slow", _hang(), timeout=0.05)
    assert result == []


@pytest.mark.asyncio
async def test_feed_or_empty_returns_empty_on_error():
    async def _boom():
        raise RuntimeError("upstream down")

    result = await _feed_or_empty("broken", _boom(), timeout=1)
    assert result == []


@pytest.mark.asyncio
async def test_feed_or_empty_passes_through_list():
    async def _ok():
        return [{"cve_id": "CVE-2024-1"}]

    result = await _feed_or_empty("cisa", _ok(), timeout=1)
    assert result == [{"cve_id": "CVE-2024-1"}]


def test_vulncheck_cache_only_skips_network(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))

    def _fail(*_args, **_kwargs):
        raise AssertionError("cache_only must not hit the network")

    monkeypatch.setattr("app.services.vuln_intel_feeds._http_get_json", _fail)
    assert fetch_vulncheck_kev("token", cache_only=True) == {}


def test_circl_cache_only_skips_network(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))

    def _fail(*_args, **_kwargs):
        raise AssertionError("cache_only must not hit the network")

    monkeypatch.setattr("app.services.vuln_intel_feeds._http_get_json", _fail)
    assert fetch_circl_kev_by_source("shadowserver", cache_only=True) == {}


def test_euvd_default_is_not_paginated():
    import inspect
    from app.api.routes.threat_intel import _fetch_euvd

    params = inspect.signature(_fetch_euvd).parameters
    assert params["paginated"].default is False


def test_cutoff_epoch_is_timezone_aware():
    cutoff = datetime.min.replace(tzinfo=timezone.utc)
    assert cutoff.tzinfo is not None


def test_list_path_vulncheck_is_cache_only():
    import inspect
    from app.api.routes.threat_intel import _fetch_vulncheck_kev

    source = inspect.getsource(_fetch_vulncheck_kev)
    assert "cache_only=True" in source
    assert "cache_only=not bool(token)" not in source


@pytest.mark.asyncio
async def test_cisa_list_path_uses_cache_not_http(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    from app.services.vuln_intel_feeds import write_json_cache
    from app.api.routes.threat_intel import _fetch_cisa_kev

    write_json_cache(
        "cisa_kev.json",
        {
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-1234",
                    "dateAdded": "2099-01-01",
                    "vendorProject": "Test",
                    "product": "App",
                    "vulnerabilityName": "Test vuln",
                    "shortDescription": "n/a",
                    "knownRansomwareUse": "Unknown",
                }
            ],
        },
    )

    class _BoomClient:
        async def get(self, *args, **kwargs):
            raise AssertionError("CISA list path must not hit the network")

    cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
    rows = await _fetch_cisa_kev(_BoomClient(), cutoff)
    assert rows[0]["cve_id"] == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_enisa_list_path_uses_cache_not_http(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    from app.services.vuln_intel_feeds import write_json_cache
    from app.api.routes.threat_intel import _fetch_enisa_kev

    write_json_cache(
        "enisa_eukev.json",
        {
            "count": 1,
            "rows": [
                {
                    "cveID": "CVE-2024-5678",
                    "dateAdded": "2099-01-01",
                    "vendorProject": "ENISA",
                    "product": "App",
                    "vulnerabilityName": "Test",
                    "shortDescription": "n/a",
                }
            ],
        },
    )

    class _BoomClient:
        async def get(self, *args, **kwargs):
            raise AssertionError("ENISA list path must not hit the network")

    cutoff = datetime(2020, 1, 1, tzinfo=timezone.utc)
    rows = await _fetch_enisa_kev(_BoomClient(), cutoff)
    assert rows[0]["cve_id"] == "CVE-2024-5678"
