"""
Tests for Delphi picking up cache files refreshed by another process.

The schedule worker refreshes the KEV/EPSS caches in its own container on the
shared delphi_cache volume. The API process must notice the newer mtime and
reload, otherwise a worker refresh stays invisible for up to DELPHI_REFRESH_HOURS.
"""

import json
import os
import time

import pytest

from app.services.delphi_enrichment_service import DelphiEnrichmentService


def _write_kev(cache_dir, cve_ids):
    payload = {
        "catalogVersion": "2026.09.09",
        "count": len(cve_ids),
        "vulnerabilities": [
            {
                "cveID": cve,
                "vendorProject": "Acme",
                "product": "Widget",
                "vulnerabilityName": f"{cve} test",
                "dateAdded": "2026-09-09",
                "knownRansomwareCampaignUse": "Known",
            }
            for cve in cve_ids
        ],
    }
    path = os.path.join(cache_dir, "cisa_kev.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


@pytest.fixture()
def svc(monkeypatch, tmp_path):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    service = DelphiEnrichmentService()

    # Any network fetch would mean the disk-reload path was skipped.
    def _no_network(*_args, **_kwargs):
        raise AssertionError("ensure_loaded must not hit the network here")

    monkeypatch.setattr("app.services.delphi_enrichment_service._http_get", _no_network)
    monkeypatch.setattr(service, "_fetch_kev", lambda force=False: None)
    monkeypatch.setattr(service, "_fetch_epss", lambda force=False: None)
    # The extended-feed loaders reach out to CIRCL/KEVIntel/VulnCheck on the
    # first ensure_loaded; stub them so these tests stay hermetic.
    monkeypatch.setattr(
        "app.services.delphi_enrichment_service.load_extended_feeds",
        lambda **_kwargs: ({}, set(), {}, set()),
    )
    return service


def test_reloads_when_cache_file_is_newer(svc, tmp_path):
    _write_kev(str(tmp_path), ["CVE-2026-1"])
    svc.ensure_loaded()
    assert "CVE-2026-1" in svc._kev
    assert "CVE-2026-2" not in svc._kev

    # Another process (the schedule worker) refreshes the shared cache.
    path = _write_kev(str(tmp_path), ["CVE-2026-1", "CVE-2026-2"])
    future = time.time() + 60
    os.utime(path, (future, future))

    svc.ensure_loaded()
    assert "CVE-2026-2" in svc._kev, "newer on-disk cache should have been reloaded"


def test_no_reload_when_cache_is_unchanged(svc, tmp_path):
    _write_kev(str(tmp_path), ["CVE-2026-1"])
    svc.ensure_loaded()

    # Make the load look strictly newer than the file, as it is in the steady state.
    svc._last_load_ts = time.time() + 60
    reloaded = {"count": 0}
    original = svc._load_kev

    def _counting_load():
        reloaded["count"] += 1
        original()

    svc._load_kev = _counting_load
    svc.ensure_loaded()
    assert reloaded["count"] == 0, "unchanged cache must not trigger a reload"


def test_disk_mtime_handles_missing_files(svc):
    # No cache files written at all — must not raise.
    assert svc._disk_cache_mtime() == 0.0
