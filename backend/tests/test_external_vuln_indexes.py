import hashlib
import json
import os
import time

from app.api.routes.threat_intel import _detection_tier, _merge_external_coverage
from app.services import external_vuln_indexes as indexes
from app.services.exploit_intelligence import build_exploit_intelligence
from app.services.external_vuln_indexes import (
    nuclei_coverage_for_cve,
    parse_nuclei_cve_index,
    parse_vulncheck_exploits,
    refresh_nuclei_cve_index,
    vulncheck_exploits_for_cve,
)


def test_nuclei_generated_index_maps_exact_cve_and_protocol_path():
    raw = "\n".join(
        [
            json.dumps({
                "ID": "CVE-2025-25257",
                "Info": {
                    "Name": "Fortinet FortiWeb - SQL Injection",
                    "Severity": "critical",
                    "Classification": {"CVSSScore": "9.8"},
                },
                "file_path": "http/cves/2025/CVE-2025-25257.yaml",
            }),
            json.dumps({
                "ID": "CVE-2025-25256",
                "Info": {"Name": "FortiSIEM", "Severity": "critical"},
                "file_path": "network/cves/2025/CVE-2025-25256.yaml",
            }),
        ]
    )
    parsed = parse_nuclei_cve_index(raw)
    assert "CVE-2025-25257" in parsed
    assert "CVE-2025-25252" not in parsed
    assert parsed["CVE-2025-25256"][0]["file_path"].startswith("network/")


def test_nuclei_index_rejects_traversal_paths():
    raw = json.dumps({
        "ID": "CVE-2025-25252",
        "Info": {"Name": "unsafe"},
        "file_path": "http/../secrets.yaml",
    })
    assert parse_nuclei_cve_index(raw) == {}


def test_nuclei_refresh_verifies_checksum_and_distinguishes_absence(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    raw = json.dumps({
        "ID": "CVE-2025-25257",
        "Info": {"Name": "FortiWeb SQLi", "Severity": "critical"},
        "file_path": "http/cves/2025/CVE-2025-25257.yaml",
    }).encode()
    checksum = hashlib.md5(raw).hexdigest().encode()  # nosec B324 - mirrors upstream checksum format

    def _download(url, **_kwargs):
        return checksum if url == indexes.NUCLEI_CVE_CHECKSUM_URL else raw

    monkeypatch.setattr(indexes, "_download", _download)
    result = refresh_nuclei_cve_index(force=True)
    assert result["status"] == "fresh"
    assert nuclei_coverage_for_cve("CVE-2025-25257")["found"] is True
    absent = nuclei_coverage_for_cve("CVE-2025-25252")
    assert absent["available"] is True
    assert absent["found"] is False


def test_nuclei_refresh_retains_stale_cache_on_failure(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    path = indexes._cache_path("nuclei")
    path.write_text(json.dumps({
        "fetched_at": "2026-09-01T00:00:00Z",
        "entries": {"CVE-2025-25257": [{"template_id": "CVE-2025-25257"}]},
    }))
    old = time.time() - 72 * 3600
    os.utime(path, (old, old))
    monkeypatch.setattr(indexes, "_download", lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError()))
    result = refresh_nuclei_cve_index(force=True)
    assert result["status"] == "stale"
    assert nuclei_coverage_for_cve("CVE-2025-25257")["found"] is True


def test_vulncheck_exploits_normalizes_xdb_metadata_without_code():
    parsed = parse_vulncheck_exploits([{
        "id": "CVE-2025-25252",
        "public_exploit_found": True,
        "inVCKEV": True,
        "exploits": [{
            "xdb_id": "a5792665e6fa",
            "xdb_url": "https://vulncheck.com/xdb/a5792665e6fa",
            "date_added": "2025-11-03T21:15:42Z",
            "exploit_type": "initial-access",
            "exploit_maturity": "poc",
            "validation_level": "vulncheck-analyst-review",
            "clone_ssh_url": "git@github.com:iptables6cv/CVE-2025-25252-POC.git",
        }],
    }])
    record = parsed["CVE-2025-25252"]
    artifact = record["artifacts"][0]
    assert record["public_exploit_found"] is True
    assert record["is_remote"] is True
    assert record["in_vulncheck_kev"] is True
    assert artifact["artifact_id"] == "vulncheck-xdb:a5792665e6fa"
    assert artifact["maturity"] == "proof_of_concept"
    assert "clone_ssh_url" not in artifact


def test_vulncheck_cache_contributes_to_public_exploit_maturity(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    indexes._cache_path("vulncheck_exploits").write_text(json.dumps({
        "fetched_at": "2026-09-14T00:00:00Z",
        "entries": parse_vulncheck_exploits([{
            "id": "CVE-2025-25252",
            "exploits": [{
                "xdb_id": "a5792665e6fa",
                "xdb_url": "https://vulncheck.com/xdb/a5792665e6fa",
                "exploit_type": "initial-access",
            }],
        }]),
    }))
    source = vulncheck_exploits_for_cve("CVE-2025-25252")
    result = build_exploit_intelligence("CVE-2025-25252", {"vulncheck": source})
    assert result["maturity"] == "proof_of_concept"
    assert result["artifact_count"] == 1


def test_vulncheck_warm_cache_uses_incremental_index(tmp_path, monkeypatch):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    path = indexes._cache_path("vulncheck_exploits")
    path.write_text(json.dumps({
        "fetched_at": "2026-09-14T00:00:00Z",
        "entries": {
            "CVE-2025-25252": {
                "cve_id": "CVE-2025-25252",
                "public_exploit_found": True,
                "artifacts": [],
            }
        },
    }))
    old = time.time() - 2 * 3600
    os.utime(path, (old, old))
    seen_urls = []

    def _download(url, **_kwargs):
        seen_urls.append(url)
        return json.dumps({
            "data": [{
                "id": "CVE-2026-99999",
                "exploits": [{
                    "xdb_id": "new-record",
                    "xdb_url": "https://vulncheck.com/xdb/new-record",
                    "exploit_type": "initial-access",
                }],
            }],
            "_meta": {},
        }).encode()

    monkeypatch.setattr(indexes, "_download", _download)
    result = indexes.refresh_vulncheck_exploit_index(
        "token", refresh_hours=1
    )

    assert result["status"] == "fresh"
    assert result["cves"] == 2
    assert result["updated_cves"] == 1
    assert any("lastModStartDate=2026-09-13" in url for url in seen_urls)
    assert all("/backup/" not in url for url in seen_urls)


def test_coverage_merge_uses_public_sources_and_preserves_unknown():
    merged = _merge_external_coverage(
        "CVE-2025-25252",
        {},
        nuclei={"available": True, "status": "ok", "found": False, "templates": []},
        vulncheck={
            "available": True,
            "status": "ok",
            "found": True,
            "is_remote": True,
            "exploit_types": ["initial-access"],
        },
    )
    assert merged["is_poc"] is True
    assert merged["is_remote"] is True
    assert merged.get("is_template") is not True
    assert _detection_tier(merged) == "poc_available"

    unknown = _merge_external_coverage(
        "CVE-2025-25252",
        {},
        nuclei={"available": False, "status": "unavailable"},
        vulncheck={"available": False, "status": "unavailable"},
    )
    assert _detection_tier(unknown) == "unknown"
