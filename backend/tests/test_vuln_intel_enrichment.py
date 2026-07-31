"""Unit tests for NVD / OSV / GHSA catalog enrichment helpers (mocked HTTP)."""

from unittest.mock import patch

from app.services.vuln_intel_enrichment import enrich_cve_catalog
from app.services.vuln_intel_feeds import load_fire_cves


def test_enrich_cve_catalog_merges_sources():
    nvd = {
        "source": "nvd",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "description": "Log4Shell",
        "cwes": ["CWE-502"],
        "references": [],
    }
    osv = {
        "source": "osv",
        "id": "CVE-2021-44228",
        "aliases": ["GHSA-jfh8-c2jp-5v3q"],
        "affected_packages": [{"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"}],
        "references": [],
    }
    ghsa = [{
        "source": "ghsa",
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2021-44228",
        "severity": "critical",
        "summary": "Log4Shell",
        "vulnerabilities": [],
    }]

    with patch("app.services.vuln_intel_enrichment._fetch_nvd", return_value=nvd), \
         patch("app.services.vuln_intel_enrichment._fetch_osv", return_value=osv), \
         patch("app.services.vuln_intel_enrichment._fetch_ghsa", return_value=ghsa):
        out = enrich_cve_catalog("CVE-2021-44228", use_cache=False)

    assert out["enriched"] is True
    assert out["nvd"]["cvss_score"] == 10.0
    assert out["osv"]["id"] == "CVE-2021-44228"
    assert out["ghsa"][0]["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"


def test_load_fire_cves_from_list(tmp_path, monkeypatch):
    path = tmp_path / "fire.json"
    path.write_text('{"cves": ["CVE-2023-34362", "not-a-cve"]}', encoding="utf-8")
    monkeypatch.setenv("DELPHI_FIRE_CVE_PATH", str(path))
    cves = load_fire_cves()
    assert cves == {"CVE-2023-34362"}
