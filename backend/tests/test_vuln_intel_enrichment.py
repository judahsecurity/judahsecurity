"""Unit tests for NVD / OSV / GHSA / exploit-source catalog enrichment (mocked HTTP)."""

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
    poc = {"source": "poc_github", "found": True, "count": 2, "pocs": [{"url": "https://github.com/x/y"}]}
    trickest = {"source": "trickest", "found": True, "count": 4, "pocs": [{"url": "https://github.com/a/b", "full_name": "a/b"}]}
    repos = {"source": "github_repos", "found": True, "count": 5, "repos": []}
    edb = {"source": "exploitdb", "found": True, "count": 3, "exploits": [{"url": "https://github.com/offensive-security/exploitdb"}]}
    cx = {"source": "cxsecurity", "found": True, "count": 1, "entries": [{"url": "https://cxsecurity.com/cveshow/CVE-2021-44228/"}]}

    with patch("app.services.vuln_intel_enrichment._fetch_nvd", return_value=nvd), \
         patch("app.services.vuln_intel_enrichment._fetch_osv", return_value=osv), \
         patch("app.services.vuln_intel_enrichment._fetch_ghsa", return_value=ghsa), \
         patch("app.services.vuln_intel_enrichment._fetch_poc_github", return_value=poc), \
         patch("app.services.vuln_intel_enrichment._fetch_trickest", return_value=trickest), \
         patch("app.services.vuln_intel_enrichment._fetch_github_repos", return_value=repos), \
         patch("app.services.vuln_intel_enrichment._fetch_exploitdb", return_value=edb), \
         patch("app.services.vuln_intel_enrichment._fetch_cxsecurity", return_value=cx):
        out = enrich_cve_catalog("CVE-2021-44228", use_cache=False)

    assert out["enriched"] is True
    assert out["nvd"]["cvss_score"] == 10.0
    assert out["osv"]["id"] == "CVE-2021-44228"
    assert out["ghsa"][0]["ghsa_id"] == "GHSA-jfh8-c2jp-5v3q"
    assert out["exploit_sources"]["poc_github"]["found"] is True
    assert out["exploit_sources"]["trickest"]["found"] is True
    assert out["exploit_sources"]["github_repos"]["found"] is True
    assert out["exploit_sources"]["exploitdb"]["found"] is True
    assert out["exploit_sources"]["cxsecurity"]["found"] is True


def test_extract_trickest_repos_prefers_github_section():
    from app.services.vuln_intel_enrichment import _extract_trickest_repos

    md = """
### POC
#### Reference
- https://github.com/noise/ref-only
#### Github
- https://github.com/alice/log4j-poc
- https://github.com/alice/log4j-poc/tree/main/src
- https://github.com/bob/scanner.git
"""
    repos = _extract_trickest_repos(md)
    names = [r["full_name"] for r in repos]
    assert names == ["alice/log4j-poc", "bob/scanner"]
    assert "noise/ref-only" not in names


def test_load_fire_cves_from_list(tmp_path, monkeypatch):
    path = tmp_path / "fire.json"
    path.write_text('{"cves": ["CVE-2023-34362", "not-a-cve"]}', encoding="utf-8")
    monkeypatch.setenv("DELPHI_FIRE_CVE_PATH", str(path))
    cves = load_fire_cves()
    assert cves == {"CVE-2023-34362"}
