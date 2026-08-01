from local_harness.findings import (
    categorize,
    load_findings,
    normalize,
    severity_counts,
    vulnerabilities,
)


def test_categorize_maps_known_classes():
    assert categorize("SQL Injection in login") == "sqli"
    assert categorize("Reflected Cross-Site Scripting") == "xss"
    assert categorize("Server-Side Request Forgery") == "ssrf"
    assert categorize("Insecure Direct Object Reference") == "idor"
    assert categorize("something totally unrelated") == "other"


def test_normalize_pulls_endpoint_from_poc():
    raw = {
        "type": "vulnerability",
        "title": "SQL Injection",
        "severity": "critical",
        "confidence": "confirmed",
        "tags": ["confirmed", "sqli"],
        "raw_data": {"poc": {"endpoint": "https://x/login"}},
    }
    f = normalize(raw)
    assert f.category == "sqli"
    assert f.endpoint == "https://x/login"
    assert f.is_vulnerability
    assert f.is_confirmed


def test_recon_types_are_not_vulnerabilities():
    f = normalize({"type": "subdomain", "title": "Subdomain: a.b.com"})
    assert not f.is_vulnerability


def test_load_findings_and_filters(tmp_path):
    p = tmp_path / "findings.jsonl"
    lines = [
        {"type": "subdomain", "title": "sub"},
        {"type": "vulnerability", "title": "SQLi", "severity": "critical"},
        {"type": "vulnerability", "title": "XSS", "severity": "high"},
        "not json",
    ]
    p.write_text(
        "\n".join(l if isinstance(l, str) else __import__("json").dumps(l) for l in lines),
        encoding="utf-8",
    )
    findings = load_findings(p)
    # The invalid line is skipped.
    assert len(findings) == 3
    vulns = vulnerabilities(findings)
    assert len(vulns) == 2
    counts = severity_counts(vulns)
    assert counts["critical"] == 1
    assert counts["high"] == 1


def test_load_findings_missing_file(tmp_path):
    assert load_findings(tmp_path / "nope.jsonl") == []
