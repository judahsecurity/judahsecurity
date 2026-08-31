import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.sarif import findings_to_sarif, finding_uri


def test_sast_finding_has_physical_location():
    f = {"title": "SQLi in query", "severity": "high", "cwe_id": "CWE-89",
         "file": "app/db.py", "line": 42, "description": "user input to execute()"}
    log = findings_to_sarif([f], source_root="")
    assert log["version"] == "2.1.0"
    res = log["runs"][0]["results"][0]
    assert res["ruleId"] == "CWE-89"
    assert res["level"] == "error"
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/db.py"
    assert loc["region"]["startLine"] == 42
    assert res["properties"]["security-severity"] == "8.0"
    assert res["partialFingerprints"]["aegis/v1"]


def test_dast_finding_uses_logical_location():
    f = {"title": "XSS", "severity": "medium", "vuln_type": "xss",
         "endpoint": "https://app.example.com/search?q="}
    log = findings_to_sarif([f])
    res = log["runs"][0]["results"][0]
    assert res["ruleId"] == "xss"
    assert res["level"] == "warning"
    assert res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"].startswith("https://")


def test_abs_path_relativised():
    f = {"title": "x", "severity": "low", "location": {"path": "/work/repo/src/a.py", "line": 3}}
    uri = finding_uri(f, source_root="/work/repo")
    assert uri == "src/a.py"


def test_rules_deduped():
    fs = [{"title": "a", "severity": "high", "cwe_id": "CWE-79", "file": "x.py"},
          {"title": "b", "severity": "high", "cwe_id": "CWE-79", "file": "y.py"}]
    log = findings_to_sarif(fs)
    assert len(log["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(log["runs"][0]["results"]) == 2


def test_empty():
    log = findings_to_sarif([])
    assert log["runs"][0]["results"] == []
