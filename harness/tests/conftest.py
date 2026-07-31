import json
import sys
from pathlib import Path

import pytest

HARNESS_ROOT = Path(__file__).resolve().parents[1]
STUB_SCANNER = Path(__file__).resolve().parent / "stub_scanner.py"

# Ensure the harness package is importable when run from anywhere.
if str(HARNESS_ROOT) not in sys.path:
    sys.path.insert(0, str(HARNESS_ROOT))


@pytest.fixture
def stub_env(tmp_path, monkeypatch):
    """Point the harness at the offline stub scanner and a tmp work dir."""
    monkeypatch.setenv(
        "AEGIS_HARNESS_SCANNER_CMD", f"{sys.executable} {STUB_SCANNER}"
    )
    monkeypatch.setenv("AEGIS_HARNESS_SCANNER_CWD", str(HARNESS_ROOT))
    monkeypatch.setenv("AEGIS_HARNESS_WORK_DIR", str(tmp_path / "runs"))
    monkeypatch.setenv("AEGIS_HARNESS_JUDGE_BACKEND", "heuristic")
    monkeypatch.setenv("AEGIS_HARNESS_SCAN_TIMEOUT", "120")
    return tmp_path


@pytest.fixture
def sample_ground_truth(tmp_path):
    corpus = {
        "_comment": "test corpus",
        "demo": {
            "target": "http://localhost:3000",
            "scope": "localhost",
            "expected_findings": [
                {"id": "D-SQLI", "category": "sqli", "severity": "critical",
                 "endpoint": "/rest/user/login", "description": "sqli login"},
                {"id": "D-XSS", "category": "xss", "severity": "high",
                 "endpoint": "/search", "description": "reflected xss"},
                {"id": "D-IDOR", "category": "idor", "severity": "high",
                 "endpoint": "/rest/basket", "description": "idor basket (missed)"},
            ],
        },
    }
    path = tmp_path / "corpus.json"
    path.write_text(json.dumps(corpus), encoding="utf-8")
    return path
