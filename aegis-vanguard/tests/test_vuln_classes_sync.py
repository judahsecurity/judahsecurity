"""data/vuln_classes.json must match Prowl's canonical proof policy."""

import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT.parent / "backend"
DATA = json.loads((ROOT / "data" / "vuln_classes.json").read_text())


def _backend_policy():
    if not (BACKEND / "app" / "services" / "agent" / "proof_policy.py").is_file():
        pytest.skip("backend checkout not present")
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))
    try:
        return importlib.import_module("app.services.agent.proof_policy")
    except Exception as exc:  # pragma: no cover - depends on environment
        pytest.skip(f"backend not importable: {exc}")


def test_shape_and_local_invariants():
    classes = DATA["classes"]
    for name, row in classes.items():
        assert isinstance(row["proof_kinds"], list), name
        assert row["confirmable"] == (bool(row["proof_kinds"]) and row["severity_cap"] is None), name
    assert classes["known_cve"]["confirmable"] is False
    assert classes["known_cve"]["severity_cap"] == "low"
    for name, kind in {"ssti": "scoped_ssti_eval", "command_injection": "scoped_cmdi_eval",
                       "path_traversal": "scoped_traversal_read",
                       "csrf": "scoped_csrf_state_change"}.items():
        assert kind in classes[name]["proof_kinds"], name
    for alias, target in DATA["vanguard_aliases"].items():
        assert target in classes, alias
    for cov, target in DATA["coverage_to_class"].items():
        assert target is None or target in classes, cov


def test_matches_backend_proofs_by_class():
    policy = _backend_policy()
    expected = {name: sorted(kinds) for name, kinds in policy.PROOFS_BY_CLASS.items()}
    actual = {name: row["proof_kinds"] for name, row in DATA["classes"].items()}
    assert actual == expected, (
        "vuln_classes.json drifted from proof_policy.PROOFS_BY_CLASS; "
        "run python3 scripts/sync_vuln_classes.py"
    )
    assert DATA["pending_upstream"] == {}, "upstream classes still pending; re-run the sync"


def test_matches_backend_coverage_catalog():
    _backend_policy()
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        sync = importlib.import_module("sync_vuln_classes")
    finally:
        sys.path.pop(0)
    source = (BACKEND / "app" / "services" / "agent" / "vulnerability_catalog.py").read_text()
    assert sorted(DATA["coverage_to_class"]) == sync.coverage_classes_from_source(source)
