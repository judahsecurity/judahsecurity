import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from agent.ci_gate import severity_gate, normalize_severity, summary_line


def test_normalize_aliases():
    assert normalize_severity("Critical") == "critical"
    assert normalize_severity("informational") == "info"
    assert normalize_severity("error") == "high"
    assert normalize_severity("") == "info"
    assert normalize_severity("bogus") == "info"


def test_gate_blocks_at_threshold():
    fs = [{"severity": "high"}, {"severity": "low"}, {"severity": "medium"}]
    g = severity_gate(fs, fail_on="high")
    assert g["exit_code"] == 1 and g["blocking"] == 1
    assert g["counts"]["high"] == 1


def test_gate_passes_below_threshold():
    fs = [{"severity": "medium"}, {"severity": "low"}]
    g = severity_gate(fs, fail_on="high")
    assert g["exit_code"] == 0 and g["blocking"] == 0


def test_gate_prefers_escalated_severity():
    fs = [{"current_severity": "low", "escalated_severity": "critical"}]
    g = severity_gate(fs, fail_on="high")
    assert g["exit_code"] == 1 and g["counts"]["critical"] == 1


def test_gate_never_mode():
    fs = [{"severity": "critical"}]
    g = severity_gate(fs, fail_on="never")
    assert g["exit_code"] == 0


def test_gate_bad_threshold():
    g = severity_gate([{"severity": "high"}], fail_on="spicy")
    assert g["exit_code"] == 2 and "invalid" in g["error"]


def test_summary_line():
    g = severity_gate([{"severity": "critical"}], fail_on="high")
    assert "BLOCKED" in summary_line(g)
