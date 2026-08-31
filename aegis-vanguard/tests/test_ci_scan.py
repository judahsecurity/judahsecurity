import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_scan


def test_load_findings_list(tmp_path):
    p = tmp_path / "f.json"; p.write_text(json.dumps([{"title": "a", "severity": "high"}]))
    assert len(ci_scan.load_findings(str(p))) == 1


def test_load_findings_wrapped(tmp_path):
    p = tmp_path / "f.json"; p.write_text(json.dumps({"findings": [{"title": "a"}]}))
    assert len(ci_scan.load_findings(str(p))) == 1


def test_load_findings_jsonl(tmp_path):
    p = tmp_path / "f.jsonl"; p.write_text('{"title":"a"}\n{"title":"b"}\n')
    assert len(ci_scan.load_findings(str(p))) == 2


def test_filter_to_changed_keeps_dast():
    fs = [{"title": "sast", "file": "src/a.py", "severity": "high"},
          {"title": "sast2", "file": "src/b.py", "severity": "high"},
          {"title": "dast", "endpoint": "https://x/y", "severity": "high"}]
    kept = ci_scan.filter_to_changed(fs, ["src/a.py"], source_root="")
    titles = {f["title"] for f in kept}
    assert titles == {"sast", "dast"}   # b.py filtered out, DAST always kept
