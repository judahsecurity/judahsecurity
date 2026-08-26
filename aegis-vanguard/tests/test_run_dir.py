"""run_dir helper for Claude Code skills."""

import importlib.util
from pathlib import Path

_LIB = Path(__file__).resolve().parents[1] / ".claude" / "skills" / "_lib" / "run_dir.py"
_spec = importlib.util.spec_from_file_location("aegis_run_dir", _LIB)
run_dir = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(run_dir)


def test_mint_then_latest(tmp_path, monkeypatch):
    monkeypatch.setattr(run_dir, "ROOT", tmp_path)
    first = run_dir.mint("app.example.com", fresh=True)
    again = run_dir.mint("app.example.com", fresh=False)
    assert again == first
    nxt = run_dir.mint("app.example.com", fresh=True)
    assert nxt != first
    assert run_dir.latest("app.example.com") == nxt
