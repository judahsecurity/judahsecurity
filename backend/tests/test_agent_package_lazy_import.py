"""Regression coverage for lightweight host workers importing agent helpers."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


def test_capability_map_import_does_not_require_llm_dependencies():
    backend_root = Path(__file__).resolve().parents[1]
    env = {**os.environ, "PYTHONPATH": str(backend_root)}
    code = """
import sys
from app.services.recon_envelope import envelope_from_normalized

result = envelope_from_normalized({
    "target": "https://example.com",
    "scope": "example.com",
    "pages_visited": ["https://example.com"],
})
assert result["capability_map"]["target"] == "https://example.com"
assert "app.services.agent.orchestrator" not in sys.modules
"""
    completed = subprocess.run(
        [sys.executable, "-S", "-c", code],
        cwd=backend_root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
