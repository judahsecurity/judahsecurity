"""
Central configuration for the Aegis Harness.

Everything is overridable via environment variables (prefix ``AEGIS_HARNESS_``)
so the same code runs on a workstation, in CI, or against a remote scanner
image without edits. Define your scanning/judging engines here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


def _repo_root() -> Path:
    """Locate the repository root (the dir that contains ``aegis-vanguard/``)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "aegis-vanguard").is_dir():
            return parent
    # Fallback: two levels up from this file (harness/local_harness/config.py).
    return here.parents[2]


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [part for part in raw.split() if part]


@dataclass
class HarnessConfig:
    """Runtime configuration for batch scanning and benchmarking."""

    # --- Scanner engine -------------------------------------------------
    # The command used to launch a single scan. The target URL is appended as
    # ``--target <url>`` and (optionally) ``--scope <domain>``.
    scanner_cmd: List[str] = field(
        default_factory=lambda: ["python3", "run_pentest.py"]
    )
    # Working directory for the scanner command (where run_pentest.py lives).
    scanner_cwd: Path = field(default_factory=lambda: _repo_root() / "aegis-vanguard")
    # Extra flags passed to every scan (e.g. ["--fast", "--max-risk", "medium"]).
    scanner_extra_args: List[str] = field(default_factory=list)
    # Hard timeout for a single scan, in seconds.
    scan_timeout_sec: int = 3600

    # --- Output ---------------------------------------------------------
    # Root directory for all harness artifacts (logs, findings, reports).
    work_dir: Path = field(default_factory=lambda: _repo_root() / "harness" / "runs")

    # --- Judge engine (benchmark mode) ----------------------------------
    # "anthropic", "openai", or "heuristic". "heuristic" needs no API key and
    # runs fully offline (category + endpoint matching); good for CI.
    judge_backend: str = "heuristic"
    judge_model: str = "claude-sonnet-4-6"
    judge_max_tokens: int = 4096

    @classmethod
    def from_env(cls) -> "HarnessConfig":
        cfg = cls()
        cfg.scanner_cmd = _env_list("AEGIS_HARNESS_SCANNER_CMD", cfg.scanner_cmd)
        if os.environ.get("AEGIS_HARNESS_SCANNER_CWD"):
            cfg.scanner_cwd = Path(os.environ["AEGIS_HARNESS_SCANNER_CWD"]).resolve()
        cfg.scanner_extra_args = _env_list(
            "AEGIS_HARNESS_SCANNER_ARGS", cfg.scanner_extra_args
        )
        cfg.scan_timeout_sec = int(
            os.environ.get("AEGIS_HARNESS_SCAN_TIMEOUT", cfg.scan_timeout_sec)
        )
        if os.environ.get("AEGIS_HARNESS_WORK_DIR"):
            cfg.work_dir = Path(os.environ["AEGIS_HARNESS_WORK_DIR"]).resolve()
        cfg.judge_backend = os.environ.get(
            "AEGIS_HARNESS_JUDGE_BACKEND", cfg.judge_backend
        ).lower()
        cfg.judge_model = os.environ.get("AEGIS_HARNESS_JUDGE_MODEL", cfg.judge_model)
        return cfg

    # Convenience paths -------------------------------------------------
    @property
    def batch_dir(self) -> Path:
        return self.work_dir / "batch"

    @property
    def benchmark_dir(self) -> Path:
        return self.work_dir / "benchmark"

    @property
    def batch_state_path(self) -> Path:
        return self.batch_dir / "state.json"


def default_config() -> HarnessConfig:
    """Return the environment-resolved configuration."""
    return HarnessConfig.from_env()
