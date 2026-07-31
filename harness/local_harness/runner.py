"""
Scan runner — invokes the Aegis Vanguard scanner for one target and captures
its findings as a stable artifact.

The scanner is launched as a subprocess (configurable via ``HarnessConfig``),
with ``AEGIS_FINDINGS_SINK`` pointed at a per-target JSONL file so we get a
machine-readable record of everything it submitted, independent of the live
platform. The subprocess launcher is injectable so the runner can be exercised
in tests without a real scanner, API key, or network.
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

from .config import HarnessConfig
from .findings import NormalizedFinding, load_findings


def slugify(target: str) -> str:
    """Filesystem-safe slug for a target URL/host."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    base = parsed.hostname or target
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", base).strip("_")
    if parsed.port:
        slug = f"{slug}_{parsed.port}"
    return slug or "target"


@dataclass
class ScanResult:
    target: str
    slug: str
    status: str  # "done" | "error" | "timeout"
    return_code: Optional[int]
    duration_sec: float
    out_dir: Path
    findings_path: Path
    log_path: Path
    findings: List[NormalizedFinding] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def finding_count(self) -> int:
        return len(self.findings)


# A subprocess launcher: (cmd, cwd, env, timeout) -> (return_code, combined_output).
SubprocessRunner = Callable[[List[str], Path, dict, int], "tuple[int, str]"]


def _default_subprocess_runner(
    cmd: List[str], cwd: Path, env: dict, timeout: int
) -> "tuple[int, str]":
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        timeout=timeout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout or ""


def build_command(config: HarnessConfig, target: str, scope: Optional[str]) -> List[str]:
    cmd = list(config.scanner_cmd) + ["--target", target]
    if scope:
        cmd += ["--scope", scope]
    cmd += list(config.scanner_extra_args)
    return cmd


def run_scan(
    target: str,
    config: HarnessConfig,
    out_root: Path,
    scope: Optional[str] = None,
    subprocess_runner: SubprocessRunner = _default_subprocess_runner,
) -> ScanResult:
    """Run a single scan against ``target`` and return a ScanResult.

    Args:
        target: Target URL (or host) to scan.
        config: Harness configuration (scanner command, timeout, ...).
        out_root: Directory under which a per-target folder is created.
        scope: Optional root-domain scope; defaults to the target host.
        subprocess_runner: Injectable launcher (defaults to real subprocess).
    """
    slug = slugify(target)
    out_dir = Path(out_root) / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.jsonl"
    log_path = out_dir / "scan.log"

    # Fresh sink per run so counts are accurate on re-runs.
    if findings_path.exists():
        findings_path.unlink()

    env = dict(os.environ)
    env["AEGIS_FINDINGS_SINK"] = str(findings_path)

    cmd = build_command(config, target, scope)

    start = time.time()
    status = "done"
    return_code: Optional[int] = None
    error: Optional[str] = None
    output = ""
    try:
        return_code, output = subprocess_runner(
            cmd, config.scanner_cwd, env, config.scan_timeout_sec
        )
        if return_code != 0:
            status = "error"
            error = f"scanner exited with code {return_code}"
    except subprocess.TimeoutExpired:
        status = "timeout"
        error = f"scan exceeded {config.scan_timeout_sec}s"
    except FileNotFoundError as e:
        status = "error"
        error = f"scanner command not found: {e}"
    except Exception as e:  # pragma: no cover - defensive
        status = "error"
        error = str(e)

    duration = time.time() - start

    log_path.write_text(
        f"$ {' '.join(cmd)}\n(cwd={config.scanner_cwd})\n\n{output}",
        encoding="utf-8",
    )

    findings = load_findings(findings_path)

    return ScanResult(
        target=target,
        slug=slug,
        status=status,
        return_code=return_code,
        duration_sec=duration,
        out_dir=out_dir,
        findings_path=findings_path,
        log_path=log_path,
        findings=findings,
        error=error,
    )
