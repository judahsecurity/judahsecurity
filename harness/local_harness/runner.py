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
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import urlparse

from .config import HarnessConfig
from .findings import FindingsArtifactError, NormalizedFinding, load_findings


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
    cost_usd: Optional[float] = None
    trace_summary: Optional[dict] = None

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
        effective_scope = scope
        target_parsed = urlparse(target if "://" in target else f"//{target}")
        scope_parsed = urlparse(scope if "://" in scope else f"//{scope}")
        # XBEN publishes each localhost target on a random host port. Carry
        # that port into the scanner scope so a benchmark run cannot pivot to
        # unrelated services on the Docker host.
        if (
            target_parsed.port is not None
            and scope_parsed.port is None
            and target_parsed.hostname == scope_parsed.hostname
        ):
            effective_scope = target_parsed.netloc
        cmd += ["--scope", effective_scope]
    cmd += list(config.scanner_extra_args)
    return cmd


def run_scan(
    target: str,
    config: HarnessConfig,
    out_root: Path,
    scope: Optional[str] = None,
    subprocess_runner: SubprocessRunner = _default_subprocess_runner,
    artifact_name: Optional[str] = None,
) -> ScanResult:
    """Run a single scan against ``target`` and return a ScanResult.

    Args:
        target: Target URL (or host) to scan.
        config: Harness configuration (scanner command, timeout, ...).
        out_root: Directory under which a per-target folder is created.
        scope: Optional root-domain scope; defaults to the target host.
        subprocess_runner: Injectable launcher (defaults to real subprocess).
        artifact_name: Stable per-target directory name. Benchmark callers use
            the corpus ID so ``--tally-only`` still works when setup assigns a
            different localhost port on every run.
    """
    slug = artifact_name or slugify(target)
    out_dir = Path(out_root) / slug
    out_dir.mkdir(parents=True, exist_ok=True)
    findings_path = out_dir / "findings.jsonl"
    log_path = out_dir / "scan.log"
    result_path = out_dir / "scan_result.json"

    # Fresh artifacts per run so findings, cost, and guardrail counts cannot be
    # inherited from an older attempt that used the same stable benchmark ID.
    if findings_path.exists():
        findings_path.unlink()
    if result_path.exists():
        result_path.unlink()
    for trace_path in out_dir.glob("trace_*.json"):
        trace_path.unlink()
    # An empty artifact is a valid zero-finding result. Pre-creating it lets us
    # distinguish that result from a scanner that deleted/failed to emit its sink.
    findings_path.touch()

    env = dict(os.environ)
    env["AEGIS_FINDINGS_SINK"] = str(findings_path)
    env["AEGIS_TRACES_DIR"] = str(out_dir)

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

    try:
        findings = load_findings(findings_path, strict=True)
    except FindingsArtifactError as exc:
        findings = []
        status = "error"
        error = str(exc)

    from .cost import load_trace_summary

    trace_summary = load_trace_summary(out_dir)
    cost_usd = None
    if trace_summary:
        cost_usd = float(trace_summary.get("estimated_cost_usd") or 0)

    result = ScanResult(
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
        cost_usd=cost_usd,
        trace_summary=trace_summary,
    )
    result_path.write_text(json.dumps({
        "target": target,
        "slug": slug,
        "status": status,
        "return_code": return_code,
        "duration_sec": round(duration, 6),
        "error": error,
        "finding_count": len(findings),
        "scanner_command": cmd,
        "model": os.environ.get("AEGIS_MODEL"),
        "llm_backend": os.environ.get("AEGIS_LLM_BACKEND", "auto"),
        "scanner_image": os.environ.get("ASM_SCANNER_IMAGE"),
        "scanner_image_digest": os.environ.get("ASM_SCANNER_IMAGE_DIGEST"),
    }, indent=2, default=str), encoding="utf-8")
    return result
