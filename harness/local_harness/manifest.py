"""
Run manifest — capture everything needed to reproduce a benchmark run.

A ``benchmark_report.json`` records *results*; a manifest records the *inputs*
that produced them, so a run is reproducible and comparable over time:

  * harness git SHA (+ dirty flag)
  * agent model id
  * scanner command + extra args
  * ground-truth file path, sha256, and target count
  * seed (if the run pinned one via AEGIS_SEED)
  * security-tool versions (best-effort probe)
  * python + platform

The tool-version probe is injectable so tests are deterministic and offline.
"""
from __future__ import annotations

import hashlib
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Binaries whose versions materially affect detection results.
_DEFAULT_TOOLS = ["nuclei", "httpx", "subfinder", "naabu", "katana", "sqlmap",
                  "ffuf", "nmap"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(cmd: List[str], cwd: Optional[Path] = None, timeout: float = 5.0) -> Optional[str]:
    try:
        out = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True,
                             text=True, timeout=timeout)
        return (out.stdout or out.stderr).strip() or None
    except Exception:
        return None


def _git_info(repo_root: Path) -> Dict[str, Any]:
    sha = _run(["git", "rev-parse", "HEAD"], cwd=repo_root)
    dirty = _run(["git", "status", "--porcelain"], cwd=repo_root)
    return {"sha": sha, "dirty": bool(dirty) if dirty is not None else None}


def _probe_tool(binary: str) -> str:
    """Best-effort version string for a security binary."""
    for flag in ("-version", "--version", "-V"):
        out = _run([binary, flag])
        if out:
            return out.splitlines()[0][:120]
    return "unavailable"


def sha256_file(path: Path) -> Optional[str]:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except Exception:
        return None


def _ground_truth_count(path: Path) -> Optional[int]:
    try:
        import json
        data = json.loads(Path(path).read_text())
        if isinstance(data, dict):
            # {targets: {...}} or flat {name: spec}
            tgts = data.get("targets") if isinstance(data.get("targets"), dict) else data
            return len(tgts)
        if isinstance(data, list):
            return len(data)
    except Exception:
        pass
    return None


def build_manifest(
    config: Any,
    ground_truth_path: Optional[Path] = None,
    model: Optional[str] = None,
    tools: Optional[List[str]] = None,
    tool_probe: Optional[Callable[[str], str]] = None,
    repo_root: Optional[Path] = None,
) -> Dict[str, Any]:
    """Assemble the reproducibility manifest for a benchmark run."""
    root = repo_root or _repo_root_from_config(config)
    probe = tool_probe or _probe_tool
    tool_list = tools if tools is not None else _DEFAULT_TOOLS

    gt_path = Path(ground_truth_path) if ground_truth_path else None
    manifest: Dict[str, Any] = {
        "generated_at": _now(),
        "harness_git": _git_info(root),
        "agent_model": model or os.environ.get("AEGIS_MODEL") or getattr(
            config, "default_model", None) or "unknown",
        "scanner": {
            "cmd": list(getattr(config, "scanner_cmd", []) or []),
            "extra_args": list(getattr(config, "scanner_extra_args", []) or []),
        },
        "seed": os.environ.get("AEGIS_SEED"),
        "ground_truth": {
            "path": str(gt_path) if gt_path else None,
            "sha256": sha256_file(gt_path) if gt_path else None,
            "target_count": _ground_truth_count(gt_path) if gt_path else None,
        },
        "tool_versions": {t: probe(t) for t in tool_list},
        "runtime": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
        },
    }
    return manifest


def _repo_root_from_config(config: Any) -> Path:
    cwd = getattr(config, "scanner_cwd", None)
    if cwd:
        return Path(cwd).resolve().parent
    return Path.cwd()


__all__ = ["build_manifest", "sha256_file"]
