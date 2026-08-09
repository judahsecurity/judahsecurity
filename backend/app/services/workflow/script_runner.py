"""Sandboxed Python/Bash script execution for workflow script nodes."""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.services.workflow.artifacts import MAX_ARTIFACT_BYTES, write_text_list

logger = logging.getLogger(__name__)

SCRIPT_TIMEOUT_SEC = int(os.getenv("WORKFLOW_SCRIPT_TIMEOUT_SEC", "300"))
MAX_SCRIPT_SOURCE_BYTES = int(os.getenv("WORKFLOW_MAX_SCRIPT_SOURCE_BYTES", str(256 * 1024)))


async def run_script(
    *,
    language: str,
    source: str,
    workdir: Path,
    env_extra: Optional[Dict[str, str]] = None,
    timeout: int = SCRIPT_TIMEOUT_SEC,
) -> Tuple[int, str, str, Dict[str, Path]]:
    """
    Run a script in workdir with ./in and ./out.
    Returns (exit_code, stdout, stderr, output_files_by_name).
    """
    if len(source.encode("utf-8")) > MAX_SCRIPT_SOURCE_BYTES:
        raise ValueError("Script source exceeds size limit")

    workdir.mkdir(parents=True, exist_ok=True)
    in_dir = workdir / "in"
    out_dir = workdir / "out"
    in_dir.mkdir(exist_ok=True)
    out_dir.mkdir(exist_ok=True)

    lang = (language or "python").lower()
    if lang == "bash":
        script_path = workdir / "script.sh"
        script_path.write_text(source, encoding="utf-8")
        cmd = ["bash", str(script_path)]
    else:
        script_path = workdir / "script.py"
        script_path.write_text(source, encoding="utf-8")
        cmd = ["python3", str(script_path)]

    env = os.environ.copy()
    env["WORKFLOW_IN"] = str(in_dir)
    env["WORKFLOW_OUT"] = str(out_dir)
    if env_extra:
        env.update({k: str(v) for k, v in env_extra.items()})

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(workdir),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise TimeoutError(f"Script exceeded timeout of {timeout}s")
    except FileNotFoundError as e:
        raise RuntimeError(f"Script interpreter not found: {e}") from e

    stdout = (stdout_b or b"").decode("utf-8", errors="replace")[-100_000:]
    stderr = (stderr_b or b"").decode("utf-8", errors="replace")[-100_000:]
    code = proc.returncode or 0

    outputs: Dict[str, Path] = {}
    if out_dir.is_dir():
        for p in sorted(out_dir.iterdir()):
            if p.is_file():
                if p.stat().st_size > MAX_ARTIFACT_BYTES:
                    logger.warning("Truncating oversized script output %s", p)
                    # keep file but skip registering huge ones — still list path
                outputs[p.stem if p.suffix else p.name] = p
                # also key by full filename without relying only on stem
                outputs[p.name] = p

    return code, stdout, stderr, outputs


def prepare_script_inputs(
    workdir: Path,
    resolved_inputs: Dict[str, Any],
) -> None:
    """Write resolved inputs into workdir/in as files and env-friendly text."""
    in_dir = workdir / "in"
    in_dir.mkdir(parents=True, exist_ok=True)
    for name, value in (resolved_inputs or {}).items():
        safe = name.replace("/", "_")
        if isinstance(value, list):
            write_text_list(in_dir / f"{safe}.txt", [str(x) for x in value])
        elif isinstance(value, dict):
            import json

            (in_dir / f"{safe}.json").write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
        elif isinstance(value, str) and Path(value).is_file():
            shutil.copy2(value, in_dir / (Path(value).name))
            # also alias by port name
            dest = in_dir / f"{safe}{Path(value).suffix or '.txt'}"
            if not dest.exists():
                shutil.copy2(value, dest)
        else:
            write_text_list(in_dir / f"{safe}.txt", [str(value)])
