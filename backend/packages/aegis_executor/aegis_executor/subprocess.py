"""Bounded subprocess runner.

This is a defense-in-depth local fallback. Production should still run it inside
a rootless, read-only worker container with scoped egress.
"""

from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional, Sequence

from .policy import ExecutionPolicy, build_environment, validate_workdir


@dataclass(frozen=True)
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_truncated: bool = False


def _limit_process(policy: ExecutionPolicy) -> None:
    os.umask(0o077)
    if os.name != "posix":
        return
    import resource

    limits = (
        (resource.RLIMIT_CPU, policy.cpu_seconds),
        (resource.RLIMIT_FSIZE, policy.max_file_bytes),
        (resource.RLIMIT_NOFILE, policy.max_open_files),
    )
    if hasattr(resource, "RLIMIT_AS"):
        limits += ((resource.RLIMIT_AS, policy.max_memory_bytes),)
    if hasattr(resource, "RLIMIT_NPROC"):
        limits += ((resource.RLIMIT_NPROC, policy.max_processes),)
    for resource_id, limit in limits:
        try:
            resource.setrlimit(resource_id, (limit, limit))
        except (OSError, ValueError):
            pass


async def _bounded_read(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    kept = bytearray()
    truncated = False
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            break
        remaining = limit - len(kept)
        if remaining > 0:
            kept.extend(chunk[:remaining])
        if len(chunk) > remaining:
            truncated = True
    return bytes(kept), truncated


async def run_process(
    command: Sequence[str],
    *,
    workdir: Path,
    policy: Optional[ExecutionPolicy] = None,
    environment: Optional[Mapping[str, str]] = None,
) -> ExecutionResult:
    policy = policy or ExecutionPolicy()
    if not command or not all(isinstance(item, str) and item for item in command):
        raise ValueError("command must be a non-empty sequence of strings")
    cwd = validate_workdir(workdir)
    env = build_environment(policy, extra=environment)
    kwargs = {
        "cwd": str(cwd),
        "env": env,
        "stdin": asyncio.subprocess.DEVNULL,
        "stdout": asyncio.subprocess.PIPE,
        "stderr": asyncio.subprocess.PIPE,
        "start_new_session": os.name == "posix",
    }
    if os.name == "posix":
        kwargs["preexec_fn"] = lambda: _limit_process(policy)

    process = await asyncio.create_subprocess_exec(*command, **kwargs)
    assert process.stdout is not None
    assert process.stderr is not None
    out_task = asyncio.create_task(_bounded_read(process.stdout, policy.max_output_bytes))
    err_task = asyncio.create_task(_bounded_read(process.stderr, policy.max_output_bytes))
    timed_out = False
    try:
        await asyncio.wait_for(process.wait(), timeout=policy.timeout_seconds)
    except asyncio.TimeoutError:
        timed_out = True
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        await process.wait()
    stdout_pair, stderr_pair = await asyncio.gather(out_task, err_task)
    stdout_b, out_truncated = stdout_pair
    stderr_b, err_truncated = stderr_pair
    return ExecutionResult(
        exit_code=process.returncode if process.returncode is not None else -1,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        timed_out=timed_out,
        output_truncated=out_truncated or err_truncated,
    )
