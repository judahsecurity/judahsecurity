"""Resource and environment policy for untrusted workflow subprocesses."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional


class ExecutionPolicyError(ValueError):
    pass


_SAFE_ENV = frozenset({"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR"})
_SECRET = re.compile(
    r"(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|COOKIE|AUTHORIZATION|CREDENTIAL)(?:_|$)",
    re.IGNORECASE,
)
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$", re.IGNORECASE)


@dataclass(frozen=True)
class ExecutionPolicy:
    timeout_seconds: int = 300
    max_output_bytes: int = 1_000_000
    max_file_bytes: int = 64 * 1024 * 1024
    max_memory_bytes: int = 512 * 1024 * 1024
    max_processes: int = 32
    max_open_files: int = 128
    cpu_seconds: int = 300
    allowed_environment: frozenset[str] = field(default_factory=lambda: _SAFE_ENV)
    allowed_extra_environment: frozenset[str] = field(default_factory=frozenset)
    allowed_extra_environment_prefixes: tuple[str, ...] = ()
    allowed_secret_environment: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not 1 <= self.timeout_seconds <= 24 * 60 * 60:
            raise ExecutionPolicyError("timeout_seconds must be between 1 and 86400")
        if self.max_output_bytes < 1024:
            raise ExecutionPolicyError("max_output_bytes must be at least 1024")
        if self.max_processes < 1 or self.max_open_files < 8:
            raise ExecutionPolicyError("invalid process or file descriptor limit")


def build_environment(
    policy: ExecutionPolicy,
    *,
    base: Optional[Mapping[str, str]] = None,
    extra: Optional[Mapping[str, str]] = None,
) -> dict[str, str]:
    """Build an allowlisted environment without leaking the backend's credentials."""
    source = base if base is not None else os.environ
    env = {
        key: str(source[key])
        for key in policy.allowed_environment
        if key in source and source[key] is not None
    }
    for key, raw in (extra or {}).items():
        name = str(key)
        if not _ENV_NAME.fullmatch(name):
            raise ExecutionPolicyError(f"invalid environment variable name: {name!r}")
        if not (
            name in policy.allowed_extra_environment
            or any(name.startswith(prefix) for prefix in policy.allowed_extra_environment_prefixes)
        ):
            raise ExecutionPolicyError(
                f"environment variable {name!r} is not authorized by this execution policy"
            )
        if _SECRET.search(name) and name not in policy.allowed_secret_environment:
            raise ExecutionPolicyError(
                f"secret-like environment variable {name!r} requires explicit authorization"
            )
        env[name] = str(raw)
    return env


def validate_workdir(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.is_dir():
        raise ExecutionPolicyError(f"workdir does not exist: {resolved}")
    if resolved == Path(resolved.anchor):
        raise ExecutionPolicyError("filesystem root cannot be an execution workdir")
    return resolved
