"""Small helpers for reading challenge docker-compose files."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional


def container_port(compose_text: str, default: Optional[int] = None) -> Optional[int]:
    """The container port a challenge listens on, from its first ``ports:`` entry.

    Handles ``- 5000`` (bare), ``- "8080:80"`` (host:container → container), and
    the long form ``target: 80``. XBEN challenges are not all on :80 — 42 of the
    104 publish 5000/5003/8000/… so trusting a hardcoded 80 breaks --setup port
    discovery for them.
    """
    # short form: "- [host:]container" — container is the number before the
    # optional trailing quote, after an optional "host:" prefix.
    m = re.search(r"ports:\s*\n\s*-\s*[\"']?(?:\d+:)?(\d+)\b", compose_text)
    if m:
        return int(m.group(1))
    # long form: "target: <n>" under ports:
    m = re.search(r"ports:\s*\n(?:.*\n)?\s*(?:-\s*)?target:\s*(\d+)", compose_text)
    if m:
        return int(m.group(1))
    return default


def container_port_of(compose_file: Path, default: Optional[int] = None) -> Optional[int]:
    try:
        return container_port(compose_file.read_text(encoding="utf-8", errors="ignore"), default)
    except OSError:
        return default
