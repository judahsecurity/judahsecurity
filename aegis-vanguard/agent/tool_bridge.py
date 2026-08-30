"""External tool bridge — grow the offensive arsenal without code changes.

HexStrike-style capability: hunters can invoke any CLI security tool listed in
``data/external_tools.json`` through a single registered ``run_external_tool``
tool. Adding a tool is a one-line manifest edit, not a new Python wrapper.

Safety model (defence in depth):
  * Only tools present in the manifest are runnable.
  * The command is always built as an ``argv`` list and executed with
    ``shell=False`` — no string ever reaches a shell.
  * The ``{target}`` placeholder is validated to a plain host / URL shape.
  * Operator-supplied ``extra_args`` are ``shlex``-split and every token is
    checked against a conservative allowlist; a single shell metacharacter
    rejects the whole call.
  * Scope is additionally enforced by the guardrail layer because the tool's
    argument is named ``target`` (see agent/guardrails.py _check_scope).
  * Missing binaries degrade gracefully to an install hint, never a crash.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("agent.tool_bridge")

_MANIFEST_PATH = (
    Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    / "data"
    / "external_tools.json"
)

# A single argv token from operator extra_args may only contain these chars.
# Deliberately excludes shell metacharacters: ; | & $ ` > < \n ( ) { } * ? ! ~ \
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._:/@=%,+\-]+$")

# A target must look like a host, host:port, or http(s) URL — no whitespace or
# shell metacharacters. FUZZ (ffuf) and simple paths are allowed.
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._:/@=%,+\-?&#\[\]]+$")

_MAX_OUTPUT_CHARS = 20000


def _load_manifest() -> Dict[str, dict]:
    try:
        raw = json.loads(_MANIFEST_PATH.read_text())
    except FileNotFoundError:
        logger.warning("tool_bridge: manifest not found at %s", _MANIFEST_PATH)
        return {}
    except Exception as exc:  # pragma: no cover - corrupt manifest
        logger.warning("tool_bridge: bad manifest (%s)", exc)
        return {}
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def list_tools() -> List[dict]:
    """Return a catalogue of available external tools (name, description, risk)."""
    out = []
    for name, spec in _load_manifest().items():
        out.append(
            {
                "name": name,
                "description": spec.get("description", ""),
                "category": spec.get("category", "recon"),
                "risk": spec.get("risk", "medium"),
                "installed": shutil.which(spec.get("binary", name)) is not None,
                "install_hint": spec.get("install_hint", ""),
            }
        )
    return out


def _valid_target(target: str) -> bool:
    if not target or len(target) > 2048:
        return False
    if any(c.isspace() for c in target):
        return False
    return bool(_SAFE_TARGET.match(target))


def _safe_extra(extra_args: str) -> List[str]:
    """Split operator extra_args and reject any token with shell metacharacters."""
    if not extra_args or not extra_args.strip():
        return []
    tokens = shlex.split(extra_args)
    for tok in tokens:
        if not _SAFE_TOKEN.match(tok):
            raise ValueError(f"unsafe token in extra_args: {tok!r}")
    return tokens


def build_argv(spec: dict, target: str, extra: List[str], outdir: str = "") -> List[str]:
    """Materialise the manifest argv template into a concrete argv list."""
    argv: List[str] = []
    for tok in spec.get("argv", []):
        if tok == "{target}":
            argv.append(target)
        elif tok == "{extra}":
            argv.extend(extra)
            extra = []  # consumed at explicit marker
        elif tok == "{outdir}":
            argv.append(outdir or tempfile.mkdtemp(prefix="aegis_ext_"))
        else:
            argv.append(tok)
    # If the template had no explicit {extra} marker, append leftovers at the end.
    if extra:
        argv.extend(extra)
    return argv


def _parse_output(mode: str, stdout: str) -> Any:
    stdout = stdout[:_MAX_OUTPUT_CHARS]
    if mode == "json":
        try:
            return json.loads(stdout)
        except Exception:
            return {"raw": stdout, "parse_error": "not valid json"}
    if mode == "json_lines":
        rows = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                rows.append({"raw": line})
        return rows
    if mode == "lines":
        return [ln for ln in (l.strip() for l in stdout.splitlines()) if ln]
    return stdout  # raw


def run_tool(
    tool_name: str,
    target: str,
    extra_args: str = "",
    timeout: Optional[int] = None,
) -> dict:
    """Execute a manifest-listed external tool against a target.

    Returns a structured dict — never raises for expected failures (unknown
    tool, missing binary, unsafe args, timeout); those come back as
    ``{"ok": False, "error": ...}``.
    """
    manifest = _load_manifest()
    spec = manifest.get(tool_name)
    if spec is None:
        return {
            "ok": False,
            "error": f"unknown tool '{tool_name}'",
            "available": sorted(manifest.keys()),
        }

    if not _valid_target(target):
        return {"ok": False, "error": f"invalid/unsafe target: {target!r}"}

    binary = spec.get("binary", tool_name)
    if shutil.which(binary) is None:
        return {
            "ok": False,
            "error": f"'{binary}' is not installed in this container",
            "install_hint": spec.get("install_hint", ""),
        }

    try:
        extra = _safe_extra(extra_args)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    argv = build_argv(spec, target, extra)
    tmo = timeout or int(spec.get("timeout", 600))
    logger.info("tool_bridge: running %s -> %s", tool_name, " ".join(argv))

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=tmo,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timeout after {tmo}s", "tool": tool_name}
    except FileNotFoundError:
        return {"ok": False, "error": f"'{binary}' not found", "tool": tool_name}

    parsed = _parse_output(spec.get("parse", "raw"), proc.stdout)
    return {
        "ok": proc.returncode == 0,
        "tool": tool_name,
        "returncode": proc.returncode,
        "argv": argv,
        "result": parsed,
        "stderr": (proc.stderr or "")[:2000],
    }
