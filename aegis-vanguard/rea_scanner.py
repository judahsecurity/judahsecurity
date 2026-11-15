#!/usr/bin/env python3
"""REA (Reverse Engineer Anything) integration for static code scanning.

Wraps the ``rea`` CLI from the ``rea-agents`` npm package
(https://github.com/morluto/rea) to cover what source-level SAST misses:
the *shipped* artifacts that sit in a checkout (build output, bundled JS,
native binaries, Electron ASARs, APKs, .NET assemblies).

Two REA commands are used. Both are static: they parse the files and do not
execute the target.

* ``rea audit-release-exposure <path>``: what a release leaks
  (source maps with ``sourcesContent``, provider-prefixed credentials in
  shipped text, debug companions such as .pdb/.dSYM/.map, Go build paths,
  Rust dependency metadata, Electron fuses, extractable payloads).
* ``rea inspect-binary-hardening <file>``: ELF / PE / Mach-O hardening
  (PIE, NX, RELRO, stack protector, FORTIFY, CET, ASLR/high-entropy VA,
  CFG, RPATH/RUNPATH, hardened runtime).

This module has no dependency on the ASM bridge so the ``/code-scan`` skill
helper and the Python SAST phase can share it.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("rea_scanner")

REA_NPM_PACKAGE = "rea-agents"
REA_PINNED_VERSION = "6.9.0"
REA_INSTALL_HINT = (
    f"npm install --global --ignore-scripts {REA_NPM_PACKAGE}@{REA_PINNED_VERSION} "
    "(needs Node.js >= 22.23.4)"
)

# Directories skipped during artifact discovery. Third-party trees are noise
# for a first-party audit; release dirs such as dist/ and build/ are kept on
# purpose because they hold the shipped output REA is meant to inspect.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".next/cache",
}

_NATIVE_MAGIC = {
    b"\x7fELF": "elf",
    b"MZ": "pe",
    b"\xfe\xed\xfa\xce": "macho",
    b"\xfe\xed\xfa\xcf": "macho",
    b"\xce\xfa\xed\xfe": "macho",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xca\xfe\xba\xbe": "macho",  # fat/universal (also Java class; filtered below)
}
_PACKAGE_EXTENSIONS = {".asar": "asar", ".apk": "apk", ".aab": "apk", ".wasm": "wasm"}

# Hardening properties where "disabled" is the weakness, with severity.
_HARDENING_WANTED = {
    "nx": "medium",
    "nx_compat": "medium",
    "pie": "low",
    "dynamic_base": "low",
    "relro": "low",
    "stack_protector": "low",
    "fortify": "info",
    "high_entropy_va": "info",
    "guard_cf": "info",
    "cfg_instrumented": "info",
    "cet_ibt_shstk": "info",
    "hardened_runtime": "low",
}
# Properties where "enabled" is the weakness.
_HARDENING_UNWANTED = {
    "allow_stack_execution": "medium",
    "rpath": "low",
    "runpath": "info",
}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------

def rea_command() -> Optional[List[str]]:
    """Return the argv prefix for the REA CLI, or None if it is not installed.

    ``REA_BIN`` overrides discovery (e.g. a path to a vendored install).
    No ``npx`` fallback: fetching a package at scan time is a supply-chain
    risk, so REA must be installed ahead of time (see the Dockerfile).
    """
    override = os.environ.get("REA_BIN", "").strip()
    if override:
        return [override]
    for name in ("rea", "rea-agents"):
        path = shutil.which(name)
        if path:
            return [path]
    return None


def is_available() -> bool:
    return rea_command() is not None


def _not_installed() -> Dict[str, Any]:
    return {"error": "rea not installed", "install_hint": REA_INSTALL_HINT}


def _run_rea(args: List[str], timeout: int) -> Dict[str, Any]:
    """Run ``rea <args> --format json`` and return parsed JSON or an error dict."""
    base = rea_command()
    if base is None:
        return _not_installed()
    cmd = base + args + ["--format", "json"]
    logger.info("Running: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": f"rea timed out after {timeout}s", "command": args[0]}
    except OSError as exc:
        return {"error": f"rea failed to start: {exc}", "command": args[0]}
    # Exit 0 = success (possibly partial), 3 = --fail_on threshold met.
    if proc.returncode not in (0, 3):
        return {
            "error": f"rea exited {proc.returncode}",
            "command": args[0],
            "stderr": (proc.stderr or proc.stdout or "")[-2000:],
        }
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {
            "error": "rea returned non-JSON output",
            "command": args[0],
            "raw_output": (proc.stdout or "")[:2000],
        }


# ---------------------------------------------------------------------------
# Artifact discovery
# ---------------------------------------------------------------------------

def _classify_file(path: str) -> Optional[str]:
    ext = os.path.splitext(path)[1].lower()
    if ext in _PACKAGE_EXTENSIONS:
        return _PACKAGE_EXTENSIONS[ext]
    if ext == ".class":
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError:
        return None
    for magic, kind in _NATIVE_MAGIC.items():
        if head.startswith(magic):
            if kind == "pe" and ext not in {".exe", ".dll", ".sys", ".node", ".efi", ".scr", ".ocx", ""}:
                # "MZ" is two bytes; only trust it with a PE-ish extension.
                return None
            return kind
    return None


def discover_artifacts(
    source_dir: str,
    max_artifacts: int = 50,
    min_bytes: int = 1024,
) -> List[Dict[str, Any]]:
    """Find shipped binaries and packages inside a checkout.

    Returns ``[{"path", "relpath", "kind", "bytes"}]`` sorted by size, largest
    first, capped at ``max_artifacts``. Symlinks are not followed.
    """
    source_dir = os.path.realpath(source_dir)
    found: List[Dict[str, Any]] = []
    for root, dirs, files in os.walk(source_dir, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < min_bytes:
                continue
            kind = _classify_file(path)
            if kind:
                found.append({
                    "path": path,
                    "relpath": os.path.relpath(path, source_dir),
                    "kind": kind,
                    "bytes": size,
                })
    found.sort(key=lambda a: a["bytes"], reverse=True)
    return found[:max_artifacts]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def audit_release_exposure(path: str, timeout: int = 600) -> Dict[str, Any]:
    """Run ``rea audit-release-exposure`` and keep only the parts we report.

    ``exposed`` checks become findings. ``unknown`` / ``not_assessed`` checks
    are kept separately as coverage gaps, never as findings.
    """
    path = os.path.realpath(path)
    if not os.path.exists(path):
        return {"error": f"Path not found: {path}"}
    data = _run_rea(["audit-release-exposure", path], timeout=timeout)
    if "error" in data:
        return data
    result = data.get("normalized_result") or {}
    checks = result.get("checks") or []
    exposed, gaps = [], []
    for check in checks:
        status = check.get("status")
        slim = {
            "id": check.get("id", ""),
            "status": status,
            "severity": check.get("severity"),
            "confidence": check.get("confidence"),
            "observation": check.get("observation"),
            "locations": [
                loc.get("path") for loc in (check.get("locations") or []) if loc.get("path")
            ][:10],
            "remediation": check.get("remediation"),
            "next_probe": check.get("next_probe"),
        }
        if status == "exposed":
            exposed.append(slim)
        elif status in ("unknown", "not_assessed"):
            gaps.append({k: slim[k] for k in ("id", "status", "next_probe")})
    return {
        "tool": "rea",
        "command": "audit-release-exposure",
        "path": path,
        "evidence_id": data.get("evidence_id"),
        "summary": result.get("summary"),
        "exposed": exposed,
        "coverage_gaps": gaps,
        "limitations": (result.get("limitations") or data.get("limitations") or [])[:5],
    }


def inspect_binary_hardening(path: str, timeout: int = 120) -> Dict[str, Any]:
    """Run ``rea inspect-binary-hardening`` on one native image."""
    path = os.path.realpath(path)
    if not os.path.isfile(path):
        return {"error": f"Not a file: {path}"}
    data = _run_rea(["inspect-binary-hardening", path], timeout=timeout)
    if "error" in data:
        return data
    result = data.get("normalized_result") or {}
    weaknesses: List[Dict[str, Any]] = []
    images = []
    for image in result.get("images") or []:
        images.append({
            "format": image.get("format"),
            "status": image.get("status"),
            "architecture": image.get("architecture"),
            "slice": image.get("slice"),
        })
        for row in image.get("rows") or []:
            weakness = hardening_weakness(row)
            if weakness:
                weakness["architecture"] = image.get("architecture")
                weaknesses.append(weakness)
    return {
        "tool": "rea",
        "command": "inspect-binary-hardening",
        "path": path,
        "format": result.get("format"),
        "evidence_id": data.get("evidence_id"),
        "images": images,
        "weaknesses": weaknesses,
    }


def hardening_weakness(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map one REA hardening row to a weakness, or None if it is fine/unknown."""
    prop = row.get("property", "")
    state = row.get("state")
    severity = None
    if prop in _HARDENING_WANTED and state in ("disabled", "partial"):
        severity = _HARDENING_WANTED[prop]
        if state == "partial" and severity != "info":
            severity = "info" if severity == "low" else "low"
    elif prop in _HARDENING_UNWANTED and state == "enabled":
        severity = _HARDENING_UNWANTED[prop]
    if severity is None:
        return None
    return {
        "property": prop,
        "state": state,
        "severity": severity,
        "confidence": row.get("confidence"),
        "basis": row.get("basis"),
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def scan(
    source_dir: str,
    max_artifacts: int = 50,
    timeout: int = 900,
    hardening: bool = True,
) -> Dict[str, Any]:
    """Full REA pass over a checkout.

    1. ``audit-release-exposure`` on the checkout root, plus each ASAR/APK
       found (an audit of a directory does not open nested packages).
    2. ``inspect-binary-hardening`` on each native image found.

    Returns normalized ``findings`` (one per exposed check / weak binary) in
    a shape close to the other SAST tools, plus the raw per-command results.
    """
    source_dir = os.path.realpath(source_dir)
    if not os.path.isdir(source_dir):
        return {"error": f"Not a directory: {source_dir}"}
    if not is_available():
        return {**_not_installed(), "source_dir": source_dir, "findings": [], "count": 0}

    artifacts = discover_artifacts(source_dir, max_artifacts=max_artifacts)
    audits: List[Dict[str, Any]] = []
    hardening_results: List[Dict[str, Any]] = []
    errors: List[str] = []

    audit_targets = [source_dir] + [a["path"] for a in artifacts if a["kind"] in ("asar", "apk")]
    for target in audit_targets:
        res = audit_release_exposure(target, timeout=timeout)
        if "error" in res:
            errors.append(f"audit {os.path.relpath(target, source_dir)}: {res['error']}")
            continue
        audits.append(res)

    if hardening:
        for art in artifacts:
            if art["kind"] not in ("elf", "pe", "macho"):
                continue
            res = inspect_binary_hardening(art["path"], timeout=min(timeout, 300))
            if "error" in res:
                errors.append(f"hardening {art['relpath']}: {res['error']}")
                continue
            hardening_results.append(res)

    findings = _findings_from(source_dir, audits, hardening_results)
    return {
        "tool": "rea",
        "source_dir": source_dir,
        "artifacts": [{k: a[k] for k in ("relpath", "kind", "bytes")} for a in artifacts],
        "findings": findings,
        "count": len(findings),
        "coverage_gaps": _dedupe(g["id"] for a in audits for g in a.get("coverage_gaps", [])),
        "errors": errors[:20],
        "audits": audits,
        "hardening": hardening_results,
    }


def _rel(source_dir: str, path: str) -> str:
    try:
        rel = os.path.relpath(path, source_dir)
    except ValueError:
        return path
    return path if rel.startswith("..") else rel


def _dedupe(items: Iterable[str]) -> List[str]:
    seen: List[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _findings_from(
    source_dir: str,
    audits: List[Dict[str, Any]],
    hardening_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for audit in audits:
        for check in audit.get("exposed", []):
            locations = [_rel(source_dir, p) for p in check.get("locations") or []]
            samples = ((check.get("observation") or {}).get("samples") or [])[:5]
            findings.append({
                "tool": "rea",
                "rule": f"rea.{check['id']}",
                "title": f"Release exposure: {check['id']}",
                "severity": check.get("severity") or "info",
                "confidence": check.get("confidence"),
                "file": locations[0] if locations else _rel(source_dir, audit["path"]),
                "locations": locations,
                "evidence": {
                    "audited_path": _rel(source_dir, audit["path"]),
                    # Samples are "path" or "rule.id /abs/path:line"; strip the checkout prefix.
                    "samples": [
                        s.replace(source_dir + os.sep, "") if isinstance(s, str) else s
                        for s in samples
                    ],
                    "counts": (check.get("observation") or {}).get("counts"),
                    "evidence_id": audit.get("evidence_id"),
                },
                "remediation": check.get("remediation"),
            })
    for res in hardening_results:
        weak = res.get("weaknesses") or []
        if not weak:
            continue
        top = max(weak, key=lambda w: _SEVERITY_RANK.get(w["severity"], 0))
        props = ", ".join(sorted({f"{w['property']}={w['state']}" for w in weak}))
        rel = _rel(source_dir, res["path"])
        findings.append({
            "tool": "rea",
            "rule": "rea.native.hardening",
            "title": f"Weak binary hardening: {rel}",
            "severity": top["severity"],
            "confidence": top.get("confidence"),
            "file": rel,
            "locations": [rel],
            "evidence": {
                "format": res.get("format"),
                "weaknesses": weak,
                "evidence_id": res.get("evidence_id"),
            },
            "remediation": f"Rebuild with the missing mitigations enabled ({props}).",
        })
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 0), reverse=True)
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Static REA pass over a checkout.")
    parser.add_argument("source_dir")
    parser.add_argument("--out", help="Write the JSON result to this file")
    parser.add_argument("--max-artifacts", type=int, default=50)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--no-hardening", action="store_true")
    args = parser.parse_args(argv)

    result = scan(
        args.source_dir,
        max_artifacts=args.max_artifacts,
        timeout=args.timeout,
        hardening=not args.no_hardening,
    )
    text = json.dumps(result, indent=2, default=str)
    if args.out:
        with open(args.out, "w") as fh:
            fh.write(text + "\n")
        print(f"rea: {result.get('count', 0)} findings -> {args.out}")
        if result.get("error"):
            print(f"rea: {result['error']} ({result.get('install_hint', '')})")
    else:
        print(text)
    return 1 if result.get("error") and "not installed" not in result["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
