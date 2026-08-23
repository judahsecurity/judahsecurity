"""Bounded CodeAgent: run a one-off HTTP/Python probe in a sandbox.

Not a Kali shell. The source is AST-checked, then executed in a subprocess
with a tiny allowlist (json/re/httpx/...) and DNS/host scope enforcement.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Iterable, List, Sequence
from urllib.parse import urlparse

ALLOWED_MODULES = {
    "json",
    "re",
    "time",
    "math",
    "base64",
    "hashlib",
    "hmac",
    "datetime",
    "collections",
    "typing",
    "decimal",
    "uuid",
    "httpx",
    "urllib",
}
FORBIDDEN_NAMES = {
    "eval",
    "exec",
    "compile",
    "open",
    "__import__",
    "breakpoint",
    "exit",
    "quit",
    "input",
    "memoryview",
    "globals",
    "locals",
    "vars",
    "dir",
    "getattr",
    "setattr",
    "delattr",
    "classmethod",
    "staticmethod",
    "type",
}
MAX_SOURCE_CHARS = 12_000
DEFAULT_TIMEOUT_SEC = 20
MAX_OUTPUT_CHARS = 20_000

_RUNNER = r'''
import json, re, time, math, base64, hashlib, hmac, datetime, collections, typing, decimal, uuid, sys
from urllib.parse import urlparse, urljoin, parse_qs, quote, unquote
import httpx

_ALLOWED = json.loads(__ALLOWED_JSON__)
_TIMEOUT = float(__TIMEOUT__)

def _host_ok(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for raw in _ALLOWED:
        allowed = (raw or "").lower().lstrip(".").rstrip(".")
        if not allowed:
            continue
        if host == allowed or host.endswith("." + allowed):
            return True
    return False

class _ScopedClient(httpx.Client):
    def request(self, method, url, **kwargs):
        host = (urlparse(str(url)).hostname or "").lower()
        if not _host_ok(host):
            raise PermissionError(f"host not in engagement scope: {host}")
        kwargs.setdefault("timeout", _TIMEOUT)
        kwargs.setdefault("follow_redirects", True)
        return super().request(method, url, **kwargs)

def get(url, **kw):
    with _ScopedClient() as c:
        return c.get(url, **kw)

def post(url, **kw):
    with _ScopedClient() as c:
        return c.post(url, **kw)

def request(method, url, **kw):
    with _ScopedClient() as c:
        return c.request(method, url, **kw)

httpx.Client = _ScopedClient
httpx.get = get
httpx.post = post
httpx.request = request
httpx.put = lambda url, **kw: request("PUT", url, **kw)
httpx.patch = lambda url, **kw: request("PATCH", url, **kw)
httpx.delete = lambda url, **kw: request("DELETE", url, **kw)
httpx.head = lambda url, **kw: request("HEAD", url, **kw)
httpx.options = lambda url, **kw: request("OPTIONS", url, **kw)

# User probe follows. Print JSON/text to stdout.
'''


def _normalize_hosts(hosts: Iterable[str]) -> List[str]:
    out: List[str] = []
    for raw in hosts or []:
        text = (raw or "").strip()
        if not text:
            continue
        if "://" in text:
            host = urlparse(text).hostname or ""
        else:
            host = text.split("/")[0].split(":")[0]
        host = host.lower().lstrip(".").rstrip(".")
        if host and host not in out:
            out.append(host)
    return out


def validate_probe_source(source: str) -> List[str]:
    errors: List[str] = []
    if not (source or "").strip():
        return ["source is empty"]
    if len(source) > MAX_SOURCE_CHARS:
        return [f"source exceeds {MAX_SOURCE_CHARS} characters"]
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [f"syntax error: {exc}"]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = (alias.name or "").split(".")[0]
                if root not in ALLOWED_MODULES:
                    errors.append(f"import not allowed: {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root = mod.split(".")[0]
            if root not in ALLOWED_MODULES:
                errors.append(f"from-import not allowed: {mod or '*'}")
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in FORBIDDEN_NAMES:
                errors.append(f"builtin not allowed: {node.id}")
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                errors.append(f"dunder access not allowed: {node.attr}")
    # de-dupe, keep order
    seen = set()
    uniq = []
    for err in errors:
        if err not in seen:
            seen.add(err)
            uniq.append(err)
    return uniq


def run_custom_probe(
    source: str,
    *,
    allowed_hosts: Sequence[str],
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Validate and run the probe. Never raises into the agent loop."""
    hosts = _normalize_hosts(allowed_hosts)
    if not hosts:
        return {
            "ok": False,
            "error": "No in-scope hosts. Pass allowed_hosts or set a primary target first.",
        }
    blocked = validate_probe_source(source)
    if blocked:
        return {"ok": False, "error": "Sandbox rejected source", "violations": blocked}

    timeout_sec = max(3.0, min(float(timeout_sec or DEFAULT_TIMEOUT_SEC), 45.0))
    prelude = (
        _RUNNER.replace("__ALLOWED_JSON__", repr(json.dumps(hosts)))
        .replace("__TIMEOUT__", repr(timeout_sec))
    )
    body = textwrap.dedent(source).strip() + "\n"
    script = prelude + "\n" + body

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PYTHONPATH": "",
        "PYTHONDONTWRITEBYTECODE": "1",
        "HTTP_PROXY": "",
        "HTTPS_PROXY": "",
        "ALL_PROXY": "",
    }
    try:
        with tempfile.NamedTemporaryFile("w", suffix="_probe.py", delete=False) as fh:
            fh.write(script)
            path = fh.name
        try:
            proc = subprocess.run(  # noqa: S603 — fixed interpreter, AST-gated source
                [sys.executable, "-I", path],
                capture_output=True,
                text=True,
                timeout=timeout_sec + 2,
                env=env,
                cwd=tempfile.gettempdir(),
            )
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"probe timed out after {timeout_sec}s", "allowed_hosts": hosts}
    except OSError as exc:
        return {"ok": False, "error": f"failed to start sandbox: {exc}"}

    stdout = (proc.stdout or "")[:MAX_OUTPUT_CHARS]
    stderr = (proc.stderr or "")[:2000]
    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "allowed_hosts": hosts,
    }
