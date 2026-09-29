"""Bounded CodeAgent: run a one-off HTTP/Python probe in a sandbox.

Not a Kali shell. The source is AST-checked, then executed in a subprocess
with a tiny allowlist (json/re/httpx/...) and DNS/host scope enforcement.
"""

from __future__ import annotations

import ast
import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
from typing import Any, Iterable, List, Sequence
from urllib.parse import urlparse

# Collaborator / OOB hosts specialists may hit to prove blind SSRF.
# Lictor still blocks metadata/localhost; this is the allowed SUBMIT path.
OOB_HOST_SUFFIXES = (
    "interact.sh",
    "oast.fun",
    "oast.pro",
    "oast.live",
    "oast.site",
    "oast.online",
    "oast.me",
    "oastify.com",
    "burpcollaborator.net",
    "projectdiscovery.io",
)

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

_OOB = json.loads(__OOB_JSON__)

def _host_ok(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for raw in list(_ALLOWED) + list(_OOB):
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

class http:
    get = staticmethod(get)
    post = staticmethod(post)
    request = staticmethod(request)

# User probe follows. Print JSON/text to stdout. Use httpx/http against in-scope
# hosts or Interactsh/OAST (never 169.254.169.254 / localhost — Lictor blocks those).
'''


def is_oob_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    for suf in OOB_HOST_SUFFIXES:
        if host == suf or host.endswith("." + suf):
            return True
    return False


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


def _prepare_probe(
    source: str,
    *,
    allowed_hosts: Sequence[str],
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> tuple[list[str], float, str, dict[str, str]] | dict[str, Any]:
    """Validate scope and source before either probe runner starts a process."""
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
        .replace("__OOB_JSON__", repr(json.dumps(list(OOB_HOST_SUFFIXES))))
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
    return hosts, timeout_sec, script, env


def run_custom_probe(
    source: str,
    *,
    allowed_hosts: Sequence[str],
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Synchronous runner for direct callers; the agent uses the async runner."""
    prepared = _prepare_probe(source, allowed_hosts=allowed_hosts, timeout_sec=timeout_sec)
    if isinstance(prepared, dict):
        return prepared
    hosts, timeout_sec, script, env = prepared
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


async def _kill_probe_process(process: asyncio.subprocess.Process | None) -> None:
    if process is None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.returncode is None:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        if process.returncode is None:
            process.kill()
    if process.returncode is None:
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            pass


async def run_custom_probe_async(
    source: str,
    *,
    allowed_hosts: Sequence[str],
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Run the agent's probe without blocking cancellation of its turn."""
    prepared = _prepare_probe(source, allowed_hosts=allowed_hosts, timeout_sec=timeout_sec)
    if isinstance(prepared, dict):
        return prepared
    hosts, timeout_sec, script, env = prepared
    path = None
    process = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix="_probe.py", delete=False) as fh:
            fh.write(script)
            path = fh.name
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-I", path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            cwd=tempfile.gettempdir(),
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout_sec + 2,
            )
        except asyncio.TimeoutError:
            await _kill_probe_process(process)
            return {"ok": False, "error": f"probe timed out after {timeout_sec}s",
                    "allowed_hosts": hosts}
    except asyncio.CancelledError:
        await asyncio.shield(_kill_probe_process(process))
        raise
    except OSError as exc:
        await _kill_probe_process(process)
        return {"ok": False, "error": f"failed to start sandbox: {exc}"}
    finally:
        if path:
            try:
                os.unlink(path)
            except OSError:
                pass
    return {
        "ok": process.returncode == 0,
        "exit_code": process.returncode,
        "stdout": stdout.decode("utf-8", errors="replace")[:MAX_OUTPUT_CHARS],
        "stderr": stderr.decode("utf-8", errors="replace")[:2000],
        "allowed_hosts": hosts,
    }
