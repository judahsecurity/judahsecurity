"""probe-runner: executes model-written probe scripts with nothing to steal.

Runs on an internal Docker network whose only peer is probe-egress, so a
script's only way out is the per-job proxy credential it is handed. The server
process holds PROBE_RUNNER_TOKEN; each script runs as an unprivileged uid in
its own empty directory, with resource limits and a hard kill on timeout, and
cannot read the server's environment.
"""

from __future__ import annotations

import glob
import hashlib
import hmac
import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUNNER_TOKEN = os.environ.get("PROBE_RUNNER_TOKEN", "")
PORT = int(os.environ.get("PROBE_RUNNER_PORT", "8000"))
PROBE_UID = int(os.environ.get("PROBE_UID", "65534"))
PROBE_GID = int(os.environ.get("PROBE_GID", "65534"))
MAX_CONCURRENT = int(os.environ.get("PROBE_MAX_CONCURRENT", "4"))
MAX_SCRIPT_BYTES = 200_000
MAX_OUTPUT = 20_000
MAX_TIMEOUT = 45.0
MAX_SHELL_TIMEOUT = 120.0
MAX_COMMAND_BYTES = 8000
SHELL = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

# The image this runner was built from, pinned by the deployment (compose sets
# it to the image digest). Part of the identity a job's provenance is bound to.
IMAGE_REF = os.environ.get("PROBE_IMAGE_REF", "")
# Tools whose presence and version define the toolbox a job ran against. A job
# cannot add to this set (unprivileged uid, read-only image), and any change to
# the inventory below changes the fingerprint, so a tool that "appeared" shows.
_INVENTORY_TOOLS = (
    "bash", "sh", "curl", "wget", "jq", "nmap", "ffuf", "sqlmap",
    "nc", "proxychains4", "python3",
)


def _tool_version(name: str) -> str:
    path = shutil.which(name)
    if not path:
        return "absent"
    for flag in ("--version", "-version", "-V"):
        try:
            out = subprocess.run([path, flag], capture_output=True, text=True,
                                 timeout=5)
            line = (out.stdout or out.stderr or "").strip().splitlines()
            if line:
                return line[0][:120]
        except (OSError, subprocess.SubprocessError):
            continue
    return "present"


def _path_executables() -> list:
    """Every executable on PATH, so an added binary changes the inventory hash."""
    names = set()
    for directory in ("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin", "/usr/sbin", "/sbin"):
        try:
            for entry in glob.glob(os.path.join(directory, "*")):
                if os.path.isfile(entry) and os.access(entry, os.X_OK):
                    names.add(os.path.basename(entry))
        except OSError:
            continue
    return sorted(names)


def _build_identity() -> dict:
    tools = {name: _tool_version(name) for name in _INVENTORY_TOOLS}
    executables = _path_executables()
    material = json.dumps({"image_ref": IMAGE_REF, "tools": tools,
                           "executables": executables}, sort_keys=True).encode()
    return {
        "image_ref": IMAGE_REF,
        "tools": tools,
        "executable_count": len(executables),
        "executables_sha256": hashlib.sha256(
            "\n".join(executables).encode()).hexdigest(),
        "fingerprint": hashlib.sha256(material).hexdigest(),
        "python": sys.version.split()[0],
    }


# Computed once at startup: the toolbox is immutable for the process lifetime.
RUNNER_IDENTITY = _build_identity()


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _drop_privileges() -> None:
    os.setsid()
    _limits()
    if os.getuid() == 0:
        os.setgroups([])
        os.setgid(PROBE_GID)
        os.setuid(PROBE_UID)


def _proxychains_conf(socks_url: str) -> str:
    """proxychains-ng config for socks5://job:token@host:port (host as an IP)."""
    from urllib.parse import urlsplit
    import socket

    parts = urlsplit(socks_url)
    if parts.scheme != "socks5" or not parts.hostname or not parts.port:
        return ""
    try:
        ip = socket.gethostbyname(parts.hostname)
    except OSError:
        return ""
    return (
        "strict_chain\nproxy_dns\nquiet_mode\ntcp_read_time_out 15000\n"
        "tcp_connect_time_out 8000\n[ProxyList]\n"
        f"socks5 {ip} {parts.port} {parts.username or ''} {parts.password or ''}\n"
    )


def run_script(script: str, timeout: float, proxy_url: str, ca_pem: str = "",
               *, command: str = "", socks_url: str = "") -> dict:
    """Run a Python probe (script) or a shell command (command) as PROBE_UID."""
    workdir = tempfile.mkdtemp(prefix="probe-")
    try:
        path = os.path.join(workdir, "probe.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script or "")
        ca_path = os.path.join(workdir, "proxy-ca.pem")
        with open(ca_path, "w", encoding="ascii") as handle:
            handle.write(ca_pem)
        chains_path = os.path.join(workdir, "proxychains.conf")
        chains = _proxychains_conf(socks_url) if socks_url else ""
        with open(chains_path, "w", encoding="ascii") as handle:
            handle.write(chains)
        if os.getuid() == 0:
            for item in (workdir, path, ca_path, chains_path):
                os.chown(item, PROBE_UID, PROBE_GID)
        # All TLS goes through probe-egress, which re-signs with its CA, so the
        # proxy CA is the only trust root a script needs. Each toolchain reads
        # a different variable.
        trust = {
            "SSL_CERT_FILE": ca_path, "REQUESTS_CA_BUNDLE": ca_path,
            "CURL_CA_BUNDLE": ca_path, "NODE_EXTRA_CA_CERTS": ca_path,
            "GIT_SSL_CAINFO": ca_path,
        } if ca_pem else {}
        env = {**trust,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": workdir,
            "PYTHONDONTWRITEBYTECODE": "1",
            "HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "ALL_PROXY": proxy_url,
            "http_proxy": proxy_url, "https_proxy": proxy_url, "all_proxy": proxy_url,
            "NO_PROXY": "", "no_proxy": "",
            # For tools that ignore the proxy variables (ffuf -x, sqlmap --proxy).
            "PROBE_PROXY": proxy_url,
            # Raw TCP (nmap -sT -Pn, nc, protocol clients): prefix with proxychains4.
            **({"PROBE_SOCKS": socks_url, "PROXYCHAINS_CONF_FILE": chains_path} if chains else {}),
            "TERM": "dumb",
        }
        argv = [SHELL, "-c", command] if command else [sys.executable, "-I", path]
        process = subprocess.Popen(  # noqa: S603 - isolated container, unprivileged uid
            argv, cwd=workdir, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=_drop_privileges,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout + 2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.communicate()
            return {"ok": False, "error": f"probe timed out after {timeout}s",
                    "runner_identity": RUNNER_IDENTITY}
        return {
            "ok": process.returncode == 0,
            "exit_code": process.returncode,
            "stdout": stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
            "stderr": stderr.decode("utf-8", "replace")[:2000],
            "runner_identity": RUNNER_IDENTITY,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "probe-runner"

    def log_message(self, *_args) -> None:
        return

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/identity":
            self._json(200, {"ok": True, "runner_identity": RUNNER_IDENTITY})
            return
        self._json(200 if self.path == "/healthz" else 404, {"ok": self.path == "/healthz"})

    def do_POST(self) -> None:
        if self.path != "/run":
            self._json(404, {"error": "not found"})
            return
        supplied = self.headers.get("Authorization", "")
        if not hmac.compare_digest(supplied.encode(), f"Bearer {RUNNER_TOKEN}".encode()):
            self._json(401, {"error": "unauthorized"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_SCRIPT_BYTES + 4096:
            self._json(413, {"error": "bad request size"})
            return
        try:
            req = json.loads(self.rfile.read(length))
            command = str(req.get("command") or "")
            script = "" if command else str(req["script"])
            proxy_url = str(req["proxy_url"])
            ceiling = MAX_SHELL_TIMEOUT if command else MAX_TIMEOUT
            timeout = max(3.0, min(float(req.get("timeout_sec") or 20), ceiling))
            ca_pem = str(req.get("ca_pem") or "")
            socks_url = str(req.get("socks_url") or "")
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "invalid job"})
            return
        if len(command.encode()) > MAX_COMMAND_BYTES:
            self._json(413, {"error": "command too long"})
            return
        if ca_pem and not ca_pem.startswith("-----BEGIN CERTIFICATE-----"):
            self._json(400, {"error": "invalid CA certificate"})
            return
        if not _slots.acquire(timeout=30):
            self._json(503, {"error": "runner busy"})
            return
        try:
            self._json(200, run_script(script, timeout, proxy_url, ca_pem, command=command, socks_url=socks_url))
        finally:
            _slots.release()


def main() -> None:
    if len(RUNNER_TOKEN) < 24:
        sys.exit("PROBE_RUNNER_TOKEN must be at least 24 characters")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
