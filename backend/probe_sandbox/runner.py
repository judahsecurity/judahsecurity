"""probe-runner: executes model-written probe scripts with nothing to steal.

Runs on an internal Docker network whose only peer is probe-egress, so a
script's only way out is the per-job proxy credential it is handed. The server
process holds PROBE_RUNNER_TOKEN; each script runs as an unprivileged uid in
its own empty directory, with resource limits and a hard kill on timeout, and
cannot read the server's environment.
"""

from __future__ import annotations

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

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


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


def run_script(script: str, timeout: float, proxy_url: str, ca_pem: str = "") -> dict:
    workdir = tempfile.mkdtemp(prefix="probe-")
    try:
        path = os.path.join(workdir, "probe.py")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(script)
        ca_path = os.path.join(workdir, "proxy-ca.pem")
        with open(ca_path, "w", encoding="ascii") as handle:
            handle.write(ca_pem)
        if os.getuid() == 0:
            for item in (workdir, path, ca_path):
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
        }
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter, isolated container
            [sys.executable, "-I", path], cwd=workdir, env=env,
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
            return {"ok": False, "error": f"probe timed out after {timeout}s"}
        return {
            "ok": process.returncode == 0,
            "exit_code": process.returncode,
            "stdout": stdout.decode("utf-8", "replace")[:MAX_OUTPUT],
            "stderr": stderr.decode("utf-8", "replace")[:2000],
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
            script = str(req["script"])
            proxy_url = str(req["proxy_url"])
            timeout = max(3.0, min(float(req.get("timeout_sec") or 20), MAX_TIMEOUT))
            ca_pem = str(req.get("ca_pem") or "")
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "invalid job"})
            return
        if ca_pem and not ca_pem.startswith("-----BEGIN CERTIFICATE-----"):
            self._json(400, {"error": "invalid CA certificate"})
            return
        if not _slots.acquire(timeout=30):
            self._json(503, {"error": "runner busy"})
            return
        try:
            self._json(200, run_script(script, timeout, proxy_url, ca_pem))
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
