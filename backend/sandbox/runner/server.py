"""Explorer sandbox runner: an authenticated exec API for one container.

The backend calls this API; the model never does. Each assessment gets a
workspace directory owned by its own unprivileged uid (20000-29999), so one
engagement cannot read another's files or process environment. Commands run
with resource limits, in their own process group, and are killed on timeout.

Network policy is not enforced here. The container entrypoint installs
iptables rules that let sandbox uids reach only the egress proxy, and the
proxy enforces scope. This process refuses to start if those rules are absent.

Endpoints (Authorization: Bearer $PROWL_SANDBOX_TOKEN):
  POST   /v1/exec       {workspace, kind: shell|python, source, timeout_sec, proxy_token}
  POST   /v1/files      {workspace, path, content}
  DELETE /v1/workspaces/<workspace>
  GET    /healthz
"""

from __future__ import annotations

import hmac
import json
import os
import re
import resource
import shutil
import signal
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WORK_ROOT = Path(os.environ.get("SANDBOX_WORK_ROOT", "/work"))
API_TOKEN = os.environ.get("PROWL_SANDBOX_TOKEN", "")
# The entrypoint resolves the proxy once (sandbox uids have no DNS) and
# exports its address; the hostname form is only a fallback.
EGRESS_PROXY = (os.environ.get("SANDBOX_EGRESS_ADDR")
                or os.environ.get("SANDBOX_EGRESS_PROXY", "prowl-sandbox-egress:8080"))
CA_BUNDLE = os.environ.get("SANDBOX_CA_BUNDLE", "/etc/prowl-sandbox/egress-ca.pem")
UID_BASE = 20000
UID_SLOTS = 10000
MAX_TIMEOUT = int(os.environ.get("SANDBOX_MAX_TIMEOUT_SEC", "600"))
OUTPUT_LIMIT = int(os.environ.get("SANDBOX_OUTPUT_LIMIT", str(64 * 1024)))
MAX_CONCURRENT = int(os.environ.get("SANDBOX_MAX_CONCURRENT", "8"))
MAX_SOURCE = 256 * 1024
PYTHON = os.environ.get("SANDBOX_PYTHON", "/opt/sandbox-venv/bin/python")
MAX_FILE = 4 * 1024 * 1024
WORKSPACE_RE = re.compile(r"^[a-f0-9]{32}$")
TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")

_slots = threading.BoundedSemaphore(MAX_CONCURRENT)
_uid_lock = threading.Lock()


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _workspace(name: str) -> Path:
    if not isinstance(name, str) or not WORKSPACE_RE.match(name):
        raise RequestError(400, "workspace must be 32 lowercase hex characters")
    return WORK_ROOT / name


def _uid_for(workspace: Path) -> int:
    """Return the workspace's uid, allocating an unused one on first use."""
    with _uid_lock:
        if workspace.exists():
            return workspace.stat().st_uid
        used = {p.stat().st_uid for p in WORK_ROOT.iterdir() if p.is_dir()}
        start = int(workspace.name[:8], 16) % UID_SLOTS
        for offset in range(UID_SLOTS):
            uid = UID_BASE + (start + offset) % UID_SLOTS
            if uid not in used:
                workspace.mkdir(mode=0o700)
                os.chown(workspace, uid, uid)
                return uid
        raise RequestError(503, "no free sandbox uid")


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_CPU, (MAX_TIMEOUT, MAX_TIMEOUT))
    resource.setrlimit(resource.RLIMIT_AS, (4 << 30, 4 << 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 << 20, 512 << 20))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _clip(data: bytes) -> dict:
    text = data[:OUTPUT_LIMIT].decode("utf-8", "replace")
    return {"text": text, "bytes": len(data), "truncated": len(data) > OUTPUT_LIMIT}


def run(body: dict) -> dict:
    workspace = _workspace(body.get("workspace"))
    kind = body.get("kind")
    source = body.get("source")
    token = body.get("proxy_token")
    if kind not in ("shell", "python"):
        raise RequestError(400, "kind must be shell or python")
    if not isinstance(source, str) or not source.strip() or len(source) > MAX_SOURCE:
        raise RequestError(400, "source must be a non-empty string under 256 KiB")
    if not isinstance(token, str) or not TOKEN_RE.match(token):
        raise RequestError(400, "proxy_token must be 32 lowercase hex characters")
    try:
        timeout = max(1, min(int(body.get("timeout_sec") or 60), MAX_TIMEOUT))
    except (TypeError, ValueError):
        raise RequestError(400, "timeout_sec must be an integer") from None
    uid = _uid_for(workspace)
    proxy = f"http://{token}:x@{EGRESS_PROXY}"
    env = {
        "HOME": str(workspace),
        "PATH": f"{Path(PYTHON).parent}:/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy,
        "http_proxy": proxy, "https_proxy": proxy, "ALL_PROXY": proxy,
        "NO_PROXY": "", "no_proxy": "",
        "SSL_CERT_FILE": CA_BUNDLE, "REQUESTS_CA_BUNDLE": CA_BUNDLE,
        "CURL_CA_BUNDLE": CA_BUNDLE, "NODE_EXTRA_CA_CERTS": CA_BUNDLE,
        "PYTHONUNBUFFERED": "1",
    }
    # Python source goes in on stdin: root never writes into a workspace the
    # sandbox uid controls, so a planted symlink cannot redirect the write.
    if kind == "python":
        argv = [PYTHON, "-"]
        stdin_data = source.encode()
    else:
        # Not a login shell: /etc/profile would reset PATH and drop the venv.
        argv = ["/bin/bash", "-c", source]
        stdin_data = b""

    def preexec() -> None:
        os.setsid()
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        _limits()

    if not _slots.acquire(timeout=30):
        raise RequestError(429, "sandbox is busy; retry shortly")
    started = time.monotonic()
    try:
        process = subprocess.Popen(  # noqa: S603 - the sandbox exists to run this
            argv, cwd=workspace, env=env, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=preexec,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=stdin_data, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
    finally:
        _slots.release()
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "duration_sec": round(time.monotonic() - started, 2),
        "stdout": _clip(stdout),
        "stderr": _clip(stderr),
    }


def write_file(body: dict) -> dict:
    workspace = _workspace(body.get("workspace"))
    path = body.get("path")
    content = body.get("content")
    if not isinstance(path, str) or not path or path.startswith("/") or "\x00" in path:
        raise RequestError(400, "path must be relative to the workspace")
    if not isinstance(content, str) or len(content.encode()) > MAX_FILE:
        raise RequestError(400, "content must be a string under 4 MiB")
    uid = _uid_for(workspace)
    target = (workspace / path).resolve()
    if workspace.resolve() not in target.parents:
        raise RequestError(400, "path escapes the workspace")
    # Create parents as the workspace uid so a symlink planted by sandbox code
    # cannot redirect a root-owned write.
    def preexec() -> None:
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    result = subprocess.run(  # noqa: S603
        [PYTHON, "-c",
         "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True, exist_ok=True);"
         " p.write_text(sys.stdin.read(), encoding='utf-8')", str(target)],
        input=content, text=True, capture_output=True, preexec_fn=preexec, timeout=30,
    )
    if result.returncode != 0:
        raise RequestError(400, "could not write file: " + result.stderr[-300:])
    return {"path": str(target.relative_to(workspace)), "bytes": len(content.encode())}


def delete_workspace(name: str) -> dict:
    workspace = _workspace(name)
    if workspace.exists():
        uid = workspace.stat().st_uid
        subprocess.run(["pkill", "-KILL", "-u", str(uid)], check=False)  # noqa: S603,S607
        shutil.rmtree(workspace, ignore_errors=True)
    return {"deleted": True}


class Handler(BaseHTTPRequestHandler):
    server_version = "prowl-sandbox/1"

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        return bool(API_TOKEN) and hmac.compare_digest(header, f"Bearer {API_TOKEN}")

    def _send(self, status: int, payload: dict) -> None:
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_FILE + 65536:
            raise RequestError(400, "invalid body length")
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            raise RequestError(400, "body must be JSON") from None
        if not isinstance(body, dict):
            raise RequestError(400, "body must be a JSON object")
        return body

    def _dispatch(self, method: str) -> None:
        if method == "GET" and self.path == "/healthz":
            return self._send(200, {"ok": True})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        try:
            if method == "POST" and self.path == "/v1/exec":
                return self._send(200, run(self._body()))
            if method == "POST" and self.path == "/v1/files":
                return self._send(200, write_file(self._body()))
            if method == "DELETE" and self.path.startswith("/v1/workspaces/"):
                return self._send(200, delete_workspace(self.path.rsplit("/", 1)[-1]))
            return self._send(404, {"error": "not found"})
        except RequestError as exc:
            return self._send(exc.status, {"error": str(exc)})

    def do_GET(self):  # noqa: N802
        self._dispatch("GET")

    def do_POST(self):  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self):  # noqa: N802
        self._dispatch("DELETE")

    def log_message(self, fmt, *args):  # keep commands out of container logs
        pass


def firewall_installed() -> bool:
    """The entrypoint's egress rules must exist before any command runs."""
    result = subprocess.run(  # noqa: S603,S607
        ["iptables", "-C", "OUTPUT", "-m", "owner", "--uid-owner",
         f"{UID_BASE}-{UID_BASE + UID_SLOTS - 1}", "-j", "PROWL_SANDBOX"],
        capture_output=True,
    )
    return result.returncode == 0


def main() -> None:
    if not API_TOKEN or len(API_TOKEN) < 32:
        raise SystemExit("PROWL_SANDBOX_TOKEN must be set (32+ characters)")
    if not firewall_installed():
        raise SystemExit("sandbox egress firewall is not installed; refusing to start")
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(WORK_ROOT, 0o711)
    server = ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("SANDBOX_PORT", "8090"))), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
