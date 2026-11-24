"""Offline Python for specialists: decode, compute, generate payloads.

Fixed probes cover known bug classes; much attack work is glue in between:
decoding a token, reversing an encoding chain, computing a signature,
generating a payload list. ``run_sandboxed_script`` runs model-written Python
for that, with no way to reach the network or the host:

* new user, mount and network namespaces (``unshare -rnm``) and a chroot
  into a throwaway root holding only read-only ``/usr`` and ``/lib`` plus the
  run's scratch folder: no network interfaces, and none of the host's own
  files (application code, configuration, secrets) are visible, even to
  native code. The run is refused if this is unavailable, unless the operator
  allows the weaker isolation explicitly;
* an audit hook installed before the script runs (it cannot be removed)
  that blocks sockets, subprocesses, exec/fork, ctypes/native loading, and
  file access outside the run's scratch folder and the standard library;
* ``-I -S``: no site-packages, user paths or environment;
* CPU, memory, file-size, process and file-descriptor limits, a wall-clock
  timeout that kills the process group, an empty environment, and a fresh
  temporary folder deleted afterwards;
* bounded code, input and output sizes.

Requests to the target still go through Prowl's scoped probe tools.
"""

from __future__ import annotations

import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

MAX_CODE_BYTES = 20_000
MAX_INPUT_BYTES = 200_000
MAX_OUTPUT_BYTES = 20_000
MAX_TIMEOUT = 20
MEMORY_BYTES = 512 * 1024 * 1024

_BOOTSTRAP = r'''
import os, sys
ROOT = os.path.realpath(os.getcwd())
LIBS = tuple(sorted({os.path.realpath(p) for p in (sys.prefix, sys.base_prefix,
                                                      sys.exec_prefix, sys.base_exec_prefix)}))
BLOCK_PREFIX = ("socket.", "subprocess.", "os.exec", "os.posix_spawn", "os.spawn",
                "os.fork", "os.forkpty", "os.system", "os.kill", "os.putenv",
                "ctypes.", "_ctypes.", "msvcrt.", "winreg.", "pty.", "fcntl.",
                "mmap.", "sys.addaudithook", "sys.setprofile", "sys.settrace",
                "os.setuid", "os.chroot", "shutil.", "urllib.", "http.", "ftplib.",
                "smtplib.", "imaplib.", "poplib.", "nntplib.", "telnetlib.",
                "webbrowser.", "os.startfile", "resource.setrlimit", "gc.get_referrers")
PATH_EVENTS = {"open", "os.listdir", "os.scandir", "os.chdir", "os.remove", "os.rename",
               "os.rmdir", "os.mkdir", "os.symlink", "os.link", "os.truncate",
               "os.chmod", "os.chown", "os.utime", "glob.glob", "shutil.rmtree"}

def inside(path, roots):
    try:
        real = os.path.realpath(os.fsdecode(path) if not isinstance(path, int) else ROOT)
    except Exception:
        return False
    return any(real == r or real.startswith(r + os.sep) for r in roots)

BLOCKED_MODULES = {"_posixsubprocess", "subprocess", "_socket", "socket", "ssl", "_ssl",
                   "ctypes", "_ctypes", "mmap", "fcntl", "pty", "termios", "resource",
                   "multiprocessing", "_multiprocessing", "_posixshmem", "asyncio",
                   "concurrent", "selectors", "select", "signal", "_signal", "faulthandler",
                   "_tracemalloc", "gc", "_testcapi", "_testinternalcapi", "_xxsubinterpreters",
                   "_interpreters", "readline", "_winapi", "winreg", "nt"}

def hook(event, args):
    if event == "import" and args:
        name = str(args[0] or "")
        if name.split(".")[0] in BLOCKED_MODULES:
            raise PermissionError(f"sandbox: import {name} is not allowed")
        filename = args[1] if len(args) > 1 else None
        if filename and inside(filename, (ROOT,)) and os.path.basename(str(filename)) != "main.py":
            raise PermissionError("sandbox: importing code written by the script is not allowed")
        search = args[2] if len(args) > 2 and isinstance(args[2], list) else sys.path
        if any(entry in ("", ".") or (isinstance(entry, str) and inside(entry, (ROOT,)))
               for entry in search):
            raise PermissionError("sandbox: importing from the run folder is not allowed")
        return
    if event.startswith(BLOCK_PREFIX):
        raise PermissionError(f"sandbox: {event} is not allowed")
    if event in PATH_EVENTS and args:
        target = args[0]
        if isinstance(target, int):
            return
        writes = event != "open" and event not in {"os.listdir", "os.scandir", "glob.glob"}
        if event == "open" and len(args) > 1 and isinstance(args[1], str):
            writes = any(c in args[1] for c in "wax+")
        if event == "open" and len(args) > 2 and isinstance(args[2], int):
            writes = writes or bool(args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
        roots = (ROOT,) if writes or event == "os.chdir" else (ROOT,) + LIBS
        if not inside(target, roots):
            raise PermissionError(f"sandbox: {event} outside the run folder")

sys.addaudithook(hook)
del hook
source = open("main.py", encoding="utf-8").read()
code = compile(source, "main.py", "exec")
del source
exec(code, {"__name__": "__main__", "__builtins__": __builtins__})
'''


def _limits(timeout: int):
    def apply() -> None:
        os.setsid()
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 1))
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_BYTES, MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (5 * 1024 * 1024, 5 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _interpreter() -> str:
    return os.path.realpath(sys.executable)


def _system_dirs() -> list[str]:
    return [d for d in ("/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin")
            if os.path.isdir(d) and not os.path.islink(d)]


def jail_available() -> bool:
    """unshare + bind mounts + chroot work, and Python lives under /usr."""
    unshare, chroot = shutil.which("unshare"), shutil.which("chroot")
    if not unshare or not chroot or not _interpreter().startswith("/usr/"):
        return False
    if not os.path.realpath(sys.base_prefix).startswith("/usr"):
        return False
    try:
        return subprocess.run(
            [unshare, "-rnm", "--fork", "sh", "-c",
             "mount --bind -o ro /usr /usr && true"],
            capture_output=True, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def network_isolation_available() -> bool:
    unshare = shutil.which("unshare")
    if not unshare:
        return False
    try:
        return subprocess.run([unshare, "-rn", "true"], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _jail_command(root: str) -> list[str]:
    """Mount the system dirs read-only into ``root`` and run Python chrooted."""
    import shlex

    mounts = []
    for directory in ("/bin", "/sbin", "/lib", "/lib64", "/lib32"):
        # Merged-/usr systems link these into /usr; mirror the link.
        if os.path.islink(directory):
            link = os.path.join(root, directory.lstrip("/"))
            if not os.path.lexists(link):
                os.symlink(os.readlink(directory), link)
    for directory in _system_dirs():
        target = os.path.join(root, directory.lstrip("/"))
        os.makedirs(target, exist_ok=True)
        mounts.append(f"mount --bind {shlex.quote(directory)} {shlex.quote(target)}")
        mounts.append(f"mount -o remount,bind,ro {shlex.quote(target)} 2>/dev/null || true")
    inner = " ".join(shlex.quote(part) for part in (
        _interpreter(), "-I", "-S", "-B", "/boot.py",
    ))
    script = "set -e; " + "; ".join(mounts) + (
        f"; exec {shlex.quote(shutil.which('chroot') or 'chroot')} {shlex.quote(root)} "
        f"/bin/sh -c {shlex.quote('cd /work && exec ' + inner)}"
    )
    return [shutil.which("unshare") or "unshare", "-rnm", "--fork", "sh", "-c", script]


def _cap(data: bytes) -> tuple[str, bool]:
    truncated = len(data) > MAX_OUTPUT_BYTES
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), truncated


def run_python(code: str, stdin: str = "", timeout: int = 10,
               *, allow_weak_isolation: bool = False) -> dict[str, Any]:
    """Run ``code`` offline; returns stdout, stderr, exit code and isolation."""
    if not isinstance(code, str) or not code.strip():
        raise ValueError("Provide Python code")
    if len(code.encode()) > MAX_CODE_BYTES:
        raise ValueError(f"Code is limited to {MAX_CODE_BYTES} bytes")
    stdin_bytes = (stdin or "").encode()
    if len(stdin_bytes) > MAX_INPUT_BYTES:
        raise ValueError(f"Input is limited to {MAX_INPUT_BYTES} bytes")
    timeout = max(1, min(int(timeout or 10), MAX_TIMEOUT))
    jail = jail_available()
    netns = jail or network_isolation_available()
    if not jail and not allow_weak_isolation:
        raise RuntimeError("Script isolation (unshare + chroot) is unavailable on this worker")
    if not netns and not allow_weak_isolation:
        raise RuntimeError("Network isolation (unshare -rn) is unavailable on this worker")
    folder = tempfile.mkdtemp(prefix="prowl-script-")
    try:
        work = os.path.join(folder, "work") if jail else folder
        os.makedirs(work, exist_ok=True)
        with open(os.path.join(work, "main.py"), "w", encoding="utf-8") as handle:
            handle.write(code)
        if jail:
            with open(os.path.join(folder, "boot.py"), "w", encoding="utf-8") as handle:
                handle.write(_BOOTSTRAP)
            command = _jail_command(folder)
        else:
            command = [sys.executable, "-I", "-S", "-B", "-c", _BOOTSTRAP]
            if netns:
                command = [shutil.which("unshare") or "unshare", "-rn", *command]
        started = time.monotonic()
        process = subprocess.Popen(
            command, cwd=work, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8"},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            preexec_fn=_limits(timeout), close_fds=True,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(stdin_bytes, timeout=timeout + 2)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            stdout, stderr = process.communicate()
        out, out_truncated = _cap(stdout)
        err, err_truncated = _cap(stderr)
        return {
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "stdout": out,
            "stderr": err,
            "truncated": out_truncated or err_truncated,
            "seconds": round(time.monotonic() - started, 3),
            "isolation": ("jail+netns+audit" if jail else
                          "netns+audit" if netns else "audit_only"),
        }
    finally:
        shutil.rmtree(folder, ignore_errors=True)
