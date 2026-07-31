"""
Target lifecycle management for benchmarking.

Many benchmark corpora ship as self-contained Docker apps (OWASP Juice Shop,
DVWA, the XBOW/XBEN CTF challenges, ...). This module optionally stands a
target up before scanning, waits for it to become ready, and tears it down
afterward.

A target's ``setup`` block in the ground-truth JSON may contain:

    "setup": {
      "up":        "<shell command to start the target>",
      "down":      "<shell command to stop/remove the target>",
      "ready_url": "http://localhost:3000/",   # explicit readiness URL, or
      "compose_file": "path/to/docker-compose.yml",  # discover the published
      "container_port": 80,                     # host port for this container port
      "ready_timeout": 120
    }

Everything (command execution, port discovery, HTTP probing) is injectable so
the manager is fully testable without Docker or network.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional
from urllib.error import URLError
from urllib.request import urlopen

# (command, timeout) -> (return_code, combined_output)
CommandRunner = Callable[[str, int], "tuple[int, str]"]
# (url) -> reachable?
HttpProbe = Callable[[str], bool]


def _default_command_runner(command: str, timeout: int) -> "tuple[int, str]":
    proc = subprocess.run(
        command, shell=True, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout or ""


def _default_http_probe(url: str) -> bool:
    try:
        with urlopen(url, timeout=5) as resp:  # noqa: S310 (benchmark localhost)
            return resp.status < 500
    except URLError:
        return False
    except Exception:
        return False


@dataclass
class SetupResult:
    ok: bool
    target_url: Optional[str]
    detail: str = ""


class TargetManager:
    """Brings dockerized benchmark targets up and down."""

    def __init__(
        self,
        command_runner: CommandRunner = _default_command_runner,
        http_probe: HttpProbe = _default_http_probe,
        poll_interval: float = 2.0,
    ):
        self.run = command_runner
        self.probe = http_probe
        self.poll_interval = poll_interval

    def setup(self, spec: Dict) -> SetupResult:
        """Start a target and return its resolved, ready URL."""
        setup = spec.get("setup") or {}
        up_cmd = setup.get("up") or setup.get("docker")
        if not up_cmd:
            # Nothing to stand up — assume the target is already reachable.
            return SetupResult(ok=True, target_url=spec.get("target"), detail="no-op")

        rc, out = self.run(up_cmd, setup.get("up_timeout", 600))
        if rc != 0:
            return SetupResult(ok=False, target_url=None, detail=f"up failed: {out[-500:]}")

        target_url = self._resolve_url(spec, setup)
        if not target_url:
            return SetupResult(ok=False, target_url=None, detail="could not resolve target URL")

        ready = self._wait_ready(
            setup.get("ready_url") or target_url,
            timeout=setup.get("ready_timeout", 120),
        )
        return SetupResult(
            ok=ready,
            target_url=target_url,
            detail="ready" if ready else "target did not become ready in time",
        )

    def teardown(self, spec: Dict) -> None:
        setup = spec.get("setup") or {}
        down_cmd = setup.get("down") or setup.get("teardown")
        if down_cmd:
            try:
                self.run(down_cmd, setup.get("down_timeout", 120))
            except Exception:
                pass  # teardown failures shouldn't fail the benchmark

    # -- helpers --------------------------------------------------------
    def _resolve_url(self, spec: Dict, setup: Dict) -> Optional[str]:
        # 1) explicit target URL wins
        if spec.get("target"):
            return spec["target"]
        # 2) dynamic docker-compose published-port discovery
        compose_file = setup.get("compose_file")
        container_port = setup.get("container_port")
        if compose_file and container_port:
            port = self._discover_compose_port(compose_file, int(container_port))
            if port:
                return f"http://localhost:{port}/"
        return setup.get("ready_url")

    def _discover_compose_port(self, compose_file: str, container_port: int) -> Optional[int]:
        rc, out = self.run(
            f"docker compose -f {compose_file} ps --format json", 30
        )
        if rc != 0 or not out.strip():
            return None
        # `docker compose ps --format json` emits either a JSON array or
        # newline-delimited JSON objects depending on version.
        entries = []
        text = out.strip()
        try:
            parsed = json.loads(text)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        for entry in entries:
            for pub in entry.get("Publishers", []) or []:
                if pub.get("TargetPort") == container_port and pub.get("PublishedPort"):
                    return int(pub["PublishedPort"])
        return None

    def _wait_ready(self, url: str, timeout: int) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.probe(url):
                return True
            time.sleep(self.poll_interval)
        return self.probe(url)
