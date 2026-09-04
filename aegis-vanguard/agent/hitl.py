"""
HITL — human-in-the-loop steering for the autonomous fireteam.

CAI's signature UX lets an operator interrupt a running agent, inject guidance,
and let it continue. Our autonomous `run_pentest.py` only had
``KeyboardInterrupt`` → abort. This adds mid-run steering: between ReAct turns
the runner polls a control channel; a pending operator directive is injected
into the live conversation as an ``OPERATOR DIRECTIVE`` so the agent adapts its
plan without losing context — matching the runbook's "you are the operator"
posture.

Two non-blocking sources, both headless-friendly (the container may have no TTY):
  * **In-memory queue** — ``submit(text)``; used programmatically and in tests.
  * **File channel** — poll a path (``AEGIS_HITL_FILE``); an operator (or a
    SIGINT wrapper) writes a directive to the file and the runner picks it up
    at the next turn boundary, then clears it.

``poll()`` never blocks and never raises — steering must never stall or crash a
run.
"""
from __future__ import annotations

import logging
import os
import threading
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional

logger = logging.getLogger("agent.hitl")


class HITLController:
    """Non-blocking operator control channel for a running agent loop."""

    def __init__(self, file_path: Optional[str] = None):
        self._queue: Deque[str] = deque()
        self._lock = threading.Lock()
        self._file = Path(file_path) if file_path else None

    # ---- producer side -------------------------------------------------

    def submit(self, directive: str) -> None:
        """Queue a directive for the next turn boundary (programmatic/tests)."""
        directive = (directive or "").strip()
        if directive:
            with self._lock:
                self._queue.append(directive)

    # ---- consumer side (called by the runner) --------------------------

    def poll(self) -> Optional[str]:
        """Return the next pending directive, or None. Non-blocking; never raises.

        Drains the in-memory queue first, then the file channel (which is
        cleared once read so a directive fires exactly once)."""
        with self._lock:
            if self._queue:
                return self._queue.popleft()
        return self._read_file()

    def poll_all(self) -> List[str]:
        """Drain and return every pending directive (queue + file)."""
        out: List[str] = []
        with self._lock:
            while self._queue:
                out.append(self._queue.popleft())
        f = self._read_file()
        if f:
            out.append(f)
        return out

    def _read_file(self) -> Optional[str]:
        if not self._file:
            return None
        try:
            if not self._file.exists():
                return None
            text = self._file.read_text(encoding="utf-8").strip()
            if not text:
                return None
            # Clear so the directive fires exactly once.
            self._file.write_text("", encoding="utf-8")
            return text
        except Exception as exc:  # never let steering break a run
            logger.warning("hitl: could not read control file %s — %s",
                           self._file, exc)
            return None


def from_env() -> Optional[HITLController]:
    """Build a controller if HITL is enabled via env, else None.

    Enabled when ``AEGIS_HITL`` is truthy or ``AEGIS_HITL_FILE`` is set. The
    file channel lets an operator steer a headless/container run:
        echo "focus on the /admin API, skip subdomain enum" >> $AEGIS_HITL_FILE
    """
    file_path = os.environ.get("AEGIS_HITL_FILE") or ""
    enabled = os.environ.get("AEGIS_HITL", "").lower() in ("1", "true", "yes")
    if not enabled and not file_path:
        return None
    if file_path:
        try:  # make sure the path exists so operators can write to it
            Path(file_path).touch(exist_ok=True)
        except Exception as exc:
            logger.warning("hitl: could not create control file %s — %s",
                           file_path, exc)
    logger.info("hitl: operator steering enabled (file=%s)", file_path or "<none>")
    return HITLController(file_path or None)


def format_directive(directive: str) -> str:
    """Render a directive as the injected user-turn text."""
    return (
        "OPERATOR DIRECTIVE (mid-run human steering): "
        f"{directive.strip()}\n"
        "Treat this as an instruction from your authorized operator. Adjust "
        "your plan and priorities for the remaining steps accordingly."
    )


__all__ = ["HITLController", "from_env", "format_directive"]
