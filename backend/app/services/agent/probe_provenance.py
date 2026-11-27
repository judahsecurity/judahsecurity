"""Provenance receipts for sandbox jobs: who ran what, against which toolbox.

The offensive-framework comparison asks a pointed question: if a tool appears
halfway through a job, can you prove which session introduced it? For Aegis the
answer is structural. The probe sandbox is a fixed image an unprivileged job
cannot write to, so no tool is added mid-job — and this module proves it:

- The runner reports its own immutable toolbox identity (image reference, the
  version of each core tool, and a hash over every executable on PATH), built
  once at startup. See ``probe_sandbox/runner.py``.
- Each sandbox job (shell command or probe script) gets a signed receipt that
  binds the command to the run, and through the run ledger to the session, the
  user and the organization that submitted it (``action_ledger``). The receipt
  records the command's hash, never its text, and the toolbox fingerprint it
  ran against.
- When an expected fingerprint is pinned (``AGENT_PROBE_RUNNER_FINGERPRINT``), a
  job whose runner reports a different one is flagged as toolbox drift, on the
  receipt and in the tool result, so a changed toolbox cannot pass unnoticed.

The signature is an HMAC over the canonical receipt using the server
``SECRET_KEY``; it makes a stored receipt tamper-evident and lets a reviewer
confirm later that the ledger row was not edited.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RECEIPT_VERSION = 1


def _sign(material: bytes) -> str:
    from app.core.config import settings

    key = str(getattr(settings, "SECRET_KEY", "") or "").encode()
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def command_digest(kind: str, command: str) -> str:
    """Hash of the exact command or script, so the receipt proves what ran
    without storing the text (which may hold payloads or tokens)."""
    return hashlib.sha256(f"{kind}\n{command or ''}".encode("utf-8", "replace")).hexdigest()


def expected_fingerprint() -> str:
    from app.core.config import settings

    return str(getattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "") or "").strip()


def check_drift(runner_identity: Any) -> Dict[str, Any]:
    """Compare the runner's reported toolbox fingerprint to the pinned one.

    ``status`` is one of: ``verified`` (matches the pin), ``drift`` (differs
    from the pin — a tool may have changed), ``unpinned`` (no pin configured,
    trust-on-first-use), or ``unreported`` (the runner sent no identity).
    """
    identity = runner_identity if isinstance(runner_identity, dict) else {}
    reported = str(identity.get("fingerprint") or "").strip()
    pinned = expected_fingerprint()
    if not reported:
        return {"status": "unreported", "reported": "", "pinned": pinned,
                "image_ref": str(identity.get("image_ref") or "")}
    if not pinned:
        status = "unpinned"
    else:
        status = "verified" if hmac.compare_digest(reported, pinned) else "drift"
    return {"status": status, "reported": reported, "pinned": pinned,
            "image_ref": str(identity.get("image_ref") or "")}


def build_receipt(
    *,
    run_id: Optional[str],
    session_id: str,
    user_id: Optional[int],
    organization_id: Optional[int],
    kind: str,
    command: str,
    scope_hosts: List[str],
    runner_identity: Any,
) -> Dict[str, Any]:
    """A signed, tamper-evident record of one sandbox job and its toolbox."""
    drift = check_drift(runner_identity)
    receipt: Dict[str, Any] = {
        "v": RECEIPT_VERSION,
        "kind": kind,
        "run_id": run_id or "",
        "session_id": session_id or "",
        "user_id": user_id if user_id is not None else None,
        "organization_id": organization_id if organization_id is not None else None,
        "command_sha256": command_digest(kind, command),
        "toolbox_fingerprint": drift["reported"],
        "image_ref": drift["image_ref"],
        "toolbox_status": drift["status"],
        "scope_hosts": sorted({str(h) for h in (scope_hosts or [])})[:40],
        "recorded_at": datetime.utcnow().isoformat() + "Z",
    }
    receipt["signature"] = _sign(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    return receipt


def verify_receipt(receipt: Dict[str, Any]) -> bool:
    """True if the receipt's signature still matches its contents."""
    if not isinstance(receipt, dict) or "signature" not in receipt:
        return False
    body = {k: v for k, v in receipt.items() if k != "signature"}
    expected = _sign(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    return hmac.compare_digest(str(receipt.get("signature") or ""), expected)


def record_sandbox_exec(
    *, kind: str, command: str, scope_hosts: List[str], runner_identity: Any,
) -> Dict[str, Any]:
    """Build the receipt, write it to the run ledger, and return a compact
    provenance block for the tool result. Never raises into the tool path."""
    from app.services.agent.action_ledger import active_run_id, append_action
    from app.services.agent.tools import (
        current_organization_id, current_session_id, current_user_id,
    )

    try:
        run_id = active_run_id.get()
        receipt = build_receipt(
            run_id=run_id,
            session_id=str(current_session_id.get() or ""),
            user_id=current_user_id.get(),
            organization_id=current_organization_id.get(),
            kind=kind, command=command, scope_hosts=list(scope_hosts or []),
            runner_identity=runner_identity,
        )
        status = receipt["toolbox_status"]
        event = "sandbox_drift" if status == "drift" else "sandbox_exec"
        detail = f"{kind} toolbox={status} image={receipt['image_ref'] or 'unknown'}"
        append_action(
            run_id, receipt["command_sha256"][:32], event, f"sandbox:{kind}",
            target=(scope_hosts or [""])[0], phase="exploitation",
            detail=detail, fingerprint=receipt["signature"],
        )
        block = {
            "receipt_signature": receipt["signature"],
            "toolbox_status": status,
            "toolbox_fingerprint": receipt["toolbox_fingerprint"][:16],
            "image_ref": receipt["image_ref"],
            "command_sha256": receipt["command_sha256"],
            "session_id": receipt["session_id"],
            "bound_to_run": bool(run_id),
        }
        if status == "drift":
            block["warning"] = (
                "Toolbox drift: the probe runner's toolbox fingerprint does not "
                "match the pinned image. A tool may have changed; treat this job's "
                "provenance as unverified and investigate the runner.")
        elif status == "unreported":
            block["warning"] = (
                "The probe runner reported no toolbox identity; update the runner "
                "image so each job records what it ran against.")
        return block
    except Exception:  # provenance must never break a probe
        logger.debug("sandbox provenance recording failed", exc_info=True)
        return {"toolbox_status": "error"}
