"""Reviewer-facing proof trail built only from execution-owned evidence IDs.

The packet carries redacted request shape and artifact references, not model
reconstructions of HTTP messages or private credential values.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def _request_shape(url: str) -> str:
    parsed = urlsplit(str(url or ""))
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
    ):
        return ""
    # Preserve names for reproduction, but never copy captured query values to
    # finding metadata, whose readers may differ from private evidence readers.
    names = sorted(
        {
            name
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
            if re.fullmatch(r"[A-Za-z0-9_.\-\[\]]{1,80}", name)
        }
    )[:20]
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            "&".join(f"{name}=<redacted>" for name in names),
            "",
        )
    )


def build_verified_proof_packet(
    store: Any, candidate: Any, receipt: dict[str, Any]
) -> dict[str, Any]:
    """Link hunter and fresh verifier artifacts into one structured trail."""
    phases = (
        ("hunter", list(getattr(candidate, "evidence_ids", []) or [])),
        ("verifier", list(receipt.get("evidence_ids") or [])),
    )
    steps: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for phase, ids in phases:
        for evidence_id in ids[:24]:
            if not isinstance(evidence_id, str) or (phase, evidence_id) in seen:
                continue
            seen.add((phase, evidence_id))
            record = store.records.get(evidence_id)
            step: dict[str, Any] = {
                "phase": phase,
                "evidence_id": evidence_id,
                "available": isinstance(record, dict),
            }
            if isinstance(record, dict):
                payload = (
                    record.get("payload")
                    if isinstance(record.get("payload"), dict)
                    else {}
                )
                request = (
                    payload.get("request")
                    if isinstance(payload.get("request"), dict)
                    else {}
                )
                response = (
                    payload.get("response")
                    if isinstance(payload.get("response"), dict)
                    else {}
                )
                step.update(
                    kind=record.get("kind", ""),
                    identity=record.get("identity", ""),
                    method=request.get("method", ""),
                    request_shape=_request_shape(
                        request.get("url") or record.get("target", "")
                    ),
                    response_status=response.get("status"),
                    artifact_sha256=record.get("sha256", ""),
                    verifier_run_id=record.get("verifier_run_id", ""),
                )
            steps.append(step)
    return {
        "candidate_id": getattr(candidate, "id", ""),
        "verifier_run_id": receipt.get("run_id", ""),
        "entry_point": _request_shape(getattr(candidate, "target", "")),
        "prerequisites": {
            "identity": getattr(candidate, "identity", ""),
            "test_class": getattr(candidate, "test_type", ""),
            "parameter": getattr(candidate, "parameter", ""),
        },
        "steps": steps,
    }


def proof_packet_steps(packet: dict[str, Any]) -> str:
    """Brief human instructions that point to exact private proof artifacts."""
    lines = [f"Entry point: {packet.get('entry_point') or 'see private evidence'}"]
    identity = packet.get("prerequisites", {}).get("identity")
    if identity:
        lines.append(f"Prerequisite: registered test identity {identity}.")
    for index, step in enumerate(packet.get("steps", []), 1):
        label = "Fresh verifier" if step["phase"] == "verifier" else "Hunter"
        if not step.get("available"):
            lines.append(
                f"{index}. {label} artifact {step['evidence_id']} is unavailable; "
                "use the retained finding proof and rerun a scoped verification if needed."
            )
            continue
        shape = (
            f" {step['method']} {step['request_shape']}"
            if step.get("request_shape")
            else ""
        )
        status = (
            f"; observed HTTP {step['response_status']}"
            if step.get("response_status") is not None
            else ""
        )
        lines.append(
            f"{index}. {label}{shape}{status}; private evidence ID {step['evidence_id']}."
        )
    return "\n".join(lines)
