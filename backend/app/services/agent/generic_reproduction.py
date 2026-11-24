"""Generic reproduction proof: the verifier recreates the hunter's observation.

Class-specific recipes are the only route to ``exploit_verified``. Bugs no
recipe covers still deserve a machine-checkable reproduction, so this proof
asks the verifier for three HTTP exchanges and checks them deterministically:

* the hunter's exchange (from the candidate's own evidence),
* a fresh verifier *probe* that replays the attack on the same method, origin
  and path, and
* a fresh verifier *control* on the same endpoint and identity, with the
  attacking input changed back to something benign.

The verifier names a literal ``signal``. It must be server-produced (absent from
both attacking requests), appear in the hunter's and the probe's response
bodies, and be missing from the control's response. A model therefore cannot
satisfy it by echoing its own input, by a status change alone, or by citing an
unrelated page. Findings confirmed this way are filed as ``reproduced`` and
capped at high, because the signal shows the behavior differs under attack, not
which bug class or impact it is.

``scoped_ssrf_readback`` is the same differential with one extra requirement:
the probe carries an internal destination (loopback, link-local metadata,
RFC 1918) in its input and the control does not, so the server-side fetch is
what produced the signal.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import unquote_plus, urlsplit

GENERIC_KIND = "replay_reproduction"
SSRF_READBACK_KIND = "scoped_ssrf_readback"
MIN_SIGNAL = 8
MAX_SIGNAL = 500

# Status-page phrases are a status change in disguise, never the signal.
_STATUS_ONLY = re.compile(
    r"(?i)^\W*(?:\d{3}\s*)?(?:not\s+found|page\s+not\s+found|forbidden|unauthori[sz]ed|"
    r"bad\s+request|internal\s+server\s+error|access\s+denied|method\s+not\s+allowed|"
    r"service\s+unavailable|gateway\s+time-?out|bad\s+gateway|too\s+many\s+requests|"
    r"request\s+rejected|invalid\s+request|something\s+went\s+wrong)\W*$"
)
_INTERNAL_DESTINATION = re.compile(
    r"(?i)(?:^|[^a-z0-9.-])(?:"
    r"localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?|"
    r"169\.254\.169\.254|169\.254(?:\.\d{1,3}){2}|metadata\.google\.internal|metadata\.azure\.com|"
    r"100\.100\.100\.200|fd00:ec2::254|"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r")(?:$|[^a-z0-9-])"
)


def _exchange(store: Any, artifact_id: Any, allowed: list[str]) -> dict | None:
    if not isinstance(artifact_id, str) or artifact_id not in (allowed or []):
        return None
    row = store.records.get(artifact_id)
    return row if row and row.get("kind") == "http_exchange" else None


def _request_text(row: dict) -> str:
    request = (row.get("payload") or {}).get("request") or {}
    return unquote_plus(json.dumps(request, default=str, sort_keys=True))


def _body(row: dict) -> str:
    return str(((row.get("payload") or {}).get("response") or {}).get("body") or "")


def _endpoint(url: str) -> tuple[str, str, int | None, str]:
    parts = urlsplit(url or "")
    return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port, parts.path or "/")


def validate_replay_reproduction(store: Any, candidate: Any, proof: dict,
                                 evidence_ids: list[str]) -> tuple[bool, str]:
    kind = proof.get("kind")
    hunter = _exchange(store, proof.get("hunter_artifact_id"), list(candidate.evidence_ids or []))
    probe = _exchange(store, proof.get("artifact_id"), evidence_ids)
    control = _exchange(store, proof.get("control_id"), evidence_ids)
    if not hunter or not probe or not control:
        return False, ("Generic reproduction needs the hunter's HTTP exchange "
                       "(hunter_artifact_id) and your fresh probe (artifact_id) and control (control_id)")
    if len({hunter["id"], probe["id"], control["id"]}) != 3:
        return False, "Hunter, probe and control must be three distinct exchanges"
    if not hunter["created_at"] < min(probe["created_at"], control["created_at"]):
        return False, "The verifier's probe and control must follow the hunter's exchange"
    requests = [(row.get("payload") or {}).get("request") or {} for row in (hunter, probe, control)]
    methods = {str(r.get("method") or "GET").upper() for r in requests}
    endpoints = {_endpoint(r.get("url", "")) for r in requests}
    if len(methods) != 1 or len(endpoints) != 1:
        return False, "Hunter, probe and control must use the same method, origin and path"
    if _endpoint(candidate.target)[:2] != next(iter(endpoints))[:2]:
        return False, "The reproduction must be on the candidate's origin"
    if probe.get("identity") != control.get("identity"):
        return False, "Probe and control must use the same identity so only the input differs"
    if _request_text(probe) == _request_text(control):
        return False, "The control must change the attacking input"
    signal = proof.get("signal")
    if not isinstance(signal, str):
        return False, "Name the literal response signal that shows the behavior"
    signal = signal.strip()
    if not MIN_SIGNAL <= len(signal) <= MAX_SIGNAL:
        return False, f"The signal must be a literal of {MIN_SIGNAL}-{MAX_SIGNAL} characters"
    if _STATUS_ONLY.match(signal):
        return False, "A status page phrase is a status change, not a reproduction signal"
    lowered = signal.lower()
    for row in (hunter, probe):
        if lowered in _request_text(row).lower():
            return False, "The signal appears in the attacking request; echoed input is not a reproduction"
    if signal not in _body(hunter):
        return False, "The signal must appear in the hunter's response"
    if signal not in _body(probe):
        return False, "Your probe's response did not reproduce the signal"
    if signal in _body(control):
        return False, "The control's response also shows the signal; the input does not cause it"
    if kind == SSRF_READBACK_KIND:
        if not _INTERNAL_DESTINATION.search(_request_text(probe)):
            return False, "SSRF readback needs an internal destination in the probe's input"
        if _INTERNAL_DESTINATION.search(_request_text(control)):
            return False, "The SSRF control must not carry an internal destination"
        if not _INTERNAL_DESTINATION.search(_request_text(hunter)):
            return False, "The hunter's exchange must also target an internal destination"
    return True, ""


VERIFIER_GUIDANCE = (
    "If no class-specific proof fits but you recreated the behavior, use proof "
    "{kind: replay_reproduction, hunter_artifact_id, artifact_id, control_id, signal}: "
    "hunter_artifact_id is the candidate's own HTTP exchange; artifact_id is your fresh replay of "
    "the attack (same method, origin and path); control_id is your fresh request on the same "
    "endpoint and identity with the attacking input made benign; signal is a literal the server "
    "returned (not text from your request) that appears in the hunter's and your probe's responses "
    "and not in the control's. It files as 'reproduced', capped at high. "
    "For SSRF that reads an internal resource back in the response, use the same shape with "
    "kind scoped_ssrf_readback; the probe must carry an internal destination such as "
    "http://169.254.169.254/ or http://127.0.0.1/ and the control must not. "
)
