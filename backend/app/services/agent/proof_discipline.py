"""Validation discipline rules applied on top of class-specific proof checks.

These rules come from findings that were confirmed and then retracted. Each one
names a specific false-positive pattern. They are enforced in code, not prompt
text, so a persuasive narrative cannot get past them.

Rules (adapted from elementalsouls/Claude-BugHunter ``bb-methodology``
PART 4, CC BY 4.0; modified):

1. Marker discipline: every run uses a random marker of at least 8 characters,
   the hunter and verifier markers differ, and the control (baseline) must not
   already show the signal.
2. Body-diff rule: a status-code change alone is never the signal. The probe
   response body must differ from the control.
3. Statistical-sample rule: a timing claim needs at least 10 interleaved
   samples per group and a probe mean at least 2 standard deviations above the
   control mean.
4. Layer-ordering rule: a 4xx validation response (400/415/422) on a malformed
   request does not prove that authentication or authorization was skipped.
   Retest with a minimal well-formed body; a 401/403 then shows auth runs first.
"""

from __future__ import annotations

import statistics
from typing import Iterable

MIN_MARKER_LENGTH = 8
MIN_TIMING_SAMPLES = 10
VALIDATION_STATUSES = frozenset({400, 415, 422})


def marker_ok(hunter: dict, verifier: dict) -> tuple[bool, str]:
    first, second = str(hunter.get("nonce") or ""), str(verifier.get("nonce") or "")
    if len(first) < MIN_MARKER_LENGTH or len(second) < MIN_MARKER_LENGTH:
        return False, "Marker discipline: each run needs a random marker of at least 8 characters"
    if first == second:
        return False, "Marker discipline: the verifier reused the hunter marker"
    for row in (hunter, verifier):
        control = row.get("control")
        if isinstance(control, dict) and control.get("signal") is True:
            return False, "Marker discipline: the control already shows the signal"
    return True, ""


def body_diff_ok(row: dict) -> tuple[bool, str]:
    """Probe and control bodies must differ; status-only differences are leads."""
    control = row.get("control") or {}
    probes = row.get("probes")
    if isinstance(probes, list):
        hit = next((p for p in probes if isinstance(p, dict)
                    and p.get("recipe") == row.get("recipe")), None)
    else:
        hit = row.get("probe") if isinstance(row.get("probe"), dict) else None
    if not hit:
        return False, "Body-diff rule: no probe observation recorded"
    control_digest, probe_digest = control.get("sha256"), hit.get("sha256")
    if control_digest and probe_digest and control_digest == probe_digest:
        return False, "Body-diff rule: probe and control bodies are identical (status-only difference)"
    return True, ""


def timing_differential_ok(control_ms: Iterable[float], probe_ms: Iterable[float]) -> tuple[bool, str]:
    control, probe = [float(v) for v in control_ms], [float(v) for v in probe_ms]
    if len(control) < MIN_TIMING_SAMPLES or len(probe) < MIN_TIMING_SAMPLES:
        return False, "Statistical-sample rule: at least 10 interleaved samples per group are required"
    sigma = statistics.pstdev(control)
    threshold = statistics.mean(control) + 2 * max(sigma, 1.0)
    if statistics.mean(probe) < threshold:
        return False, "Statistical-sample rule: probe mean is not 2 standard deviations above control"
    return True, ""


def layer_ordering_ok(status: int | None, *, well_formed_retest_status: int | None = None) -> tuple[bool, str]:
    """A validation error is not evidence that auth was bypassed."""
    if status in VALIDATION_STATUSES:
        if well_formed_retest_status is None:
            return False, ("Layer-ordering rule: a validation error on a malformed request is not an "
                           "auth bypass; retest with a minimal well-formed body")
        if well_formed_retest_status in {401, 403}:
            return False, "Layer-ordering rule: the well-formed retest shows auth runs first"
        if not 200 <= int(well_formed_retest_status) < 300:
            return False, "Layer-ordering rule: the well-formed retest did not succeed"
    return True, ""


def check_discipline(kind: str, hunter: dict, verifier: dict) -> tuple[bool, str]:
    """Apply the rules that fit this proof kind to both receipts."""
    ok, why = marker_ok(hunter, verifier)
    if not ok:
        return ok, why
    if kind in {"scoped_ssti_eval", "scoped_cmdi_eval", "scoped_traversal_read",
                "scoped_nosql_operator", "scoped_jwt_forgery"}:
        for row in (hunter, verifier):
            ok, why = body_diff_ok(row)
            if not ok:
                return ok, why
    for row in (hunter, verifier):
        samples = row.get("timing_samples")
        if isinstance(samples, dict):
            ok, why = timing_differential_ok(samples.get("control") or [], samples.get("probe") or [])
            if not ok:
                return ok, why
    return True, ""
