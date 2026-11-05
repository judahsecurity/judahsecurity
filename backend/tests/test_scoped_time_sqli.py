"""Time-based (blind) SQLi proof must be a conservative, repeated timing differential.

The lane only confirms when the two true branches each run slow while every
baseline and false control runs fast, and the slow/fast gap reflects the injected
delay. A uniformly slow endpoint, a wrong database family, or mere jitter must all
fail safe, and an independent verifier with a fresh nonce is still required.
"""

import hashlib
import re
from types import SimpleNamespace
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from app.services.agent.evidence_store import (
    EvidenceStore,
    VerificationRun,
    verification_run,
)
from app.services.agent.proof_policy import PROOFS_BY_CLASS, validate_proof
from app.services.agent.scoped_assessment import sqli_time

TARGET = "https://app.example.test/catalog"
URL = TARGET + "?category=gin"
ORIGINS = ["https://app.example.test"]
_SHA = hashlib.sha256(b"stable-body").hexdigest()


def _row(elapsed_ms, *, status=200, content_type="text/html",
         truncated=False, redirected=False):
    return {
        "status": status, "content_type": content_type, "bytes_captured": 2048,
        "truncated": truncated, "body_sha256": _SHA, "redirected": redirected,
        "elapsed_ms": elapsed_ms,
    }


def _result(checks, *, family="mysql", nonce="31337"):
    result = {
        "operation": "sqli_time_string", "proof_recipe": "string_time_v1",
        "target": TARGET, "method": "GET", "location": "query",
        "parameter": "category", "nonce": nonce, "sql_family": family,
        "delay_ms": sqli_time.DELAY_MS, "requests_sent": len(sqli_time.TIME_CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only",
        "input_encoding": "plain", "checks": checks,
    }
    result["proof_confirmed"] = sqli_time.time_sql_proof_valid(result)
    return result


def _confirming_checks():
    fast, slow = 200, sqli_time.DELAY_MS + 200
    return {
        "baseline_first": _row(fast), "false_first": _row(fast),
        "true_first": _row(slow), "false_second": _row(fast),
        "true_second": _row(slow), "baseline_last": _row(fast),
    }


# ── planner ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("family", sqli_time.FAMILIES)
def test_planner_sleeps_only_on_the_true_branch(family):
    _, variants, nonce = sqli_time.plan_string_time(
        URL, parameter="category", allowed_origins=ORIGINS, family=family,
    )
    assert set(variants) == set(sqli_time.TIME_CHECK_ORDER)
    assert variants["baseline_first"] == URL == variants["baseline_last"]
    assert variants["true_first"] == variants["true_second"]
    assert variants["false_first"] == variants["false_second"]
    true_value = unquote(parse_qs(urlsplit(variants["true_first"]).query)["category"][0])
    false_value = unquote(parse_qs(urlsplit(variants["false_first"]).query)["category"][0])
    # The nonce equality is the whole condition: equal in true, unequal in false.
    false_nonce = nonce[:-1] + str((int(nonce[-1]) + 1) % 10)
    assert f"{nonce}={nonce}" in true_value
    assert f"{nonce}={false_nonce}" in false_value
    # A sleep primitive appears, and the original observed value is preserved.
    assert re.search(r"SLEEP|PG_SLEEP|WAITFOR", true_value, re.IGNORECASE)
    assert true_value.startswith("gin'") and false_value.startswith("gin'")


def test_planner_rejects_unknown_family_and_non_observed_value():
    with pytest.raises(ValueError):
        sqli_time.plan_string_time(URL, parameter="category", allowed_origins=ORIGINS, family="db2")
    with pytest.raises(ValueError):
        sqli_time.plan_string_time(
            TARGET + "?category=a'b", parameter="category",
            allowed_origins=ORIGINS, family="mysql",
        )
    with pytest.raises(ValueError):  # must occur exactly once
        sqli_time.plan_string_time(
            TARGET + "?category=gin&category=rum", parameter="category",
            allowed_origins=ORIGINS, family="mysql",
        )


# ── proof math ───────────────────────────────────────────────────────────────

def test_proof_confirms_on_repeated_slow_true_vs_fast_controls():
    assert sqli_time.time_sql_proof_valid(_result(_confirming_checks())) is True


def test_uniformly_slow_endpoint_is_not_proof():
    slow = sqli_time.DELAY_MS + 200
    checks = {key: _row(slow) for key in sqli_time.TIME_CHECK_ORDER}
    assert sqli_time.time_sql_proof_valid(_result(checks)) is False


def test_wrong_family_false_branch_also_sleeps_is_not_proof():
    slow = sqli_time.DELAY_MS + 200
    checks = _confirming_checks()
    checks["false_first"] = _row(slow)
    checks["false_second"] = _row(slow)
    assert sqli_time.time_sql_proof_valid(_result(checks)) is False


def test_jitter_without_delay_sized_gap_is_not_proof():
    checks = _confirming_checks()
    checks["true_first"] = _row(1300)   # only mildly slower than the 200ms controls
    checks["true_second"] = _row(1300)
    assert sqli_time.time_sql_proof_valid(_result(checks)) is False


def test_one_fast_true_branch_breaks_the_repetition():
    checks = _confirming_checks()
    checks["true_second"] = _row(200)
    assert sqli_time.time_sql_proof_valid(_result(checks)) is False


def test_non_200_or_redirect_or_truncation_rejected():
    for mutate in (
        lambda c: c.__setitem__("true_first", _row(sqli_time.DELAY_MS + 200, status=500)),
        lambda c: c.__setitem__("true_first", _row(sqli_time.DELAY_MS + 200, redirected=True)),
        lambda c: c.__setitem__("baseline_first", _row(200, truncated=True)),
        lambda c: c.__setitem__("true_first", _row(sqli_time.DELAY_MS + 200, content_type="application/json")),
    ):
        checks = _confirming_checks()
        mutate(checks)
        assert sqli_time.time_sql_proof_valid(_result(checks)) is False


def test_bad_envelope_fields_rejected():
    assert sqli_time.time_sql_proof_valid(_result(_confirming_checks(), family="db2")) is False
    assert sqli_time.time_sql_proof_valid(_result(_confirming_checks(), nonce="42")) is False


# ── end-to-end probe over a stubbed observation ──────────────────────────────

def test_probe_builds_confirmed_result_from_timed_observations(monkeypatch):
    def observe(url, allowed_origins, storage_state):
        value = unquote(parse_qs(urlsplit(url).query)["category"][0])
        pair = re.search(r"(\d+)=(\d+)", value)
        condition_true = bool(pair) and pair.group(1) == pair.group(2)
        sleeps = bool(re.search(r"SLEEP|PG_SLEEP|WAITFOR", value, re.IGNORECASE))
        elapsed = sqli_time.DELAY_MS + 150 if (condition_true and sleeps) else 180
        return _row(elapsed)

    monkeypatch.setattr(sqli_time, "observe_get", observe)
    baseline, variants, nonce = sqli_time.plan_string_time(
        URL, parameter="category", allowed_origins=ORIGINS, family="mysql",
    )
    result = sqli_time.probe_string_time(
        baseline, variants, nonce, parameter="category", family="mysql",
        allowed_origins=ORIGINS, storage_state=None, before_request=lambda: None,
    )
    assert result["proof_confirmed"] is True
    assert result["proof_recipe"] == "string_time_v1"
    assert result["requests_sent"] == len(sqli_time.TIME_CHECK_ORDER)


# ── two-actor policy integration ─────────────────────────────────────────────

def test_time_recipe_is_registered_for_sql_injection():
    assert "string_time_sqli" in PROOFS_BY_CLASS["sql_injection"]


def test_proof_policy_requires_independent_fresh_nonce_receipts():
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _result(_confirming_checks(), nonce="31337"),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _result(_confirming_checks(), nonce="42424"),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                vulnerability_class="sql_injection",
                                title="Time-based SQL injection in category")
    receipt = {"kind": "string_time_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert validate_proof(store, candidate, receipt, [verifier])[0]
    # Ordering guard: the hunter receipt cannot stand in for the verifier.
    assert not validate_proof(store, candidate, receipt, [hunter])[0]


def test_proof_policy_rejects_reused_nonce():
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _result(_confirming_checks(), nonce="31337"),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _result(_confirming_checks(), nonce="31337"),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                vulnerability_class="sql_injection", title="t")
    receipt = {"kind": "string_time_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert not validate_proof(store, candidate, receipt, [verifier])[0]
