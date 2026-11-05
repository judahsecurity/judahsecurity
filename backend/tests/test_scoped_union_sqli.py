"""UNION-based SQLi proof must make the database emit a server-owned marker.

Plain reflection cannot satisfy the recipe: the payload only ever carries an
encoded expression, so a plaintext marker in the response means the database
decoded and selected it. A wrong family or column layout never reflects, and an
independent verifier with a fresh nonce is still required.
"""

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
from app.services.agent.scoped_assessment import sqli_union

TARGET = "https://app.example.test/catalog"
URL = TARGET + "?category=gin"
ORIGINS = ["https://app.example.test"]


def _row(reflected, *, status=200, truncated=False, redirected=False):
    return {
        "status": status, "content_type": "text/html", "bytes_captured": 2048,
        "truncated": truncated, "body_sha256": "x" * 64, "redirected": redirected,
        "reflection_detected": reflected,
    }


def _result(checks, *, family="mysql", nonce="31337", columns=3, position=2):
    result = {
        "operation": "sqli_union_string", "proof_recipe": "string_union_v1",
        "target": TARGET, "method": "GET", "location": "query",
        "parameter": "category", "nonce": nonce, "sql_family": family,
        "column_count": columns, "reflected_position": position,
        "requests_sent": len(sqli_union.UNION_CHECK_ORDER),
        "identity_transport": "named_identity_cookies_only",
        "input_encoding": "plain", "checks": checks,
    }
    result["proof_confirmed"] = sqli_union.union_sql_proof_valid(result)
    return result


def _confirming_checks():
    return {
        "baseline_first": _row(False), "union_first": _row(True),
        "union_second": _row(True), "baseline_last": _row(False),
    }


# ── payload construction ─────────────────────────────────────────────────────

@pytest.mark.parametrize("family", sqli_union.FAMILIES)
def test_marker_never_appears_in_payload(family):
    marker = sqli_union.marker_for("31337")
    expr = sqli_union._encoded_marker_expression(family, marker)
    suffix = unquote(sqli_union._union_suffix(family, 3, 2, marker))
    # The plaintext marker never rides in the request; only its encoded form does.
    assert marker not in expr and marker not in suffix
    # Three columns, marker expression flanked by NULLs. (The expression itself
    # may contain commas inside function parens, so match structurally.)
    select = re.search(r"UNION SELECT (.+?)-- ", suffix).group(1)
    assert select.startswith("NULL,") and select.endswith(",NULL")
    assert expr in select


def test_union_suffix_rejects_bad_layout():
    marker = sqli_union.marker_for("31337")
    with pytest.raises(ValueError):
        sqli_union._union_suffix("mysql", 0, 1, marker)
    with pytest.raises(ValueError):
        sqli_union._union_suffix("mysql", 3, 4, marker)
    with pytest.raises(ValueError):
        sqli_union._encoded_marker_expression("db2", marker)


# ── proof math ───────────────────────────────────────────────────────────────

def test_proof_confirms_when_only_union_branches_reflect():
    assert sqli_union.union_sql_proof_valid(_result(_confirming_checks())) is True


def test_proof_rejects_when_union_does_not_reflect():
    checks = _confirming_checks()
    checks["union_second"] = _row(False)
    assert sqli_union.union_sql_proof_valid(_result(checks)) is False


def test_proof_rejects_marker_in_baseline():
    checks = _confirming_checks()
    checks["baseline_first"] = _row(True)  # collision/echo, not UNION execution
    assert sqli_union.union_sql_proof_valid(_result(checks)) is False


def test_proof_rejects_non_200_or_redirect():
    for mutate in (
        lambda c: c.__setitem__("union_first", _row(True, status=500)),
        lambda c: c.__setitem__("union_first", _row(True, redirected=True)),
        lambda c: c.__setitem__("baseline_first", _row(False, truncated=True)),
    ):
        checks = _confirming_checks()
        mutate(checks)
        assert sqli_union.union_sql_proof_valid(_result(checks)) is False


def test_proof_rejects_bad_envelope():
    assert sqli_union.union_sql_proof_valid(_result(_confirming_checks(), family="db2")) is False
    assert sqli_union.union_sql_proof_valid(_result(_confirming_checks(), nonce="42")) is False
    assert sqli_union.union_sql_proof_valid(_result(_confirming_checks(), position=4)) is False


# ── end-to-end discovery + confirm over a stubbed observation ────────────────

def test_probe_discovers_column_layout_and_confirms(monkeypatch):
    # The fake app renders the second column of a three-column UNION only.
    def observe(url, allowed_origins, storage_state=None, *, reflection_marker="",
                **kwargs):
        value = unquote(parse_qs(urlsplit(url).query)["category"][0])
        reflected = False
        m = re.search(r"UNION SELECT (.+?)-- ", value)
        if m:
            cells = m.group(1).split(",")
            reflected = (len(cells) == 3 and cells[0] == "NULL"
                         and cells[1].startswith("0x") and cells[2] == "NULL")
        row = _row(reflected)
        row["reflection_detected"] = bool(reflection_marker) and reflected
        return row

    monkeypatch.setattr(sqli_union, "observe_get", observe)
    result = sqli_union.probe_string_union(
        URL, parameter="category", family="mysql", allowed_origins=ORIGINS,
        storage_state=None, before_request=lambda: None,
    )
    assert result is not None
    assert result["proof_confirmed"] is True
    assert result["column_count"] == 3 and result["reflected_position"] == 2


def test_probe_returns_none_when_nothing_reflects(monkeypatch):
    monkeypatch.setattr(
        sqli_union, "observe_get",
        lambda *a, reflection_marker="", **k: _row(False),
    )
    result = sqli_union.probe_string_union(
        URL, parameter="category", family="mysql", allowed_origins=ORIGINS,
        storage_state=None, before_request=lambda: None,
    )
    assert result is None


# ── two-actor policy integration ─────────────────────────────────────────────

def test_union_recipe_registered_for_sql_injection():
    assert "string_union_sqli" in PROOFS_BY_CLASS["sql_injection"]


def test_policy_requires_independent_fresh_nonce_matching_layout():
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
                                vulnerability_class="sql_injection", title="UNION SQLi")
    receipt = {"kind": "string_union_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert validate_proof(store, candidate, receipt, [verifier])[0]
    assert not validate_proof(store, candidate, receipt, [hunter])[0]


def test_policy_rejects_mismatched_column_layout():
    store = EvidenceStore()
    hunter = store.record(
        "scoped_string_sqli", _result(_confirming_checks(), nonce="31337", position=2),
        target=TARGET, identity="anonymous",
    )
    token = verification_run.set(VerificationRun("verifier-run", "candidate", 1, "fresh"))
    try:
        verifier = store.record(
            "scoped_string_sqli", _result(_confirming_checks(), nonce="42424", position=1),
            target=TARGET, identity="anonymous",
        )
    finally:
        verification_run.reset(token)
    candidate = SimpleNamespace(target=TARGET, evidence_ids=[hunter],
                                vulnerability_class="sql_injection", title="t")
    receipt = {"kind": "string_union_sqli", "hunter_artifact_id": hunter,
               "artifact_id": verifier}
    assert not validate_proof(store, candidate, receipt, [verifier])[0]
