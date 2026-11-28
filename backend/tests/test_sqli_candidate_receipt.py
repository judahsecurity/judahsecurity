"""A GET SQLi candidate gets the structured receipt its proof requires.

The verifier confirms GET SQLi only from a matching pair of scoped_string_sqli
(or scoped_numeric_sqli) receipts. On ginandjuice.shop a hunter submitted the
catalog category lead from manual comparisons, so it could never confirm.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest

from app.services.agent import evidence_store as evidence_module
from app.services.agent.scoped_assessment.sqli_string import (
    CHECK_ORDER, string_sql_proof_gaps, string_sql_proof_valid,
)
from app.services.agent.tools import ASMToolsManager

TARGET = "https://ginandjuice.shop/catalog?category=Gin"


class FakeManager:
    def __init__(self, store_records=None, string_result=None, numeric_result=None, raises=None):
        self.calls = []
        self.store = SimpleNamespace(records=dict(store_records or {}))
        self._string = string_result
        self._numeric = numeric_result
        self._raises = raises or {}

    async def scoped_string_sqli(self, url, parameter, identity="anonymous", artifact_id=""):
        self.calls.append(("string", url, parameter))
        if parameter in self._raises:
            raise ValueError(self._raises[parameter])
        return json.dumps(self._string)

    async def scoped_numeric_sqli(self, artifact_id="", parameter="", identity="anonymous", url=""):
        self.calls.append(("numeric", url, parameter))
        return json.dumps(self._numeric)


@pytest.fixture
def attach(monkeypatch):
    def run(manager, target=TARGET, claim="SQL injection in category", evidence_ids=()):
        monkeypatch.setattr(evidence_module, "evidence_store", lambda _m: manager.store)
        return asyncio.run(ASMToolsManager._attach_structured_sqli_receipt(
            manager, target, claim, list(evidence_ids)))
    return run


def test_manual_comparison_candidate_gets_a_structured_receipt(attach):
    manager = FakeManager(string_result={
        "evidence_id": "ev-sqli-1", "proof_confirmed": True, "operation": "sqli_boolean_string",
        "target": "https://ginandjuice.shop/catalog?category=Gin"})
    target, evidence_ids, note = attach(manager, evidence_ids=["ev-manual-500"])
    assert manager.calls == [("string", TARGET, "category")]
    assert evidence_ids == ["ev-manual-500", "ev-sqli-1"]
    assert target == "https://ginandjuice.shop/catalog?category=Gin"
    assert "held its controls" in note


def test_existing_structured_receipt_is_left_alone(attach):
    manager = FakeManager(store_records={"ev-s": {"kind": "scoped_string_sqli"}})
    assert attach(manager, evidence_ids=["ev-s"]) is None
    assert manager.calls == []


def test_numeric_values_use_the_numeric_probe_and_claimed_parameter_first(attach):
    manager = FakeManager(numeric_result={"evidence_id": "ev-n", "proof_confirmed": True})
    target = "https://ginandjuice.shop/catalog/product?productId=1&utm=x"
    attach(manager, target=target, claim="SQLi on productId")
    assert manager.calls == [("numeric", target, "productId")]


def test_failed_probe_is_attached_with_the_failed_control_named(attach):
    rows = {key: {"status": 200, "truncated": False, "redirected": False,
                  "body_sha256": "a" * 64, "bytes_captured": 10000,
                  "content_type": "text/html"} for key in CHECK_ORDER}
    rows["quote_error"]["status"] = 500
    rows["true_first"].update(body_sha256="b" * 64, bytes_captured=10600)
    rows["true_second"].update(body_sha256="b" * 64, bytes_captured=10600)
    result = {"evidence_id": "ev-weak", "proof_confirmed": False,
              "operation": "sqli_boolean_string", "proof_recipe": "string_or_boolean_v1",
              "method": "GET", "location": "query", "target": TARGET, "parameter": "category",
              "nonce": "12345", "checks": rows}
    assert not string_sql_proof_valid(result)
    manager = FakeManager(string_result=result)
    _target, evidence_ids, note = attach(manager)
    assert evidence_ids == ["ev-weak"]
    # 600 bytes of growth over a 10000-byte control: needs 1000.
    assert "true branch grew 600 bytes over the largest control; needs 1000" in note


def test_probe_errors_leave_the_candidate_unchanged(attach):
    manager = FakeManager(raises={"category": "input not observed in the map"})
    assert attach(manager) is None


def test_targets_without_query_inputs_are_skipped(attach):
    manager = FakeManager()
    assert attach(manager, target="https://ginandjuice.shop/login") is None
    assert manager.calls == []


def test_gap_report_names_each_failed_control():
    rows = {key: {"status": 200, "truncated": False, "redirected": False,
                  "body_sha256": "a" * 64, "bytes_captured": 5000,
                  "content_type": "text/html"} for key in CHECK_ORDER}
    result = {"operation": "sqli_boolean_string", "proof_recipe": "string_or_boolean_v1",
              "method": "GET", "location": "query", "target": TARGET, "parameter": "category",
              "nonce": "12345", "checks": rows}
    gaps = string_sql_proof_gaps(result)
    assert "quote_error returned 200, expected 5xx" in gaps
    assert "true and false responses identical" in gaps
    assert string_sql_proof_gaps({"operation": "other"})[0].startswith("no boolean SQLi recipe")
