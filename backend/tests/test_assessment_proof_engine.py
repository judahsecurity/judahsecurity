import json

import pytest

from app.services.agent.assessment_sessions import IdentityRegistry
from app.services.agent.evidence_store import (
    EvidenceStore,
    VerificationRun,
    verification_run,
)
from app.services.agent.proof_engine import ProofEngine
from app.services.agent.authorization_engine import apply_proof_result
from app.services.agent.engagement_brain import EngagementBrain


def fixture_plan(strategy="authorization_mutation"):
    return dict(
        strategy=strategy,
        controlled_resource=True,
        target="https://app.test/items/1",
        owner_identity="a",
        object_path="/id",
        value_path="/marker",
        setup=dict(
            url="https://app.test/items",
            method="POST",
            body={
                "marker": "{{nonce}}" if strategy == "authorization_read" else "before"
            },
        ),
        control=dict(url="https://app.test/items/2", method="GET"),
        attack=dict(
            url="https://app.test/items/{{object_id}}",
            method="GET" if strategy == "authorization_read" else "PATCH",
            body=None if strategy == "authorization_read" else {"marker": "{{nonce}}"},
        ),
        verify=dict(url="https://app.test/items/{{object_id}}"),
    )


def fixture_cell():
    return dict(
        hypothesis_id="h1",
        operation_id="op1",
        identity="b",
        parameter="",
        expected="deny",
    )


def registry():
    r = IdentityRegistry()
    for name in ("a", "b"):
        r.register(name, "https://app.test", role="user", tenant=name)
        r.resolve(name, "https://app.test")["authenticated"] = True
        r.resolve(name, "https://app.test")["identity_check"] = {"expected": name}
    return r


class App:
    def __init__(self, store, vulnerable=True, status_only=False):
        self.store, self.vulnerable, self.status_only = store, vulnerable, status_only
        self.object = {"id": 1, "marker": "before"}
        self.calls = []

    async def exchange(
        self, method, url, identity, headers, body, hypothesis_id, follow_redirects
    ):
        self.calls.append((method, url, identity))
        if method == "POST":
            self.object.update(body)
        if method == "PATCH" and self.vulnerable and not self.status_only:
            self.object.update(body)
        data = dict(self.object)
        if url.endswith("/2"):
            data = {"id": 2, "marker": "other"}
        elif identity == "b" and not self.vulnerable:
            data = {"error": "forbidden"}
        status = 200
        payload = dict(
            request=dict(method=method, url=url, identity=identity, body=body),
            response=dict(status=status, body=json.dumps(data)),
        )
        eid = self.store.record(
            "http_exchange",
            payload,
            target=url,
            identity=identity,
            hypothesis_id=hypothesis_id,
        )
        return dict(
            response={"status": status}, _body_text=json.dumps(data), evidence_id=eid
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "vulnerable,expected", [(True, "confirmed"), (False, "refuted")]
)
async def test_mutation_requires_owner_readback(vulnerable, expected):
    store = EvidenceStore()
    app = App(store, vulnerable)
    engine = ProofEngine(store)
    receipt = await engine.run(
        fixture_plan(), fixture_cell(), execute=app.exchange, registry=registry()
    )
    assert receipt.verdict == expected
    assert len(receipt.evidence_ids) == 3
    assert [call[2] for call in app.calls] == ["a", "b", "a"]


@pytest.mark.asyncio
async def test_status_only_cannot_confirm_and_missing_identity_blocks():
    store = EvidenceStore()
    app = App(store, status_only=True)
    result = await ProofEngine(store).run(
        fixture_plan(), fixture_cell(), execute=app.exchange, registry=registry()
    )
    assert result.verdict == "refuted"
    r = registry()
    r.resolve("b", "https://app.test")["authenticated"] = False
    app.calls.clear()
    result = await ProofEngine(store).run(
        fixture_plan(), fixture_cell(), execute=app.exchange, registry=r
    )
    assert result.verdict == "blocked" and app.calls == []


@pytest.mark.asyncio
async def test_read_proof_requires_fresh_owned_canary_and_distinct_control():
    store = EvidenceStore()
    plan = fixture_plan("authorization_read")
    result = await ProofEngine(store).run(
        plan, fixture_cell(), execute=App(store).exchange, registry=registry()
    )
    assert result.verdict == "confirmed" and len(result.evidence_ids) == 4
    plan["control"]["url"] = "https://app.test/items/1"
    result = await ProofEngine(store).run(
        plan, fixture_cell(), execute=App(store).exchange, registry=registry()
    )
    assert result.verdict == "inconclusive"


@pytest.mark.asyncio
async def test_receipt_binds_verifier_and_does_not_close_neighbor():
    store = EvidenceStore()
    token = verification_run.set(VerificationRun("vr1", "candidate1", 2, "nonce"))
    try:
        result = await ProofEngine(store).run(
            fixture_plan(),
            fixture_cell(),
            execute=App(store).exchange,
            registry=registry(),
        )
    finally:
        verification_run.reset(token)
    assert result.verifier_run_id == "vr1" and result.candidate_revision == 2
    brain = EngagementBrain(
        authorization_matrix=[
            dict(fixture_cell(), id="h1", status="untested"),
            dict(fixture_cell(), id="h2", hypothesis_id="h2", status="untested"),
        ]
    )
    apply_proof_result(brain, result.to_dict())
    assert brain.authorization_matrix[0]["status"] == "tested"
    assert brain.authorization_matrix[1]["status"] == "untested"
    assert brain.confirmed_findings == []


@pytest.mark.asyncio
async def test_cross_origin_step_never_sends_owner_credentials():
    store = EvidenceStore()
    app = App(store)
    plan = fixture_plan()
    plan["attack"]["url"] = "https://other.test/items/{{object_id}}"
    result = await ProofEngine(store).run(
        plan, fixture_cell(), execute=app.exchange, registry=registry()
    )
    assert result.verdict == "inconclusive" and len(app.calls) == 1


@pytest.mark.asyncio
async def test_aliases_of_same_account_and_reflected_read_canary_are_rejected():
    store = EvidenceStore()
    r = registry()
    r.resolve("b", "https://app.test")["identity_check"] = {"expected": "a"}
    app = App(store)
    result = await ProofEngine(store).run(
        fixture_plan(), fixture_cell(), execute=app.exchange, registry=r
    )
    assert result.verdict == "blocked" and app.calls == []
    plan = fixture_plan("authorization_read")
    plan["attack"]["body"] = {"marker": "{{nonce}}"}
    with pytest.raises(ValueError, match="reflected"):
        await ProofEngine(store).run(
            plan, fixture_cell(), execute=app.exchange, registry=registry()
        )
    assert app.calls == []
