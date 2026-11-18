"""Durable fact ledger: dedupe, idempotent append, scope-checked drain."""

from types import SimpleNamespace

import app.db.database as database_module
from app.models.agent_fact_event import AgentFactEvent
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.fact_events import (
    append_fact_event,
    consume_fact_events_into_brain,
    drain_fact_events_into_brain,
    fact_dedupe_key,
)


def _fact(kind="credential", target="https://app.example.test", key="k1", payload=None):
    return SimpleNamespace(
        id=1, kind=kind, target=target, dedupe_key=key,
        evidence_ids=["e1"], payload=payload or {},
    )


def test_dedupe_key_is_stable_and_discriminating():
    a = fact_dedupe_key(1, "credential", "https://app.example.test", "svc")
    b = fact_dedupe_key(1, "credential", "https://app.example.test", "svc")
    c = fact_dedupe_key(1, "credential", "https://app.example.test", "other")
    assert a == b and a != c and len(a) == 32


def test_consume_ingests_in_scope_and_dedupes():
    brain = EngagementBrain()
    rows = [_fact(key="k1"), _fact(key="k1")]  # same fact twice
    ingested, consumed = consume_fact_events_into_brain(
        brain, rows, ["app.example.test"],
    )
    assert ingested == 1
    assert consumed == [1, 1]
    assert len(brain.recon_observations) == 1
    assert brain.recon_observations[0]["kind"] == "fact_credential"


def test_credential_fact_creates_assignable_card():
    brain = EngagementBrain()
    consume_fact_events_into_brain(brain, [_fact(kind="credential")], ["app.example.test"])
    assert len(brain.hypotheses) == 1
    card = brain.hypotheses[0]
    assert card.specialist == "api_authz" and card.status == "open"
    assert card.source == "chain" and card.observation_id == brain.recon_observations[0]["dedupe_key"]
    # re-draining the same fact does not duplicate the card
    consume_fact_events_into_brain(brain, [_fact(kind="credential")], ["app.example.test"])
    assert len(brain.hypotheses) == 1


def test_verified_finding_fact_creates_business_logic_card():
    brain = EngagementBrain()
    consume_fact_events_into_brain(
        brain, [_fact(kind="verified_finding", key="vf1")], ["app.example.test"],
    )
    assert brain.hypotheses and brain.hypotheses[0].specialist == "business_logic"


def test_capture_fact_is_observation_only():
    brain = EngagementBrain()
    ingested, _ = consume_fact_events_into_brain(
        brain, [_fact(kind="capture", key="c1")], ["app.example.test"],
    )
    assert ingested == 1
    assert len(brain.recon_observations) == 1
    assert brain.hypotheses == []  # capture is context, not its own card


def test_consume_drops_out_of_scope_fact():
    brain = EngagementBrain()
    ingested, consumed = consume_fact_events_into_brain(
        brain, [_fact(target="https://evil.example.test")], ["app.example.test"],
    )
    assert ingested == 0
    assert consumed == [1]  # consumed (not actionable), not left to re-process
    assert brain.recon_observations == []


def test_consume_requires_scope():
    brain = EngagementBrain()
    ingested, consumed = consume_fact_events_into_brain(brain, [_fact()], [])
    assert ingested == 0 and consumed == [1]


def test_append_guards_reject_bad_input():
    assert append_fact_event(organization_id=0, session_id="s", kind="credential") is None
    assert append_fact_event(organization_id=1, session_id="s", kind="not_a_kind") is None
    assert append_fact_event(organization_id=1, session_id="", kind="credential") is None


class _Store:
    def __init__(self):
        self.rows: list = []


class _FakeQuery:
    def __init__(self, store):
        self._store = store
        self._limit = None

    def filter(self, *a, **k):
        return self

    def order_by(self, *a, **k):
        return self

    def limit(self, n):
        self._limit = n
        return self

    def first(self):
        return self._store.rows[0] if self._store.rows else None

    def all(self):
        rows = [r for r in self._store.rows if r.consumed_at is None]
        return rows[: self._limit] if self._limit else rows

    def update(self, values, synchronize_session=False):
        for r in self._store.rows:
            for col, val in values.items():
                setattr(r, getattr(col, "key", str(col)), val)
        return len(self._store.rows)

    def delete(self, synchronize_session=False):
        n = len(self._store.rows)
        self._store.rows.clear()
        return n


class _FakeSession:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def query(self, *entity):
        return _FakeQuery(self.store)

    def add(self, row):
        row.id = len(self.store.rows) + 1
        if getattr(row, "consumed_at", None) is None:
            row.consumed_at = None
        self.store.rows.append(row)

    def commit(self):
        pass

    def rollback(self):
        pass


def test_append_is_idempotent_on_repeat(monkeypatch):
    store = _Store()
    monkeypatch.setattr(database_module, "SessionLocal", lambda: _FakeSession(store))
    first = append_fact_event(
        organization_id=1, session_id="sess", kind="credential",
        target="https://app.example.test", dedupe_parts=["svc"],
        scope_hosts=["app.example.test"], payload={"username": "svc"},
    )
    second = append_fact_event(
        organization_id=1, session_id="sess", kind="credential",
        target="https://app.example.test", dedupe_parts=["svc"],
        scope_hosts=["app.example.test"], payload={"username": "svc"},
    )
    assert first is not None and second is None
    assert len(store.rows) == 1
    # no raw secret leaked into the durable payload
    assert "secret" not in store.rows[0].payload


def test_drain_ingests_then_marks_consumed(monkeypatch):
    store = _Store()
    row = AgentFactEvent(
        organization_id=1, session_id="sess", kind="credential",
        target="https://app.example.test", dedupe_key="k1",
        scope={"allowed_hosts": ["app.example.test"]}, evidence_ids=["e1"], payload={},
    )
    row.id, row.consumed_at = 1, None
    store.rows.append(row)
    monkeypatch.setattr(database_module, "SessionLocal", lambda: _FakeSession(store))
    brain = EngagementBrain()
    ingested = drain_fact_events_into_brain(
        brain, organization_id=1, session_id="sess", scope_hosts=["app.example.test"],
    )
    assert ingested == 1
    assert len(brain.recon_observations) == 1
    assert store.rows[0].consumed_at is not None
    # second drain is a no-op (already consumed)
    assert drain_fact_events_into_brain(
        brain, organization_id=1, session_id="sess", scope_hosts=["app.example.test"],
    ) == 0


def test_prune_consumed_fact_events(monkeypatch):
    from app.services.agent.fact_events import prune_consumed_fact_events

    store = _Store()
    store.rows.append(SimpleNamespace(consumed_at="2020-01-01"))
    monkeypatch.setattr(database_module, "SessionLocal", lambda: _FakeSession(store))
    assert prune_consumed_fact_events(older_than_days=14) == 1
    assert store.rows == []


def test_prior_fact_summaries_scope_filtered_and_deduped():
    from app.services.agent.fact_events import prior_fact_summaries

    rows = [
        SimpleNamespace(target="https://app.example.test/x", kind="verified_finding",
                        dedupe_key="k1", payload={"summary": "verified finding 5"}),
        SimpleNamespace(target="https://app.example.test/y", kind="verified_finding",
                        dedupe_key="k1", payload={"summary": "dup"}),  # same key
        SimpleNamespace(target="https://out.example.test/z", kind="credential",
                        dedupe_key="k2", payload={}),  # out of scope
    ]
    out = prior_fact_summaries(rows, ["app.example.test"], limit=20)
    assert len(out) == 1
    assert out[0]["host"] == "app.example.test" and out[0]["dedupe_key"] == "k1"
    # no scope -> nothing
    assert prior_fact_summaries(rows, [], limit=20) == []
