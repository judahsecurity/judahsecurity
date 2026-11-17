"""Pre-registered engagement identities: authorization, scope, crypto, hydration."""

from types import SimpleNamespace

from app.models.agent_engagement_identity import AgentEngagementIdentity
from app.services.agent.engagement_brain import EngagementBrain
from app.services.agent.engagement_identities import (
    apply_pre_registered_identities,
    load_engagement_credentials,
    register_engagement_identity,
    select_authorized_identities,
)


def _row(label, *, enabled=True, valid_on=None):
    return SimpleNamespace(label=label, enabled=enabled, valid_on=valid_on or [])


def test_select_requires_authorized_label_and_in_scope_host():
    rows = [
        _row("tester_a", valid_on=["app.example.test"]),
        _row("tester_b", valid_on=["other.example.test"]),
        _row("tester_a", valid_on=[], enabled=False),
    ]
    selected = select_authorized_identities(
        rows, allowed_identities=["tester_a"], scope_hosts=["app.example.test"],
    )
    assert [r.label for r in selected] == ["tester_a"]


def test_select_excludes_anonymous_and_unscoped():
    rows = [_row("tester_a", valid_on=["app.example.test"])]
    # anonymous is never loaded from the durable table
    assert select_authorized_identities(rows, ["anonymous"], ["app.example.test"]) == []
    # no host scope -> nothing usable even if authorized
    assert select_authorized_identities(rows, ["tester_a"], []) == []
    # empty valid_on is usable only when the run has a host scope
    empty = [_row("tester_a", valid_on=[])]
    assert len(select_authorized_identities(empty, ["tester_a"], ["app.example.test"])) == 1


def test_model_encrypts_secret_at_rest():
    ident = AgentEngagementIdentity(organization_id=1, label="tester_a")
    ident.secret = "hunter2"
    assert ident.secret_encrypted and ident.secret_encrypted != "hunter2"
    assert ident.secret == "hunter2"


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *a, **k):
        return self

    def all(self):
        return self._rows

    def one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeDB:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.added = []

    def query(self, *a, **k):
        return _FakeQuery(self._rows)

    def add(self, row):
        self.added.append(row)

    def commit(self):
        pass

    def refresh(self, row):
        pass


def test_load_decrypts_and_maps_to_credential_records():
    ident = AgentEngagementIdentity(
        organization_id=1, label="tester_a", username="svc_a",
        valid_on=["app.example.test"], enabled=True,
    )
    ident.secret = "s3cret"
    creds = load_engagement_credentials(
        _FakeDB([ident]), 1, ["tester_a"], ["app.example.test"],
    )
    assert len(creds) == 1
    assert creds[0].username == "svc_a"
    assert creds[0].secret == "s3cret"
    assert creds[0].source == "pre_registered"


def test_load_returns_empty_without_authorized_label():
    ident = AgentEngagementIdentity(organization_id=1, label="tester_a", valid_on=[])
    ident.secret = "x"
    assert load_engagement_credentials(_FakeDB([ident]), 1, ["anonymous"], ["h"]) == []


def test_register_upserts_and_encrypts():
    db = _FakeDB([])
    row = register_engagement_identity(
        db, organization_id=1, label="tester_a", secret="pw",
        username="svc", valid_on=["app.example.test"], approved_by=7,
    )
    assert row in db.added
    assert row.secret == "pw" and row.secret_encrypted != "pw"
    assert row.valid_on == ["app.example.test"] and row.approved_by == 7


def test_apply_is_idempotent_and_clears_idle_note():
    brain = EngagementBrain()
    brain.notes = ["Credentials were omitted from the restart snapshot; register identities again."]
    creds = load_engagement_credentials(
        _FakeDB([_identity("tester_a", "pw", "app.example.test")]),
        1, ["tester_a"], ["app.example.test"],
    )
    assert apply_pre_registered_identities(brain, creds) == 1
    assert len(brain.credentials) == 1
    # idle note cleared, re-apply adds nothing
    assert all("register identities again" not in n for n in brain.notes)
    assert apply_pre_registered_identities(brain, creds) == 0
    assert len(brain.credentials) == 1


def _identity(label, secret, host):
    ident = AgentEngagementIdentity(
        organization_id=1, label=label, username=label, valid_on=[host], enabled=True,
    )
    ident.secret = secret
    return ident
