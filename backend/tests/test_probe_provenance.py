"""Sandbox provenance: a signed receipt binds each job to a session and toolbox."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.models.organization import Organization  # noqa: F401 - ledger FK metadata
from app.models.user import User  # noqa: F401 - ledger FK metadata
from app.models.agent_conversation import AgentConversation
from app.models.agent_run_ledger import AgentActionReceipt, AgentHypothesisCoverage, AgentRunLedger
from app.services.agent import action_ledger, probe_provenance
from app.services.agent import tools as agent_tools

IDENTITY = {"image_ref": "asm-probe-runner@sha256:abc", "fingerprint": "f" * 64,
            "tools": {"sqlmap": "1.9.12"}, "executable_count": 42}


def _isolated_ledger(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    for model in (AgentRunLedger, AgentActionReceipt, AgentHypothesisCoverage, AgentConversation):
        model.__table__.create(engine)
    monkeypatch.setattr(action_ledger, "SessionLocal", sessionmaker(bind=engine))
    return sessionmaker(bind=engine)


def test_command_digest_hashes_and_does_not_store_the_command():
    digest = probe_provenance.command_digest("shell", "curl http://t/?token=SECRET")
    assert len(digest) == 64 and "SECRET" not in digest
    # Same text, different kind, different digest.
    assert digest != probe_provenance.command_digest("probe", "curl http://t/?token=SECRET")


def test_receipt_is_signed_and_tamper_evident(monkeypatch):
    monkeypatch.setattr(settings, "SECRET_KEY", "x" * 40, raising=False)
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "f" * 64, raising=False)
    receipt = probe_provenance.build_receipt(
        run_id="run1", session_id="s1", user_id=7, organization_id=12,
        kind="shell", command="sqlmap -u http://t", scope_hosts=["t", "t"],
        runner_identity=IDENTITY)
    assert probe_provenance.verify_receipt(receipt)
    assert receipt["toolbox_status"] == "verified"
    assert receipt["session_id"] == "s1" and receipt["user_id"] == 7
    assert receipt["scope_hosts"] == ["t"]  # deduped
    assert "sqlmap -u" not in str(receipt)  # only the hash is stored
    # Any edit breaks the signature.
    tampered = dict(receipt, session_id="attacker")
    assert not probe_provenance.verify_receipt(tampered)


def test_drift_states():
    # Pinned and matching.
    verified = probe_provenance.check_drift(IDENTITY)
    # Pinned mismatch is drift; empty pin is trust-on-first-use; no identity is unreported.
    assert probe_provenance.check_drift({"fingerprint": "d" * 64})["status"] in ("drift", "unpinned")


def test_drift_when_pin_differs(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "a" * 64, raising=False)
    assert probe_provenance.check_drift(IDENTITY)["status"] == "drift"
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "", raising=False)
    assert probe_provenance.check_drift(IDENTITY)["status"] == "unpinned"
    assert probe_provenance.check_drift({})["status"] == "unreported"
    assert probe_provenance.check_drift(None)["status"] == "unreported"


def test_record_sandbox_exec_writes_a_ledger_receipt(monkeypatch):
    factory = _isolated_ledger(monkeypatch)
    monkeypatch.setattr(settings, "SECRET_KEY", "x" * 40, raising=False)
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "f" * 64, raising=False)
    run_id = action_ledger.start_run(session_id="sess-9", organization_id=12, user_id=7,
                                     objective="https://t.example", mode="agent", budget_seconds=600)
    tokens = []
    for var, value in ((action_ledger.active_run_id, run_id),
                       (agent_tools.current_session_id, "sess-9"),
                       (agent_tools.current_user_id, 7),
                       (agent_tools.current_organization_id, 12)):
        tokens.append((var, var.set(value)))
    try:
        block = probe_provenance.record_sandbox_exec(
            kind="shell", command="proxychains4 nmap -sT -Pn t",
            scope_hosts=["t.example"], runner_identity=IDENTITY)
    finally:
        for var, token in tokens:
            var.reset(token)

    assert block["toolbox_status"] == "verified" and block["bound_to_run"] is True
    assert block["session_id"] == "sess-9" and "warning" not in block
    with factory() as db:
        row = db.query(AgentActionReceipt).filter(
            AgentActionReceipt.event == "sandbox_exec").one()
        assert row.tool_name == "sandbox:shell" and row.fingerprint == block["receipt_signature"]
        assert row.target == "t.example"


def test_record_sandbox_exec_flags_drift(monkeypatch):
    factory = _isolated_ledger(monkeypatch)
    monkeypatch.setattr(settings, "SECRET_KEY", "x" * 40, raising=False)
    monkeypatch.setattr(settings, "AGENT_PROBE_RUNNER_FINGERPRINT", "pinned" + "0" * 58, raising=False)
    run_id = action_ledger.start_run(session_id="sess-d", organization_id=1, user_id=2,
                                     objective="https://t", mode="agent", budget_seconds=600)
    tokens = [(v, v.set(val)) for v, val in (
        (action_ledger.active_run_id, run_id),
        (agent_tools.current_session_id, "sess-d"),
        (agent_tools.current_user_id, 2),
        (agent_tools.current_organization_id, 1))]
    try:
        block = probe_provenance.record_sandbox_exec(
            kind="shell", command="sqlmap", scope_hosts=["t"], runner_identity=IDENTITY)
    finally:
        for v, t in tokens:
            v.reset(t)
    assert block["toolbox_status"] == "drift" and "warning" in block
    with factory() as db:
        assert db.query(AgentActionReceipt).filter(
            AgentActionReceipt.event == "sandbox_drift").count() == 1


def test_record_never_raises_without_a_run(monkeypatch):
    _isolated_ledger(monkeypatch)
    monkeypatch.setattr(settings, "SECRET_KEY", "x" * 40, raising=False)
    # No active run and no ctx: still returns a block, just unbound.
    block = probe_provenance.record_sandbox_exec(
        kind="probe", command="print(1)", scope_hosts=[], runner_identity={})
    assert block["bound_to_run"] is False and block["toolbox_status"] == "unreported"
