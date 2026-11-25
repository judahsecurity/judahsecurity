"""Org-scoped agent attack graph on the /attacks page."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models.organization import Organization  # noqa: F401 - FK metadata
from app.models.user import User  # noqa: F401 - FK metadata
from app.models.agent_conversation import AgentConversation
from app.api.routes import attacks
from app.services.agent import evograph
import app.services.agent.attack_graph as attack_graph


@pytest.fixture()
def db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    AgentConversation.__table__.create(engine)
    session = sessionmaker(bind=engine)()
    session.add(AgentConversation(session_id="s-org1", user_id=1, organization_id=1, messages=[]))
    session.add(AgentConversation(session_id="s-org2", user_id=2, organization_id=2, messages=[]))
    session.commit()
    monkeypatch.setattr(evograph, "get_session_chain", lambda sid: {"nodes": [], "edges": [], "meta": {"session_id": sid}})
    monkeypatch.setattr(attack_graph, "load_session_proofs", lambda *a, **k: [])
    yield session
    session.close()


def _user(org, superuser=False):
    return SimpleNamespace(organization_id=org, is_superuser=superuser)


def test_org_member_can_read_another_members_session(db):
    teammate = _user(1)  # did not run s-org1, but is in the same org
    out = attacks.get_attack_session_graph("s-org1", organization_id=None, db=db, current_user=teammate)
    assert set(out) == {"nodes", "edges", "meta"}


def test_other_org_session_is_404(db):
    with pytest.raises(HTTPException) as e:
        attacks.get_attack_session_graph("s-org2", organization_id=None, db=db, current_user=_user(1))
    assert e.value.status_code == 404


def test_cannot_select_another_org(db):
    with pytest.raises(HTTPException) as e:
        attacks.get_attack_session_graph("s-org2", organization_id=2, db=db, current_user=_user(1))
    assert e.value.status_code == 403
