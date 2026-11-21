"""Knowledge search rewrites security terms so abbreviations find spelled-out docs."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.services.agent import knowledge
from app.services.agent.knowledge import query_variants, search_knowledge


def test_query_variants():
    assert query_variants("sqli in login form") == [
        "sqli in login form", "sql injection in login form", "sql in login form"]
    assert query_variants("idor on orders")[1] == "bola on orders"
    assert query_variants("plain question") == ["plain question"]
    assert query_variants("XSS") == ["xss", "cross-site scripting", "cross site scripting"]
    # Whole-term matches only: "sqlite" is not "sql"
    assert query_variants("sqlite tuning") == ["sqlite tuning"]


@pytest.fixture
def kb(monkeypatch):
    from app.models.agent_knowledge import AgentKnowledge
    from app.models.organization import Organization

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Organization.__table__.create(engine)
    AgentKnowledge.__table__.create(engine)
    maker = sessionmaker(bind=engine)
    monkeypatch.setattr(knowledge, "SessionLocal", maker)
    with maker() as db:
        db.add(Organization(id=1, name="Acme"))
        db.add(AgentKnowledge(organization_id=1, title="Broken object level authorization playbook",
                              content="Test BOLA by swapping object ids between two test identities."))
        db.add(AgentKnowledge(organization_id=1, title="Rate limiting notes",
                              content="Login throttling and lockout behaviour."))
        for n in range(6):
            db.add(AgentKnowledge(organization_id=1, title=f"Orders API changelog {n}",
                                  content="Release checks for the orders api pagination."))
        db.commit()
    return maker


def test_abbreviation_finds_spelled_out_document(kb):
    # The playbook never says "idor", "orders" or "api"; before query rewriting
    # the keyword shortlist missed it entirely.
    rows = search_knowledge(1, "idor checks for the orders api", limit=10)
    titles = [r["title"] for r in rows]
    assert "Broken object level authorization playbook" in titles


def test_intent_terms():
    from app.services.agent.knowledge import intent_terms

    assert "bola" in intent_terms("idor on /orders")
    assert intent_terms("nothing security related") == []
