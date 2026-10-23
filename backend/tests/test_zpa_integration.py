"""ZPA evidence must remain scoped, idempotent, and conservative."""

import hashlib
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.database import Base
import app.models  # noqa: F401,E402
from app.models.asset import Asset
from app.models.organization import Organization
from app.models.zpa_integration import ZpaIntegration, ZpaObservation
from app.services.zpa_service import ingest_events, parse_event


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Asset.__table__, ZpaIntegration.__table__, ZpaObservation.__table__,
    ])
    session = sessionmaker(bind=engine)()
    session.add_all([Organization(id=1, name="One"), Organization(id=2, name="Two")])
    session.add(ZpaIntegration(id=10, organization_id=1, name="ZPA", token_hash=hashlib.sha256(b"secret").hexdigest()))
    session.commit()
    yield session
    session.close()


def flow(zone="zone-a", direction="OUTBOUND", disposition="CONNECTED", destination="10.1.2.3"):
    return {
        "ResourceID": "resource-1", "ResourceName": "app-1", "AppZoneID": zone,
        "ConnectionStartTime": "2025-01-21T17:32:33.463Z",
        "SourceIP": "10.18.12.32", "DestinationIP": destination,
        "DestinationPort": 1443, "Protocol": 6, "Direction": direction,
        "EnforcementAction": "ALLOW" if disposition == "CONNECTED" else "BLOCK",
        "EnforcementDisposition": disposition,
    }


def test_connected_and_blocked_flows_do_not_conflate_reachability():
    connected = parse_event(flow(), 10)
    blocked = parse_event(flow(disposition="REJECTED"), 10)
    assert connected is not None and connected.connected and connected.protocol == "TCP"
    assert blocked is not None and not blocked.connected
    assert parse_event(flow(direction="INBOUND"), 10) is None


def test_same_private_ip_in_different_zones_creates_separate_candidates(db):
    integration = db.query(ZpaIntegration).one()
    result = ingest_events(db, integration, [flow("zone-a"), flow("zone-b"), flow("zone-a")])
    assert result == {"received": 3, "accepted": 2, "duplicates": 1, "ignored": 0, "assets_created": 2}
    assets = db.query(Asset).order_by(Asset.id).all()
    assert len(assets) == 2
    assert assets[0].value == assets[1].value == "10.1.2.3"
    assert assets[0].metadata_["network_scope_id"] != assets[1].metadata_["network_scope_id"]
    assert all(not asset.is_owned and not asset.in_scope and not asset.is_public and not asset.is_live for asset in assets)
    assert db.query(ZpaObservation).count() == 2


def test_user_activity_is_private_app_evidence_and_does_not_store_user(db):
    integration = db.query(ZpaIntegration).one()
    event = {
        "Application": "Payroll", "ServerIP": "10.1.2.3", "ServerPort": 443,
        "TimestampConnectionStart": "2025-01-21T17:32:33Z", "ConnectionID": "conn-1",
        "ConnectionStatus": "CONNECTED", "Username": "secret@example.com",
        "ClientPrivateIP": "10.0.0.9",
    }
    assert ingest_events(db, integration, [event])["accepted"] == 1
    observation = db.query(ZpaObservation).one()
    assert observation.feed == "user_activity" and observation.connected
    assert "secret@example.com" not in str(observation.__dict__)
    assert db.query(Asset).one().metadata_["network_scope_id"].endswith(":Payroll")


def test_unscoped_or_unusable_events_are_ignored():
    assert parse_event({"DestinationIP": "10.1.2.3", "Direction": "OUTBOUND",
                        "ConnectionStartTime": "2025-01-21T17:32:33Z"}, 10) is None
    assert parse_event(flow(destination="not-an-address"), 10) is None


def test_graph_projects_connected_and_rejected_evidence_separately(db, monkeypatch):
    from app.services import zpa_graph_service

    integration = db.query(ZpaIntegration).one()
    ingest_events(db, integration, [flow(), flow(disposition="REJECTED")])
    statements = []

    class FakeSession:
        def run(self, query, **params):
            statements.append((query, params))

        def execute_write(self, callback):
            callback(self)

    fake = FakeSession()
    graph = SimpleNamespace(
        _connected=True,
        session=lambda: nullcontext(fake),
        _sync_asset=lambda tx, asset, org: statements.append(("sync asset", {"asset_id": asset.id, "org": org})),
    )
    monkeypatch.setattr(zpa_graph_service, "get_graph_service", lambda: graph)
    monkeypatch.setattr(zpa_graph_service, "SessionLocal", sessionmaker(bind=db.bind))
    result = zpa_graph_service.project_zpa_integration(10, 1)
    assert result == {"ok": True, "assets": 1, "edges": 2}
    queries = [query for query, _ in statements]
    assert any("OBSERVED_OUTBOUND_TO" in query for query in queries)
    assert any("ATTEMPTED_OUTBOUND_TO" in query for query in queries)
    assert all(params.get("org_id", 1) == 1 for _, params in statements)
