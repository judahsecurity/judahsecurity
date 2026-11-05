"""Observed IP links must preserve tenant boundaries and CDN uncertainty."""

import importlib.util
import sys
from enum import Enum
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from sqlalchemy import JSON, Boolean, Enum as SqlEnum, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


class Base(DeclarativeBase):
    pass


class AssetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    URL = "URL"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    organization_id: Mapped[int] = mapped_column(Integer)
    asset_type: Mapped[AssetType] = mapped_column(SqlEnum(AssetType))
    value: Mapped[str] = mapped_column(String)
    parent_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    resolved_from: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_addresses: Mapped[list] = mapped_column(JSON, default=list)
    hosting_type: Mapped[str | None] = mapped_column(String, nullable=True)
    hosting_provider: Mapped[str | None] = mapped_column(String, nullable=True)
    is_owned: Mapped[bool] = mapped_column(Boolean, default=False)


def _load_service():
    asset_module = ModuleType("app.models.asset")
    asset_module.Asset = Asset
    asset_module.AssetType = AssetType
    modules = {
        "app": ModuleType("app"),
        "app.models": ModuleType("app.models"),
        "app.models.asset": asset_module,
    }
    path = Path(__file__).resolve().parents[1] / "app/services/asset_relationships.py"
    spec = importlib.util.spec_from_file_location("asset_relationships_under_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


def test_links_dns_answers_and_discovery_ips_without_claiming_origin():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([
            Asset(id=1, organization_id=1, asset_type=AssetType.DOMAIN, value="example.com", ip_addresses=[]),
            Asset(id=2, organization_id=1, asset_type=AssetType.SUBDOMAIN, value="app.example.com", parent_id=1, ip_address="198.51.100.42", ip_addresses=["198.51.100.42"]),
            Asset(id=3, organization_id=1, asset_type=AssetType.IP_ADDRESS, value="104.16.1.1", parent_id=2, resolved_from="app.example.com", hosting_type="cdn", hosting_provider="cloudflare", ip_addresses=[]),
            Asset(id=4, organization_id=2, asset_type=AssetType.SUBDOMAIN, value="app.example.com", ip_address="104.16.1.1", ip_addresses=["104.16.1.1"]),
            Asset(id=5, organization_id=2, asset_type=AssetType.IP_ADDRESS, value="203.0.113.9", parent_id=2, resolved_from="unrelated.example", ip_addresses=[]),
        ])
        db.commit()
        hosts = db.query(Asset).filter(Asset.id.in_([2, 4])).all()
        links = _load_service().batch_ip_relationships(db, hosts)

    assert links[2] == [
        {"ip": "104.16.1.1", "role": "cdn_edge", "provider": "cloudflare", "source": "dns_or_discovery"},
        {"ip": "198.51.100.42", "role": "observed", "provider": None, "source": "dns_or_discovery"},
    ]
    assert links[4] == [
        {"ip": "104.16.1.1", "role": "observed", "provider": None, "source": "dns_or_discovery"},
    ]
    assert all("origin_ip" not in link for row in links.values() for link in row)


def test_live_inventory_collapses_related_edges_but_keeps_direct_ips():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add_all([
            Asset(id=1, organization_id=1, asset_type=AssetType.SUBDOMAIN, value="app.example.com", ip_addresses=[]),
            Asset(id=2, organization_id=1, asset_type=AssetType.IP_ADDRESS, value="104.16.1.1", resolved_from="app.example.com", hosting_type="cdn", hosting_provider="cloudflare", ip_addresses=[]),
            Asset(id=3, organization_id=1, asset_type=AssetType.IP_ADDRESS, value="198.51.100.42", ip_addresses=[]),
            Asset(id=4, organization_id=1, asset_type=AssetType.IP_ADDRESS, value="203.0.113.5", hosting_type="cdn", is_owned=True, ip_addresses=[]),
        ])
        db.commit()
        clause = _load_service().standalone_asset_filter()
        ids = {row[0] for row in db.query(Asset.id).filter(clause).all()}

    assert ids == {1, 3, 4}
