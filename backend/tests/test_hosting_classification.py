"""Hosting classification from the organization's IP inventory."""

import pytest

pytest.importorskip("sqlalchemy")

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.db.database import Base  # noqa: E402
import app.models  # noqa: E402,F401
from app.models.asset import Asset, AssetType  # noqa: E402
from app.models.netblock import Netblock  # noqa: E402
from app.models.organization import Organization  # noqa: E402
from app.services.hosting_classification import classify_asset_hosting  # noqa: E402


@pytest.fixture()
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine, tables=[Organization.__table__, Netblock.__table__, Asset.__table__])
    session = sessionmaker(bind=engine)()
    org = Organization(id=1, name="Acme")
    other = Organization(id=2, name="Globex")
    session.add_all([org, other])
    session.add(Netblock(
        organization_id=1, inetnum="145.97.0.0 - 145.97.255.255", start_ip="145.97.0.0",
        end_ip="145.97.255.255", cidr_notation="145.97.0.0/16", is_owned=True, in_scope=True,
    ))
    session.commit()
    yield session
    session.close()


def _asset(db, value, asset_type=AssetType.DOMAIN, org=1, **kw):
    a = Asset(name=value, value=value, asset_type=asset_type, organization_id=org, **kw)
    db.add(a)
    db.commit()
    return a


def test_ip_in_owned_netblock_is_org_hosted(db):
    h = classify_asset_hosting(db, _asset(db, "145.97.10.10", AssetType.IP_ADDRESS))
    assert h["hosting_type"] == "owned"
    assert h["organization_name"] == "Acme"
    assert "Acme's IP inventory" in h["basis"]


def test_domain_uses_resolved_ip_assets(db):
    domain = _asset(db, "portal.acme.com")
    _asset(db, "145.97.20.20", AssetType.IP_ADDRESS, resolved_from="portal.acme.com")
    assert classify_asset_hosting(db, domain)["hosting_type"] == "owned"


def test_cloud_range_is_third_party(db):
    h = classify_asset_hosting(db, _asset(db, "app.acme.com", ip_address="20.1.2.3"))
    assert h["hosting_type"] == "third_party"
    assert h["hosting_provider"] == "azure"


def test_outside_org_inventory_is_third_party(db):
    h = classify_asset_hosting(db, _asset(db, "vendor.acme.com", ip_address="62.210.5.5"))
    assert h["hosting_type"] == "third_party"
    assert "not in any of Acme's 1 owned netblock" in h["basis"]


def test_private_ip_is_internal(db):
    assert classify_asset_hosting(db, _asset(db, "intranet.acme.com", ip_address="10.0.0.5"))["hosting_type"] == "internal"


def test_other_orgs_netblocks_do_not_count(db):
    # Globex has no netblocks, so Acme's range must not make it "owned".
    h = classify_asset_hosting(db, _asset(db, "145.97.30.30", AssetType.IP_ADDRESS, org=2))
    assert h["hosting_type"] == "unknown"
    assert "Globex has no owned netblocks" in h["basis"]


def test_no_ips_is_unknown(db):
    assert classify_asset_hosting(db, _asset(db, "new.acme.com"))["hosting_type"] == "unknown"
