import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.models  # noqa: F401 - register model relationships and foreign keys
from app.api.routes.scan_profiles import (
    create_scan_profile,
    delete_scan_profile,
    list_scan_profiles,
    update_scan_profile,
)
from app.db.database import Base
from app.models.organization import Organization
from app.models.scan_profile import ProfileType, ScanProfile
from app.models.user import User, UserRole
from app.schemas.scan_profile import ScanProfileCreate, ScanProfileUpdate
from app.services.scan_profiles import get_visible_scan_profile


@pytest.fixture()
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)


def seeded_tenants(db):
    first = Organization(name="First", is_active=True)
    second = Organization(name="Second", is_active=True)
    db.add_all([first, second])
    db.flush()
    analyst = User(
        email="analyst@example.com",
        username="analyst",
        hashed_password="unused",
        role=UserRole.ANALYST,
        organization_id=first.id,
        is_active=True,
    )
    built_in = ScanProfile(name="Quick", profile_type=ProfileType.NUCLEI, organization_id=None)
    other_tenant = ScanProfile(name="Secret", profile_type=ProfileType.NUCLEI, organization_id=second.id)
    db.add_all([analyst, built_in, other_tenant])
    db.commit()
    return first, second, analyst, built_in, other_tenant


def test_profile_lookup_never_crosses_tenants(db):
    first, _second, _analyst, built_in, other_tenant = seeded_tenants(db)

    assert get_visible_scan_profile(db, built_in.id, first.id).id == built_in.id
    assert get_visible_scan_profile(db, other_tenant.id, first.id) is None


def test_profile_crud_is_scoped_and_builtins_are_immutable(db):
    first, second, analyst, built_in, other_tenant = seeded_tenants(db)
    created = create_scan_profile(
        ScanProfileCreate(name="Daily web", profile_type=ProfileType.NUCLEI),
        db=db,
        current_user=analyst,
    )
    assert created.organization_id == first.id
    assert created.created_by == analyst.username

    visible = list_scan_profiles(
        organization_id=None,
        include_inactive=False,
        db=db,
        current_user=analyst,
    )
    assert {profile.id for profile in visible} == {built_in.id, created.id}
    assert other_tenant.id not in {profile.id for profile in visible}

    updated = update_scan_profile(
        created.id,
        ScanProfileUpdate(nuclei_rate_limit=25, is_default=True),
        db=db,
        current_user=analyst,
    )
    assert updated.nuclei_rate_limit == 25
    assert updated.is_default is True

    with pytest.raises(HTTPException, match="Built-in"):
        update_scan_profile(
            built_in.id,
            ScanProfileUpdate(name="Changed"),
            db=db,
            current_user=analyst,
        )
    with pytest.raises(HTTPException, match="Access denied"):
        delete_scan_profile(other_tenant.id, db=db, current_user=analyst)
    with pytest.raises(HTTPException, match="Access denied"):
        create_scan_profile(
            ScanProfileCreate(
                name="Wrong tenant",
                profile_type=ProfileType.NUCLEI,
                organization_id=second.id,
            ),
            db=db,
            current_user=analyst,
        )

    delete_scan_profile(created.id, db=db, current_user=analyst)
    assert db.query(ScanProfile).filter(ScanProfile.id == created.id).first() is None
