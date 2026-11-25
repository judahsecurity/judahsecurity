"""Identity ingest, leak-to-identity matching and exposure prioritization."""

from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.identity import (
    CREDENTIAL_EMAIL_ONLY,
    CREDENTIAL_PASSWORD,
    CREDENTIAL_PASSWORD_HASH,
    CREDENTIAL_PASSWORD_PLAINTEXT,
    CredentialExposure,
    Identity,
    IdentitySourceSync,
)
from app.models.organization import Organization
from app.services import credential_exposure_service as ces
from app.services import identity_sync_service as iss
from app.services.identity_risk import score_exposure, score_identity
from app.api.routes import credential_exposure as routes


NOW = datetime(2026, 11, 25)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([Organization(id=1, name="Acme"), Organization(id=2, name="Other")])
        session.commit()
        yield session


def _snow_user(sys_id, user_name, email, title="", dept="", active="true", vip="false"):
    return {
        "sys_id": {"value": sys_id, "display_value": sys_id},
        "user_name": {"value": user_name, "display_value": user_name},
        "email": {"value": email, "display_value": email},
        "name": {"value": user_name, "display_value": user_name.title()},
        "title": {"value": title, "display_value": title},
        "department": {"value": "dep1", "display_value": dept},
        "manager": {"value": "mgr1", "display_value": "Pat Manager"},
        "active": {"value": active, "display_value": active},
        "vip": {"value": vip, "display_value": vip},
        "employee_number": {"value": "", "display_value": ""},
        "locked_out": {"value": "false", "display_value": "false"},
    }


# ── Scoring ──────────────────────────────────────────────────────────────────

def test_privileged_group_outranks_title_keywords():
    priv, factors, is_priv = score_identity(
        title="Analyst", department="Ops", groups=["Domain Admins"], is_vip=False, is_active=True
    )
    plain, _, plain_priv = score_identity(
        title="Systems Engineer", department="IT", groups=["All Staff"], is_vip=False, is_active=True
    )
    assert is_priv and not plain_priv
    assert priv > plain
    assert any(f.key == "privileged_group" for f in factors)


def test_executive_in_finance_scores_high_and_inactive_is_halved():
    active, _, _ = score_identity(
        title="Chief Financial Officer", department="Finance", groups=[], is_vip=True, is_active=True
    )
    inactive, factors, _ = score_identity(
        title="Chief Financial Officer", department="Finance", groups=[], is_vip=True, is_active=False
    )
    assert active == 60  # executive 25 + finance 20 + VIP 15
    assert inactive == 30
    assert factors[-1].key == "inactive_in_source"


def test_service_account_flagged():
    score, factors, _ = score_identity(
        title="", department="", groups=[], is_vip=False, is_active=True, username="svc_backup"
    )
    assert score == 20 and factors[0].key == "service_account"


def test_exposure_priority_combines_identity_credential_and_recency():
    fresh_admin, sev, _ = score_exposure(
        credential_type=CREDENTIAL_PASSWORD_PLAINTEXT,
        leak_date=NOW - timedelta(days=10),
        identity_score=90,
        identity_privileged=True,
        now=NOW,
    )
    old_unknown, old_sev, factors = score_exposure(
        credential_type=CREDENTIAL_EMAIL_ONLY,
        leak_date=NOW - timedelta(days=6 * 365),
        identity_score=None,
        now=NOW,
    )
    assert sev == "critical" and fresh_admin >= 75
    assert old_sev == "info" and old_unknown < 15
    assert any(f.key == "identity_unmatched" for f in factors)


@pytest.mark.parametrize(
    "classes,expected",
    [
        (["Email addresses", "Passwords"], CREDENTIAL_PASSWORD),
        (["Email addresses", "Password hints"], CREDENTIAL_EMAIL_ONLY),
        (["Usernames", "bcrypt password hashes"], CREDENTIAL_PASSWORD_HASH),
        (["Plaintext passwords"], CREDENTIAL_PASSWORD_PLAINTEXT),
        ([], CREDENTIAL_EMAIL_ONLY),
    ],
)
def test_credential_type_from_data_classes(classes, expected):
    assert ces.credential_type_from_data_classes(classes) == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2019", datetime(2019, 1, 1)),
        ("2019-05", datetime(2019, 5, 1)),
        ("2019-05-14", datetime(2019, 5, 14)),
        ("2023-02-01T10:00:00Z", datetime(2023, 2, 1, 10)),
        ("Breached in March 2021", datetime(2021, 1, 1)),
        (None, None),
        ("unknown", None),
    ],
)
def test_parse_leak_date(raw, expected):
    assert ces.parse_leak_date(raw) == expected


# ── ServiceNow ingest ────────────────────────────────────────────────────────

def test_normalize_sys_user_keeps_only_scoring_fields():
    values = iss.normalize_sys_user(_snow_user("a1", "JDoe", "John.Doe@Acme.com", "CFO", "Finance"))
    assert values["email"] == "john.doe@acme.com"
    assert values["username"] == "jdoe"
    assert values["aliases"] == ["jdoe", "john.doe@acme.com"]
    assert values["department"] == "Finance"
    assert values["manager_name"] == "Pat Manager"
    assert iss.normalize_sys_user({"sys_id": {"value": "x"}}) is None


def test_upsert_identities_scores_and_deactivates_missing(db):
    users = [
        _snow_user("a1", "jdoe", "jdoe@acme.com", "Chief Financial Officer", "Finance"),
        _snow_user("a2", "asmith", "asmith@acme.com", "Marketing Associate", "Marketing"),
    ]
    stats = iss.upsert_identities(
        db, 1, "servicenow", users, {"a2": ["Domain Admins"]}, complete=True
    )
    assert stats["created"] == 2
    smith = db.query(Identity).filter_by(source_id="a2").one()
    assert smith.is_privileged and smith.risk_score >= 45
    active_score = smith.risk_score

    stats = iss.upsert_identities(db, 1, "servicenow", users[:1], {}, complete=True)
    assert stats == {"created": 0, "updated": 1, "deactivated": 1, "skipped": 0}
    smith = db.query(Identity).filter_by(source_id="a2").one()
    # Still holds admin groups, so still privileged, but the score is halved.
    assert smith.is_active is False and smith.is_privileged
    assert smith.risk_score == active_score // 2


def test_incomplete_pull_does_not_deactivate(db):
    iss.upsert_identities(db, 1, "servicenow", [_snow_user("a1", "jdoe", "jdoe@acme.com")], {}, complete=True)
    stats = iss.upsert_identities(db, 1, "servicenow", [], {}, complete=False)
    assert stats["deactivated"] == 0
    assert db.query(Identity).one().is_active


@pytest.mark.asyncio
async def test_servicenow_client_pages_and_requests_minimal_fields():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        table = request.url.path.rsplit("/", 1)[-1]
        offset = int(request.url.params["sysparm_offset"])
        if table == "sys_user":
            rows = [_snow_user(f"u{offset + i}", f"user{offset + i}", f"user{offset + i}@acme.com")
                    for i in range(2 if offset == 0 else 1)]
        else:
            rows = [{"user": {"value": "u0"}, "group": {"display_value": "Domain Admins"}}]
        return httpx.Response(200, json={"result": rows})

    integration = SimpleNamespace(
        webhook_url="https://acme.service-now.com/api/x/notify",
        username="svc_asm",
        get_password=lambda: "pw",
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = iss.ServiceNowIdentityClient(integration, client=http)
        iss.PAGE_SIZE, old = 2, iss.PAGE_SIZE
        try:
            users = await client.fetch_users(10)
            groups = await client.fetch_group_memberships(10)
        finally:
            iss.PAGE_SIZE = old

    assert len(users) == 3
    assert groups == {"u0": ["Domain Admins"]}
    first = seen[0]
    assert first.url.host == "acme.service-now.com"
    assert first.url.params["sysparm_fields"] == iss.SYS_USER_FIELDS
    assert "phone" not in iss.SYS_USER_FIELDS and "street" not in iss.SYS_USER_FIELDS
    assert first.headers["Authorization"].startswith("Basic ")


@pytest.mark.asyncio
async def test_servicenow_client_reports_missing_acl():
    integration = SimpleNamespace(
        webhook_url="https://acme.service-now.com/api/x", username="svc", get_password=lambda: "pw"
    )
    transport = httpx.MockTransport(lambda r: httpx.Response(403, json={}))
    async with httpx.AsyncClient(transport=transport) as http:
        client = iss.ServiceNowIdentityClient(integration, client=http)
        with pytest.raises(iss.IdentitySyncError, match="read ACLs on sys_user"):
            await client.fetch_users(10)


class _FakeClient:
    def __init__(self, users, groups_error=False):
        self.users = users
        self.groups_error = groups_error

    async def fetch_users(self, max_users):
        return self.users

    async def fetch_group_memberships(self, max_rows):
        if self.groups_error:
            raise iss.IdentitySyncError("no ACL")
        return {}


@pytest.mark.asyncio
async def test_sync_rescores_existing_exposures_and_records_state(db):
    index = ces.build_identity_index(db, 1)
    exposure, _ = ces.upsert_exposure(
        db, 1, index, identifier="jdoe@acme.com", provider="xposedornot",
        source_type="breach", source_name="Example", credential_type=CREDENTIAL_PASSWORD,
    )
    assert exposure.identity_id is None
    before = exposure.priority_score

    stats = await iss.sync_servicenow_identities(
        db, 1,
        client=_FakeClient([_snow_user("a1", "jdoe", "jdoe@acme.com", "Chief Financial Officer", "Finance")],
                           groups_error=True),
    )
    db.refresh(exposure)
    assert stats["exposures_rescored"] == 1
    assert stats["group_memberships_loaded"] is False
    assert exposure.identity_id is not None
    assert exposure.priority_score > before
    row = db.query(IdentitySourceSync).one()
    assert row.last_sync_ok is True and row.running is False


@pytest.mark.asyncio
async def test_sync_failure_is_recorded(db):
    class Boom(_FakeClient):
        async def fetch_users(self, max_users):
            raise iss.IdentitySyncError("ServiceNow sys_user returned HTTP 500")

    assert iss.claim_sync(db, 1, "servicenow")
    assert not iss.claim_sync(db, 1, "servicenow")
    with pytest.raises(iss.IdentitySyncError):
        await iss.sync_servicenow_identities(db, 1, client=Boom([]))
    row = db.query(IdentitySourceSync).one()
    assert row.last_sync_ok is False and "HTTP 500" in row.last_error and row.running is False


# ── Matching and ingest ──────────────────────────────────────────────────────

def test_identity_index_matches_alias_and_login_name(db):
    iss.upsert_identities(db, 1, "servicenow", [_snow_user("a1", "jdoe", "john.doe@acme.com")], {}, complete=True)
    index = ces.build_identity_index(db, 1)
    assert index.match("JOHN.DOE@acme.com") is not None
    assert index.match("jdoe") is not None
    assert index.match("jdoe@acme.com") is not None  # login name at the email domain
    assert index.match("jdoe@other.com") is None


def test_ingest_email_breach_results_dedups_and_matches(db):
    iss.upsert_identities(
        db, 1, "servicenow",
        [_snow_user("a1", "jdoe", "jdoe@acme.com", "Chief Financial Officer", "Finance")], {}, complete=True,
    )
    results = {
        "jdoe@acme.com": {
            "breached": True,
            "breaches": [
                {"name": "BigLeak", "date": "2026-10", "data_classes": ["Email addresses", "Passwords"]},
                {"name": "OldForum", "date": "2014", "data_classes": ["Email addresses"]},
            ],
        },
        "nobody@acme.com": {"breached": True, "breaches": [{"name": "BigLeak", "date": "2026"}]},
        "clean@acme.com": {"breached": False, "breaches": []},
    }
    stats = ces.ingest_email_breach_results(db, 1, results)
    assert stats == {"created": 3, "refreshed": 0, "matched_identity": 2}
    stats = ces.ingest_email_breach_results(db, 1, results)
    assert stats["created"] == 0 and stats["refreshed"] == 3

    ranked = db.query(CredentialExposure).order_by(CredentialExposure.priority_score.desc()).all()
    assert ranked[0].source_name == "BigLeak" and ranked[0].identifier == "jdoe@acme.com"
    assert ranked[0].credential_type == CREDENTIAL_PASSWORD
    assert all(e.secret_fingerprint is None for e in ranked)


def test_secret_values_are_fingerprinted_not_stored(db):
    index = ces.build_identity_index(db, 1)
    exposure, _ = ces.upsert_exposure(
        db, 1, index, identifier="a@acme.com", provider="test", source_type="stealer_log",
        source_name="LummaC2", credential_type=CREDENTIAL_PASSWORD_PLAINTEXT,
        secret_value="Hunter2!", affected_url="https://vpn.acme.com/login",
    )
    assert exposure.secret_fingerprint.startswith("sha256:")
    stored = " ".join(str(getattr(exposure, c.name)) for c in CredentialExposure.__table__.columns)
    assert "Hunter2!" not in stored


def test_emails_to_check_prefers_risky_identities_then_assets(db):
    iss.upsert_identities(
        db, 1, "servicenow",
        [
            _snow_user("a1", "low", "low@acme.com", "Associate", "Marketing"),
            _snow_user("a2", "cfo", "cfo@acme.com", "Chief Financial Officer", "Finance"),
        ],
        {}, complete=True,
    )
    db.add(Asset(organization_id=1, value="found@acme.com", asset_type=AssetType.OTHER, name="found@acme.com"))
    db.commit()
    assert ces.emails_to_check(db, 1, 2) == ["cfo@acme.com", "low@acme.com"]
    assert ces.emails_to_check(db, 1, 5)[-1] == "found@acme.com"
    assert ces.emails_to_check(db, 2, 5) == []


# ── Routes ───────────────────────────────────────────────────────────────────

def _user(org_id):
    return SimpleNamespace(organization_id=org_id, is_superuser=False)


def test_exposure_routes_are_org_scoped(db):
    index = ces.build_identity_index(db, 1)
    exposure, _ = ces.upsert_exposure(
        db, 1, index, identifier="a@acme.com", provider="test", source_type="breach",
        source_name="X", credential_type=CREDENTIAL_PASSWORD,
    )
    db.commit()

    mine = routes.list_exposures(
        severity=None, status_filter="open", matched_only=False, q=None, limit=50, offset=0,
        db=db, current_user=_user(1),
    )
    theirs = routes.list_exposures(
        severity=None, status_filter="open", matched_only=False, q=None, limit=50, offset=0,
        db=db, current_user=_user(2),
    )
    assert mine.total == 1 and theirs.total == 0

    with pytest.raises(HTTPException) as err:
        routes.update_exposure_status(
            exposure.id, routes.ExposureStatusUpdate(status="resolved"), db=db, current_user=_user(2)
        )
    assert err.value.status_code == 404

    with pytest.raises(HTTPException) as err:
        routes.update_exposure_status(
            exposure.id, routes.ExposureStatusUpdate(status="bogus"), db=db, current_user=_user(1)
        )
    assert err.value.status_code == 422

    out = routes.update_exposure_status(
        exposure.id, routes.ExposureStatusUpdate(status="resolved"), db=db, current_user=_user(1)
    )
    assert out.status == "resolved"


def test_identity_list_counts_exposures(db):
    iss.upsert_identities(
        db, 1, "servicenow", [_snow_user("a1", "jdoe", "jdoe@acme.com", "CFO", "Finance")], {}, complete=True
    )
    ces.ingest_email_breach_results(
        db, 1, {"jdoe@acme.com": {"breached": True, "breaches": [{"name": "A"}, {"name": "B"}]}}
    )
    db.commit()
    page = routes.list_identities(
        min_score=0, privileged_only=False, exposed_only=True, q=None, limit=50, offset=0,
        db=db, current_user=_user(1),
    )
    assert page.total == 1 and page.items[0].exposure_count == 2
    empty = routes.list_identities(
        min_score=0, privileged_only=False, exposed_only=False, q=None, limit=50, offset=0,
        db=db, current_user=_user(2),
    )
    assert empty.total == 0


def test_credential_exposure_permissions():
    from app.core.permissions import route_permission

    assert route_permission("POST", "/credential-exposure/identities/sync/servicenow") == "integrations.manage"
    assert route_permission("PATCH", "/credential-exposure/exposures/1") == "findings.edit"
    assert route_permission("GET", "/credential-exposure/exposures") is None
