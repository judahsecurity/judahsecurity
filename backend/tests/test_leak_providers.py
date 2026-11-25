"""XposedOrNot parsing, Hudson Rock adapter, email harvesting and the full check."""

from datetime import datetime
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.routes import credential_exposure as routes
from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.identity import (
    CREDENTIAL_EMAIL_ONLY,
    CREDENTIAL_PASSWORD_HASH,
    CREDENTIAL_PASSWORD_PLAINTEXT,
    CredentialExposure,
    StealerDomainSummary,
    StealerUrlExposure,
)
from app.models.organization import Organization
from app.services import credential_exposure_service as ces
from app.services import email_breach_service as ebs
from app.services import email_harvest_service as harvest
from app.services import hudsonrock_service as hr
from app.services import identity_sync_service as iss
from app.services.identity_risk import classify_login_url, score_stealer_url

NOW = datetime(2026, 11, 25)

# Shapes match live responses; values are synthetic.
HR_DOMAIN = {
    "total": 120, "employees": 80, "users": 40, "third_parties": 3,
    "last_employee_compromised": "2026-11-20T00:00:00.000Z",
    "last_user_compromised": "2026-10-01T00:00:00.000Z",
    "stealerFamilies": {"total": 50, "RedLine": 30, "Lumma": 20},
    "employeePasswords": {"totalPass": 10, "weak": {"qty": 6, "perc": 60.0}},
    "data": {
        "employees_urls": [
            {"occurrence": 1500, "type": "Employee", "url": "https://idp.example.com/adfs/oauth2/authorize"},
            {"occurrence": 12, "type": "Employee", "url": "https://mfaportal.example.com/mfaportal/login.aspx"},
            {"occurrence": 4, "type": "Employee", "url": "ftp://files.example.com/"},
            {"occurrence": 9, "type": "Employee", "url": "https://*****.example.com/login"},
        ],
        "clients_urls": [
            {"occurrence": 700, "type": "User", "url": "https://www.example.com/account/create-account"},
        ],
    },
}
HR_EMAIL = {
    "message": "...",
    "stealers": [
        {"total_corporate_services": 12, "total_user_services": 300,
         "date_compromised": "2026-11-01T00:00:00.000Z", "computer_name": "DESKTOP-X (bob)",
         "ip": "1.2.**.**", "malware_path": "C:\\\\x.exe", "top_passwords": ["P****d"]},
    ],
}


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([
            Organization(id=1, name="Example", domain="example.com"),
            Organization(id=2, name="Other", domain="other.com"),
        ])
        session.commit()
        yield session


# ── XposedOrNot ──────────────────────────────────────────────────────────────

def test_parse_breach_analytics_details():
    data = {"ExposedBreaches": {"breaches_details": [{
        "breach": "BigLeak", "xposed_date": "2026", "xposed_records": 5,
        "xposed_data": "Email addresses;Passwords", "password_risk": "plaintextpassword",
        "verified": "Yes",
    }]}}
    [rec] = ebs.parse_breach_analytics(data)
    assert rec.name == "BigLeak" and rec.date == "2026"
    assert rec.data_classes == ["Email addresses", "Passwords"]
    assert rec.password_risk == "plaintextpassword"


def test_parse_check_email_nested_lists():
    """check-email returns [["A", "B"]]; the old parser read this as no breaches."""
    recs = ebs.parse_breach_analytics({"breaches": [["Epik", "Trello"]]})
    assert [r.name for r in recs] == ["Epik", "Trello"]


@pytest.mark.asyncio
async def test_domain_search_skipped_without_key(monkeypatch):
    monkeypatch.setattr(ebs, "_xon_api_key", lambda: None)
    result = await ebs.EmailBreachService().check_domain_breach_exposure("example.com")
    assert result.success is False and "XPOSEDORNOT_API_KEY" in result.error


@pytest.mark.parametrize(
    "breach,expected",
    [
        ({"data_classes": ["Passwords"], "password_risk": "hardtocrack"}, CREDENTIAL_PASSWORD_HASH),
        ({"data_classes": ["Email addresses"], "password_risk": "hardtocrack"}, CREDENTIAL_EMAIL_ONLY),
        ({"data_classes": ["Email addresses"], "password_risk": "plaintextpassword"},
         CREDENTIAL_PASSWORD_PLAINTEXT),
    ],
)
def test_credential_type_for_breach(breach, expected):
    assert ces.credential_type_for_breach(breach) == expected


# ── Hudson Rock ──────────────────────────────────────────────────────────────

def test_parse_domain_response_skips_masked_urls_and_keeps_counts():
    result = hr.parse_domain_response("example.com", HR_DOMAIN)
    assert result.employees == 80 and result.users == 40
    assert result.stealer_families == {"RedLine": 30, "Lumma": 20}
    assert len(result.urls) == 4
    assert {u.host for u in result.urls} >= {"idp.example.com", "files.example.com"}
    assert result.summary()["top_employee_urls"][0]["occurrence"] == 1500


def test_parse_email_response_drops_machine_details():
    [inf] = hr.parse_email_response(HR_EMAIL)
    assert inf.date_compromised == datetime(2026, 11, 1)
    assert inf.corporate_services == 12
    assert not hasattr(inf, "computer_name") and not hasattr(inf, "ip")


@pytest.mark.asyncio
async def test_client_raises_on_rate_limit():
    transport = httpx.MockTransport(lambda r: httpx.Response(429))
    async with httpx.AsyncClient(transport=transport) as http:
        with pytest.raises(hr.HudsonRockError, match="429"):
            await hr.HudsonRockClient(client=http).search_by_domain("example.com")


@pytest.mark.parametrize(
    "url,category",
    [
        ("https://idp.example.com/adfs/oauth2/authorize", "sso"),
        ("https://fs.example.com/adfs/ls", "sso"),
        ("https://mfaportal.example.com/mfaportal/login.aspx", "mfa"),
        ("https://vpn.example.com/remote/login", "remote_access"),
        ("ftp://raftp.example.com/", "file_transfer"),
        ("https://www.example.com/account/reset-password", "password_reset"),
        ("https://jobs.example.com/profile/login", "login"),
        ("https://www.example.com/", "other"),
    ],
)
def test_classify_login_url(url, category):
    assert classify_login_url(url)[0] == category


def test_employee_sso_outranks_customer_signup():
    sso, sso_sev, _, _ = score_stealer_url(
        url="https://idp.example.com/adfs/oauth2/authorize", audience="employee",
        occurrence=1500, last_compromised=datetime(2026, 11, 20), asset_matched=True, now=NOW,
    )
    signup, signup_sev, _, _ = score_stealer_url(
        url="https://www.example.com/account/create-account", audience="user",
        occurrence=700, last_compromised=datetime(2026, 10, 1), asset_matched=True, now=NOW,
    )
    assert sso_sev == "critical" and sso > signup
    assert signup_sev in ("low", "medium")


def test_ingest_domain_matches_inventory_hosts(db):
    db.add_all([
        Asset(organization_id=1, name="idp.example.com", value="idp.example.com",
              asset_type=AssetType.SUBDOMAIN, root_domain="example.com"),
        Asset(organization_id=2, name="files.example.com", value="files.example.com",
              asset_type=AssetType.SUBDOMAIN, root_domain="example.com"),
    ])
    db.commit()
    result = hr.parse_domain_response("example.com", HR_DOMAIN)
    stats = ces.ingest_hudsonrock_domain(db, 1, result, now=NOW)
    assert stats == {"created": 4, "refreshed": 0, "asset_matched": 1}
    top = db.query(StealerUrlExposure).order_by(StealerUrlExposure.priority_score.desc()).first()
    assert top.host == "idp.example.com" and top.asset_id is not None and top.login_category == "sso"
    # files.example.com belongs to another org's inventory: no cross-org match.
    ftp = db.query(StealerUrlExposure).filter_by(host="files.example.com").one()
    assert ftp.asset_id is None
    assert db.query(StealerDomainSummary).one().summary["employees"] == 80

    stats = ces.ingest_hudsonrock_domain(db, 1, result, now=NOW)
    assert stats["created"] == 0 and stats["refreshed"] == 4


def test_ingest_email_infections_dedup_per_machine(db):
    index = ces.build_identity_index(db, 1)
    infections = hr.parse_email_response(HR_EMAIL)
    assert ces.ingest_hudsonrock_email(db, 1, index, "bob@example.com", infections)["created"] == 1
    assert ces.ingest_hudsonrock_email(db, 1, index, "bob@example.com", infections)["refreshed"] == 1
    exp = db.query(CredentialExposure).one()
    assert exp.source_type == "stealer_log" and exp.credential_type == CREDENTIAL_PASSWORD_PLAINTEXT
    assert exp.severity in ("high", "critical")  # plaintext + infected 24 days ago
    stored = " ".join(str(getattr(exp, c.name)) for c in CredentialExposure.__table__.columns)
    assert "DESKTOP" not in stored and "1.2." not in stored


# ── Email harvesting ─────────────────────────────────────────────────────────

def test_extract_emails_filters_domains_and_filenames():
    text = (
        "Contact jane.doe@example.com or ops@mail.example.com; "
        "mailto:sales@example.com, logo@2x.png, someone@gmail.com, x@notexample.com"
    )
    assert harvest.extract_emails(text, ["example.com"]) == {
        "jane.doe@example.com", "ops@mail.example.com", "sales@example.com",
    }


def test_harvest_reads_dns_certs_metadata_and_scans(db):
    from app.models.scan import Scan, ScanType

    db.add_all([
        Asset(organization_id=1, name="example.com", value="example.com", asset_type=AssetType.DOMAIN,
              dns_records={"SOA": ["ns1.example.com. hostmaster.example.com. 1 2 3 4 5"],
                           "TXT": ["v=DMARC1; rua=mailto:dmarc@example.com"]},
              ssl_info={"subject": {"emailAddress": "pki@example.com"}},
              metadata_={"whois": {"registrant_email": "domains@example.com"}}),
        Asset(organization_id=2, name="leak", value="leak", asset_type=AssetType.OTHER,
              metadata_={"x": "hidden@example.com"}),
        Scan(organization_id=1, name="crawl", scan_type=ScanType.EMAIL_BREACH,
             results={"links": ["mailto:jane.doe@example.com"]}),
    ])
    db.commit()
    found = harvest.harvest_organization_emails(db, 1, ["example.com"])
    assert set(found) == {
        "hostmaster@example.com", "dmarc@example.com", "pki@example.com",
        "domains@example.com", "jane.doe@example.com",
    }
    assert "dns_soa" in found["hostmaster@example.com"]

    stats = harvest.save_email_assets(db, 1, found)
    assert stats["created"] == 5
    jane = db.query(Asset).filter_by(value="jane.doe@example.com").one()
    assert jane.asset_type == AssetType.EMAIL and jane.metadata_["role_account"] is False
    assert harvest.save_email_assets(db, 1, found)["refreshed"] == 5

    # Personal addresses are checked before role mailboxes.
    assert ces.emails_to_check(db, 1, 1) == ["jane.doe@example.com"]


def test_organization_domains_uses_org_and_inventory(db):
    db.add_all([
        Asset(organization_id=1, name="a", value="a.acq.com", asset_type=AssetType.SUBDOMAIN,
              root_domain="acq.com", in_scope=True),
        Asset(organization_id=2, name="b", value="b.other.net", asset_type=AssetType.SUBDOMAIN,
              root_domain="other.net", in_scope=True),
    ])
    db.commit()
    assert ces.organization_domains(db, 1) == ["example.com", "acq.com"]


# ── Full check ───────────────────────────────────────────────────────────────

class _FakeBreaches:
    async def check_domain_breach_exposure(self, domain):
        return ebs.DomainBreachResult(domain=domain, error="Skipped")

    async def batch_check_emails(self, emails):
        out = {}
        for email in emails:
            r = ebs.EmailBreachResult(email=email, success=True)
            if email.startswith("cfo"):
                r.breached = True
                r.breaches = [ebs.BreachRecord(name="BigLeak", date="2026", data_classes=["Passwords"])]
            out[email] = r
        return out


class _FakeHudsonRock:
    def __init__(self, fail_email=False):
        self.fail_email = fail_email
        self.email_calls = []

    async def search_by_domain(self, domain):
        return hr.parse_domain_response(domain, HR_DOMAIN)

    async def search_by_email(self, email):
        self.email_calls.append(email)
        if self.fail_email:
            raise hr.HudsonRockError("Hudson Rock rate limit reached (HTTP 429)")
        return hr.parse_email_response(HR_EMAIL) if email.startswith("cfo") else []


def _snow(sys_id, user, email, title):
    return {"sys_id": {"value": sys_id}, "user_name": {"value": user}, "email": {"value": email},
            "title": {"display_value": title}, "active": {"value": "true"}}


@pytest.mark.asyncio
async def test_full_check_end_to_end(db):
    iss.upsert_identities(
        db, 1, "servicenow",
        [_snow("a1", "cfo", "cfo@example.com", "Chief Financial Officer"),
         _snow("a2", "intern", "intern@example.com", "Intern")],
        {}, complete=True,
    )
    db.commit()
    fake_hr = _FakeHudsonRock()
    out = await ces.run_credential_exposure_check(
        db, 1, breach_service=_FakeBreaches(), hudsonrock=fake_hr, max_emails=10,
    )
    assert out["domains"] == ["example.com"]
    assert out["hudsonrock_domains"]["example.com"]["urls"] == 4
    assert out["xposedornot_emails"]["breached"] == 1
    assert out["hudsonrock_emails"] == {"infected": 1, "created": 1, "refreshed": 0}
    assert fake_hr.email_calls[0] == "cfo@example.com"  # riskiest identity first

    top = db.query(CredentialExposure).order_by(CredentialExposure.priority_score.desc()).first()
    assert top.identifier == "cfo@example.com" and top.provider == "hudsonrock"
    assert top.identity_id is not None


@pytest.mark.asyncio
async def test_full_check_stops_email_lookups_on_rate_limit(db):
    out = await ces.run_credential_exposure_check(
        db, 1, emails=["a@example.com", "b@example.com"],
        breach_service=_FakeBreaches(), hudsonrock=_FakeHudsonRock(fail_email=True),
    )
    assert any("429" in e for e in out["errors"])
    assert out["hudsonrock_emails"]["infected"] == 0


# ── Routes ───────────────────────────────────────────────────────────────────

def test_stealer_url_routes_are_org_scoped(db):
    ces.ingest_hudsonrock_domain(db, 1, hr.parse_domain_response("example.com", HR_DOMAIN), now=NOW)
    db.commit()
    user1 = SimpleNamespace(organization_id=1, is_superuser=False)
    user2 = SimpleNamespace(organization_id=2, is_superuser=False)

    page = routes.list_stealer_urls(audience="employee", status_filter="open", asset_matched=False,
                                    limit=50, offset=0, db=db, current_user=user1)
    assert page.total == 3 and page.items[0].login_category == "sso"
    other = routes.list_stealer_urls(audience=None, status_filter=None, asset_matched=False,
                                     limit=50, offset=0, db=db, current_user=user2)
    assert other.total == 0
    assert len(routes.list_domain_summaries(db=db, current_user=user1)) == 1
    assert routes.list_domain_summaries(db=db, current_user=user2) == []

    row_id = page.items[0].id
    with pytest.raises(HTTPException) as err:
        routes.update_stealer_url_status(row_id, routes.ExposureStatusUpdate(status="resolved"),
                                         db=db, current_user=user2)
    assert err.value.status_code == 404
    out = routes.update_stealer_url_status(row_id, routes.ExposureStatusUpdate(status="accepted"),
                                           db=db, current_user=user1)
    assert out.status == "accepted"
