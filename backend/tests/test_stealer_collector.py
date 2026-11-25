"""Safe stealer-log parsing, engagement-scope enforcement, and signed intake."""

import io
import time
import zipfile
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.asset import Asset, AssetType
from app.models.identity import CredentialExposure, ExposureScope
from app.models.organization import Organization
from app.services import credential_exposure_service as ces
from app.services import exposure_intake_service as intake
from app.services import exposure_scope_service as scope_svc
from app.services import stealer_log_parser as parser

PASSWORDS_TXT = """\
URL: https://idp.rockwellautomation.com/adfs/ls/idpinitiatedsignon.aspx
Username: jdoe@rockwellautomation.com
Password: Sup3rSecret!
Application: Google [Chrome]

Soft: Mozilla Firefox
Host: https://store.example.com/login
Login: shopper@gmail.com
Pass: hunter2

URL: https://portal.rockwellautomation.com
Username: contractor@vendor.com
Password:
"""


def _zip(entries, *, symlink=None):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
        if symlink:
            name, target = symlink
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 | 0) << 16  # S_IFLNK
            zf.writestr(info, target)
    return buf.getvalue()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add_all([
            Organization(id=1, name="Rockwell", domain="rockwellautomation.com"),
            Organization(id=2, name="Other", domain="other.com"),
        ])
        session.commit()
        yield session


# ── Parsing ──────────────────────────────────────────────────────────────────

def test_parse_credential_text_blocks():
    records = parser.parse_credential_text(PASSWORDS_TXT, "Passwords.txt")
    # Third block has a URL + username but no password: still a usable sighting.
    assert len(records) == 3
    first = records[0]
    assert first.url.endswith("idpinitiatedsignon.aspx")
    assert first.username == "jdoe@rockwellautomation.com"
    assert first.password == "Sup3rSecret!"
    assert records[1].username == "shopper@gmail.com" and records[1].password == "hunter2"


def test_parse_only_reads_allowlisted_files():
    data = _zip({
        "logs/Passwords.txt": PASSWORDS_TXT,
        "logs/malware.exe": b"MZ\x90\x00" * 100,
        "logs/screenshot.png": b"\x89PNG" * 100,
        "logs/System.txt": "IP: 1.2.3.4\n",
    })
    result = parser.parse_zip_bytes(data)
    assert result.files_read == 1  # only Passwords.txt
    assert result.skipped_other >= 3
    assert {r.source_file for r in result.records} == {"Passwords.txt"}


def test_parse_skips_symlinks_and_traversal():
    data = _zip(
        {"../../etc/Passwords.txt": PASSWORDS_TXT, "ok/Passwords.txt": PASSWORDS_TXT},
        symlink=("Passwords.txt", "/etc/shadow"),
    )
    result = parser.parse_zip_bytes(data)
    # Only the single safe entry is read; traversal and symlink are skipped.
    assert result.files_read == 1
    assert result.skipped_unsafe >= 2


def test_parse_rejects_decompression_bomb():
    data = _zip({"Passwords.txt": "A" * (2 * 1024 * 1024)})  # highly compressible
    result = parser.parse_zip_bytes(data)
    # Either skipped as a bomb or read within caps, but never expanded unbounded.
    assert result.bytes_read <= parser.MAX_TOTAL_BYTES


def test_parse_bad_zip_raises():
    with pytest.raises(parser.StealerLogError):
        parser.parse_zip_bytes(b"not a zip")


# ── Scope matching ───────────────────────────────────────────────────────────

def test_scope_matcher_host_and_audience():
    m = scope_svc.ScopeMatcher([
        scope_svc.ScopeRule("rockwellautomation.com", include_subdomains=True, audience_scope="both"),
    ])
    assert m.allows("jdoe@rockwellautomation.com")
    assert m.allows("https://idp.rockwellautomation.com/adfs/ls")
    assert m.allows("fs.rockwellautomation.com")
    assert not m.allows("jdoe@gmail.com")
    assert not m.allows("https://rockwellautomation.com.evil.com/login")


def test_scope_audience_restriction():
    m = scope_svc.ScopeMatcher([
        scope_svc.ScopeRule("rockwellautomation.com", include_subdomains=True, audience_scope="employees"),
    ])
    assert m.allows("jdoe@rockwellautomation.com", audience="employee")
    assert not m.allows("https://shop.rockwellautomation.com", audience="customer")


def test_add_and_load_scope(db):
    scope_svc.add_scope(db, 1, "RockwellAutomation.com ", authorized_by="analyst@x", note="SOW-123")
    db.commit()
    m = scope_svc.load_scope(db, 1)
    assert m.domains() == ["rockwellautomation.com"]
    assert scope_svc.load_scope(db, 2).is_empty
    with pytest.raises(ValueError):
        scope_svc.add_scope(db, 1, "not-a-domain")


# ── Scope-enforced ingest ────────────────────────────────────────────────────

def _recs():
    return parser.parse_credential_text(PASSWORDS_TXT)


def test_ingest_refuses_out_of_scope_without_authorization(db):
    stats = ces.ingest_stealer_log_records(db, 1, _recs())
    assert stats["in_scope"] == 0 and stats["out_of_scope"] >= 1
    assert db.query(CredentialExposure).count() == 0


def test_ingest_keeps_only_in_scope_and_fingerprints(db):
    scope_svc.add_scope(db, 1, "rockwellautomation.com", authorized_by="a@x")
    db.add(Asset(organization_id=1, name="idp", value="idp.rockwellautomation.com",
                 asset_type=AssetType.SUBDOMAIN, root_domain="rockwellautomation.com"))
    db.commit()

    stats = ces.ingest_stealer_log_records(db, 1, _recs(), source_name="Lumma 2026-11")
    # jdoe@rockwell (employee) and contractor@vendor saved for a rockwell portal
    # are kept; shopper@gmail on store.example.com is dropped.
    assert stats["in_scope"] == 2 and stats["out_of_scope"] == 1
    assert stats["asset_matched"] == 1

    exp = db.query(CredentialExposure).filter_by(identifier="jdoe@rockwellautomation.com").one()
    assert exp.identifier == "jdoe@rockwellautomation.com"
    assert exp.source_type == "stealer_log" and exp.asset_id is not None
    assert exp.secret_fingerprint and exp.secret_fingerprint.startswith("sha256:")
    stored = " ".join(str(getattr(exp, c.name)) for c in CredentialExposure.__table__.columns)
    assert "Sup3rSecret!" not in stored


def test_ingest_keeps_customer_creds_for_in_scope_url(db):
    # Authorize customer audience; a credential saved for a rockwell URL counts
    # even when the username is a personal address.
    scope_svc.add_scope(db, 1, "rockwellautomation.com", audience_scope="both")
    db.commit()
    records = [SimpleNamespace(url="https://store.rockwellautomation.com/login",
                               username="buyer@gmail.com", password="pw", application=None)]
    stats = ces.ingest_stealer_log_records(db, 1, records)
    assert stats["in_scope"] == 1
    assert db.query(CredentialExposure).one().affected_host == "store.rockwellautomation.com"


# ── Signed intake ────────────────────────────────────────────────────────────

def test_sign_and_verify_roundtrip():
    body = b'{"organization_id": 1}'
    ts = str(int(time.time()))
    sig = intake.sign_payload("secret", ts, body)
    ok, reason = intake.verify_signature(
        secret="secret", signature=sig, timestamp=ts, body=body, max_skew_seconds=300
    )
    assert ok and reason == "ok"


def test_verify_rejects_tampering_and_replay():
    body = b'{"organization_id": 1}'
    ts = str(int(time.time()))
    sig = intake.sign_payload("secret", ts, body)

    bad, reason = intake.verify_signature(
        secret="secret", signature=sig, timestamp=ts, body=b'{"organization_id": 2}',
        max_skew_seconds=300,
    )
    assert not bad and "mismatch" in reason.lower()

    old_ts = str(int(time.time()) - 10_000)
    stale, reason = intake.verify_signature(
        secret="secret", signature=intake.sign_payload("secret", old_ts, body),
        timestamp=old_ts, body=body, max_skew_seconds=300,
    )
    assert not stale and "replay" in reason.lower()

    wrong, _ = intake.verify_signature(
        secret="other", signature=sig, timestamp=ts, body=body, max_skew_seconds=300
    )
    assert not wrong

    off, reason = intake.verify_signature(
        secret=None, signature=sig, timestamp=ts, body=body, max_skew_seconds=300
    )
    assert not off and "not configured" in reason.lower()


# ── Intake route ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_intake_route_verifies_signature_and_enforces_scope(db, monkeypatch):
    import json

    from app.api.routes import credential_exposure as routes
    from app.core.config import settings

    monkeypatch.setattr(settings, "EXPOSURE_COLLECTOR_SECRET", "shared-secret")
    scope_svc.add_scope(db, 1, "rockwellautomation.com", authorized_by="a@x")
    db.commit()

    payload = {
        "organization_id": 1,
        "source_name": "Lumma 2026-11",
        "records": [
            {"url": "https://idp.rockwellautomation.com/adfs/ls",
             "username": "jdoe@rockwellautomation.com", "password": "pw"},
            {"url": "https://store.example.com", "username": "x@gmail.com", "password": "pw"},
        ],
    }
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    sig = intake.sign_payload("shared-secret", ts, body)

    class _Req:
        def __init__(self, body, headers):
            self._body = body
            self.headers = headers

        async def body(self):
            return self._body

    good = _Req(body, {intake.SIGNATURE_HEADER: sig, intake.TIMESTAMP_HEADER: ts})
    out = await routes.collector_intake(good, db=db)
    assert out["in_scope"] == 1 and out["out_of_scope"] == 1 and out["received"] == 2

    bad = _Req(body, {intake.SIGNATURE_HEADER: "deadbeef", intake.TIMESTAMP_HEADER: ts})
    with pytest.raises(Exception) as err:
        await routes.collector_intake(bad, db=db)
    assert getattr(err.value, "status_code", None) == 401


@pytest.mark.asyncio
async def test_intake_refuses_without_scope(db, monkeypatch):
    import json

    from app.api.routes import credential_exposure as routes
    from app.core.config import settings

    monkeypatch.setattr(settings, "EXPOSURE_COLLECTOR_SECRET", "shared-secret")
    raw = json.dumps({"organization_id": 2, "records": []}).encode()
    ts = str(int(time.time()))

    class _Req:
        def __init__(self):
            self.headers = {
                intake.SIGNATURE_HEADER: intake.sign_payload("shared-secret", ts, raw),
                intake.TIMESTAMP_HEADER: ts,
            }

        async def body(self):
            return raw

    with pytest.raises(Exception) as err:
        await routes.collector_intake(_Req(), db=db)
    assert getattr(err.value, "status_code", None) == 403
