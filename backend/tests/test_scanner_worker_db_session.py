"""Regression: intel handlers must get their DB session from the worker.

handle_email_breach / handle_dns_threat / handle_urlhaus_lookup /
handle_bgp_lookup previously called a bare ``SessionLocal()`` that was never
imported, so every job died with NameError before doing any work.
"""

import asyncio
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.scan import Scan, ScanStatus, ScanType
from app.services import email_breach_service
from app.workers.scanner_worker import ScannerWorker


class _FakeDomainResult:
    def to_dict(self):
        return {"domain": "example.com", "breached": False}


class _FakeBreachService:
    async def check_domain_breach_exposure(self, domain):
        assert domain == "example.com"
        return _FakeDomainResult()

    async def batch_check_emails(self, emails):  # pragma: no cover - not reached
        return {}


def _worker(session_factory):
    worker = object.__new__(ScannerWorker)
    worker.get_db_session = session_factory
    return worker


def test_email_breach_uses_worker_session_and_completes_scan(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'scans.sqlite'}")
    Scan.__table__.create(engine)
    factory = sessionmaker(bind=engine)

    with factory() as db:
        db.add(Scan(
            id=1,
            name="Email breach",
            scan_type=ScanType.EMAIL_BREACH,
            organization_id=1,
            status=ScanStatus.PENDING,
            started_at=datetime.utcnow(),
            config={},
        ))
        db.commit()

    opened = []

    def tracking_factory():
        session = factory()
        opened.append(session)
        return session

    monkeypatch.setattr(
        email_breach_service, "get_email_breach_service", lambda: _FakeBreachService()
    )
    worker = _worker(tracking_factory)
    # Fail loudly instead of silently swallowing errors via _mark_scan_failed.
    worker._mark_scan_failed = lambda scan_id, msg: (_ for _ in ()).throw(AssertionError(msg))

    asyncio.run(worker.handle_email_breach({
        "scan_id": 1,
        "config": {"domain": "example.com"},
    }))

    assert opened, "handler did not request a session from the worker"
    with factory() as db:
        scan = db.get(Scan, 1)
        assert scan.status == ScanStatus.COMPLETED
        assert scan.progress == 100
        assert scan.results["domain"] == "example.com"
        assert scan.results["data"]["domain"]["breached"] is False


def test_intel_handlers_return_cleanly_without_db():
    worker = _worker(lambda: None)
    body = {"scan_id": 1, "organization_id": 1, "config": {}}
    for handler in (
        worker.handle_email_breach,
        worker.handle_dns_threat,
        worker.handle_urlhaus_lookup,
        worker.handle_bgp_lookup,
    ):
        assert asyncio.run(handler(body)) is None
