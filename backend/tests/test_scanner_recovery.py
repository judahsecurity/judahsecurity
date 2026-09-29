"""Regression coverage for scan ownership and stale recovery."""

import asyncio
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models.scan import Scan, ScanStatus, ScanType
from app.models.scan_schedule import ScanSchedule, ScheduleFrequency
from app.workers import scanner_worker, schedule_worker
from app.workers.scanner_worker import ScannerWorker
from app.workers.schedule_worker import ScheduleWorker, split_target_batches


def _scan(scan_id, status, *, updated_minutes_ago=90, retries=0):
    return Scan(
        id=scan_id,
        name=f"Scan {scan_id}",
        scan_type=ScanType.LOGIN_PORTAL,
        organization_id=1,
        status=status,
        started_at=datetime.utcnow() - timedelta(minutes=90),
        updated_at=datetime.utcnow() - timedelta(minutes=updated_minutes_ago),
        config={"_retry_count": retries},
    )


def _worker(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'scans.sqlite'}")
    Scan.__table__.create(engine)
    session = sessionmaker(bind=engine)
    worker = object.__new__(ScannerWorker)
    worker.get_db_session = session
    worker.claimed_scan_ids = set()
    worker.active_scan_tasks = {}
    monkeypatch.setattr(scanner_worker, "active_scans", set())
    return worker, session


def test_recovery_only_retries_unowned_scans_without_a_recent_heartbeat(tmp_path, monkeypatch):
    worker, session = _worker(tmp_path, monkeypatch)
    with session() as db:
        db.add_all([
            _scan(1, ScanStatus.RUNNING),
            _scan(2, ScanStatus.RUNNING),
            _scan(3, ScanStatus.RUNNING, updated_minutes_ago=1),
            _scan(4, ScanStatus.RUNNING, retries=2),
        ])
        db.commit()

    scanner_worker.active_scans.add(1)
    assert asyncio.run(worker.recover_stale_scans()) == 1

    with session() as db:
        assert db.get(Scan, 1).status == ScanStatus.RUNNING
        assert db.get(Scan, 2).status == ScanStatus.PENDING
        assert db.get(Scan, 2).config["_retry_count"] == 1
        assert db.get(Scan, 3).status == ScanStatus.RUNNING
        assert db.get(Scan, 4).status == ScanStatus.FAILED


def test_claim_is_conditional_on_pending_status(tmp_path, monkeypatch):
    worker, session = _worker(tmp_path, monkeypatch)
    other = object.__new__(ScannerWorker)
    other.get_db_session = session
    other.claimed_scan_ids = set()
    with session() as db:
        db.add(_scan(5, ScanStatus.PENDING))
        db.commit()

    assert worker._mark_scan_running(5)
    assert not other._mark_scan_running(5)
    assert worker.claimed_scan_ids == {5}
    assert other.claimed_scan_ids == set()


def test_heartbeat_prevents_another_worker_from_recovering_active_scan(tmp_path, monkeypatch):
    worker, session = _worker(tmp_path, monkeypatch)
    worker.claimed_scan_ids.add(6)
    with session() as db:
        db.add(_scan(6, ScanStatus.RUNNING))
        db.commit()

    async def heartbeat_once():
        task = asyncio.create_task(worker._heartbeat_active_scans())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(heartbeat_once())
    with session() as db:
        assert db.get(Scan, 6).updated_at > datetime.utcnow() - timedelta(minutes=1)

    other = object.__new__(ScannerWorker)
    other.get_db_session = session
    other.claimed_scan_ids = set()
    assert asyncio.run(other.recover_stale_scans()) == 0


def test_scheduled_target_batches_cover_every_target_once():
    targets = ["e.example", "c.example", "a.example", "d.example", "b.example"]
    batches = split_target_batches(targets, 2)

    assert [len(batch) for batch in batches] == [2, 2, 1]
    assert set().union(*(set(batch) for batch in batches)) == set(targets)
    assert sum(map(len, batches)) == len(targets)


def test_schedule_queues_bounded_full_coverage_and_waits_for_outstanding_jobs(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'schedule.sqlite'}")
    Scan.__table__.create(engine)
    ScanSchedule.__table__.create(engine)
    session = sessionmaker(bind=engine)
    monkeypatch.setattr(schedule_worker, "validate_rules_of_engagement", lambda *_args: None)
    monkeypatch.setattr(schedule_worker, "send_scan_to_sqs", lambda _scan: False)
    worker = object.__new__(ScheduleWorker)
    targets = [f"host-{index}.example" for index in range(5)]

    with session() as db:
        schedule = ScanSchedule(
            id=1,
            name="Login checks",
            organization_id=1,
            scan_type="login_portal",
            targets=targets,
            config={"max_targets_per_scan": 2},
            frequency=ScheduleFrequency.DAILY,
            timezone="UTC",
            run_at_hour=2,
            run_count=0,
            consecutive_failures=0,
        )
        db.add(schedule)
        db.commit()

        asyncio.run(worker.run_schedule(db, schedule))
        scans = db.query(Scan).order_by(Scan.id).all()
        assert [len(scan.targets) for scan in scans] == [2, 2, 1]
        assert {target for scan in scans for target in scan.targets} == set(targets)
        assert schedule.last_scan_id == scans[-1].id

        asyncio.run(worker.run_schedule(db, schedule))
        assert db.query(Scan).count() == 3

        for scan in scans:
            scan.status = ScanStatus.COMPLETED
        db.commit()
        asyncio.run(worker.run_schedule(db, schedule))
        assert db.query(Scan).count() == 6
