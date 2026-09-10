from datetime import datetime, timezone

import pytest

from app.models.scan_schedule import ScanSchedule, ScheduleFrequency


def make_schedule(**values):
    defaults = {
        "name": "test",
        "organization_id": 1,
        "scan_type": "nuclei",
        "frequency": ScheduleFrequency.DAILY,
        "run_at_hour": 2,
        "timezone": "UTC",
    }
    return ScanSchedule(**{**defaults, **values})


def test_daily_schedule_honors_local_timezone():
    schedule = make_schedule(timezone="America/Chicago", run_at_hour=9)
    now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)  # 07:00 local

    assert schedule.calculate_next_run(now) == datetime(
        2026, 9, 9, 14, 0, tzinfo=timezone.utc
    )


def test_weekly_can_run_later_on_the_same_day():
    schedule = make_schedule(
        frequency=ScheduleFrequency.WEEKLY,
        run_on_day=2,  # Wednesday
        run_at_hour=18,
    )
    now = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)

    assert schedule.calculate_next_run(now) == datetime(
        2026, 9, 9, 18, 0, tzinfo=timezone.utc
    )


def test_monthly_day_is_clamped_to_the_real_month_end():
    schedule = make_schedule(
        frequency=ScheduleFrequency.MONTHLY,
        run_on_day=31,
        run_at_hour=8,
    )
    now = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)

    assert schedule.calculate_next_run(now) == datetime(
        2026, 4, 30, 8, 0, tzinfo=timezone.utc
    )


def test_invalid_timezone_is_rejected():
    schedule = make_schedule(timezone="Mars/Olympus_Mons")
    with pytest.raises(ValueError, match="Unknown schedule timezone"):
        schedule.calculate_next_run(datetime(2026, 9, 9, tzinfo=timezone.utc))
