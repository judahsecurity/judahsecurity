"""Unit tests for ENISA EUKEV parsing helpers (no live network)."""

from datetime import datetime, timezone

from app.api.routes.threat_intel import _parse_enisa_date


def test_parse_enisa_date_slash_format():
    dt = _parse_enisa_date("2026/07/31")
    assert dt is not None
    assert dt == datetime(2026, 7, 31, tzinfo=timezone.utc)


def test_parse_enisa_date_iso():
    dt = _parse_enisa_date("2024-01-15")
    assert dt is not None
    assert dt.year == 2024 and dt.month == 1 and dt.day == 15


def test_parse_enisa_date_empty():
    assert _parse_enisa_date("") is None
    assert _parse_enisa_date("not-a-date") is None
