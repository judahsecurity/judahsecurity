"""Early Interceptor queue + job reuse helpers."""

from app.services.recon_jobs_service import _normalize_job_url
from app.services.interceptor_service import apply_pentester_defaults


def test_normalize_job_url_strips_slash_and_lowercases_host():
    a = _normalize_job_url("https://WWW.Example.com/app/")
    b = _normalize_job_url("https://www.example.com/app")
    assert a == b == "https://www.example.com/app"


def test_normalize_job_url_adds_https():
    assert _normalize_job_url("example.com") == "https://example.com/"


def test_queue_opts_carry_pentester_defaults():
    out = apply_pentester_defaults({"url": "https://customer.test/"})
    assert out["interact"] is True
    assert out["depth"] == 3
    assert out["max_pages"] == 25
