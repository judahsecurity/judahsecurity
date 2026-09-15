from app.workers import vuln_intel_worker as worker


def test_refresh_interval_defaults_and_clamps(monkeypatch):
    monkeypatch.delenv("VULN_INTEL_REFRESH_INTERVAL_SECONDS", raising=False)
    assert worker.refresh_interval_seconds() == 3600
    monkeypatch.setenv("VULN_INTEL_REFRESH_INTERVAL_SECONDS", "10")
    assert worker.refresh_interval_seconds() == 300
    monkeypatch.setenv("VULN_INTEL_REFRESH_INTERVAL_SECONDS", "invalid")
    assert worker.refresh_interval_seconds() == 3600


def test_refresh_once_updates_vulncheck_and_public_indexes(monkeypatch):
    calls = {}
    monkeypatch.setattr(worker, "_resolve_token", lambda: ("token", "test"))
    monkeypatch.setattr(worker, "fetch_cisa_kev_catalog", lambda **kw: calls.setdefault("cisa", kw) or [])
    monkeypatch.setattr(worker, "fetch_enisa_eukev_catalog", lambda **kw: calls.setdefault("enisa", kw) or [])
    monkeypatch.setattr(
        worker,
        "fetch_vulncheck_kev",
        lambda token, **kw: calls.setdefault("kev", {"token": token, **kw}) or {},
    )
    monkeypatch.setattr(
        worker,
        "refresh_vulncheck_exploit_index",
        lambda token, **kw: calls.setdefault("xdb", {"token": token, **kw}) or {"status": "fresh", "cves": 1},
    )
    monkeypatch.setattr(
        worker,
        "refresh_nuclei_cve_index",
        lambda **kw: calls.setdefault("nuclei", kw) or {"status": "fresh", "cves": 2},
    )

    result = worker.refresh_once(interval_seconds=1800)

    assert result["token_configured"] is True
    assert calls["kev"]["token"] == "token"
    assert calls["xdb"]["refresh_hours"] == 0.5
    assert calls["nuclei"]["refresh_hours"] == 0.5
