"""refresh_vuln_intel CLI helpers (no live network)."""

from app.scripts.refresh_vuln_intel import main


def test_refresh_intel_status_empty_cache(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DELPHI_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("VULNCHECK_API_TOKEN", raising=False)
    monkeypatch.setattr("app.scripts.refresh_vuln_intel._resolve_token", lambda: ("", "none"))
    rc = main(["--status"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "vulncheck_kev: 0 entries" in out
    assert "MISSING" in out
