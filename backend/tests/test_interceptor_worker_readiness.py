"""Readiness contract for real Interceptor browser workers."""

import asyncio

from app.services import interceptor_recon, interceptor_worker, recon_jobs_service


def test_verbose_status_requires_reachable_extension():
    assert interceptor_recon.InterceptorCLI.status_is_reachable(
        "mode: browser-only\ndaemon: running\nextension: reachable\n"
    )
    assert not interceptor_recon.InterceptorCLI.status_is_reachable(
        "mode: browser-only\ndaemon: running\nextension: not reachable\n"
    )
    assert not interceptor_recon.InterceptorCLI.status_is_reachable(
        "mode: browser-only\ndaemon: not running\n"
    )


def test_cli_nonzero_exit_is_not_treated_as_browser_output(tmp_path):
    binary = tmp_path / "interceptor"
    binary.write_text("#!/bin/sh\necho 'error: extension timed out'\nexit 7\n")
    binary.chmod(0o755)
    out = asyncio.run(interceptor_recon.InterceptorCLI(str(binary)).run("open", "about:blank"))
    assert out.startswith("__error__ exit 7:")


def test_probe_runtime_reports_missing_binary(monkeypatch):
    monkeypatch.setattr(interceptor_recon, "resolve_bin", lambda: None)
    meta = asyncio.run(interceptor_worker.probe_runtime())
    assert meta["interceptor_ready"] is False
    assert "binary not found" in meta["readiness_error"]


def test_probe_runtime_exposes_safe_component_health(monkeypatch):
    monkeypatch.setattr(interceptor_recon, "resolve_bin", lambda: "/opt/interceptor")

    async def fake_run(self, *args, **kwargs):
        if args == ("--version",):
            return "interceptor 1.0.1\n"
        return "mode: browser-only\ndaemon: running\nextension: reachable\n"

    monkeypatch.setattr(interceptor_recon.InterceptorCLI, "run", fake_run)
    meta = asyncio.run(interceptor_worker.probe_runtime())
    assert meta["interceptor_ready"] is True
    assert meta["interceptor_version"] == "interceptor 1.0.1"
    assert meta["extension"] == "reachable"
    assert "status" not in meta


def test_unready_worker_kind_is_not_online(monkeypatch):
    monkeypatch.setattr(
        recon_jobs_service,
        "list_online_workers",
        lambda ttl_sec: [
            {
                "worker_kind": "ubuntu",
                "online": False,
                "meta": {"interceptor_ready": False},
            }
        ],
    )
    assert recon_jobs_service.online_kinds() == []
