"""Falcon host evidence against a simulated Falcon API — never a live tenant.

``no_network`` makes any real HTTP call fail the test, so nothing here can
reach a CrowdStrike deployment.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest

from app.services import falcon_host_evidence as falcon
from app.services import host_evidence_service as hes


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("test attempted a real HTTP call")

    monkeypatch.setattr(httpx.AsyncClient, "request", refuse)
    monkeypatch.setattr(httpx.AsyncClient, "send", refuse)
    monkeypatch.setattr(falcon, "RTR_POLL_SECONDS", 0.0)


UBUNTU = {"device_id": "aid-12", "platform_name": "Linux", "os_version": "Ubuntu 22.04", "os_product_name": "Ubuntu",
          "kernel_version": "6.8.0-45-generic"}
MAIN = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nLoginGraceTime 2m\nPermitRootLogin no\n" \
       "Match User backup\n    PasswordAuthentication yes\n"


class FakeFalcon:
    """Answers the read-only Falcon endpoints the collector uses."""

    def __init__(self, device=UBUNTU, files=None, dirs=None, apps=None, apps_error=None, rtr_open=True):
        self.device, self.apps, self.apps_error, self.rtr_open = device, apps or [], apps_error, rtr_open
        self.files = {"/etc/ssh/sshd_config": MAIN, "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication no\n"} \
            if files is None else files
        self.dirs = {"/etc/ssh/sshd_config.d": ["50-cloud-init.conf", "README"]} if dirs is None else dirs
        self.calls, self._pending = [], {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def _request(self, method, path, **kw):
        self.calls.append((method, path, kw))
        if path == "/devices/entities/devices/v2":
            return {"resources": [self.device]}
        if path == "/real-time-response/entities/sessions/v1":
            return {"resources": [{"session_id": "s-1"}] if self.rtr_open and method == "POST" else [{}]}
        if path == "/real-time-response/entities/command/v1" and method == "POST":
            body = kw["json"]
            rid = f"r-{len(self._pending)}"
            self._pending[rid] = body["command_string"]
            return {"resources": [{"cloud_request_id": rid}]}
        if path == "/real-time-response/entities/command/v1":
            cmd = self._pending[kw["params"]["cloud_request_id"]]
            base, arg = cmd.split(" ", 1)
            if base == "cat":
                if arg in self.files:
                    return {"resources": [{"complete": True, "stdout": self.files[arg], "stderr": ""}]}
                return {"resources": [{"complete": True, "stdout": "", "stderr": f"{arg}: No such file or directory"}]}
            if arg in self.dirs:
                if self.dirs[arg] is None:
                    return {"resources": [{"complete": True, "stdout": "", "stderr": "permission denied"}]}
                return {"resources": [{"complete": True, "stdout": "\n".join(self.dirs[arg]), "stderr": ""}]}
            return {"resources": [{"complete": True, "stdout": "", "stderr": "No such file or directory"}]}
        raise AssertionError(f"unexpected Falcon call {method} {path}")

    async def _pages(self, path, *, params, cursor_key):
        self.calls.append(("GET", path, {"params": params}))
        assert path == "/discover/combined/applications/v1"
        if self.apps_error:
            raise RuntimeError(self.apps_error)
        yield self.apps

    def commands(self):
        return [c[2]["json"]["command_string"] for c in self.calls if c[0] == "POST" and c[1].endswith("command/v1")]


def run(coro):
    return asyncio.run(coro)


# ── Pure helpers ──────────────────────────────────────────────────────────────

def test_device_facts():
    assert falcon.device_facts(UBUNTU) == {
        "os.platform": "linux", "os.product": "Ubuntu", "os.version": "Ubuntu 22.04",
        "kernel.release": "6.8.0-45-generic", "os.id": "ubuntu", "os.version_id": "22.04"}
    assert falcon.device_facts({"platform_name": "Linux", "os_version": "RHEL 9.2"})["os.id"] == "rhel"
    win = falcon.device_facts({"platform_name": "Windows", "os_version": "Windows Server 2022"})
    assert win["os.platform"] == "windows" and "os.id" not in win
    assert falcon.device_facts({"platform_name": "Mac"})["os.platform"] == "mac"


def test_application_facts_only_assert_recent_use():
    now = datetime(2026, 11, 17, tzinfo=timezone.utc)
    facts = falcon.application_facts([
        {"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.6", "last_used_timestamp": "2026-11-16T10:00:00Z"},
        {"name": "Google Chrome", "version": "131.0.6778.86", "last_used_timestamp": (now - timedelta(days=90)).isoformat()},
        {"name": "libxml2", "version": "2.9.13"},
        {"version": "no name"},
    ], now)
    assert facts["package.openssh-server"] == "1:8.9p1-3ubuntu0.6"
    assert facts["package.openssh-server.used"] == "true"
    assert facts["package.google-chrome.installed"] == "true" and "package.google-chrome.used" not in facts
    assert "package.libxml2.used" not in facts and "package.libxml2.last_used" not in facts
    assert not any(k.endswith("._complete") for k in facts)  # Discover isn't a complete package list


def test_sshd_seconds():
    assert falcon.sshd_seconds("120") == "120"
    assert falcon.sshd_seconds("2m") == "120"
    assert falcon.sshd_seconds("1h30m") == "5400"
    assert falcon.sshd_seconds("0") == "0"
    assert falcon.sshd_seconds("soon") is None


def _resolve(files, dirs=None, root="/etc/ssh", main="/etc/ssh/sshd_config"):
    async def read(path):
        return files.get(path)

    async def list_dir(path):
        return (dirs or {}).get(path, [])

    return run(falcon.effective_sshd_from_files(main, read, list_dir, root=root))


def test_sshd_files_first_value_wins_through_includes():
    facts, info = _resolve(
        {"/etc/ssh/sshd_config": MAIN, "/etc/ssh/sshd_config.d/10-hardening.conf": "LoginGraceTime 0\n"},
        {"/etc/ssh/sshd_config.d": ["10-hardening.conf", "notes.txt"]},
    )
    # The Include comes first, so its LoginGraceTime 0 beats the later 2m.
    assert facts["sshd.logingracetime"] == "0"
    assert facts["sshd.permitrootlogin"] == "no"
    assert "sshd.passwordauthentication" not in facts  # only set inside Match
    assert facts["sshd.maxstartups"] == "10:30:100"  # default
    assert info["match_blocks"] and info["files"] == ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-hardening.conf"]


def test_sshd_files_defaults_and_time_units():
    facts, _ = _resolve({"/etc/ssh/sshd_config": "LoginGraceTime 2m\n"})
    assert facts["sshd.logingracetime"] == "120"
    facts, _ = _resolve({"/etc/ssh/sshd_config": "# nothing set\n"})
    assert facts["sshd.logingracetime"] == "120"


def test_sshd_absent_and_unresolvable_includes():
    facts, info = _resolve({})
    assert facts == {} and info["absent"]

    async def read(path):
        return MAIN

    async def cannot_list(path):
        return None

    with pytest.raises(falcon.FalconCheckError, match="could not list"):
        run(falcon.effective_sshd_from_files("/etc/ssh/sshd_config", read, cannot_list, root="/etc/ssh"))
    with pytest.raises(falcon.FalconCheckError, match="outside"):
        _resolve({"/etc/ssh/sshd_config": "Include /etc/shadow\n"})
    with pytest.raises(falcon.FalconCheckError, match="outside"):
        _resolve({"/etc/ssh/sshd_config": "Include ../../etc/shadow\n"})
    with pytest.raises(falcon.FalconCheckError, match="could not be read"):
        _resolve({"/etc/ssh/sshd_config": "Include /etc/ssh/extra.conf\n"})


def test_windows_sshd_paths():
    facts, info = _resolve({"C:\\ProgramData\\ssh\\sshd_config": "LoginGraceTime 30\n"},
                           root="C:\\ProgramData\\ssh", main="C:\\ProgramData\\ssh\\sshd_config")
    assert facts["sshd.logingracetime"] == "30"


def test_rtr_allows_only_read_commands_and_safe_paths():
    api = falcon.FalconHostAPI(FakeFalcon(), "aid-12")
    for base, arg in (("rm", "/etc/ssh/sshd_config"), ("runscript", "-Raw=```id```"), ("put", "x"),
                      ("cat", "/etc/ssh/sshd_config; reboot"), ("cat", "/etc/ssh/a b")):
        with pytest.raises(falcon.FalconCheckError):
            run(api.rtr(base, arg))


# ── Collection ────────────────────────────────────────────────────────────────

def test_collect_with_rtr():
    fake = FakeFalcon(apps=[{"name": "openssh-server", "version": "1:8.9p1-3ubuntu0.6"}])
    record = run(falcon.collect(falcon.FalconHostAPI(fake, "aid-12"), applications=True, rtr=True))
    assert not record.get("error")
    facts = record["facts"]
    assert facts["sshd.logingracetime"] == "120" and facts["sshd.passwordauthentication"] == "no"
    assert facts["package.openssh-server"] == "1:8.9p1-3ubuntu0.6"
    assert set(record["probes"]) == {"os", "kernel", "package", "sshd"}
    assert all(p["ok"] for p in record["probes"].values())
    assert fake.commands() == ["cat /etc/ssh/sshd_config", "ls /etc/ssh/sshd_config.d",
                               "cat /etc/ssh/sshd_config.d/50-cloud-init.conf"]
    assert ("DELETE", "/real-time-response/entities/sessions/v1") in [(c[0], c[1]) for c in fake.calls]


def test_collect_without_rtr_never_opens_a_session():
    fake = FakeFalcon()
    record = run(falcon.collect(falcon.FalconHostAPI(fake, "aid-12"), applications=True, rtr=False))
    assert "sshd" not in record["probes"]
    assert not any("real-time-response" in c[1] for c in fake.calls)


def test_partial_failures_are_recorded_per_probe():
    fake = FakeFalcon(apps_error="CrowdStrike denied /discover/combined/applications/v1 (HTTP 403)",
                      dirs={"/etc/ssh/sshd_config.d": None})
    record = run(falcon.collect(falcon.FalconHostAPI(fake, "aid-12"), applications=True, rtr=True))
    assert record["probes"]["os"]["ok"]
    assert not record["probes"]["package"]["ok"] and "403" in record["probes"]["package"]["error"]
    assert not record["probes"]["sshd"]["ok"] and "could not list" in record["probes"]["sshd"]["error"]
    assert not any(k.startswith("sshd.") for k in record["facts"])


def test_offline_host_cannot_open_rtr():
    record = run(falcon.collect(falcon.FalconHostAPI(FakeFalcon(rtr_open=False), "aid-12"), applications=False, rtr=True))
    assert "online" in record["probes"]["sshd"]["error"]


def test_failed_falcon_probe_reaches_oracle_as_could_not_check():
    asset = SimpleNamespace(metadata_={})
    record = run(falcon.collect(falcon.FalconHostAPI(FakeFalcon(dirs={"/etc/ssh/sshd_config.d": None}), "aid-12"),
                                applications=False, rtr=True))
    hes.store_host_facts(asset, record)
    host, _, evidence = hes.host_signals_for_oracle(asset, "asm-1")
    assert host["os.id"] == "ubuntu"
    assert evidence["host.os.*"][0]["freshness"] == "fresh" and evidence["host.os.*"][0]["source"] == "falcon"
    sshd = evidence["host.sshd.*"][0]
    assert sshd["freshness"] == "error" and "could not list" in sshd["error"]


# ── Through host checks, against a database ──────────────────────────────────

@pytest.fixture()
def db(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.database import Base
    import app.models  # noqa: F401 — registers every model
    from app.models.api_config import APIConfig
    from app.models.asset import Asset
    from app.models.business_application import BusinessApplication
    from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
    from app.models.netblock import Netblock
    from app.models.organization import Organization
    from app.models.port_service import PortService
    from app.models.technology import Technology, asset_technologies
    from app.models.vulnerability import Vulnerability
    from app.services import oracle_enrichment_service as oes
    from app.services import severity_intel

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[
        Organization.__table__, Netblock.__table__, BusinessApplication.__table__, Asset.__table__,
        Vulnerability.__table__, APIConfig.__table__, PortService.__table__, Technology.__table__,
        asset_technologies, CrowdStrikeIntegration.__table__, CrowdStrikeAssetLink.__table__])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    s.commit()

    monkeypatch.setattr(severity_intel, "live_intel", lambda cve_id: {})

    def analyze(cve_id, asset_payload):  # stands in for the Oracle daemon
        lgt = (asset_payload["signals"].get("host") or {}).get("sshd.logingracetime")
        status = "unknown" if lgt is None else ("satisfied" if lgt != "0" else "unsatisfied")
        reason = "not populated" if lgt is None else f'value "{lgt}" {"matched" if status == "satisfied" else "did not match"} regex'
        evals = [{"precondition": {"id": "lgt", "description": "sshd's LoginGraceTime is non-zero", "severity": "blocker",
                                   "verification_signal": "host.sshd.logingracetime"}, "status": status, "reason": reason}]
        tasks = [{"task_kind": "host_probe", "status": "open", "expected_signal_path": "host.sshd.logingracetime"}] if lgt is None else []
        return oes._build_payload(mode="full", finding={"opes": {}, "preconditions_evaluated": evals,
                                                        "verification_tasks": tasks}, intrinsic=None, exploitation={})

    monkeypatch.setattr(oes, "_call_analyze", analyze)
    yield s
    s.close()


def _falcon_host(db, name, aid, *, evidence=True, rtr=True):
    from app.models.asset import Asset, AssetType
    from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
    from app.models.vulnerability import Severity, Vulnerability

    integration = CrowdStrikeIntegration(organization_id=1, connection_name=f"Falcon {name}", cloud_region="us-1",
                                         client_id_encrypted="test-only", client_secret_encrypted="test-only",
                                         collect_host_evidence=evidence, host_evidence_rtr=rtr)
    asset = Asset(name=name, value=name, asset_type=AssetType.OTHER, organization_id=1)
    db.add_all([integration, asset])
    db.flush()
    db.add(CrowdStrikeAssetLink(integration_id=integration.id, asset_id=asset.id, source_kind="host", source_id=aid))
    v = Vulnerability(title="OpenSSH regreSSHion", cve_id="CVE-2024-6387", severity=Severity.HIGH, asset_id=asset.id,
                      detected_by="crowdstrike", metadata_={"oracle": {"verification_tasks": [
                          {"task_kind": "host_probe", "status": "open", "expected_signal_path": "host.sshd.logingracetime"}]}})
    db.add(v)
    db.commit()
    return v


def test_host_checks_use_falcon_and_respect_the_opt_in(db):
    v07 = _falcon_host(db, "lnx-web-07", "aid-07")
    v12 = _falcon_host(db, "lnx-web-12", "aid-12")
    voff = _falcon_host(db, "lnx-web-20", "aid-20", evidence=False)
    fakes = {}

    def client_factory(integration):
        files = {"/etc/ssh/sshd_config": "LoginGraceTime 0\n"} if "07" in integration.connection_name else None
        fakes[integration.connection_name] = FakeFalcon(files=files)
        return fakes[integration.connection_name]

    summary = hes.run_pending_host_checks(db, 1, falcon_client_factory=client_factory)
    assert (summary["checked"], summary["skipped"], summary["failed"]) == (2, 1, 0)
    by_asset = {r["asset_id"]: r for r in summary["assets"]}
    assert by_asset[v07.asset_id]["collector"] == "falcon"
    assert "not a Falcon host with host evidence enabled" in by_asset[voff.asset_id]["skipped"]
    assert "Falcon lnx-web-20" not in fakes  # opted-out integration was never contacted
    db.refresh(v07), db.refresh(v12)
    assert v07.metadata_["severity_eval"]["exploit_realism"]["tier"] == "blocked"
    assert v12.metadata_["severity_eval"]["exploit_realism"]["tier"] == "likely"


def test_scheduled_falcon_sync_does_not_collect_host_evidence():
    import inspect

    from app.services import crowdstrike_service

    src = inspect.getsource(crowdstrike_service.sync_integration)
    assert "host_evidence" not in src and "real-time-response" not in inspect.getsource(crowdstrike_service)
