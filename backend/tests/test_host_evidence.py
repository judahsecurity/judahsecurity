"""Host evidence: read-only probes → Oracle host signals → risk verdicts.

Mirrors the regreSSHion (CVE-2024-6387) case: three Linux servers, one CVE.
  lnx-web-12  sshd running, LoginGraceTime 120  → conditions met
  lnx-web-07  sshd running, LoginGraceTime 0    → blocked, with the observed value
  lnx-web-03  SSH login rejected                → unknown, says why, never "safe"
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.services import host_evidence_service as hes
from app.services.oracle_enrichment_service import _build_oracle_asset
from app.services.severity_evaluation import FindingContext, Precond, exploit_realism

OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\nID_LIKE=debian\n'
PS = "systemd         /sbin/init\nsshd            sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\nnode            node --permissions --allow-fs-read=/srv server.js\n"
SSHD_T = "port 22\nlogingracetime 120\nmaxstartups 10:30:100\nhostkey /etc/ssh/ssh_host_rsa_key\nhostkey /etc/ssh/ssh_host_ed25519_key\n"
DPKG = "openssh-server\t1:8.9p1-3ubuntu0.6\tii \nlibc6\t2.35-0ubuntu3.8\tii \nold-pkg\t1.0\trc \n"
RPM = "openssh-server\t(none):8.7p1-38.el9\nkernel\t0:5.14.0-427.el9\n"
SYSCTL = "kernel.unprivileged_userns_clone = 1\nnet.ipv4.tcp_sack = 1\nnet.ipv4.ip_forward = 0\n"
SS = "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\nLISTEN 0 511 [::]:443 [::]:*\nLISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*\n"


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_parsers():
    assert hes.parse_os_release(OS_RELEASE) == {"os.id": "ubuntu", "os.version_id": "22.04"}
    assert hes.parse_uname("6.8.0-45-generic\n") == {"kernel.release": "6.8.0-45-generic"}
    procs = hes.parse_processes(PS)
    assert procs["process.sshd.running"] == "true"
    assert procs["process.node.args"] == "node --permissions --allow-fs-read=/srv server.js"
    sshd = hes.parse_sshd_t(SSHD_T)
    assert sshd["sshd.logingracetime"] == "120"
    assert sshd["sshd.hostkey"] == "/etc/ssh/ssh_host_rsa_key,/etc/ssh/ssh_host_ed25519_key"
    pkgs = hes.parse_packages(DPKG)
    assert pkgs["package.openssh-server"] == "1:8.9p1-3ubuntu0.6"
    assert "package.old-pkg" not in pkgs  # removed, config files only
    assert hes.parse_packages(RPM) == {
        "package.openssh-server": "8.7p1-38.el9", "package.openssh-server.installed": "true",
        "package.kernel": "5.14.0-427.el9", "package.kernel.installed": "true",
    }
    assert hes.parse_sysctl(SYSCTL) == {
        "sysctl.kernel.unprivileged_userns_clone": "1", "sysctl.net.ipv4.ip_forward": "0",
    }
    assert hes.parse_listening(SS) == {"listening.tcp": "22,53,443"}
    assert hes.parse_listening("tcp 0 0 0.0.0.0:22 0.0.0.0:* LISTEN\n") == {"listening.tcp": "22"}


# ── Probing ───────────────────────────────────────────────────────────────────

class FakeRunner(hes.CommandRunner):
    host_key_fingerprint = "SHA256:abc"

    def __init__(self, lgt="120", sshd_fails=False):
        self.lgt, self.sshd_fails, self.commands = lgt, sshd_fails, []

    def run(self, command):
        self.commands.append(command)
        if command.startswith("cat /etc/os-release"):
            return 0, OS_RELEASE, ""
        if command == "uname -r":
            return 0, "6.8.0-45-generic\n", ""
        if command.startswith("ps "):
            return 0, PS, ""
        if "dpkg-query" in command:
            return 0, DPKG, ""
        if "sshd -T" in command:
            if self.sshd_fails:
                return 1, "", "sshd: no hostkeys available -- exiting.\n"
            return 0, SSHD_T.replace("logingracetime 120", f"logingracetime {self.lgt}"), ""
        if "sysctl" in command:
            return 255, SYSCTL, "sysctl: permission denied on key 'fs.protected_regular'\n"
        if "ss -Hltn" in command:
            return 0, SS, ""
        raise AssertionError(f"unexpected command {command!r}")


def test_probe_catalog_is_read_only():
    forbidden = (" rm ", ">", "tee ", "chmod", "chown", "systemctl", "kill", "apt", "yum", "dnf", "curl", "wget")
    for probe in hes.PROBES:
        cmd = probe.command.replace("2>/dev/null", "").replace(">/dev/null 2>&1", "").replace("2>&1", "")
        assert not any(f in cmd for f in forbidden), probe.command


def test_run_probes_records_each_probe():
    facts, probes = hes.run_probes(FakeRunner())
    assert facts["sshd.logingracetime"] == "120"
    assert facts["process._complete"] == "true" and facts["package._complete"] == "true"
    assert facts["sysctl.kernel.unprivileged_userns_clone"] == "1"  # non-zero exit tolerated for optional probe
    assert all(p["ok"] for p in probes.values())


def test_failed_probe_is_an_error_not_a_negative():
    facts, probes = hes.run_probes(FakeRunner(sshd_fails=True))
    assert not any(k.startswith("sshd.") for k in facts)
    assert probes["sshd"]["ok"] is False
    assert "no hostkeys available" in probes["sshd"]["error"]
    assert probes["process"]["ok"]


def test_without_sudo_the_sshd_probe_runs_plain():
    runner = FakeRunner()
    hes.run_probes(runner, use_sudo=False)
    assert not any("sudo" in c for c in runner.commands)


# ── Scope ─────────────────────────────────────────────────────────────────────

def _asset(**kw):
    base = dict(
        id=12, value="lnx-web-12.corp.example", ip_address="10.20.1.12", metadata_={}, organization_id=1,
        updated_at=datetime.now(timezone.utc), port_services=[], technologies=[], http_headers=None, http_title=None,
        ssl_info=None, operating_system=None, has_login_portal=False, login_portals=None, device_class=None,
        device_subclass=None, system_type=None, hosting_type=None, hosting_provider=None, country_code=None,
        tags=[], asset_type="ip_address", is_public=True, criticality="high",
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _cred(**kw):
    base = dict(username="judah-probe", secret="x", targets=["10.20.0.0/16"])
    base.update(kw)
    return hes.HostCredential(**base)


def test_target_scope():
    a = _asset()
    assert hes.in_target_scope(a, ["10.20.0.0/16"])
    assert hes.in_target_scope(a, ["*.corp.example"])
    assert not hes.in_target_scope(a, ["10.30.0.0/16", "*.prod.example"])
    assert not hes.in_target_scope(a, [])  # nothing configured → nothing contacted


def test_out_of_scope_asset_is_never_contacted():
    called = []
    record = hes.collect_host_facts(_asset(), _cred(targets=["192.168.0.0/24"]),
                                    runner_factory=lambda *a: called.append(a) or FakeRunner())
    assert called == []
    assert "not in the host-check target scope" in record["error"]


def test_connect_failure_is_recorded():
    def boom(*_):
        raise hes.HostCheckError("ssh connect failed: AuthenticationException: Authentication failed.")

    record = hes.collect_host_facts(_asset(), _cred(), runner_factory=boom)
    assert record["facts"] == {}
    assert "Authentication failed" in record["error"]


# ── Projection into Oracle's asset payload ───────────────────────────────────

def _collected(asset, runner):
    record = hes.collect_host_facts(asset, _cred(), runner_factory=lambda *a: runner)
    hes.store_host_facts(asset, record)
    return asset


def test_oracle_payload_carries_host_signals_and_probe_evidence():
    asset = _collected(_asset(), FakeRunner(lgt="0"))
    payload = _build_oracle_asset(asset)
    signals = payload["signals"]
    assert signals["host"]["sshd.logingracetime"] == "0"
    assert signals["runtime_flags"]["node"].startswith("node --permissions")
    ev = signals["signal_evidence"]
    sshd = ev["host.sshd.*"][0]
    assert sshd["scope"] == payload["asset_id"] == "asm-12"
    assert sshd["freshness"] == "fresh" and sshd["source"] == "host_ssh_probe"
    assert ev["runtime_flags.node"][0]["value"] == signals["runtime_flags"]["node"]


def test_failed_run_reaches_oracle_as_an_error():
    def boom(*_):
        raise hes.HostCheckError("ssh connect failed: timed out")

    asset = _asset()
    hes.store_host_facts(asset, hes.collect_host_facts(asset, _cred(), runner_factory=boom))
    signals = _build_oracle_asset(asset)["signals"]
    assert "host" not in signals
    err = signals["signal_evidence"]["host.*"][0]
    assert err["freshness"] == "error" and "timed out" in err["error"]


def test_old_facts_are_stale():
    asset = _collected(_asset(), FakeRunner())
    asset.metadata_["host_facts"]["observed_at"] = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
    _, _, ev = hes.host_signals_for_oracle(asset, "asm-12")
    assert ev["host.sshd.*"][0]["freshness"] == "stale"


def test_host_key_pin_survives_a_failed_run():
    asset = _collected(_asset(), FakeRunner())
    assert asset.metadata_["host_facts"]["host_key"] == "SHA256:abc"

    def boom(*_):
        raise hes.HostCheckError("host key changed")

    hes.store_host_facts(asset, hes.collect_host_facts(asset, _cred(), runner_factory=boom))
    assert asset.metadata_["host_facts"]["host_key"] == "SHA256:abc"


def test_pushed_facts_are_validated():
    asset = _asset()
    hes.ingest_host_facts(asset, {"host.sshd.logingracetime": 0, "process.sshd.running": True},
                          source="osquery", complete_families=["process"])
    facts = asset.metadata_["host_facts"]["facts"]
    assert facts == {"sshd.logingracetime": "0", "process.sshd.running": "true", "process._complete": "true"}
    assert asset.metadata_["host_facts"]["collector"] == "push:osquery"
    with pytest.raises(ValueError):
        hes.ingest_host_facts(asset, {"bad key!": "1"}, source="x")
    with pytest.raises(ValueError):
        hes.ingest_host_facts(asset, {"process._complete": "true"}, source="x")
    with pytest.raises(ValueError):
        hes.ingest_host_facts(asset, {}, source="x", complete_families=["sysctl"])


def test_pending_host_checks():
    vuln = SimpleNamespace(metadata_={"oracle": {"verification_tasks": [
        {"task_kind": "host_probe", "status": "open", "expected_signal_path": "host.sshd.logingracetime"},
        {"task_kind": "manual", "status": "open", "expected_signal_path": "tenant.runs_user_code"},
    ]}})
    assert [t["expected_signal_path"] for t in hes.pending_host_checks(vuln)] == ["host.sshd.logingracetime"]
    legacy = SimpleNamespace(metadata_={"oracle": {"preconditions_evaluated": [
        {"status": "unknown", "precondition": {"id": "lgt", "verification_signal": "host.sshd.logingracetime"}},
        {"status": "unknown", "precondition": {"id": "x", "verification_signal": "tech_stack.openssh"}},
    ]}})
    assert len(hes.pending_host_checks(legacy)) == 1


# ── Verdicts in the risk model ───────────────────────────────────────────────

SSHD = "The OpenSSH server (sshd) is running on the host."
LGT = "sshd's effective LoginGraceTime is non-zero, so the SIGALRM handler can fire."


def _ctx(*preconds):
    return FindingContext(cve_id="CVE-2024-6387", exposure="internet", preconditions=list(preconds),
                          attacker_capability="unauthenticated_network", detection_confidence="version_only")


def test_verdict_exploitable_when_every_condition_holds():
    r = exploit_realism(_ctx(
        Precond("sshd-running", SSHD, True, "satisfied", "signal matched: equal to true"),
        Precond("lgt", LGT, True, "satisfied", 'signal matched: value "120" matched regex /^[1-9][0-9]*$/'),
    ))
    assert r["tier"] == "likely" and r["score"] == 4
    assert any('observed "120"' in x for x in r["reasons"])


def test_verdict_blocked_with_the_observed_value():
    r = exploit_realism(_ctx(
        Precond("sshd-running", SSHD, True, "satisfied", "signal matched: equal to true"),
        Precond("lgt", LGT, True, "unsatisfied",
                'signal contradicts precondition: value "0" did not match regex /^[1-9][0-9]*$/'),
    ))
    assert r["tier"] == "blocked" and r["score"] == 0
    assert any("not met" in x and 'observed "0"' in x for x in r["reasons"])


def test_verdict_uncheckable_is_never_safe():
    why = "could not check `host.sshd.logingracetime` on this asset: ssh connect failed: timed out (host_ssh_probe)"
    r = exploit_realism(_ctx(
        Precond("sshd-running", SSHD, True, "unknown", why.replace("sshd.logingracetime", "process.sshd.running")),
        Precond("lgt", LGT, True, "unknown", why),
    ))
    assert r["tier"] == "unverified" and r["score"] == 3
    assert all("could not check" in x and "timed out" in x and "not treated as safe" in x for x in r["reasons"])


def test_verdict_partial_check_is_unverified_not_likely():
    r = exploit_realism(_ctx(
        Precond("sshd-running", SSHD, True, "satisfied", "signal matched: equal to true"),
        Precond("lgt", LGT, True, "unknown",
                "could not check `host.sshd.logingracetime` on this asset: exit 1: sshd: no hostkeys available"),
    ))
    assert r["tier"] == "unverified" and r["score"] == 3
    assert r["reasons"][0].startswith("required condition met")
    assert "can fire (exit 1: sshd: no hostkeys available)" in r["reasons"][1]


# ── Executor + routes against a database ─────────────────────────────────────

@pytest.fixture()
def db():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.database import Base
    import app.models  # noqa: F401
    from app.models.api_config import APIConfig
    from app.models.asset import Asset
    from app.models.business_application import BusinessApplication
    from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration
    from app.models.netblock import Netblock
    from app.models.organization import Organization
    from app.models.port_service import PortService
    from app.models.technology import Technology, asset_technologies
    from app.models.vulnerability import Vulnerability

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine, tables=[Organization.__table__, Netblock.__table__, BusinessApplication.__table__,
                                             Asset.__table__, Vulnerability.__table__, APIConfig.__table__,
                                             PortService.__table__, Technology.__table__, asset_technologies,
                                             CrowdStrikeIntegration.__table__, CrowdStrikeAssetLink.__table__])
    s = sessionmaker(bind=engine)()
    s.add(Organization(id=1, name="Acme"))
    cfg = APIConfig(organization_id=1, service_name="host_ssh", api_user="judah-probe",
                    config={"auth": "key", "targets": ["10.20.0.0/16"], "trust_on_first_use": True})
    cfg.set_api_key("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----")
    s.add(cfg)
    s.commit()
    yield s
    s.close()


def _regresshion_finding(db, name, ip):
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability

    asset = Asset(name=name, value=name, asset_type=AssetType.IP_ADDRESS, organization_id=1, ip_address=ip, is_public=True)
    db.add(asset)
    db.flush()
    v = Vulnerability(title="OpenSSH regreSSHion", cve_id="CVE-2024-6387", severity=Severity.HIGH, asset_id=asset.id,
                      detected_by="nuclei", metadata_={"oracle": {"verification_tasks": [
                          {"task_kind": "host_probe", "status": "open", "expected_signal_path": "host.sshd.logingracetime"}]}})
    db.add(v)
    db.commit()
    return v, asset


@pytest.fixture()
def fake_oracle(monkeypatch):
    """Stands in for the Oracle daemon: evaluates the regreSSHion blocker
    against the host signals the backend actually sends."""
    from app.services import oracle_enrichment_service as oes
    from app.services import severity_intel

    monkeypatch.setattr(severity_intel, "live_intel", lambda cve_id: {})  # no feed downloads in tests

    def analyze(cve_id, asset_payload):
        signals = asset_payload["signals"]
        lgt = (signals.get("host") or {}).get("sshd.logingracetime")
        err = ((signals.get("signal_evidence") or {}).get("host.*") or [{}])[0].get("error")
        desc = "sshd's effective LoginGraceTime is non-zero"
        if lgt is None:
            status, reason = "unknown", f"could not check `host.sshd.logingracetime` on this asset: {err or 'not populated'}"
        elif lgt != "0":
            status, reason = "satisfied", f'signal matched: value "{lgt}" matched regex /^[1-9][0-9]*$/'
        else:
            status, reason = "unsatisfied", f'signal contradicts precondition: value "{lgt}" did not match regex'
        evals = [{"precondition": {"id": "lgt", "description": desc, "severity": "blocker",
                                   "verification_signal": "host.sshd.logingracetime"}, "status": status, "reason": reason}]
        tasks = [{"task_kind": "host_probe", "status": "open", "expected_signal_path": "host.sshd.logingracetime"}] if status == "unknown" else []
        return oes._build_payload(mode="full", finding={"opes": {}, "preconditions_evaluated": evals,
                                                        "verification_tasks": tasks}, intrinsic=None, exploitation={})

    monkeypatch.setattr(oes, "_call_analyze", analyze)


def test_executor_checks_pending_assets_and_rescores(db, fake_oracle):
    v12, _ = _regresshion_finding(db, "lnx-web-12", "10.20.1.12")
    v07, _ = _regresshion_finding(db, "lnx-web-07", "10.20.1.7")
    v99, _ = _regresshion_finding(db, "partner-host", "192.0.2.9")  # outside targets

    def factory(addr, cred, pin):
        return FakeRunner(lgt="0" if addr.endswith(".7") else "120")

    summary = hes.run_pending_host_checks(db, 1, runner_factory=factory)
    assert (summary["checked"], summary["skipped"], summary["failed"]) == (2, 1, 0)
    db.refresh(v12), db.refresh(v07), db.refresh(v99)
    assert v12.metadata_["severity_eval"]["exploit_realism"]["tier"] == "likely"
    assert v07.metadata_["severity_eval"]["exploit_realism"]["tier"] == "blocked"
    assert any('observed "0"' in r for r in v07.metadata_["severity_eval"]["exploit_realism"]["reasons"])
    assert hes.pending_host_checks(v12) == [] and hes.pending_host_checks(v07) == []
    assert "severity_eval" not in v99.metadata_  # never contacted, untouched
    assert v99.asset.metadata_ in (None, {}) or "host_facts" not in v99.asset.metadata_


def test_routes(db, fake_oracle, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from app.api.deps import get_db, require_admin, require_analyst
    from app.api.routes import host_checks

    user = SimpleNamespace(role=SimpleNamespace(value="analyst"), organization_id=1, is_superuser=False)
    app = FastAPI()
    app.include_router(host_checks.router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[require_admin] = lambda: user
    app.dependency_overrides[require_analyst] = lambda: user
    client = TestClient(app)

    v03, a03 = _regresshion_finding(db, "lnx-web-03", "10.20.1.3")
    pending = client.get("/host-checks/organizations/1/pending").json()
    assert pending["credential_configured"] and pending["pending"][0]["in_target_scope"]
    assert client.get("/host-checks/organizations/2/pending").status_code == 403

    def unreachable(addr, cred, pin):
        raise hes.HostCheckError("ssh connect failed: timed out")

    monkeypatch.setattr(hes, "SSHRunner", unreachable)
    res = client.post(f"/host-checks/assets/{a03.id}/collect").json()
    assert "timed out" in res["error"]
    after = res["findings"][0]["after"]
    assert after["tier"] == "unverified" and "timed out" in after["reasons"][0]

    res = client.post(f"/host-checks/assets/{a03.id}/facts",
                      json={"source": "osquery", "facts": {"sshd.logingracetime": "0"}}).json()
    assert res["findings"][0]["after"]["tier"] == "blocked"
    facts = client.get(f"/host-checks/assets/{a03.id}/facts").json()
    assert facts["collector"] == "push:osquery" and facts["facts"]["sshd.logingracetime"] == "0"
    assert client.post(f"/host-checks/assets/{a03.id}/facts", json={"source": "x", "facts": {"bad key": 1}}).status_code == 422
