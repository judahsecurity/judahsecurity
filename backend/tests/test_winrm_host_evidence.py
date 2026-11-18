"""Agentless Windows checks over WinRM, credential profiles, and macOS over
SSH — all against simulated hosts; no network connections are made."""

import json
import socket
from types import SimpleNamespace

import pytest

from app.services import host_evidence_service as hes
from app.services import winrm_host_evidence as win
from app.services.oracle_enrichment_service import _build_oracle_asset


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("test attempted a real network connection")

    monkeypatch.setattr(socket.socket, "connect", refuse)


OS = json.dumps({"caption": "Microsoft Windows Server 2022 Datacenter", "version": "10.0.20348", "build": "20348",
                 "ubr": 2849, "display": "21H2"})
HOTFIX = json.dumps([{"HotFixID": "KB5044281"}, {"HotFixID": "KB5043936"}, {"HotFixID": "not-a-kb"}])
PACKAGES = json.dumps([{"DisplayName": "OpenSSH", "DisplayVersion": "9.5.0.0"},
                       {"DisplayName": "Microsoft Edge", "DisplayVersion": "131.0.2903.70"},
                       {"DisplayName": "Tool Without Version", "DisplayVersion": None}])
PROCS = json.dumps([{"Name": "System", "CommandLine": None}, {"Name": "sshd.exe", "CommandLine": "C:\\Windows\\System32\\OpenSSH\\sshd.exe"},
                    {"Name": "spoolsv.exe", "CommandLine": None}])
SERVICES = json.dumps([{"Name": "Spooler", "Status": "Running"}, {"Name": "sshd", "Status": "Running"},
                       {"Name": "W3SVC", "Status": "Stopped"}])
LISTEN = json.dumps([22, 135, 445, 3389])
WINCFG = json.dumps({"smb1": False, "rdp": True, "nla": True})
SSHD = json.dumps({"files": {"C:\\ProgramData\\ssh\\sshd_config": "Include sshd_config.d\\*.conf\nLoginGraceTime 2m\n",
                             "C:\\ProgramData\\ssh\\sshd_config.d\\10-harden.conf": "LoginGraceTime 0\n"},
                   "dirs": {"C:\\ProgramData\\ssh\\sshd_config.d": ["10-harden.conf"]}})


# ── Parsers ───────────────────────────────────────────────────────────────────

def test_windows_parsers():
    assert win.parse_os(OS) == {"os.platform": "windows", "os.id": "windows",
                                "os.product": "Microsoft Windows Server 2022 Datacenter",
                                "os.version": "10.0.20348", "os.version_id": "21H2", "os.build": "20348.2849"}
    assert win.parse_hotfixes(HOTFIX) == {"hotfix.kb5044281.installed": "true", "hotfix.kb5043936.installed": "true"}
    pkgs = win.parse_packages(PACKAGES)
    assert pkgs["package.openssh"] == "9.5.0.0" and pkgs["package.microsoft-edge.installed"] == "true"
    assert "package.tool-without-version" not in pkgs and pkgs["package.tool-without-version.installed"] == "true"
    procs = win.parse_processes(PROCS)
    assert procs["process.sshd.running"] == "true"  # ".exe" dropped: same name as Linux
    assert procs["process.sshd.args"].endswith("sshd.exe") and "process.spoolsv.args" not in procs
    assert win.parse_services(SERVICES) == {"service.spooler.running": "true", "service.sshd.running": "true",
                                            "service.w3svc.running": "false"}
    assert win.parse_listening(LISTEN) == {"listening.tcp": "22,135,445,3389"}
    assert win.parse_listening("3389") == {"listening.tcp": "3389"}  # single port prints bare
    assert win.parse_windows_config(WINCFG) == {"windows.smb1_enabled": "false", "windows.rdp_enabled": "true",
                                                "windows.rdp_nla_required": "true"}
    assert win.parse_windows_config(json.dumps({"rdp": True})) == {"windows.rdp_enabled": "true"}  # SMB needs admin


def test_windows_sshd_bundle_first_value_wins():
    assert win.parse_sshd_bundle(SSHD)["sshd.logingracetime"] == "0"


def test_windows_probe_catalog_is_read_only():
    write_verbs = ("Set-", "Remove-", "New-", "Stop-", "Start-", "Restart-", "Invoke-WebRequest", "Invoke-Expression",
                   "Invoke-RestMethod", "Out-File", "Add-", "Enable-", "Disable-", "Install-", "Uninstall-", "iex ")
    for probe in win.WIN_PROBES:
        assert not any(v in probe.command for v in write_verbs), probe.prefix


# ── Running the catalog ───────────────────────────────────────────────────────

class FakeWindows(hes.CommandRunner):
    def __init__(self, admin=True, lgt_override=True):
        self.admin, self.lgt_override, self.commands = admin, lgt_override, []

    def run(self, command):
        self.commands.append(command)
        if "Win32_OperatingSystem" in command:
            return 0, OS, ""
        if "Get-HotFix" in command:
            return 0, HOTFIX, ""
        if "Uninstall" in command:
            return 0, PACKAGES, ""
        if "Win32_Process" in command:
            return 0, PROCS, ""
        if "Get-Service" in command:
            return 0, SERVICES, ""
        if "Get-NetTCPConnection" in command:
            return 0, LISTEN, ""
        if "Get-SmbServerConfiguration" in command:
            return 0, (WINCFG if self.admin else json.dumps({"rdp": True, "nla": True})), ""
        if "ProgramData" in command:
            if not self.lgt_override:
                return 0, json.dumps({"files": {"C:\\ProgramData\\ssh\\sshd_config": "Port 22\n"}, "dirs": {}}), ""
            return 0, SSHD, ""
        raise AssertionError(command)


def _win_asset(**kw):
    base = dict(id=31, value="win-app-31.corp.example", ip_address="10.40.0.31", metadata_={}, organization_id=1,
                updated_at=None, port_services=[], technologies=[], http_headers=None, http_title=None, ssl_info=None,
                operating_system="Windows Server 2022", has_login_portal=False, login_portals=None, device_class=None,
                device_subclass=None, system_type=None, hosting_type=None, hosting_provider=None, country_code=None,
                tags=[], asset_type="ip_address", is_public=False, criticality="high")
    base.update(kw)
    return SimpleNamespace(**base)


def _profile(**kw):
    base = dict(username="CORP\\svc-judah", secret="pw", kind="winrm", name="host_winrm:windows-prod",
                targets=["10.40.0.0/16"], port=5986)
    base.update(kw)
    return hes.HostCredential(**base)


def test_winrm_collection_feeds_oracle():
    asset = _win_asset()
    record = hes.collect_host_facts(asset, _profile(), runner_factory=lambda *a: FakeWindows())
    assert record["collector"] == "host_winrm_probe" and record["profile"] == "host_winrm:windows-prod"
    assert all(p["ok"] for p in record["probes"].values()), record["probes"]
    assert "host_key" not in record
    hes.store_host_facts(asset, record)
    signals = _build_oracle_asset(asset)["signals"]
    host = signals["host"]
    assert host["os.build"] == "20348.2849" and host["service.spooler.running"] == "true"
    assert host["service._complete"] == "true" and host["process._complete"] == "true"
    assert host["sshd.logingracetime"] == "0"
    assert signals["signal_evidence"]["host.service.*"][0]["source"] == "host_winrm_probe"


def test_non_admin_account_reports_what_it_could_not_read():
    record = hes.collect_host_facts(_win_asset(), _profile(), runner_factory=lambda *a: FakeWindows(admin=False))
    assert record["probes"]["windows"]["ok"]
    assert "windows.smb1_enabled" not in record["facts"]  # unknown, not "false"
    assert record["facts"]["windows.rdp_enabled"] == "true"


def test_winrm_login_failure_is_could_not_check():
    def boom(*_):
        raise hes.HostCheckError("winrm connect failed: InvalidCredentialsError: the specified credentials were rejected")

    asset = _win_asset()
    hes.store_host_facts(asset, hes.collect_host_facts(asset, _profile(), runner_factory=boom))
    err = _build_oracle_asset(asset)["signals"]["signal_evidence"]["host.*"][0]
    assert err["freshness"] == "error" and "credentials were rejected" in err["error"]


def test_bad_probe_output_is_a_probe_error():
    class Garbled(FakeWindows):
        def run(self, command):
            if "Get-Service" in command:
                return 0, "<Objs Version=...>not json", ""
            return super().run(command)

    record = hes.collect_host_facts(_win_asset(), _profile(), runner_factory=lambda *a: Garbled())
    assert not record["probes"]["service"]["ok"] and "could not parse" in record["probes"]["service"]["error"]
    assert record["probes"]["os"]["ok"]


# ── Credential profiles ──────────────────────────────────────────────────────

def _cfg(service, **config):
    return SimpleNamespace(service_name=service, api_user="u", config=config, get_api_key=lambda: "secret")


def test_profiles_from_api_config():
    w = hes.HostCredential.from_api_config(_cfg("host_winrm:windows-prod", targets=["10.40.0.0/16"]))
    assert (w.kind, w.port, w.https, w.transport) == ("winrm", 5986, True, "ntlm")
    assert hes.HostCredential.from_api_config(_cfg("host_winrm", https=False)).port == 5985
    s = hes.HostCredential.from_api_config(_cfg("host_ssh:linux-dmz", priority=10))
    assert (s.kind, s.port, s.priority, s.name) == ("ssh", 22, 10, "host_ssh:linux-dmz")
    assert hes._is_profile("host_ssh") and hes._is_profile("host_winrm:x") and not hes._is_profile("shodan")


def test_first_matching_profile_wins():
    broad = _profile(name="host_ssh:all", kind="ssh", targets=["10.0.0.0/8"], priority=100)
    windows = _profile(priority=50)
    nothing = _profile(name="host_ssh:other", kind="ssh", targets=["192.168.0.0/16"], priority=1)
    ordered = sorted([broad, windows, nothing], key=lambda c: c.priority)
    assert hes.credential_for_asset(ordered, _win_asset()).name == "host_winrm:windows-prod"
    assert hes.credential_for_asset(ordered, _win_asset(ip_address="10.9.9.9", value="lnx")).name == "host_ssh:all"
    assert hes.credential_for_asset(ordered, _win_asset(ip_address="172.16.0.1", value="x")) is None


# ── macOS over SSH ───────────────────────────────────────────────────────────

def test_macos_parsing():
    assert hes.parse_os_release("ProductName:\t\tmacOS\nProductVersion:\t\t14.5\nBuildVersion:\t\t23F79\n") == {
        "os.id": "macos", "os.platform": "mac", "os.version_id": "14.5"}
    netstat = ("tcp4       0      0  *.22                   *.*                    LISTEN\n"
               "tcp4       0      0  127.0.0.1.631          *.*                    LISTEN\n"
               "tcp6       0      0  *.5000                 *.*                    LISTEN\n")
    assert hes.parse_listening(netstat) == {"listening.tcp": "22,631,5000"}
