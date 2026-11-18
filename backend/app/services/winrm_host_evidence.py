"""
Windows host evidence over WinRM — the agentless option for Windows servers
that can't run an agent and aren't Falcon hosts.

Same contract as the SSH collector (host_evidence_service): a FIXED catalog of
read-only PowerShell probes, each printing JSON, mapped to Oracle's host.*
signals. Nothing an LLM wrote is ever executed.

Least privilege: a domain or local account in "Remote Management Users"
covers OS/build, hotfixes, installed software, process names, services,
listening ports and the RDP registry settings. SMB server configuration and
other users' process command lines need local admin; those probes then fail
on their own and are reported as "could not check", never as negatives.

Transport: HTTPS (5986) with certificate validation by default, optionally
against a customer CA (``ca_cert``). Plain HTTP is only allowed with
NTLM/Kerberos message encryption forced on.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from app.services import host_evidence_service as hes

COLLECTOR_WINRM = "host_winrm_probe"
SSHD_ROOT = "C:\\ProgramData\\ssh"
ALLOWED_TRANSPORTS = ("ntlm", "kerberos")


def _items(out: str) -> List[Any]:
    """ConvertTo-Json prints one object bare and many as an array."""
    out = (out or "").strip()
    if not out:
        return []
    data = json.loads(out)
    return data if isinstance(data, list) else [data]


def _name_key(name: str) -> str:
    key = re.sub(r"[^a-z0-9._+-]+", "-", str(name).strip().lower()).strip("-.")
    return key[:150]


# ── Parsers (pure; unit-tested) ───────────────────────────────────────────────

def parse_os(out: str) -> Dict[str, str]:
    items = _items(out)
    if not items:
        return {}
    o = items[0]
    facts = {"os.platform": "windows", "os.id": "windows"}
    if o.get("caption"):
        facts["os.product"] = str(o["caption"]).strip()
    if o.get("version"):
        facts["os.version"] = str(o["version"])
    if o.get("display"):
        facts["os.version_id"] = str(o["display"])
    if o.get("build") not in (None, ""):
        # CurrentBuild.UBR (e.g. 20348.2849) is the reliable patch level:
        # cumulative updates bump UBR even when the KB list is incomplete.
        facts["os.build"] = f"{o['build']}.{o['ubr']}" if o.get("ubr") not in (None, "") else str(o["build"])
    return facts


def parse_hotfixes(out: str) -> Dict[str, str]:
    facts = {}
    for item in _items(out):
        kb = str(item.get("HotFixID") or "").strip().lower()
        if re.match(r"^kb\d+$", kb):
            facts[f"hotfix.{kb}.installed"] = "true"
    return facts  # never marked complete: superseded KBs aren't listed


def parse_packages(out: str) -> Dict[str, str]:
    facts = {}
    for item in _items(out):
        key = _name_key(item.get("DisplayName") or "")
        if not key or not hes._KEY_RE.match(key):
            continue
        if item.get("DisplayVersion"):
            facts.setdefault(f"package.{key}", str(item["DisplayVersion"]).strip())
        facts[f"package.{key}.installed"] = "true"
    return facts  # registry Uninstall keys miss MSIX/Store apps: not complete


def parse_processes(out: str) -> Dict[str, str]:
    facts = {}
    for item in _items(out):
        name = str(item.get("Name") or "").strip().lower()
        if name.endswith(".exe"):
            name = name[:-4]  # host.process.sshd.running matches Linux naming
        key = _name_key(name)
        if not key or not hes._KEY_RE.match(key):
            continue
        facts[f"process.{key}.running"] = "true"
        if item.get("CommandLine"):
            facts.setdefault(f"process.{key}.args", str(item["CommandLine"])[: hes.MAX_VALUE_LEN])
    return facts


def parse_services(out: str) -> Dict[str, str]:
    facts = {}
    for item in _items(out):
        key = _name_key(item.get("Name") or "")
        if key and hes._KEY_RE.match(key):
            facts[f"service.{key}.running"] = "true" if str(item.get("Status")).lower() == "running" else "false"
    return facts


def parse_listening(out: str) -> Dict[str, str]:
    ports = sorted({int(p) for p in _items(out) if str(p).isdigit() and 0 < int(p) < 65536})
    return {"listening.tcp": ",".join(map(str, ports))} if ports else {}


def parse_windows_config(out: str) -> Dict[str, str]:
    items = _items(out)
    o = items[0] if items else {}
    facts = {}
    for src, key in (("smb1", "windows.smb1_enabled"), ("rdp", "windows.rdp_enabled"), ("nla", "windows.rdp_nla_required")):
        if isinstance(o.get(src), bool):
            facts[key] = str(o[src]).lower()
    return facts


def parse_sshd_bundle(out: str) -> Dict[str, str]:
    """Files read on the host by the sshd probe, resolved with the same
    first-value-wins rules as the Falcon RTR path."""
    from app.services.falcon_host_evidence import effective_sshd_from_files

    items = _items(out)
    bundle = items[0] if items else {}
    files = {str(k): str(v) for k, v in (bundle.get("files") or {}).items() if v is not None}
    dirs = {str(k): [str(n) for n in (v if isinstance(v, list) else [v])] for k, v in (bundle.get("dirs") or {}).items() if v is not None}
    lower_files = {k.lower(): v for k, v in files.items()}

    async def read(path: str) -> Optional[str]:
        return lower_files.get(path.lower())

    async def list_dir(path: str) -> Optional[List[str]]:
        for k, v in dirs.items():
            if k.lower() == path.lower():
                return v
        return None

    facts, _info = asyncio.run(effective_sshd_from_files(f"{SSHD_ROOT}\\sshd_config", read, list_dir, root=SSHD_ROOT))
    return facts


# ── Probe catalog (fixed, read-only) ─────────────────────────────────────────

_PS = "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "

WIN_PROBES: Tuple[hes.Probe, ...] = (
    hes.Probe("os", _PS + "$o=Get-CimInstance Win32_OperatingSystem; "
              "$cv=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'; "
              "[pscustomobject]@{caption=$o.Caption;version=$o.Version;build=$cv.CurrentBuild;ubr=$cv.UBR;"
              "display=$cv.DisplayVersion} | ConvertTo-Json -Compress", parse_os),
    hes.Probe("hotfix", _PS + "Get-HotFix | Select-Object HotFixID | ConvertTo-Json -Compress", parse_hotfixes, optional=True),
    hes.Probe("package", _PS + "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
              "'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | "
              "Where-Object DisplayName | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Compress", parse_packages),
    hes.Probe("process", _PS + "Get-CimInstance Win32_Process | Select-Object Name,CommandLine | ConvertTo-Json -Compress",
              parse_processes, complete_list=True),
    hes.Probe("service", _PS + "Get-Service | Select-Object Name,@{n='Status';e={$_.Status.ToString()}} | "
              "ConvertTo-Json -Compress", parse_services, complete_list=True),
    hes.Probe("listening", _PS + "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort -Unique | "
              "ConvertTo-Json -Compress", parse_listening, optional=True),
    hes.Probe("windows", _PS + "$r=@{}; try { $r.smb1=(Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}; "
              "$ts=Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -ErrorAction SilentlyContinue; "
              "if ($ts) { $r.rdp=($ts.fDenyTSConnections -eq 0) }; "
              "$w=Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
              "-ErrorAction SilentlyContinue; if ($w) { $r.nla=($w.UserAuthentication -eq 1) }; "
              "[pscustomobject]$r | ConvertTo-Json -Compress", parse_windows_config, optional=True),
    # Reads only files under C:\ProgramData\ssh; Includes elsewhere are skipped
    # on the host, and the resolver then reports them as an error.
    hes.Probe("sshd", _PS + "$root='C:\\ProgramData\\ssh'; $main=Join-Path $root 'sshd_config'; "
              "if (-not (Test-Path $main)) { '__absent__'; exit 0 }; $files=@{}; $dirs=@{}; "
              "$files[$main]=Get-Content -Raw $main; "
              "foreach ($m in (Select-String -Path $main -Pattern '^\\s*Include\\s+(.+)$')) { "
              "foreach ($pat in ($m.Matches[0].Groups[1].Value -split '\\s+')) { "
              "if (-not [IO.Path]::IsPathRooted($pat)) { $pat=Join-Path $root $pat }; "
              "if (-not $pat.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or $pat.Contains('..')) { continue }; "
              "$dir=Split-Path $pat; $dirs[$dir]=@(Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | "
              "ForEach-Object Name); foreach ($f in (Get-ChildItem -Path $pat -File -ErrorAction SilentlyContinue)) { "
              "$files[$f.FullName]=Get-Content -Raw $f.FullName } } }; "
              "[pscustomobject]@{files=$files;dirs=$dirs} | ConvertTo-Json -Compress -Depth 4", parse_sshd_bundle, optional=True),
)


# ── Transport ────────────────────────────────────────────────────────────────

class WinRMRunner(hes.CommandRunner):  # pragma: no cover - needs a live host
    def __init__(self, address: str, cred: "hes.HostCredential", _pin: str = ""):
        try:
            import winrm
        except ImportError as e:
            raise hes.HostCheckError("pywinrm is not installed on the backend") from e
        if cred.transport not in ALLOWED_TRANSPORTS:
            raise hes.HostCheckError(f"WinRM transport must be one of {ALLOWED_TRANSPORTS}")
        scheme = "https" if cred.https else "http"
        self._ca_path = ""
        kwargs: Dict[str, Any] = dict(
            auth=(cred.username, cred.secret), transport=cred.transport,
            operation_timeout_sec=int(hes.COMMAND_TIMEOUT_S), read_timeout_sec=int(hes.COMMAND_TIMEOUT_S) + 10,
        )
        if cred.https:
            kwargs["server_cert_validation"] = "validate"
            if cred.ca_cert:
                fd, self._ca_path = tempfile.mkstemp(suffix=".pem")
                with os.fdopen(fd, "w") as fh:
                    fh.write(cred.ca_cert)
                kwargs["ca_trust_path"] = self._ca_path
        else:
            kwargs["message_encryption"] = "always"  # NTLM/Kerberos sealing over HTTP
        self._session = winrm.Session(f"{scheme}://{address}:{cred.port}/wsman", **kwargs)
        try:
            status, _, err = self.run("$PSVersionTable.PSVersion.Major")
        except Exception as e:
            self.close()
            raise hes.HostCheckError(f"winrm connect failed: {type(e).__name__}: {e}") from e
        if status != 0:
            self.close()
            raise hes.HostCheckError(f"winrm connect failed: {err.strip()[:200] or f'exit {status}'}")

    def run(self, command: str) -> Tuple[int, str, str]:
        r = self._session.run_ps(command)
        return r.status_code, r.std_out.decode("utf-8", "replace"), r.std_err.decode("utf-8", "replace")

    def close(self) -> None:
        if self._ca_path:
            try:
                os.unlink(self._ca_path)
            except OSError:
                pass
            self._ca_path = ""
