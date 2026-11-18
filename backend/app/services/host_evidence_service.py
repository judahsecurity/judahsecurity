"""
Host evidence — read facts from inside a server so Aegis Oracle can settle
exploit preconditions that external scanning can't see.

Oracle defines what has to be true on a host for a CVE to be exploitable
(e.g. regreSSHion needs sshd running with a non-zero LoginGraceTime). The
ASM only sees a host from outside, so those conditions stay "unknown" and
Oracle files a verification task. This module resolves the ``host_probe``
tasks without a person:

  1. collect   — log in over SSH with an org-scoped, read-only credential and
                 run a FIXED catalog of read-only commands (never commands an
                 LLM wrote). Other collectors (osquery, EDR exports) can push
                 the same facts through ``ingest_host_facts``.
  2. store     — keep the facts and per-probe provenance on the asset
                 (``Asset.metadata_["host_facts"]``).
  3. project   — ``host_signals_for_oracle`` turns them into Oracle's
                 ``signals.host`` map plus evidence, which
                 ``_build_oracle_asset`` sends with every /analyze call.
  4. reassess  — re-run Oracle and the severity model for the asset's open
                 CVE findings, so verdicts move to exploitable / blocked with
                 the evidence attached.

A probe that can't run is recorded as an error, never as a negative: Oracle
then reports "could not check <signal>: <why>" and the finding is not
called safe.

Credential profiles: ``APIConfig`` rows, one per profile, so different server
groups can use different accounts:

  service_name  "host_ssh" / "host_ssh:<label>"      Linux, macOS (SSH)
                "host_winrm" / "host_winrm:<label>"  Windows (WinRM, see
                                                      winrm_host_evidence.py)
  api_user      username ("DOMAIN\\user" or "user@domain" for WinRM)
  api_key       private key (SSH) or password (encrypted at rest)
  config        {"targets": ["10.20.0.0/16", "*.corp.example"],  # required
                 "priority": 100,                                  # lower wins
                 # SSH:   "auth": "key"|"password", "port": 22,
                 #        "known_hosts": "...", "trust_on_first_use": false, "sudo": true
                 # WinRM: "transport": "ntlm"|"kerberos", "port": 5986, "https": true,
                 #        "ca_cert": "<PEM>"}

An asset is checked with the first active profile (by priority, then id)
whose ``targets`` match it; nothing outside every profile's targets is ever
contacted. SSH host keys are verified against ``known_hosts``; unknown keys
are rejected unless ``trust_on_first_use`` pins the first key per asset.
WinRM uses HTTPS with certificate validation unless the profile turns HTTPS
off, in which case NTLM/Kerberos message encryption is forced.
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

HOST_SSH_SERVICE = "host_ssh"
COLLECTOR_SSH = "host_ssh_probe"
HOST_FACT_TTL_HOURS = int(os.getenv("HOST_FACT_TTL_HOURS", "24"))
COMMAND_TIMEOUT_S = float(os.getenv("HOST_PROBE_COMMAND_TIMEOUT", "20"))
CONNECT_TIMEOUT_S = float(os.getenv("HOST_PROBE_CONNECT_TIMEOUT", "10"))
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_KEY_LEN = 200
MAX_VALUE_LEN = 4000

# Families whose probe returns the full list, so a missing entry means
# "absent" (Oracle derives host.package.X.installed / host.process.X.running
# = false from the "<family>._complete" marker).
LIST_FAMILIES = ("package", "process")
_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:+@-]*$")


# ── Parsers (pure; unit-tested) ───────────────────────────────────────────────

def parse_os_release(out: str) -> Dict[str, str]:
    """/etc/os-release, or macOS ``sw_vers`` ("ProductName: macOS")."""
    facts: Dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line and "=" not in line:
            k, _, v = line.partition(":")
            k, v = k.strip(), v.strip()
            if k == "ProductName":
                facts["os.id"] = "macos" if "mac" in v.lower() else v.lower()
                facts["os.platform"] = "mac"
            elif k == "ProductVersion":
                facts["os.version_id"] = v
            continue
        k, sep, v = line.partition("=")
        if not sep:
            continue
        v = v.strip().strip('"').strip("'")
        if k == "ID":
            facts["os.id"] = v.lower()
        elif k == "VERSION_ID":
            facts["os.version_id"] = v
    return facts


def parse_uname(out: str) -> Dict[str, str]:
    release = out.strip().splitlines()[0].strip() if out.strip() else ""
    return {"kernel.release": release} if release else {}


def parse_processes(out: str) -> Dict[str, str]:
    """``ps -eo comm=,args=`` → process.<comm>.running / .args."""
    facts: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        comm, _, args = line.partition(" ")
        comm = comm.strip().lower()
        if not comm or not _KEY_RE.match(comm):
            continue
        facts[f"process.{comm}.running"] = "true"
        facts.setdefault(f"process.{comm}.args", args.strip() or comm)
    return facts


def parse_sshd_t(out: str) -> Dict[str, str]:
    """``sshd -T`` prints one "keyword value" pair per line, lowercase."""
    facts: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or " " not in line:
            continue
        key, value = line.split(" ", 1)
        key = key.lower()
        if not re.match(r"^[a-z0-9]+$", key):
            continue
        # Repeated keywords (hostkey, listenaddress, ...) accumulate.
        full = f"sshd.{key}"
        facts[full] = f"{facts[full]},{value.strip()}" if full in facts else value.strip()
    return facts


def parse_packages(out: str) -> Dict[str, str]:
    """Lines of ``name<TAB>version[<TAB>status]`` from dpkg-query or rpm."""
    facts: Dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, version = parts[0].strip().lower(), parts[1].strip()
        if len(parts) >= 3 and not parts[2].strip().startswith("ii"):
            continue  # dpkg: only fully installed packages
        if version.startswith("(none):"):
            version = version[len("(none):"):]
        elif version.startswith("0:"):
            version = version[2:]
        if not name or not version or not _KEY_RE.match(name):
            continue
        facts[f"package.{name}"] = version
        facts[f"package.{name}.installed"] = "true"
    return facts


_SYSCTL_PREFIXES = ("kernel.", "fs.", "user.", "vm.mmap_min_addr", "net.ipv4.ip_forward", "net.ipv4.conf.all.")


def parse_sysctl(out: str) -> Dict[str, str]:
    facts: Dict[str, str] = {}
    for line in out.splitlines():
        key, sep, value = line.partition("=")
        key = key.strip().lower()
        if not sep or not key.startswith(_SYSCTL_PREFIXES):
            continue
        facts[f"sysctl.{key}"] = " ".join(value.split())
    return facts


def parse_listening(out: str) -> Dict[str, str]:
    """``ss -Hltn`` / ``netstat -ltn`` → listening.tcp = "22,443".

    The local address is the first column ending in ":<port>"; the peer
    column ("*:*", "0.0.0.0:*") never ends in digits.
    """
    ports = set()
    for line in out.splitlines():
        for token in line.split():
            host, sep, port = token.rpartition(":")
            if not (sep and host and port.isdigit()) and "LISTEN" in line:
                host, sep, port = token.rpartition(".")  # macOS netstat: "*.22", "127.0.0.1.631"
            if sep and host and port.isdigit():
                if 0 < int(port) < 65536:
                    ports.add(int(port))
                break
    return {"listening.tcp": ",".join(str(p) for p in sorted(ports))} if ports else {}


@dataclass(frozen=True)
class Probe:
    prefix: str          # facts family; evidence is recorded under host.<prefix>.*
    command: str         # fixed, read-only
    parse: Callable[[str], Dict[str, str]]
    complete_list: bool = False
    optional: bool = False  # missing tool → no facts, not an error


_PATH = 'PATH="$PATH:/usr/sbin:/sbin"'

PROBES: Tuple[Probe, ...] = (
    Probe("os", "cat /etc/os-release 2>/dev/null || sw_vers", parse_os_release),
    Probe("kernel", "uname -r", parse_uname),
    Probe("process", "ps -eo comm=,args=", parse_processes, complete_list=True),
    Probe(
        "package",
        "if command -v dpkg-query >/dev/null 2>&1; then "
        "dpkg-query -W -f='${Package}\\t${Version}\\t${db:Status-Abbrev}\\n'; "
        "elif command -v rpm >/dev/null 2>&1; then "
        "rpm -qa --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\n'; "
        "else echo '__unsupported__'; exit 3; fi",
        parse_packages,
        complete_list=True,
    ),
    # Effective config needs root to read host keys; sudo -n never prompts.
    Probe(
        "sshd",
        f"{_PATH}; command -v sshd >/dev/null 2>&1 || {{ echo '__absent__'; exit 0; }}; "
        "sudo -n sshd -T 2>/dev/null || sshd -T",
        parse_sshd_t,
        optional=True,
    ),
    Probe("sysctl", f"{_PATH}; sysctl -a 2>/dev/null", parse_sysctl, optional=True),
    Probe("listening", f"{_PATH}; ss -Hltn 2>/dev/null || netstat -ltn 2>/dev/null || netstat -an -p tcp | grep LISTEN",
          parse_listening, optional=True),
)


# ── Credential + scope ───────────────────────────────────────────────────────

HOST_WINRM_SERVICE = "host_winrm"


@dataclass
class HostCredential:
    username: str
    secret: str
    auth: str = "key"  # key | password (SSH)
    port: int = 22
    targets: List[str] = field(default_factory=list)
    known_hosts: str = ""
    trust_on_first_use: bool = False
    use_sudo: bool = True
    kind: str = "ssh"  # ssh | winrm
    name: str = HOST_SSH_SERVICE
    priority: int = 100
    transport: str = "ntlm"  # WinRM: ntlm | kerberos
    https: bool = True  # WinRM
    ca_cert: str = ""  # WinRM: PEM to validate the listener certificate

    @classmethod
    def from_api_config(cls, cfg: Any) -> "HostCredential":
        conf = cfg.config or {}
        service = str(getattr(cfg, "service_name", "") or HOST_SSH_SERVICE)
        kind = "winrm" if service.split(":", 1)[0] == HOST_WINRM_SERVICE else "ssh"
        return cls(
            username=cfg.api_user or "",
            secret=cfg.get_api_key() or "",
            auth=str(conf.get("auth") or "key").lower(),
            port=int(conf.get("port") or (5986 if kind == "winrm" and conf.get("https", True) else
                                          5985 if kind == "winrm" else 22)),
            targets=[str(t).strip() for t in conf.get("targets") or [] if str(t).strip()],
            known_hosts=str(conf.get("known_hosts") or ""),
            trust_on_first_use=bool(conf.get("trust_on_first_use", False)),
            use_sudo=bool(conf.get("sudo", True)),
            kind=kind,
            name=service,
            priority=int(conf.get("priority", 100)),
            transport=str(conf.get("transport") or "ntlm").lower(),
            https=bool(conf.get("https", True)),
            ca_cert=str(conf.get("ca_cert") or ""),
        )


def _is_profile(service_name: str) -> bool:
    head = (service_name or "").split(":", 1)[0]
    return head in (HOST_SSH_SERVICE, HOST_WINRM_SERVICE)


def load_credentials(db: Any, organization_id: int) -> List[HostCredential]:
    """Active credential profiles for the org, in match order."""
    from app.models.api_config import APIConfig

    rows = (
        db.query(APIConfig)
        .filter(APIConfig.organization_id == organization_id, APIConfig.is_active == True)  # noqa: E712
        .order_by(APIConfig.id.asc())
        .all()
    )
    creds = [HostCredential.from_api_config(r) for r in rows
             if _is_profile(r.service_name) and r.api_user and r.api_key_encrypted]
    return sorted(creds, key=lambda c: c.priority)  # stable: ties keep id order


def load_credential(db: Any, organization_id: int) -> Optional[HostCredential]:
    """First profile (kept for callers that only need one)."""
    creds = load_credentials(db, organization_id)
    return creds[0] if creds else None


def credential_for_asset(creds: Iterable[HostCredential], asset: Any) -> Optional[HostCredential]:
    for cred in creds or []:
        if in_target_scope(asset, cred.targets):
            return cred
    return None


def asset_address(asset: Any) -> str:
    return (getattr(asset, "ip_address", None) or getattr(asset, "value", None) or "").strip()


def in_target_scope(asset: Any, targets: Iterable[str]) -> bool:
    """True only when the asset's IP or hostname matches a configured target
    (CIDR or hostname glob). No targets → nothing is in scope."""
    names = {str(getattr(asset, "value", "") or "").lower(), str(getattr(asset, "ip_address", "") or "").lower()}
    names.discard("")
    ips = []
    for n in names:
        try:
            ips.append(ipaddress.ip_address(n))
        except ValueError:
            pass
    for target in targets:
        t = target.lower()
        try:
            net = ipaddress.ip_network(t, strict=False)
            if any(ip in net for ip in ips):
                return True
            continue
        except ValueError:
            pass
        if any(fnmatch.fnmatchcase(n, t) for n in names):
            return True
    return False


# ── Collection ───────────────────────────────────────────────────────────────

class HostCheckError(RuntimeError):
    """The host could not be checked at all (connect, auth, host key)."""


class CommandRunner:
    """Executes one command and returns (exit_status, stdout, stderr)."""

    host_key_fingerprint: str = ""

    def run(self, command: str) -> Tuple[int, str, str]:  # pragma: no cover - interface
        raise NotImplementedError

    def close(self) -> None:
        pass


class SSHRunner(CommandRunner):  # pragma: no cover - needs a live host
    def __init__(self, address: str, cred: HostCredential, pinned_fingerprint: str = ""):
        try:
            import paramiko
        except ImportError as e:
            raise HostCheckError("paramiko is not installed on the backend") from e
        self._paramiko = paramiko
        client = paramiko.SSHClient()
        if cred.known_hosts:
            for line in cred.known_hosts.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                entry = paramiko.hostkeys.HostKeyEntry.from_line(line)
                if entry is not None:
                    for name in entry.hostnames:
                        client.get_host_keys().add(name, entry.key.get_name(), entry.key)
        pinned = pinned_fingerprint

        class _Policy(paramiko.MissingHostKeyPolicy):
            def missing_host_key(self, _client, hostname, key):
                fp = _fingerprint(key.asbytes())
                if not cred.trust_on_first_use:
                    raise HostCheckError(
                        f"host key {fp} for {hostname} is not in known_hosts (add it, or enable trust_on_first_use)"
                    )
                if pinned and pinned != fp:
                    raise HostCheckError(f"host key changed for {hostname}: pinned {pinned}, got {fp}")

        client.set_missing_host_key_policy(_Policy())
        kwargs: Dict[str, Any] = dict(
            hostname=address, port=cred.port, username=cred.username,
            timeout=CONNECT_TIMEOUT_S, banner_timeout=CONNECT_TIMEOUT_S, auth_timeout=CONNECT_TIMEOUT_S,
            allow_agent=False, look_for_keys=False,
        )
        if cred.auth == "password":
            kwargs["password"] = cred.secret
        else:
            kwargs["pkey"] = _load_private_key(paramiko, cred.secret)
        try:
            client.connect(**kwargs)
        except HostCheckError:
            raise
        except Exception as e:
            raise HostCheckError(f"ssh connect failed: {type(e).__name__}: {e}") from e
        self._client = client
        key = client.get_transport().get_remote_server_key()
        self.host_key_fingerprint = _fingerprint(key.asbytes())

    def run(self, command: str) -> Tuple[int, str, str]:
        _, stdout, stderr = self._client.exec_command(command, timeout=COMMAND_TIMEOUT_S)
        out = stdout.read(MAX_OUTPUT_BYTES).decode("utf-8", "replace")
        err = stderr.read(64 * 1024).decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), out, err

    def close(self) -> None:
        self._client.close()


def _fingerprint(raw: bytes) -> str:
    import base64

    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _load_private_key(paramiko: Any, pem: str) -> Any:  # pragma: no cover - needs real keys
    for cls_name in ("Ed25519Key", "ECDSAKey", "RSAKey"):
        cls = getattr(paramiko, cls_name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(pem))
        except Exception:
            continue
    raise HostCheckError("could not load the SSH private key (supported: ed25519, ecdsa, rsa; unencrypted)")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def run_probes(
    runner: CommandRunner, *, use_sudo: bool = True, catalog: Optional[Tuple[Probe, ...]] = None
) -> Tuple[Dict[str, str], Dict[str, Dict[str, Any]]]:
    """Run every probe; a failing probe is recorded, the rest still run."""
    facts: Dict[str, str] = {}
    probes: Dict[str, Dict[str, Any]] = {}
    for probe in (catalog if catalog is not None else PROBES):
        command = probe.command if use_sudo else probe.command.replace("sudo -n sshd -T 2>/dev/null || ", "")
        try:
            status, out, err = runner.run(command)
        except Exception as e:
            probes[probe.prefix] = {"ok": False, "error": f"{type(e).__name__}: {e}", "command": command}
            continue
        if "__absent__" in out and probe.optional:
            probes[probe.prefix] = {"ok": True, "absent": True, "command": command}
            continue
        try:
            parsed = probe.parse(out) if "__unsupported__" not in out else {}
        except Exception as e:
            probes[probe.prefix] = {"ok": False, "error": f"could not parse output: {type(e).__name__}: {e}"[:300],
                                    "command": command}
            continue
        # Optional probes (sysctl, ss) can exit non-zero over a few unreadable
        # entries while still printing what we need.
        if status != 0 and not (probe.optional and parsed):
            msg = (err or out).strip().splitlines()[-1:] or [f"exit status {status}"]
            probes[probe.prefix] = {"ok": False, "error": f"exit {status}: {msg[0][:300]}", "command": command}
            continue
        if probe.complete_list and parsed:
            parsed[f"{probe.prefix}._complete"] = "true"
        if not parsed and not probe.optional:
            probes[probe.prefix] = {"ok": False, "error": "command ran but produced no parsable output", "command": command}
            continue
        facts.update(parsed)
        probes[probe.prefix] = {"ok": True, "facts": len(parsed), "command": command}
    return facts, probes


def collect_host_facts(
    asset: Any,
    cred: HostCredential,
    *,
    runner_factory: Optional[Callable[[str, HostCredential, str], CommandRunner]] = None,
) -> Dict[str, Any]:
    """Collect facts from one asset. Never raises for host-side problems:
    the result records the failure so Oracle can say "could not check"."""
    address = asset_address(asset)
    previous = _stored(asset)
    winrm = cred.kind == "winrm"
    if winrm:
        from app.services import winrm_host_evidence as win
    record: Dict[str, Any] = {
        "collector": win.COLLECTOR_WINRM if winrm else COLLECTOR_SSH,
        "profile": cred.name,
        "observed_at": _now().isoformat(),
        "target": address,
        "facts": {},
        "probes": {},
    }
    if not in_target_scope(asset, cred.targets):
        record["error"] = "asset is not in the host-check target scope"
        return record
    default = (lambda addr, c, pin: win.WinRMRunner(addr, c, pin)) if winrm else (lambda addr, c, pin: SSHRunner(addr, c, pin))
    factory = runner_factory or default
    runner: Optional[CommandRunner] = None
    try:
        runner = factory(address, cred, "" if winrm else previous.get("host_key", ""))
        facts, probes = run_probes(runner, use_sudo=cred.use_sudo, catalog=win.WIN_PROBES if winrm else PROBES)
        record["facts"], record["probes"] = facts, probes
        if runner.host_key_fingerprint:
            record["host_key"] = runner.host_key_fingerprint
    except HostCheckError as e:
        record["error"] = str(e)
    except Exception as e:  # never let one host break a batch
        logger.exception("host check failed for %s", address)
        record["error"] = f"{type(e).__name__}: {e}"
    finally:
        if runner is not None:
            try:
                runner.close()
            except Exception:
                pass
    return record


# ── Storage ──────────────────────────────────────────────────────────────────

def _stored(asset: Any) -> Dict[str, Any]:
    meta = getattr(asset, "metadata_", None)
    return dict((meta or {}).get("host_facts") or {}) if isinstance(meta, dict) else {}


def store_host_facts(asset: Any, record: Dict[str, Any]) -> Dict[str, Any]:
    """Save a collection record on the asset. A failed run keeps the last
    good facts out of the evidence (they'd be stale) but keeps the pinned
    host key."""
    previous = _stored(asset)
    if not record.get("host_key") and previous.get("host_key"):
        record["host_key"] = previous["host_key"]
    meta = dict(asset.metadata_) if isinstance(asset.metadata_, dict) else {}
    meta["host_facts"] = record
    asset.metadata_ = meta
    return record


def ingest_host_facts(
    asset: Any,
    facts: Dict[str, Any],
    *,
    source: str,
    complete_families: Iterable[str] = (),
    observed_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Accept facts pushed by another collector (osquery, EDR, CMDB export).
    Keys use the same host.* vocabulary without the "host." prefix."""
    clean: Dict[str, str] = {}
    for raw_key, raw_value in (facts or {}).items():
        key = str(raw_key).strip().lower()
        if key.startswith("host."):
            key = key[5:]
        if not key or len(key) > MAX_KEY_LEN or not _KEY_RE.match(key) or key.endswith("._complete"):
            raise ValueError(f"invalid host fact key: {raw_key!r}")
        value = raw_value if isinstance(raw_value, str) else (str(raw_value).lower() if isinstance(raw_value, bool) else str(raw_value))
        clean[key] = value[:MAX_VALUE_LEN]
    families = {k.split(".", 1)[0] for k in clean}
    for fam in complete_families:
        if fam not in LIST_FAMILIES:
            raise ValueError(f"complete_families supports {LIST_FAMILIES}, got {fam!r}")
        clean[f"{fam}._complete"] = "true"
        families.add(fam)
    when = observed_at or _now()
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    record = {
        "collector": f"push:{source}"[:80],
        "observed_at": when.isoformat(),
        "target": asset_address(asset),
        "facts": clean,
        "probes": {fam: {"ok": True, "facts": sum(1 for k in clean if k.split(".", 1)[0] == fam)} for fam in sorted(families)},
    }
    return store_host_facts(asset, record)


# ── Projection into Oracle's asset payload ───────────────────────────────────

def host_signals_for_oracle(asset: Any, asset_id: str) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, List[Dict[str, Any]]]]:
    """Return (host map, runtime_flags map, signal_evidence) for Oracle.

    Evidence is recorded per probe ("host.sshd.*"), which Oracle applies to
    every key that probe produced; a failed run is recorded under "host.*"
    with the error so unknowns read "could not check: <why>".
    """
    record = _stored(asset)
    if not record:
        return {}, {}, {}
    try:
        observed = datetime.fromisoformat(str(record.get("observed_at")).replace("Z", "+00:00"))
    except ValueError:
        return {}, {}, {}
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=timezone.utc)
    valid_until = observed + timedelta(hours=HOST_FACT_TTL_HOURS)
    fresh = valid_until >= _now()
    source = str(record.get("collector") or COLLECTOR_SSH)

    def obs(path: str, *, error: str = "", value: str = "") -> Dict[str, Any]:
        o = {
            "signal_path": path,
            "source": source,
            "scope": asset_id,
            "collected_by": "judah-asm",
            "observed_at": observed.isoformat(),
            "valid_until": valid_until.isoformat(),
            "freshness": "error" if error else ("fresh" if fresh else "stale"),
        }
        if value:
            o["value"] = value
        if error:
            o["error"] = error
        return o

    evidence: Dict[str, List[Dict[str, Any]]] = {}
    if record.get("error"):
        evidence["host.*"] = [obs("host.*", error=str(record["error"]))]
        return {}, {}, evidence

    host = {str(k): str(v) for k, v in (record.get("facts") or {}).items()}
    for prefix, status in (record.get("probes") or {}).items():
        path = f"host.{prefix}.*"
        if status.get("ok"):
            evidence[path] = [obs(path)]
        else:
            evidence[path] = [obs(path, error=str(status.get("error") or "probe failed"))]

    # Back-compat for preconditions written against runtime_flags.<process>.
    runtime_flags: Dict[str, str] = {}
    for key, value in host.items():
        if key.startswith("process.") and key.endswith(".args"):
            name = key[len("process."):-len(".args")]
            runtime_flags[name] = value
            evidence[f"runtime_flags.{name}"] = [obs(f"runtime_flags.{name}", value=value)]
    return host, runtime_flags, evidence


# ── Executor: resolve host_probe verification tasks ──────────────────────────

def pending_host_checks(vuln: Any) -> List[Dict[str, Any]]:
    """Open host_probe verification tasks on a finding's Oracle payload."""
    meta = vuln.metadata_ if isinstance(getattr(vuln, "metadata_", None), dict) else {}
    oracle = meta.get("oracle") or {}
    tasks = [t for t in oracle.get("verification_tasks") or [] if isinstance(t, dict)]
    out = [t for t in tasks if t.get("task_kind") == "host_probe" and t.get("status", "open") == "open"]
    if out:
        return out
    # Payloads from before the host_probe task kind: infer from the signal.
    for e in oracle.get("preconditions_evaluated") or []:
        p = e.get("precondition") or {}
        if e.get("status") == "unknown" and str(p.get("verification_signal") or "").startswith("host."):
            out.append({"precondition_id": p.get("id"), "expected_signal_path": p.get("verification_signal"),
                        "task_kind": "host_probe", "status": "open"})
    return out


def _verdict(vuln: Any) -> Dict[str, Any]:
    meta = vuln.metadata_ if isinstance(vuln.metadata_, dict) else {}
    real = (meta.get("severity_eval") or {}).get("exploit_realism") or {}
    oracle = meta.get("oracle") or {}
    return {
        "tier": real.get("tier"),
        "reasons": real.get("reasons") or [],
        "context_state": (oracle.get("contextual_assessment") or {}).get("state"),
        "opes_label": oracle.get("opes_label"),
    }


def reassess_asset(db: Any, asset: Any, *, only_pending: bool = False) -> List[Dict[str, Any]]:
    """Re-run Oracle and the severity model for the asset's open CVE findings
    now that host evidence changed. Returns before/after verdicts."""
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus
    from app.services.oracle_enrichment_service import (
        OracleInputError, OracleUnavailable, enrich_vulnerability,
    )
    from app.services.severity_evaluation import evaluate_finding

    vulns = (
        db.query(Vulnerability)
        .filter(Vulnerability.asset_id == asset.id, Vulnerability.status == VulnerabilityStatus.OPEN,
                Vulnerability.cve_id.isnot(None))
        .all()
    )
    results = []
    for v in vulns:
        if only_pending and not pending_host_checks(v):
            continue
        before = _verdict(v)
        try:
            enrich_vulnerability(db, v, force=True)
        except (OracleUnavailable, OracleInputError) as e:
            results.append({"vulnerability_id": v.id, "cve_id": v.cve_id, "error": str(e), "before": before})
            continue
        evaluate_finding(db, v)
        db.commit()
        results.append({"vulnerability_id": v.id, "cve_id": v.cve_id, "before": before, "after": _verdict(v),
                        "still_pending": [t.get("expected_signal_path") for t in pending_host_checks(v)]})
    return results


def check_asset(
    db: Any,
    asset: Any,
    cred: Optional[HostCredential] = None,
    *,
    collector: Optional[Callable[[Any], Dict[str, Any]]] = None,
    **kw: Any,
) -> Dict[str, Any]:
    """Collect → store → reassess one asset, with ``collector`` (e.g. Falcon)
    when given, else the SSH credential."""
    if collector is not None:
        record = collector(asset)
    elif cred is not None:
        record = collect_host_facts(asset, cred, **kw)
    else:
        return {"asset_id": asset.id, "skipped": "no host-check collector configured for this asset"}
    if record.get("error") == "asset is not in the host-check target scope":
        return {"asset_id": asset.id, "skipped": record["error"]}
    store_host_facts(asset, record)
    db.add(asset)
    db.commit()
    return {
        "asset_id": asset.id,
        "collector": record.get("collector"),
        "target": record.get("target"),
        "error": record.get("error"),
        "probes": {k: {kk: vv for kk, vv in v.items() if kk != "command"} for k, v in record.get("probes", {}).items()},
        "findings": reassess_asset(db, asset),
    }


def assets_needing_host_checks(db: Any, organization_id: int, limit: int = 200) -> List[Any]:
    """Assets in the org with at least one open finding waiting on a
    host_probe task."""
    from app.models.asset import Asset
    from app.models.vulnerability import Vulnerability, VulnerabilityStatus

    rows = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Asset.organization_id == organization_id, Vulnerability.status == VulnerabilityStatus.OPEN,
                Vulnerability.cve_id.isnot(None))
        .all()
    )
    seen, out = set(), []
    for v in rows:
        if v.asset_id in seen or not pending_host_checks(v):
            continue
        seen.add(v.asset_id)
        out.append(v.asset)
        if len(out) >= limit:
            break
    return out


def collector_for_asset(
    db: Any, asset: Any, creds: Any, **kw: Any
) -> Tuple[str, Optional[Callable[[Any], Dict[str, Any]]]]:
    """Pick how to check an asset: the Falcon sensor when the asset is a
    Falcon host with host evidence enabled (no login needed), else the first
    credential profile (SSH or WinRM) whose targets match it."""
    from app.services import falcon_host_evidence as falcon

    link = falcon.falcon_link_for(db, asset)
    if link is not None:
        integration, aid = link
        return "falcon", falcon.collector_for(integration, aid, client_factory=kw.get("falcon_client_factory"))
    if isinstance(creds, HostCredential):
        creds = [creds]
    cred = credential_for_asset(creds or [], asset)
    if cred is not None:
        factory = kw.get("runner_factory")
        return cred.kind, (lambda a: collect_host_facts(a, cred, runner_factory=factory))
    return "", None


def run_pending_host_checks(db: Any, organization_id: int, *, limit: int = 200, **kw: Any) -> Dict[str, Any]:
    creds = load_credentials(db, organization_id)
    assets = assets_needing_host_checks(db, organization_id, limit=limit)
    summary: Dict[str, Any] = {"assets": [], "checked": 0, "skipped": 0, "failed": 0}
    for asset in assets:
        kind, collector = collector_for_asset(db, asset, creds, **kw)
        if collector is None:
            result = {"asset_id": asset.id, "skipped": "no host-check collector: not a Falcon host with host "
                                                         "evidence enabled, and no credential profile targets it"}
        else:
            result = check_asset(db, asset, collector=collector)
        summary["assets"].append(result)
        if result.get("skipped"):
            summary["skipped"] += 1
        elif result.get("error"):
            summary["failed"] += 1
        else:
            summary["checked"] += 1
    if not assets:
        summary["message"] = "no open findings are waiting on host evidence"
    return summary


__all__ = [
    "HOST_SSH_SERVICE", "HOST_WINRM_SERVICE", "PROBES", "load_credentials", "credential_for_asset", "HostCredential", "HostCheckError", "CommandRunner",
    "parse_os_release", "parse_uname", "parse_processes", "parse_sshd_t", "parse_packages",
    "parse_sysctl", "parse_listening", "run_probes", "collect_host_facts", "store_host_facts",
    "ingest_host_facts", "host_signals_for_oracle", "pending_host_checks", "reassess_asset",
    "check_asset", "collector_for_asset", "assets_needing_host_checks", "run_pending_host_checks", "in_target_scope",
    "load_credential",
]
