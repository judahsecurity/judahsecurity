"""
Falcon host evidence — settle Oracle's host preconditions through the
CrowdStrike Falcon sensor already on the host, instead of an SSH login.

Three read-only sources, each opt-in per CrowdStrike integration:

  device        /devices/entities/devices/v2           OS, kernel   (Hosts: read)
  applications  /discover/combined/applications/v1     installed software and when it
                                                       was last used (Assets: read)
  rtr           Real Time Response, read-only commands  sshd configuration files
                ``cat`` and ``ls`` only                 (Real time response: read)

``collect_host_evidence`` enables device + applications. ``host_evidence_rtr``
additionally opens RTR sessions; both default to off, and nothing here runs
on the scheduled Falcon sync — only when a host check is requested.

Output is the same record shape as the SSH collector
(``host_evidence_service``), so Oracle sees identical ``host.*`` signals.

Differences from the SSH path, recorded on each probe so verdicts stay honest:
  * sshd settings come from the config files, not ``sshd -T``. Global
    settings and Include files are resolved in sshd's first-value-wins order;
    keywords set only inside Match blocks are not reported, and a failed
    Include listing makes the whole sshd probe an error (never a guess).
  * running processes are not collected yet (RTR ``ps`` output needs
    validating against a real tenant first), so host.process.* stays unknown.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import fnmatch
import posixpath
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from app.services import host_evidence_service as hes

COLLECTOR = "falcon"
APP_USED_DAYS = 30
RTR_POLL_SECONDS = 1.0
RTR_TIMEOUT_SECONDS = 45.0
RTR_ALLOWED_COMMANDS = frozenset({"cat", "ls"})
MAX_INCLUDED_FILES = 20

SSHD_CONFIG = {"linux": "/etc/ssh/sshd_config", "mac": "/etc/ssh/sshd_config",
               "windows": "C:\\ProgramData\\ssh\\sshd_config"}
SSHD_ROOT = {"linux": "/etc/ssh", "mac": "/etc/ssh", "windows": "C:\\ProgramData\\ssh"}
# Paths read over RTR must stay under the sshd config directory and contain
# no characters RTR could treat as argument separators.
_SAFE_PATH = re.compile(r"^(/[A-Za-z0-9._*/-]+|[A-Za-z]:\\[A-Za-z0-9._*\\-]+)$")
_MISSING = re.compile(r"no such file|cannot find|does not exist|not found", re.I)


class FalconCheckError(RuntimeError):
    pass


# ── Pure helpers (unit-tested) ────────────────────────────────────────────────

def platform_key(device: Dict[str, Any]) -> str:
    name = str(device.get("platform_name") or "").lower()
    return "windows" if name.startswith("win") else "mac" if name.startswith("mac") else "linux"


def device_facts(device: Dict[str, Any]) -> Dict[str, str]:
    facts: Dict[str, str] = {"os.platform": platform_key(device)}
    for key, field in (("os.product", "os_product_name"), ("os.version", "os_version")):
        if device.get(field):
            facts[key] = str(device[field])
    if device.get("kernel_version"):
        facts["kernel.release"] = str(device["kernel_version"])
    if facts["os.platform"] == "linux":
        m = re.match(r"^\s*([A-Za-z]+)[^0-9]*([0-9][0-9.]*)", str(device.get("os_version") or ""))
        if m:
            facts["os.id"] = {"red": "rhel", "redhat": "rhel"}.get(m.group(1).lower(), m.group(1).lower())
            facts["os.version_id"] = m.group(2).rstrip(".")
    return facts


def package_key(name: str) -> str:
    key = re.sub(r"[^a-z0-9._+-]+", "-", name.strip().lower()).strip("-.")
    return key[: hes.MAX_KEY_LEN - 20]


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        ts = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def application_facts(apps: List[Dict[str, Any]], now: Optional[datetime] = None) -> Dict[str, str]:
    """Falcon Discover applications → host.package.<name>[.installed|.last_used|.used].

    ``used`` is only ever set to "true" (last used within APP_USED_DAYS);
    Falcon not recording use is not evidence the software is idle.
    """
    now = now or datetime.now(timezone.utc)
    facts: Dict[str, str] = {}
    for app in apps:
        if not isinstance(app, dict) or not app.get("name"):
            continue
        key = package_key(str(app["name"]))
        if not key or not hes._KEY_RE.match(key):
            continue
        version = str(app.get("version") or "").strip()
        if version:
            facts[f"package.{key}"] = version
        facts[f"package.{key}.installed"] = "true"
        used = _parse_ts(app.get("last_used_timestamp"))
        if used:
            facts[f"package.{key}.last_used"] = used.isoformat()
            if now - used <= timedelta(days=APP_USED_DAYS):
                facts[f"package.{key}.used"] = "true"
    return facts


_TIME_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_TIME_KEYS = {"logingracetime", "clientaliveinterval"}
# sshd builds where these defaults have held for over a decade; anything else
# is reported only when set explicitly.
_SSHD_DEFAULTS = {"logingracetime": "120", "maxstartups": "10:30:100", "maxauthtries": "6", "port": "22"}
_SSHD_MULTI = {"hostkey", "listenaddress", "port", "acceptenv", "subsystem", "setenv"}


def sshd_seconds(value: str) -> Optional[str]:
    """sshd time format ("90", "2m", "1h30m") → seconds, as ``sshd -T`` prints."""
    total, pos, v = 0, 0, value.strip().lower()
    for m in re.finditer(r"(\d+)([smhdw]?)", v):
        if m.start() != pos:
            return None
        total += int(m.group(1)) * _TIME_UNITS[m.group(2)]
        pos = m.end()
    return str(total) if pos == len(v) and v else None


async def effective_sshd_from_files(
    main_path: str,
    read: Callable[[str], Awaitable[Optional[str]]],
    list_dir: Callable[[str], Awaitable[Optional[List[str]]]],
    *,
    root: str,
) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """Resolve global sshd settings from config files the way sshd reads them:
    Include expands in place (globs sorted), the first value of a keyword
    wins, Match blocks are conditional and skipped.

    Returns (facts, info). ``info["absent"]`` when sshd_config doesn't exist;
    raises FalconCheckError when a file or Include can't be resolved.
    """
    values: Dict[str, str] = {}
    info: Dict[str, Any] = {"method": "sshd_config files (not sshd -T)", "files": [], "match_blocks": False}
    windows = "\\" in root

    def resolve(path: str) -> str:
        if windows:
            return path if re.match(r"^[A-Za-z]:\\", path) else f"{root}\\{path}"
        return path if path.startswith("/") else posixpath.join(root, path)

    def under_root(path: str) -> bool:
        norm = path if windows else posixpath.normpath(path)
        prefix = root.rstrip("\\/") + ("\\" if windows else "/")
        return bool(_SAFE_PATH.match(path)) and (norm.lower() if windows else norm).startswith(prefix.lower() if windows else prefix) and ".." not in path

    async def process(path: str, depth: int, *, explicit: bool) -> None:
        if len(info["files"]) >= MAX_INCLUDED_FILES:
            raise FalconCheckError(f"sshd config includes more than {MAX_INCLUDED_FILES} files")
        if depth > 0 and not under_root(path):
            raise FalconCheckError(f"sshd Include {path!r} is outside {root}; not read")
        content = await read(path)
        if content is None:
            if depth == 0:
                info["absent"] = True
                return
            if explicit:
                raise FalconCheckError(f"sshd Include {path} could not be read")
            return
        info["files"].append(path)
        in_match = False
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = re.split(r"\s*=\s*|\s+", line, maxsplit=1)
            keyword, value = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
            if keyword == "match":
                in_match = True
                info["match_blocks"] = True
                continue
            if in_match:
                continue
            if keyword == "include":
                for pattern in value.split():
                    target = resolve(pattern)
                    if any(ch in target for ch in "*?["):
                        directory, base = (target.rsplit("\\", 1) if windows else posixpath.split(target))
                        if not under_root(directory + ("\\" if windows else "/") + "x"):
                            raise FalconCheckError(f"sshd Include {pattern!r} is outside {root}; not read")
                        names = await list_dir(directory)
                        if names is None:
                            raise FalconCheckError(f"could not list {directory} for sshd Include {pattern}")
                        for name in sorted(n for n in names if fnmatch.fnmatchcase(n, base)):
                            await process((f"{directory}\\{name}" if windows else posixpath.join(directory, name)),
                                          depth + 1, explicit=False)
                    else:
                        await process(target, depth + 1, explicit=True)
                continue
            if not value or not re.match(r"^[a-z0-9]+$", keyword):
                continue
            if keyword in _TIME_KEYS:
                value = sshd_seconds(value) or value
            elif value.lower() in ("yes", "no"):
                value = value.lower()
            if keyword in _SSHD_MULTI:
                values[keyword] = f"{values[keyword]},{value}" if keyword in values else value
            elif keyword not in values:
                values[keyword] = value

    await process(main_path, 0, explicit=True)
    if info.get("absent"):
        return {}, info
    for keyword, default in _SSHD_DEFAULTS.items():
        values.setdefault(keyword, default)
    return {f"sshd.{k}": v for k, v in values.items()}, info


# ── Falcon calls (the only network-facing part; replaced by fakes in tests) ──

class FalconHostAPI:
    """Thin read-only wrapper over CrowdStrikeClient for one host."""

    def __init__(self, client: Any, aid: str):
        self.client, self.aid = client, aid
        self.session_id: Optional[str] = None

    async def device(self) -> Dict[str, Any]:
        payload = await self.client._request("GET", "/devices/entities/devices/v2", params={"ids": [self.aid]})
        resources = payload.get("resources") or []
        if not resources or not isinstance(resources[0], dict):
            raise FalconCheckError("Falcon returned no device record for this host")
        return resources[0]

    async def applications(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        async for batch in self.client._pages(
            "/discover/combined/applications/v1",
            params={"filter": f"host.id:'{self.aid}'", "limit": 1000, "facet": ["install_usage"]},
            cursor_key="after",
        ):
            out.extend(item for item in batch if isinstance(item, dict))
        return out

    async def rtr_open(self) -> None:
        payload = await self.client._request("POST", "/real-time-response/entities/sessions/v1",
                                             json={"device_id": self.aid, "origin": "judah-host-evidence",
                                                   "queue_offline": False})
        resources = payload.get("resources") or [{}]
        self.session_id = resources[0].get("session_id")
        if not self.session_id:
            raise FalconCheckError("Falcon RTR did not open a session (is the host online?)")

    async def rtr(self, base_command: str, argument: str) -> Tuple[str, str]:
        if base_command not in RTR_ALLOWED_COMMANDS:
            raise FalconCheckError(f"RTR command {base_command!r} is not allowed")
        if not _SAFE_PATH.match(argument):
            raise FalconCheckError(f"RTR argument {argument!r} rejected")
        if not self.session_id:
            await self.rtr_open()
        payload = await self.client._request("POST", "/real-time-response/entities/command/v1", json={
            "base_command": base_command, "command_string": f"{base_command} {argument}",
            "session_id": self.session_id, "device_id": self.aid, "persist": False,
        })
        request_id = (payload.get("resources") or [{}])[0].get("cloud_request_id")
        if not request_id:
            raise FalconCheckError("Falcon RTR did not accept the command")
        waited = 0.0
        while waited <= RTR_TIMEOUT_SECONDS:
            result = await self.client._request("GET", "/real-time-response/entities/command/v1",
                                                params={"cloud_request_id": request_id, "sequence_id": 0})
            res = (result.get("resources") or [{}])[0]
            if res.get("complete"):
                return str(res.get("stdout") or ""), str(res.get("stderr") or "")
            await asyncio.sleep(RTR_POLL_SECONDS)
            waited += RTR_POLL_SECONDS
        raise FalconCheckError(f"Falcon RTR {base_command} timed out after {int(RTR_TIMEOUT_SECONDS)}s")

    async def rtr_close(self) -> None:
        if not self.session_id:
            return
        try:
            await self.client._request("DELETE", "/real-time-response/entities/sessions/v1",
                                       params={"session_id": self.session_id})
        except Exception:
            pass  # sessions expire on their own; DELETE often returns no body
        self.session_id = None


async def collect(api: FalconHostAPI, *, applications: bool, rtr: bool) -> Dict[str, Any]:
    record: Dict[str, Any] = {"collector": COLLECTOR, "observed_at": datetime.now(timezone.utc).isoformat(),
                              "target": f"falcon:{api.aid}", "facts": {}, "probes": {}}
    try:
        device = await api.device()
    except Exception as e:
        record["error"] = f"Falcon device lookup failed: {e}"
        return record
    platform = platform_key(device)
    dev = device_facts(device)
    record["facts"].update(dev)
    record["probes"]["os"] = {"ok": True, "facts": sum(k.startswith("os.") for k in dev), "source": "falcon_device"}
    if "kernel.release" in dev:
        record["probes"]["kernel"] = {"ok": True, "facts": 1, "source": "falcon_device"}

    if applications:
        try:
            pkgs = application_facts(await api.applications())
            record["facts"].update(pkgs)
            record["probes"]["package"] = {"ok": True, "facts": len(pkgs), "source": "falcon_discover"}
        except Exception as e:
            record["probes"]["package"] = {"ok": False, "error": f"Falcon Discover applications: {e}"}

    if rtr:
        async def read(path: str) -> Optional[str]:
            out, err = await api.rtr("cat", path)
            if err.strip():
                if _MISSING.search(err):
                    return None
                raise FalconCheckError(f"cat {path}: {err.strip()[:200]}")
            return out

        async def list_dir(path: str) -> Optional[List[str]]:
            out, err = await api.rtr("ls", path)
            if err.strip():
                return [] if _MISSING.search(err) else None
            names = []
            for token in out.split():
                name = re.split(r"[\\/]", token)[-1]
                if name and name not in (".", ".."):
                    names.append(name)
            return names

        try:
            facts, info = await effective_sshd_from_files(SSHD_CONFIG[platform], read, list_dir, root=SSHD_ROOT[platform])
            record["facts"].update(facts)
            record["probes"]["sshd"] = {"ok": True, "facts": len(facts), "source": "falcon_rtr", **info}
        except Exception as e:
            record["probes"]["sshd"] = {"ok": False, "error": f"Falcon RTR: {e}", "source": "falcon_rtr"}
        finally:
            await api.rtr_close()
    return record


# ── Wiring into host checks ──────────────────────────────────────────────────

def falcon_link_for(db: Any, asset: Any) -> Optional[Tuple[Any, str]]:
    """The Falcon integration + host id (aid) that can check this asset, if any."""
    from app.models.crowdstrike_integration import CrowdStrikeAssetLink, CrowdStrikeIntegration

    row = (
        db.query(CrowdStrikeIntegration, CrowdStrikeAssetLink.source_id)
        .join(CrowdStrikeAssetLink, CrowdStrikeAssetLink.integration_id == CrowdStrikeIntegration.id)
        .filter(CrowdStrikeAssetLink.asset_id == asset.id, CrowdStrikeAssetLink.source_kind == "host",
                CrowdStrikeIntegration.organization_id == asset.organization_id,
                CrowdStrikeIntegration.is_active == True,  # noqa: E712
                CrowdStrikeIntegration.collect_host_evidence == True)  # noqa: E712
        .first()
    )
    return (row[0], row[1]) if row else None


def _run(coro_factory: Callable[[], Awaitable[Any]]) -> Any:
    # Callers are sync (routes, background tasks); keep the event loop on its
    # own thread so this also works if a loop is already running.
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro_factory())).result()


def collector_for(integration: Any, aid: str, *, client_factory: Optional[Callable[[Any], Any]] = None) -> Callable[[Any], Dict[str, Any]]:
    """A sync ``asset -> record`` collector for host_evidence_service.check_asset."""
    from app.services.crowdstrike_service import _client_for

    factory = client_factory or _client_for
    rtr = bool(getattr(integration, "host_evidence_rtr", False))

    def run(_asset: Any) -> Dict[str, Any]:
        async def go() -> Dict[str, Any]:
            async with factory(integration) as client:
                return await collect(FalconHostAPI(client, aid), applications=True, rtr=rtr)

        try:
            return _run(go)
        except Exception as e:
            return {"collector": COLLECTOR, "observed_at": datetime.now(timezone.utc).isoformat(),
                    "target": f"falcon:{aid}", "facts": {}, "probes": {}, "error": f"Falcon check failed: {e}"}

    return run
