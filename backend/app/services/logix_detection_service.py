"""Read-only Allen-Bradley Logix runtime and program-schema detection.

Runtime checks deliberately disable pycomm3 tag initialization.  The optional
inventory mode uploads tag definitions but never reads tag values, changes the
controller mode, or writes to the device.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Optional


LOGIX_PORT = 44818
LOGIX_IDENTITY_MARKERS = (
    "allen-bradley",
    "compactlogix",
    "controllogix",
    "guardlogix",
    "micro800",
    "programmable logic controller",
    "rockwell",
)
CHANGE_FIELDS = (
    "serial",
    "product_name",
    "product_code",
    "revision",
    "project_name",
    "keyswitch",
    "inventory_hash",
)


def _string(value: Any, limit: int = 500) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.hex()
    return str(value)[:limit]


def normalize_revision(info: dict) -> Optional[str]:
    """Support both legacy dict and current string pycomm3 revision shapes."""
    revision = info.get("revision")
    if isinstance(revision, dict):
        major = revision.get("major")
        minor = revision.get("minor")
        if major is not None and minor is not None:
            return f"{major}.{int(minor):03d}"
    if revision is not None:
        return _string(revision, 100)
    major = info.get("version_major")
    minor = info.get("version_minor")
    if major is not None and minor is not None:
        return f"{major}.{int(minor):03d}"
    return None


def classify_keyswitch(value: Any) -> dict:
    keyswitch = (_string(value, 100) or "UNKNOWN").strip().upper()
    if keyswitch == "RUN":
        posture = "hard_run"
    elif keyswitch == "REMOTE RUN":
        posture = "remote_run"
    elif keyswitch == "REMOTE PROGRAM":
        posture = "remote_program"
    elif "PROGRAM" in keyswitch:
        posture = "program_mode"
    else:
        posture = "unknown"
    return {
        "keyswitch": keyswitch,
        "hard_run": keyswitch == "RUN",
        "remote_mode": keyswitch.startswith("REMOTE"),
        "posture": posture,
    }


def _tag_summary(tag: dict) -> dict:
    """Keep schema metadata only; discard type classes and any values."""
    return {
        "name": _string(tag.get("tag_name"), 500),
        "tag_type": _string(tag.get("tag_type"), 100),
        "data_type": _string(tag.get("data_type_name"), 200),
        "external_access": _string(tag.get("external_access"), 100),
        "dimensions": list(tag.get("dimensions") or [])[:3],
        "alias": bool(tag.get("alias", False)),
    }


def _inventory(info: dict, tags: list[dict], max_stored_tags: int) -> dict:
    summaries = sorted(
        (_tag_summary(tag) for tag in tags),
        key=lambda item: item.get("name") or "",
    )
    programs = sorted(str(name) for name in (info.get("programs") or {}).keys())
    tasks = sorted(str(name) for name in (info.get("tasks") or {}).keys())
    modules = sorted(str(name) for name in (info.get("modules") or {}).keys())
    canonical = {
        "programs": programs,
        "tasks": tasks,
        "modules": modules,
        "tags": summaries,
    }
    digest = hashlib.sha256(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "inventory_hash": digest,
        "program_count": len(programs),
        "programs": programs[:200],
        "task_count": len(tasks),
        "tasks": tasks[:200],
        "module_count": len(modules),
        "modules": modules[:500],
        "tag_count": len(summaries),
        "tags": summaries[:max(0, max_stored_tags)],
        "tags_truncated": len(summaries) > max(0, max_stored_tags),
    }


def inspect_logix_controller(
    target: str,
    *,
    slot: Optional[int] = None,
    include_program_inventory: bool = False,
    max_stored_tags: int = 500,
    socket_timeout: float = 5.0,
    driver_factory: Optional[Callable[..., Any]] = None,
) -> dict:
    """Collect identity/runtime posture and optional tag-schema inventory."""
    ip = str(ipaddress.ip_address(str(target).strip()))
    path = f"{ip}/{int(slot)}" if slot is not None else ip
    observed_at = datetime.now(timezone.utc).isoformat()

    try:
        if driver_factory is None:
            from pycomm3 import LogixDriver

            driver_factory = LogixDriver

        driver = driver_factory(
            path,
            init_tags=False,
            init_program_tags=False,
        )
        driver.socket_timeout = max(1.0, min(float(socket_timeout), 30.0))

        with driver as plc:
            info = dict(plc.info or {})
            tag_inventory = None
            if include_program_inventory:
                # Explicit opt-in. This uploads schemas, never tag values.
                tags = list(plc.get_tag_list(program="*", cache=False) or [])
                # The upload populates programs, tasks, and modules in plc.info.
                info = dict(plc.info or info)
                tag_inventory = _inventory(info, tags, max_stored_tags)

        keyswitch = classify_keyswitch(info.get("keyswitch"))
        result = {
            "target": ip,
            "path": path,
            "reachable": True,
            "unauthenticated_read": True,
            "read_only": True,
            "inventory_included": include_program_inventory,
            "vendor": _string(info.get("vendor"), 200),
            "product_type": _string(info.get("product_type"), 200),
            "product_code": info.get("product_code"),
            "product_name": _string(
                info.get("product_name") or info.get("device_type"), 300
            ),
            "revision": normalize_revision(info),
            "serial": _string(info.get("serial"), 200),
            "status": _string(info.get("status"), 200),
            "project_name": _string(info.get("name"), 300),
            "observed_at": observed_at,
            **keyswitch,
        }
        if tag_inventory is not None:
            result.update(tag_inventory)
        return result
    except Exception as exc:
        return {
            "target": ip,
            "path": path,
            "reachable": False,
            "unauthenticated_read": False,
            "read_only": True,
            "inventory_included": include_program_inventory,
            "observed_at": observed_at,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        }


def detect_observation_changes(previous: Optional[dict], current: dict) -> list[dict]:
    """Return material runtime/identity changes from a previous successful read."""
    if not previous or not previous.get("reachable") or not current.get("reachable"):
        return []
    changes = []
    for field in CHANGE_FIELDS:
        before = previous.get(field)
        after = current.get(field)
        if before is not None and after is not None and before != after:
            changes.append({"field": field, "before": before, "after": after})
    return changes


def select_logix_candidates(
    port_results: Iterable[Any],
    *,
    require_identity_evidence: bool = True,
    max_hosts: int = 10,
) -> list[str]:
    """Select Logix candidates from successful EtherNet/IP scan evidence."""
    if max_hosts <= 0:
        return []

    candidates = []
    seen = set()
    for result in port_results:
        if int(getattr(result, "port", 0) or 0) != LOGIX_PORT:
            continue
        if str(getattr(result, "state", "")).lower() != "open":
            continue

        scripts = getattr(result, "script_results", None) or {}
        evidence = " ".join(
            str(value)
            for value in (
                getattr(result, "service_name", None),
                getattr(result, "service_product", None),
                getattr(result, "service_version", None),
                scripts,
            )
            if value is not None
        ).lower()
        if require_identity_evidence and not any(
            marker in evidence for marker in LOGIX_IDENTITY_MARKERS
        ):
            continue

        raw_host = getattr(result, "ip", None) or getattr(result, "host", None)
        try:
            host = str(ipaddress.ip_address(str(raw_host)))
        except ValueError:
            continue
        if host not in seen:
            seen.add(host)
            candidates.append(host)
        if len(candidates) >= max(0, max_hosts):
            break
    return candidates
