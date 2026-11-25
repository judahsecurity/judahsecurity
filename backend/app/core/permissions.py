"""Fine-grained permissions on top of the built-in admin/analyst/viewer roles.

Every user keeps a built-in role. An org admin can additionally assign a
*custom role* (``OrgRole``), whose permissions are intersected with the
built-in role's: a custom role can only take access away, never add it. Users
without a custom role are unaffected, so existing role checks stay valid.

Enforcement:

* ``enforce_route_permission`` — app-wide dependency mapping (method, path)
  to a permission; only consulted for users with a custom role.
* ``user_can`` — explicit checks (agent WebSocket, agent tools).
"""

from __future__ import annotations

import re
import time
from typing import Dict, FrozenSet, Iterable, Optional, Tuple

PERMISSIONS: Dict[str, str] = {
    "agent.run": "Start and steer AI agent runs",
    "agent.active_testing": "Let the agent run active tools (beyond read-only queries and light recon)",
    "agent.approve_tools": "Approve or deny the agent's pending tool calls",
    "scans.run": "Create, start, cancel and schedule scans",
    "assets.edit": "Add, edit, import and delete assets",
    "findings.edit": "Create, triage, edit and delete findings",
    "reports.export": "Export reports",
    "integrations.manage": "Configure integrations",
    "settings.edit": "Change organization settings",
    "users.manage": "Manage users and roles",
    "audit.read": "Read and export the audit log",
}

_ALL = frozenset(PERMISSIONS)
# What each built-in role can reach today through the existing route checks.
BUILTIN: Dict[str, FrozenSet[str]] = {
    "admin": _ALL,
    "analyst": _ALL - {"users.manage", "audit.read"},
    "viewer": frozenset({"agent.run", "agent.active_testing", "reports.export", "settings.edit"}),
}

# (methods, path regex below the API prefix) -> permission. First match wins.
ROUTE_PERMISSIONS: Tuple[Tuple[FrozenSet[str], "re.Pattern[str]", str], ...] = tuple(
    (frozenset(methods), re.compile(pattern), perm) for methods, pattern, perm in (
        ({"POST"}, r"^/agent/confirmations/[^/]+/decide$", "agent.approve_tools"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/agent/(query|approve|answer|scoped-assessments"
         r"|sessions/[^/]+/(steer|load|compact|stop|candidates))$", "agent.run"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/(scans|scan-schedules|schedules|scan-profiles)(/|$)",
         "scans.run"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/(assets|asset-inventory)(/|$)", "assets.edit"),
        ({"GET"}, r"^/asset-inventory/export$", "reports.export"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/(vulnerabilities|exceptions)(/|$)", "findings.edit"),
        ({"GET", "POST"}, r"^/reports/(assets/[^/]+/report|findings/report)$", "reports.export"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/integrations(/|$)", "integrations.manage"),
        ({"POST"}, r"^/credential-exposure/identities/sync(/|$)", "integrations.manage"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/credential-exposure(/|$)", "findings.edit"),
        ({"PUT", "POST", "PATCH", "DELETE"}, r"^/organizations/[^/]+/(settings|discovery-settings"
         r"|notifications)(/|$)", "settings.edit"),
        ({"POST", "PUT", "PATCH", "DELETE"}, r"^/(users|roles)(/|$)", "users.manage"),
        ({"GET"}, r"^/audit(/|$)", "audit.read"),
    )
)

_CACHE_TTL = 30.0
_cache: Dict[int, Tuple[float, Optional[FrozenSet[str]]]] = {}


def builtin_permissions(user) -> FrozenSet[str]:
    if getattr(user, "is_superuser", False):
        return _ALL
    role = getattr(getattr(user, "role", None), "value", getattr(user, "role", None))
    return BUILTIN.get(str(role or "viewer"), BUILTIN["viewer"])


def validate_permissions(names: Iterable[str]) -> list:
    names = sorted({str(n) for n in names or []})
    unknown = [n for n in names if n not in PERMISSIONS]
    if unknown:
        raise ValueError("Unknown permissions: " + ", ".join(unknown))
    return names


def _custom_permissions(db, user) -> Optional[FrozenSet[str]]:
    role_id = getattr(user, "custom_role_id", None)
    if not role_id:
        return None
    from app.models.org_role import OrgRole

    role = db.get(OrgRole, role_id)
    if role is None or role.organization_id != getattr(user, "organization_id", None):
        return frozenset()  # dangling or cross-org assignment: fail closed
    return frozenset(p for p in (role.permissions or []) if p in PERMISSIONS)


def effective_permissions(db, user) -> FrozenSet[str]:
    base = builtin_permissions(user)
    if getattr(user, "is_superuser", False) or not getattr(user, "custom_role_id", None):
        return base
    custom = _custom_permissions(db, user)
    return base if custom is None else base & custom


def user_can(user, permission: str, db=None) -> bool:
    """Cached check for hot paths (agent tools)."""
    if getattr(user, "is_superuser", False) or not getattr(user, "custom_role_id", None):
        return permission in builtin_permissions(user)
    key = int(getattr(user, "id", 0) or 0)
    hit = _cache.get(key)
    now = time.monotonic()
    if hit is None or now - hit[0] > _CACHE_TTL:
        if db is None:
            from app.db.database import SessionLocal

            with SessionLocal() as session:
                perms = effective_permissions(session, user)
        else:
            perms = effective_permissions(db, user)
        _cache[key] = (now, perms)
        hit = _cache[key]
    return permission in (hit[1] or frozenset())


_id_cache: Dict[int, Tuple[float, Optional[FrozenSet[str]]]] = {}


def user_id_restricted_from(user_id: int, permission: str) -> bool:
    """True when this user's custom role withholds ``permission`` (30 s cache).

    Users without a custom role return False (their built-in role's existing
    checks apply unchanged).
    """
    key = int(user_id)
    now = time.monotonic()
    hit = _id_cache.get(key)
    if hit is None or now - hit[0] > _CACHE_TTL:
        from app.db.database import SessionLocal
        from app.models.user import User

        with SessionLocal() as db:
            user = db.get(User, key)
            perms = (None if user is None or user.is_superuser or not user.custom_role_id
                     else effective_permissions(db, user))
        _id_cache[key] = (now, perms)
        hit = _id_cache[key]
    return hit[1] is not None and permission not in hit[1]


def clear_cache(user_id: Optional[int] = None) -> None:
    if user_id is None:
        _cache.clear()
        _id_cache.clear()
    else:
        _cache.pop(int(user_id), None)
        _id_cache.pop(int(user_id), None)


def route_permission(method: str, path: str, api_prefix: str = "") -> Optional[str]:
    if api_prefix and path.startswith(api_prefix):
        path = path[len(api_prefix):]
    for methods, pattern, permission in ROUTE_PERMISSIONS:
        if method.upper() in methods and pattern.search(path):
            return permission
    return None
