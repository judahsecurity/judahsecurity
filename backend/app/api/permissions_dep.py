"""App-wide permission enforcement for users with a custom role."""

from __future__ import annotations

from fastapi import HTTPException, status
from starlette.requests import HTTPConnection

from app.core.config import settings
from app.core.permissions import effective_permissions, route_permission


def enforce_route_permission(request: HTTPConnection) -> None:
    if request.scope.get("type") != "http":
        return  # websockets authenticate in-band; agent_websocket checks agent.run
    permission = route_permission(request.scope.get("method", "GET"), request.url.path,
                                  settings.API_PREFIX)
    if permission is None:
        return
    auth = request.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        return  # the route's own auth dependency rejects the request
    from app.core.security import decode_token
    from app.db.database import SessionLocal
    from app.models.user import User

    payload = decode_token(auth.split(" ", 1)[1].strip())
    subject = (payload or {}).get("sub") if (payload or {}).get("type") == "access" else None
    if not subject:
        return
    with SessionLocal() as db:
        user = db.query(User).filter((User.username == subject) | (User.email == subject)).first()
        if user is None or not getattr(user, "custom_role_id", None) or user.is_superuser:
            return
        allowed = permission in effective_permissions(db, user)
        if not allowed:
            from app.services.platform_audit import record as audit

            audit("permission.denied", user=user, target=f"{request.scope.get('method')} {request.url.path}",
                  outcome="denied", detail={"permission": permission})
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail=f"Your role does not include '{permission}'")
