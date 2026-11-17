"""Pre-registered engagement identities: durable, approved, host-scoped.

The restart snapshot drops live credentials on purpose, so an authz hypothesis
or a resumed run would idle waiting for an operator to re-enter working creds.
These helpers let the autonomy turn re-hydrate operator-approved identities from
``agent_engagement_identities`` into the in-memory engagement brain — but only
for identity labels the run's limits authorize (``allowed_identities``) and only
for hosts in scope. Secrets never return to the snapshot; they live encrypted in
the durable table and are decrypted into brain memory for the turn alone.
"""

from __future__ import annotations

from typing import Any, Iterable

from app.services.agent.recon_observation_adapter import _allowed

# An identity label that grants no durable secret; never loaded from the table.
_ANONYMOUS = "anonymous"


def select_authorized_identities(
    rows: Iterable[Any],
    allowed_identities: Iterable[str],
    scope_hosts: Iterable[str],
) -> list[Any]:
    """Filter pre-registered rows to those this run may actually use.

    An identity is usable when it is enabled, its label is explicitly authorized
    by the run's limits (and is not the anonymous pseudo-identity), and at least
    one of its ``valid_on`` hosts is in scope. An empty ``valid_on`` means "any
    host this run is already scoped to", so it is usable only when the run has a
    non-empty host scope. Pure function: no DB, no decryption.
    """
    authorized = {
        str(label) for label in (allowed_identities or ())
        if isinstance(label, str) and label and label != _ANONYMOUS
    }
    scope = [str(h) for h in (scope_hosts or ()) if isinstance(h, str) and h]
    if not authorized or not scope:
        return []
    selected: list[Any] = []
    for row in rows:
        if not getattr(row, "enabled", False):
            continue
        if str(getattr(row, "label", "") or "") not in authorized:
            continue
        valid_on = [str(h) for h in (getattr(row, "valid_on", None) or []) if isinstance(h, str) and h]
        if valid_on and not any(_allowed(host, scope) for host in valid_on):
            continue
        selected.append(row)
    return selected


def register_engagement_identity(
    db: Any,
    *,
    organization_id: int,
    label: str,
    secret: str,
    username: str = "",
    secret_type: str = "password",
    valid_on: list[str] | None = None,
    login_url: str = "",
    schedule_id: int | None = None,
    approved_by: int | None = None,
    notes: str = "",
    enabled: bool = True,
) -> Any:
    """Create or update an operator-approved identity (secret encrypted at rest).

    Upserts on ``(organization_id, schedule_id, label)`` so re-registering the
    same identity rotates its secret rather than duplicating it.
    """
    from app.models.agent_engagement_identity import AgentEngagementIdentity

    if not label or not secret:
        raise ValueError("label and secret are required")
    row = (
        db.query(AgentEngagementIdentity)
        .filter(
            AgentEngagementIdentity.organization_id == organization_id,
            AgentEngagementIdentity.schedule_id == schedule_id,
            AgentEngagementIdentity.label == label,
        )
        .one_or_none()
    )
    if row is None:
        row = AgentEngagementIdentity(
            organization_id=organization_id, schedule_id=schedule_id, label=label,
        )
        db.add(row)
    row.username = username or ""
    row.secret = secret  # encrypts via the model property
    row.secret_type = secret_type or "password"
    row.valid_on = list(valid_on or [])
    row.login_url = login_url or ""
    row.enabled = bool(enabled)
    if approved_by is not None:
        row.approved_by = approved_by
    row.notes = notes or ""
    db.commit()
    db.refresh(row)
    return row


def load_engagement_credentials(
    db: Any,
    organization_id: int,
    allowed_identities: Iterable[str],
    scope_hosts: Iterable[str],
) -> list[Any]:
    """Return ``CredentialRecord``s for the approved, in-scope identities.

    Decryption happens here, once, into transient brain memory. Returns an empty
    list when nothing is authorized or in scope.
    """
    from app.models.agent_engagement_identity import AgentEngagementIdentity
    from app.services.agent.engagement_brain import CredentialRecord

    authorized = {
        str(label) for label in (allowed_identities or ())
        if isinstance(label, str) and label and label != _ANONYMOUS
    }
    if not authorized:
        return []
    rows = (
        db.query(AgentEngagementIdentity)
        .filter(
            AgentEngagementIdentity.organization_id == organization_id,
            AgentEngagementIdentity.enabled.is_(True),
            AgentEngagementIdentity.label.in_(authorized),
        )
        .all()
    )
    creds: list[Any] = []
    for row in select_authorized_identities(rows, authorized, scope_hosts):
        try:
            secret = row.secret
        except Exception:
            continue
        if not secret:
            continue
        creds.append(CredentialRecord(
            username=row.username or row.label,
            secret=secret,
            secret_type=row.secret_type or "password",
            source="pre_registered",
            valid_on=list(row.valid_on or []),
            notes=row.notes or "",
        ))
    return creds


def apply_pre_registered_identities(brain: Any, creds: list[Any]) -> int:
    """Hydrate approved identities into the brain's credential list, idempotently.

    Returns the number newly added. Also clears the restart "register identities
    again" idle note once creds are present, so an authz hypothesis stops waiting.
    """
    if not creds:
        return 0
    existing = {
        (getattr(c, "username", ""), getattr(c, "secret", ""))
        for c in (getattr(brain, "credentials", None) or [])
    }
    added = 0
    for cred in creds:
        key = (getattr(cred, "username", ""), getattr(cred, "secret", ""))
        if key in existing:
            continue
        brain.credentials.append(cred)
        existing.add(key)
        added += 1
    if added:
        notes = [
            note for note in (getattr(brain, "notes", None) or [])
            if "register identities again" not in str(note)
        ]
        brain.notes = notes
    return added
