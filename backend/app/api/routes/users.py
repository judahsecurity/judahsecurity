"""User management routes."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserUpdate, UserResponse
from app.core.security import get_password_hash
from app.api.deps import get_current_active_user, require_admin

router = APIRouter(prefix="/users", tags=["Users"])


@router.get("/", response_model=List[UserResponse])
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """List users. Superusers see all users; org admins see only users in their own org."""
    query = db.query(User)
    if not current_user.is_superuser:
        # Org-level admins are scoped to their own organization
        if current_user.organization_id:
            query = query.filter(User.organization_id == current_user.organization_id)
        else:
            return []
    users = query.offset(skip).limit(limit).all()
    return users


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new user (admin only)."""
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username already exists
    existing_username = db.query(User).filter(User.username == user_data.username).first()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Create new user. The initial password is treated as temporary by default,
    # forcing the user to set their own password on first login.
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
        organization_id=user_data.organization_id,
        is_active=True,
        is_superuser=False,
        must_change_password=user_data.must_change_password,
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    from app.services.platform_audit import record as audit

    audit("user.create", user=current_user, organization_id=new_user.organization_id,
          target=new_user.email or new_user.username or str(new_user.id),
          detail={"user_id": new_user.id, "role": getattr(new_user.role, "value", new_user.role)})
    return new_user


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user by ID. Users see themselves; org admins see users in their own org; superusers see all."""
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    if current_user.id != user_id:
        if current_user.is_superuser:
            pass  # full access
        elif current_user.role.value == "admin" and current_user.organization_id:
            # Org admins can only see users within their own organization
            if user.organization_id != current_user.organization_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied"
            )

    return user


@router.put("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_data: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update user. Users update themselves; org admins update users in their own org; superusers update all."""
    is_superuser = current_user.is_superuser
    is_org_admin = (not is_superuser and current_user.role.value == "admin")
    is_self = current_user.id == user_id

    # Fetch target user first so we can check org membership
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if not is_superuser and not is_self:
        if is_org_admin and current_user.organization_id:
            # Org admins can only modify users within their own organization
            if user.organization_id != current_user.organization_id:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # Non-superusers (including org admins) cannot change role, active status, or org membership
    if not is_superuser:
        user_data.role = None
        user_data.is_active = None
        user_data.organization_id = None

    # Update fields
    update_data = user_data.model_dump(exclude_unset=True)

    # Hash password if being updated
    if "password" in update_data and update_data["password"]:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    elif "password" in update_data:
        del update_data["password"]

    for field, value in update_data.items():
        setattr(user, field, value)

    db.commit()
    db.refresh(user)
    from app.services.platform_audit import record as audit

    changed = {k: getattr(v, "value", v) for k, v in update_data.items()
               if k not in ("password", "hashed_password")}
    if "hashed_password" in update_data or "password" in getattr(user_data, "model_fields_set", set()):
        changed["password"] = "changed"
    audit("user.update", user=current_user, organization_id=user.organization_id,
          target=user.email or user.username or str(user.id),
          detail={"user_id": user.id, "changed": changed})
    return user


@router.post("/{user_id}/force-password-reset", response_model=UserResponse)
def force_password_reset(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Force a user to set a new password on their next request (admin only).

    Sets must_change_password=True. Because the auth dependency re-checks this
    flag from the database on every request, any active session is immediately
    gated (403 password_change_required) until the user changes their password —
    no token revocation needed. The user's existing password still works for the
    change-password step.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user.must_change_password = True
    db.add(user)
    db.commit()
    db.refresh(user)
    from app.services.platform_audit import record as audit

    audit("user.force_password_reset", user=current_user, organization_id=user.organization_id,
          target=user.email or user.username or str(user.id), detail={"user_id": user.id})
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete user (admin only)."""
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete yourself"
        )
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    target = user.email or user.username or str(user.id)
    org_id = user.organization_id
    db.delete(user)
    db.commit()
    from app.services.platform_audit import record as audit

    audit("user.delete", user=current_user, organization_id=org_id, target=target,
          detail={"user_id": user_id})
    return None

















