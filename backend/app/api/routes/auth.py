"""Authentication routes."""

from datetime import datetime
from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User, UserRole
from app.schemas.user import UserCreate, UserResponse, UserLogin, PasswordChange
from app.schemas.token import Token
from app.core.config import settings
from app.core.captcha import verify_captcha
from app.core.rate_limit import limiter
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token
)
from app.api.deps import get_current_active_user, get_current_user_active_only

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/config")
def auth_config():
    """Public auth configuration for the frontend (no secrets).

    Lets the login/register UI decide whether to render a CAPTCHA widget and
    which provider/site key to use.
    """
    return {
        "captcha": {
            "enabled": bool(settings.CAPTCHA_ENABLED and settings.CAPTCHA_SITE_KEY),
            "provider": settings.CAPTCHA_PROVIDER,
            "site_key": settings.CAPTCHA_SITE_KEY,
        },
        "public_registration": settings.ALLOW_PUBLIC_REGISTRATION,
    }


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.RATE_LIMIT_REGISTER)
def register_user(request: Request, user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user.

    Public self-registration is disabled unless ALLOW_PUBLIC_REGISTRATION is set.
    When disabled, admins provision accounts via POST /users/.
    """
    if not settings.ALLOW_PUBLIC_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled. Contact an administrator for an account."
        )

    # Bot / abuse protection (no-op unless CAPTCHA is configured)
    verify_captcha(
        request.headers.get("x-captcha-token"),
        remote_ip=request.client.host if request.client else None,
    )

    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email or username already exists"
        )
    
    # Create new user. Public registration cannot set role or organization — only admins via POST /users/ can.
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.full_name,
        role=UserRole.VIEWER,
        organization_id=None,
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return new_user


@router.post("/login", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT tokens."""
    # Bot / brute-force protection (no-op unless CAPTCHA is configured)
    verify_captcha(
        request.headers.get("x-captcha-token"),
        remote_ip=request.client.host if request.client else None,
    )

    # Find user by username OR email (for flexibility)
    user = db.query(User).filter(
        (User.username == form_data.username) | (User.email == form_data.username)
    ).first()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )

    # Ensure username is populated for JWT subject; fallback to email if missing
    if not user.username:
        # Backfill username with email to keep tokens consistent
        user.username = user.email
        db.add(user)
        db.commit()
        db.refresh(user)
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Create tokens
    subject = user.username or user.email
    access_token = create_access_token(data={"sub": subject})
    refresh_token = create_refresh_token(data={"sub": subject})
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh", response_model=Token)
@limiter.limit(settings.RATE_LIMIT_REFRESH)
def refresh_token(request: Request, refresh_token: str = Body(..., embed=True), db: Session = Depends(get_db)):
    """Refresh access token using refresh token."""
    payload = decode_token(refresh_token)
    
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    username = payload.get("sub")
    user = db.query(User).filter(
        (User.username == username) | (User.email == username)
    ).first()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user"
        )
    
    # Create new tokens
    new_access_token = create_access_token(data={"sub": user.username})
    new_refresh_token = create_refresh_token(data={"sub": user.username})
    
    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_info(current_user: User = Depends(get_current_user_active_only)):
    """Get current user information.

    Uses the non-gated dependency so a user pending a forced password change can
    still read their own profile (and see must_change_password) to drive the UI.
    """
    return current_user


@router.post("/change-password", response_model=UserResponse)
def change_password(
    payload: PasswordChange,
    current_user: User = Depends(get_current_user_active_only),
    db: Session = Depends(get_db),
):
    """Change the authenticated user's password and clear the reset flag.

    Reachable while must_change_password is set (uses the non-gated dependency),
    which is exactly the flow that lifts the gate.
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    if verify_password(payload.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password",
        )

    current_user.hashed_password = get_password_hash(payload.new_password)
    current_user.must_change_password = False
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user


@router.post("/logout")
def logout(current_user: User = Depends(get_current_user_active_only)):
    """Logout current user (client should discard tokens)."""
    # In a production system, you might want to blacklist the token
    return {"message": "Successfully logged out"}




