"""
Credential profiles and secret stores for agentless host checks.

  GET    /host-credentials                      stores + profiles for the screen
  POST   /host-credentials/stores               add a vault connection
  PUT    /host-credentials/stores/{id}
  DELETE /host-credentials/stores/{id}          refused while a profile uses it
  POST   /host-credentials/stores/{id}/test     authenticate to the vault
  POST   /host-credentials/profiles             add a credential profile
  PUT    /host-credentials/profiles/{id}
  DELETE /host-credentials/profiles/{id}
  POST   /host-credentials/profiles/{id}/test   fetch the secret; optionally log in to one asset

Secrets are write-only: responses report ``has_secret`` and never the value.
Writes and tests need the admin role; reading needs analyst.
"""

import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin, require_analyst
from app.models.asset import Asset
from app.models.host_credential import HostCredentialProfile, HostSecretStore
from app.models.user import User
from app.services import host_evidence_service as hes
from app.services import secret_stores

router = APIRouter(prefix="/host-credentials", tags=["host-credentials"])

STORE_CONFIG_KEYS = {
    "hashicorp_vault": {"address", "namespace", "auth_method", "role_id", "approle_mount", "kv_mount", "kv_version", "ca_cert"},
    "aws_secrets_manager": {"region", "role_arn", "external_id"},
    "cyberark_ccp": {"url", "app_id", "ca_cert", "client_cert"},
}
STORE_REQUIRED = {
    "hashicorp_vault": ("address",),
    "aws_secrets_manager": ("region",),
    "cyberark_ccp": ("url", "app_id"),
}
SECRET_REF_KEYS = {
    "hashicorp_vault": {"path", "key"},
    "aws_secrets_manager": {"secret_id", "key", "version_stage"},
    "cyberark_ccp": {"safe", "object"},
}
SECRET_REF_REQUIRED = {"hashicorp_vault": ("path",), "aws_secrets_manager": ("secret_id",), "cyberark_ccp": ("safe", "object")}
OPTION_KEYS = {
    "ssh": {"auth", "port", "known_hosts", "trust_on_first_use", "sudo"},
    "winrm": {"transport", "port", "https", "ca_cert"},
}
_HOST_GLOB = re.compile(r"^(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9*-]+)*$|^[A-Za-z0-9*?.-]+$")


def _org(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


def _now() -> datetime:
    return datetime.utcnow()


# ── Validation ───────────────────────────────────────────────────────────────

def _validate_targets(targets: List[str]) -> List[str]:
    """CIDRs (no broader than /8 IPv4, /32 IPv6) or hostname globs; never
    a match-everything entry."""
    out = []
    for raw in targets:
        t = str(raw).strip().lower()
        if not t:
            continue
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.prefixlen < (8 if net.version == 4 else 32):
                raise HTTPException(status_code=422, detail=f"target {t} is too broad; use /8 or narrower (/32 for IPv6)")
            out.append(str(net))
            continue
        except ValueError:
            pass
        if t in ("*", "*.*", "?") or t.replace("*", "").replace(".", "").replace("?", "") == "" or not _HOST_GLOB.match(t):
            raise HTTPException(status_code=422, detail=f"target {raw!r} must be a CIDR or a hostname pattern like *.corp.example")
        out.append(t)
    if not out:
        raise HTTPException(status_code=422, detail="at least one target is required; only matching servers are ever contacted")
    return sorted(set(out), key=out.index)


def _validate_store_config(provider: str, config: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(config) - STORE_CONFIG_KEYS[provider]
    if unknown:
        raise HTTPException(status_code=422, detail=f"unsupported settings for {provider}: {', '.join(sorted(unknown))}")
    clean = {k: v for k, v in config.items() if v not in (None, "")}
    missing = [k for k in STORE_REQUIRED[provider] if not clean.get(k)]
    if missing:
        raise HTTPException(status_code=422, detail=f"{provider} needs: {', '.join(missing)}")
    for key in ("address", "url"):
        if key in clean and not str(clean[key]).startswith("https://"):
            raise HTTPException(status_code=422, detail=f"{key} must start with https://")
    if provider == "hashicorp_vault":
        if clean.get("auth_method", "token") not in ("token", "approle"):
            raise HTTPException(status_code=422, detail="auth_method must be token or approle")
        if clean.get("auth_method") == "approle" and not clean.get("role_id"):
            raise HTTPException(status_code=422, detail="AppRole needs role_id")
        if str(clean.get("kv_version", "2")) not in ("1", "2"):
            raise HTTPException(status_code=422, detail="kv_version must be 1 or 2")
    for key in ("ca_cert", "client_cert"):
        if key in clean and "PRIVATE KEY" in str(clean[key]):
            raise HTTPException(status_code=422, detail=f"{key} must be a certificate; put private keys in the secret field")
    return clean


def _validate_options(kind: str, options: Dict[str, Any]) -> Dict[str, Any]:
    unknown = set(options) - OPTION_KEYS[kind]
    if unknown:
        raise HTTPException(status_code=422, detail=f"unsupported {kind} options: {', '.join(sorted(unknown))}")
    clean = {k: v for k, v in options.items() if v not in (None, "")}
    if "port" in clean and not (isinstance(clean["port"], int) and 0 < clean["port"] < 65536):
        raise HTTPException(status_code=422, detail="port must be 1-65535")
    if kind == "ssh" and clean.get("auth", "key") not in ("key", "password"):
        raise HTTPException(status_code=422, detail="auth must be key or password")
    if kind == "winrm" and clean.get("transport", "ntlm") not in ("ntlm", "kerberos"):
        raise HTTPException(status_code=422, detail="transport must be ntlm or kerberos")
    return clean


# ── Schemas ──────────────────────────────────────────────────────────────────

Provider = Literal["hashicorp_vault", "aws_secrets_manager", "cyberark_ccp"]


class StoreIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    provider: Provider
    config: Dict[str, Any] = Field(default_factory=dict)
    secret: Optional[str] = Field(None, description="Vault token or AppRole secret ID; CyberArk client private key")
    is_active: bool = True


class StoreUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    config: Optional[Dict[str, Any]] = None
    secret: Optional[str] = Field(None, description="Leave out to keep the current secret; empty string clears it")
    is_active: Optional[bool] = None


class ProfileIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    kind: Literal["ssh", "winrm"]
    username: str = Field("", max_length=255)
    secret_source: Literal["stored", "store"] = "stored"
    secret: Optional[str] = Field(None, description="Password or private key when secret_source is stored")
    secret_store_id: Optional[int] = None
    secret_ref: Dict[str, Any] = Field(default_factory=dict)
    targets: List[str] = Field(..., min_length=1, max_length=500)
    priority: int = Field(100, ge=0, le=1000)
    options: Dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class ProfileUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    username: Optional[str] = Field(None, max_length=255)
    secret_source: Optional[Literal["stored", "store"]] = None
    secret: Optional[str] = None
    secret_store_id: Optional[int] = None
    secret_ref: Optional[Dict[str, Any]] = None
    targets: Optional[List[str]] = Field(None, min_length=1, max_length=500)
    priority: Optional[int] = Field(None, ge=0, le=1000)
    options: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class ProfileTestIn(BaseModel):
    asset_id: Optional[int] = Field(None, description="Also log in to this asset (it must match the profile's targets)")


def _store_out(store: HostSecretStore, in_use: int) -> Dict[str, Any]:
    return {
        "id": store.id, "name": store.name, "provider": store.provider, "config": store.config or {},
        "has_secret": bool(store.secret_encrypted), "is_active": store.is_active, "in_use": in_use,
        "last_tested_at": store.last_tested_at, "last_test_ok": store.last_test_ok, "last_error": store.last_error,
        "created_at": store.created_at, "updated_at": store.updated_at,
    }


def _profile_out(p: HostCredentialProfile, store: Optional[HostSecretStore]) -> Dict[str, Any]:
    return {
        "id": p.id, "name": p.name, "kind": p.kind, "username": p.username, "secret_source": p.secret_source,
        "has_secret": bool(p.secret_encrypted) if p.secret_source == "stored" else store is not None,
        "secret_store_id": p.secret_store_id, "secret_store_name": store.name if store else None,
        "secret_store_provider": store.provider if store else None, "secret_ref": p.secret_ref or {},
        "targets": p.targets or [], "priority": p.priority, "options": p.options or {}, "is_active": p.is_active,
        "last_tested_at": p.last_tested_at, "last_test_ok": p.last_test_ok, "last_error": p.last_error,
        "created_at": p.created_at, "updated_at": p.updated_at,
    }


def _get_store(db: Session, org: int, store_id: int) -> HostSecretStore:
    store = db.query(HostSecretStore).filter_by(id=store_id, organization_id=org).first()
    if store is None:
        raise HTTPException(status_code=404, detail="Secret store not found")
    return store


def _get_profile(db: Session, org: int, profile_id: int) -> HostCredentialProfile:
    p = db.query(HostCredentialProfile).filter_by(id=profile_id, organization_id=org).first()
    if p is None:
        raise HTTPException(status_code=404, detail="Credential profile not found")
    return p


def _check_secret_settings(db: Session, org: int, p: HostCredentialProfile) -> Optional[HostSecretStore]:
    if p.secret_source == "store":
        if not p.secret_store_id:
            raise HTTPException(status_code=422, detail="choose the secret store this profile reads from")
        store = _get_store(db, org, p.secret_store_id)
        ref = p.secret_ref or {}
        unknown = set(ref) - SECRET_REF_KEYS[store.provider]
        if unknown:
            raise HTTPException(status_code=422, detail=f"unsupported secret reference fields: {', '.join(sorted(unknown))}")
        missing = [k for k in SECRET_REF_REQUIRED[store.provider] if not str(ref.get(k) or "").strip()]
        if missing:
            raise HTTPException(status_code=422, detail=f"secret reference needs: {', '.join(missing)}")
        if store.provider != "cyberark_ccp" and not p.username:
            raise HTTPException(status_code=422, detail="username is required (only CyberArk can supply it)")
        p.secret_encrypted = None  # never keep a stale stored secret alongside a vault reference
        return store
    p.secret_store_id, p.secret_ref = None, {}
    if not p.username:
        raise HTTPException(status_code=422, detail="username is required")
    if not p.secret_encrypted:
        raise HTTPException(status_code=422, detail="a password or private key is required")
    return None


def _unique_name(db: Session, model: Any, org: int, name: str, current_id: Optional[int] = None) -> None:
    q = db.query(model).filter(model.organization_id == org, model.name == name)
    if current_id is not None:
        q = q.filter(model.id != current_id)
    if q.first():
        raise HTTPException(status_code=409, detail=f"a {'profile' if model is HostCredentialProfile else 'secret store'} named {name!r} already exists")


# ── Routes ───────────────────────────────────────────────────────────────────

@router.get("")
def list_all(db: Session = Depends(get_db), user: User = Depends(require_analyst)) -> Dict[str, Any]:
    org = _org(user)
    stores = db.query(HostSecretStore).filter_by(organization_id=org).order_by(HostSecretStore.name).all()
    profiles = db.query(HostCredentialProfile).filter_by(organization_id=org).order_by(
        HostCredentialProfile.priority, HostCredentialProfile.id).all()
    by_id = {s.id: s for s in stores}
    use = {s.id: sum(1 for p in profiles if p.secret_store_id == s.id) for s in stores}
    return {"stores": [_store_out(s, use[s.id]) for s in stores],
            "profiles": [_profile_out(p, by_id.get(p.secret_store_id)) for p in profiles]}


@router.post("/stores", status_code=201)
def create_store(body: StoreIn, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Dict[str, Any]:
    org = _org(user)
    _unique_name(db, HostSecretStore, org, body.name)
    store = HostSecretStore(organization_id=org, name=body.name, provider=body.provider,
                            config=_validate_store_config(body.provider, body.config), is_active=body.is_active)
    store.set_secret(body.secret or "")
    db.add(store)
    db.commit()
    db.refresh(store)
    return _store_out(store, 0)


@router.put("/stores/{store_id}")
def update_store(store_id: int, body: StoreUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Dict[str, Any]:
    org = _org(user)
    store = _get_store(db, org, store_id)
    if body.name is not None:
        _unique_name(db, HostSecretStore, org, body.name, store.id)
        store.name = body.name
    if body.config is not None:
        store.config = _validate_store_config(store.provider, body.config)
    if body.secret is not None:
        store.set_secret(body.secret)
    if body.is_active is not None:
        store.is_active = body.is_active
    db.commit()
    db.refresh(store)
    return _store_out(store, db.query(HostCredentialProfile).filter_by(secret_store_id=store.id).count())


@router.delete("/stores/{store_id}", status_code=204)
def delete_store(store_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> None:
    store = _get_store(db, _org(user), store_id)
    used = db.query(HostCredentialProfile).filter_by(secret_store_id=store.id).count()
    if used:
        raise HTTPException(status_code=409, detail=f"{used} credential profile(s) read from this store; change them first")
    db.delete(store)
    db.commit()


@router.post("/stores/{store_id}/test")
def test_store(store_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Dict[str, Any]:
    store = _get_store(db, _org(user), store_id)
    try:
        message, ok = secret_stores.test_store(store), True
    except secret_stores.SecretStoreError as e:
        message, ok = str(e), False
    store.last_tested_at, store.last_test_ok, store.last_error = _now(), ok, None if ok else message
    db.commit()
    return {"ok": ok, "message": message}


def _apply_profile(db: Session, org: int, p: HostCredentialProfile, data: Dict[str, Any]) -> None:
    if "name" in data:
        _unique_name(db, HostCredentialProfile, org, data["name"], p.id)
        p.name = data["name"]
    for field in ("username", "secret_source", "secret_store_id", "secret_ref", "priority", "is_active"):
        if field in data:
            setattr(p, field, data[field] if data[field] is not None else getattr(p, field))
    if "targets" in data:
        p.targets = _validate_targets(data["targets"])
    if "options" in data:
        p.options = _validate_options(p.kind, data["options"] or {})
    if data.get("secret") is not None:
        p.set_secret(data["secret"])
    p.username = (p.username or "").strip()
    _check_secret_settings(db, org, p)


@router.post("/profiles", status_code=201)
def create_profile(body: ProfileIn, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Dict[str, Any]:
    org = _org(user)
    p = HostCredentialProfile(organization_id=org, kind=body.kind, name=body.name)
    _apply_profile(db, org, p, body.model_dump())
    db.add(p)
    db.commit()
    db.refresh(p)
    return _profile_out(p, db.get(HostSecretStore, p.secret_store_id) if p.secret_store_id else None)


@router.put("/profiles/{profile_id}")
def update_profile(profile_id: int, body: ProfileUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> Dict[str, Any]:
    org = _org(user)
    p = _get_profile(db, org, profile_id)
    try:
        _apply_profile(db, org, p, body.model_dump(exclude_unset=True))
    except HTTPException:
        db.rollback()
        raise
    db.commit()
    db.refresh(p)
    return _profile_out(p, db.get(HostSecretStore, p.secret_store_id) if p.secret_store_id else None)


@router.delete("/profiles/{profile_id}", status_code=204)
def delete_profile(profile_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> None:
    p = _get_profile(db, _org(user), profile_id)
    db.delete(p)
    db.commit()


def _runner_for(asset: Any, cred: "hes.HostCredential") -> "hes.CommandRunner":  # replaced in tests
    if cred.kind == "winrm":
        from app.services.winrm_host_evidence import WinRMRunner

        return WinRMRunner(hes.asset_address(asset), cred)
    return hes.SSHRunner(hes.asset_address(asset), cred, hes._stored(asset).get("host_key", ""))


@router.post("/profiles/{profile_id}/test")
def test_profile(profile_id: int, body: Optional[ProfileTestIn] = None, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)) -> Dict[str, Any]:
    """Fetch the profile's secret (from Judah or the vault). With an asset,
    also log in and log out — no probes run."""
    org = _org(user)
    body = body or ProfileTestIn()
    p = _get_profile(db, org, profile_id)
    store = db.get(HostSecretStore, p.secret_store_id) if p.secret_store_id else None
    cred = hes.HostCredential.from_profile(p, store)
    steps: List[str] = []
    ok = True
    try:
        cred = cred.with_secret()
        steps.append(f"Fetched the credential for {cred.username!r} from "
                     f"{'Judah' if p.secret_source == 'stored' else store.name if store else 'the vault'}.")
        if body.asset_id is not None:
            asset = db.query(Asset).filter_by(id=body.asset_id, organization_id=org).first()
            if asset is None:
                raise HTTPException(status_code=404, detail="Asset not found")
            if not hes.in_target_scope(asset, cred.targets):
                raise HTTPException(status_code=400, detail="that asset is not in this profile's targets")
            runner = _runner_for(asset, cred)
            runner.close()
            steps.append(f"Logged in to {hes.asset_address(asset)} over {cred.kind.upper()}.")
    except secret_stores.SecretStoreError as e:
        ok = False
        steps.append(f"Could not fetch the credential: {e}")
    except hes.HostCheckError as e:
        ok = False
        steps.append(f"Login failed: {e}")
    p.last_tested_at, p.last_test_ok, p.last_error = _now(), ok, None if ok else steps[-1]
    db.commit()
    return {"ok": ok, "message": " ".join(steps)}
