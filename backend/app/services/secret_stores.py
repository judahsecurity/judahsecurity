"""
Fetch host-check credentials from the customer's password vault at check
time, so Judah doesn't have to store server credentials.

Providers (all read-only; nothing is written to the vault):

  hashicorp_vault      KV v2 (default) or v1 read. Auth: token, or AppRole
                       (role_id in config, secret_id as the store secret).
                       Optional Enterprise namespace and CA certificate.
  aws_secrets_manager  GetSecretValue with the backend's own AWS identity
                       (e.g. the EC2 instance role), optionally assuming a
                       customer role (role_arn + external_id).
  cyberark_ccp         Central Credential Provider REST API
                       (GET /AIMWebService/api/Accounts) with the AppID,
                       optional client-certificate authentication and CA.

Errors are raised as SecretStoreError with text that never includes the
secret, the token, or a response body, so they can be shown to users and
recorded as "could not check" on findings.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

import httpx

HTTP_TIMEOUT = float(os.getenv("SECRET_STORE_TIMEOUT", "15"))
_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._/@+=,-]+$")


class SecretStoreError(RuntimeError):
    """Safe to show: no secrets, tokens or response bodies."""


@dataclass
class FetchedSecret:
    secret: str
    username: str = ""  # CyberArk returns the account name; others leave it to the profile


# Tests replace these to keep everything offline.
def _http_client(**kwargs: Any) -> httpx.Client:
    return httpx.Client(timeout=HTTP_TIMEOUT, **kwargs)


def _boto3_client(service: str, **kwargs: Any) -> Any:
    import boto3

    return boto3.client(service, **kwargs)


@contextmanager
def _pem_files(*pems: str) -> Iterator[Tuple[Optional[str], ...]]:
    paths = []
    try:
        for pem in pems:
            if pem:
                fd, path = tempfile.mkstemp(suffix=".pem")
                with os.fdopen(fd, "w") as fh:
                    fh.write(pem)
                os.chmod(path, 0o600)
                paths.append(path)
            else:
                paths.append(None)
        yield tuple(paths)
    finally:
        for path in paths:
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _https_url(url: str, label: str) -> str:
    url = (url or "").strip().rstrip("/")
    if not re.match(r"^https://[A-Za-z0-9.-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$", url):
        raise SecretStoreError(f"{label} must be an https:// URL")
    return url


def _ref(ref: Dict[str, Any], key: str, label: str, *, required: bool = True) -> str:
    value = str((ref or {}).get(key) or "").strip()
    if required and not value:
        raise SecretStoreError(f"{label} is required")
    if value and (not _SAFE_SEGMENT.match(value) or ".." in value.split("/") or "//" in value):
        raise SecretStoreError(f"{label} contains unsupported characters")
    return value


def _status_error(provider: str, response: httpx.Response) -> SecretStoreError:
    code = response.status_code
    hint = {401: "authentication failed", 403: "access denied by policy", 404: "secret not found"}.get(code, "request failed")
    return SecretStoreError(f"{provider}: {hint} (HTTP {code})")


def _pick_key(value: Any, key: str, provider: str) -> str:
    if not key:
        if isinstance(value, str):
            return value
        raise SecretStoreError(f"{provider}: the secret has several fields; set the key to read")
    if not isinstance(value, dict) or key not in value:
        raise SecretStoreError(f"{provider}: field {key!r} not found in the secret")
    picked = value[key]
    if not isinstance(picked, str) or not picked:
        raise SecretStoreError(f"{provider}: field {key!r} is empty or not text")
    return picked


# ── HashiCorp Vault ──────────────────────────────────────────────────────────

def _vault_session(config: Dict[str, Any], store_secret: str, client: httpx.Client) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if config.get("namespace"):
        headers["X-Vault-Namespace"] = _ref(config, "namespace", "Vault namespace")
    method = str(config.get("auth_method") or "token")
    base = _https_url(config.get("address", ""), "Vault address")
    if method == "token":
        if not store_secret:
            raise SecretStoreError("Vault token is not set")
        headers["X-Vault-Token"] = store_secret
    elif method == "approle":
        mount = _ref(config, "approle_mount", "AppRole mount", required=False) or "approle"
        role_id = _ref(config, "role_id", "AppRole role ID")
        if not store_secret:
            raise SecretStoreError("AppRole secret ID is not set")
        r = client.post(f"{base}/v1/auth/{mount}/login", json={"role_id": role_id, "secret_id": store_secret}, headers=headers)
        if r.status_code >= 400:
            raise _status_error("Vault AppRole login", r)
        token = ((r.json() or {}).get("auth") or {}).get("client_token")
        if not token:
            raise SecretStoreError("Vault AppRole login returned no token")
        headers["X-Vault-Token"] = token
    else:
        raise SecretStoreError("Vault auth method must be token or approle")
    return headers


def _vault_fetch(config: Dict[str, Any], store_secret: str, ref: Dict[str, Any]) -> FetchedSecret:
    base = _https_url(config.get("address", ""), "Vault address")
    mount = _ref(config, "kv_mount", "KV mount", required=False) or "secret"
    path = _ref(ref, "path", "Secret path").strip("/")
    key = _ref(ref, "key", "Secret key", required=False)
    v2 = str(config.get("kv_version") or "2") != "1"
    with _pem_files(config.get("ca_cert", "")) as (ca,):
        with _http_client(verify=ca or True) as client:
            headers = _vault_session(config, store_secret, client)
            url = f"{base}/v1/{mount}/data/{path}" if v2 else f"{base}/v1/{mount}/{path}"
            r = client.get(url, headers=headers)
    if r.status_code >= 400:
        raise _status_error("Vault read", r)
    data = (r.json() or {}).get("data") or {}
    if v2:
        data = data.get("data") or {}
    return FetchedSecret(secret=_pick_key(data, key, "Vault"))


def _vault_test(config: Dict[str, Any], store_secret: str) -> str:
    base = _https_url(config.get("address", ""), "Vault address")
    with _pem_files(config.get("ca_cert", "")) as (ca,):
        with _http_client(verify=ca or True) as client:
            headers = _vault_session(config, store_secret, client)
            r = client.get(f"{base}/v1/auth/token/lookup-self", headers=headers)
    if r.status_code >= 400:
        raise _status_error("Vault token lookup", r)
    policies = ((r.json() or {}).get("data") or {}).get("policies") or []
    return f"Authenticated to Vault (policies: {', '.join(map(str, policies)) or 'none'})."


# ── AWS Secrets Manager ──────────────────────────────────────────────────────

def _aws_kwargs(config: Dict[str, Any]) -> Dict[str, Any]:
    region = str(config.get("region") or "").strip()
    if not re.match(r"^[a-z]{2}(-gov)?-[a-z]+-\d$", region):
        raise SecretStoreError("AWS region is required, e.g. us-east-1")
    kwargs: Dict[str, Any] = {"region_name": region}
    role_arn = str(config.get("role_arn") or "").strip()
    if role_arn:
        if not re.match(r"^arn:aws[a-z-]*:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$", role_arn):
            raise SecretStoreError("AWS role ARN is not valid")
        params = {"RoleArn": role_arn, "RoleSessionName": "judah-host-evidence", "DurationSeconds": 900}
        if config.get("external_id"):
            params["ExternalId"] = str(config["external_id"])
        try:
            creds = _boto3_client("sts", region_name=region).assume_role(**params)["Credentials"]
        except Exception as e:
            raise SecretStoreError(f"AWS could not assume {role_arn}: {_aws_reason(e)}") from None
        kwargs.update(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                      aws_session_token=creds["SessionToken"])
    return kwargs


def _aws_reason(e: Exception) -> str:
    code = getattr(e, "response", {}).get("Error", {}).get("Code") if hasattr(e, "response") else None
    return code or type(e).__name__


def _aws_fetch(config: Dict[str, Any], ref: Dict[str, Any]) -> FetchedSecret:
    secret_id = str((ref or {}).get("secret_id") or "").strip()
    if not secret_id or not re.match(r"^[A-Za-z0-9/_+=.@:-]{1,2048}$", secret_id):
        raise SecretStoreError("AWS secret ID (name or ARN) is required")
    params: Dict[str, Any] = {"SecretId": secret_id}
    if ref.get("version_stage"):
        params["VersionStage"] = _ref(ref, "version_stage", "Version stage")
    try:
        resp = _boto3_client("secretsmanager", **_aws_kwargs(config)).get_secret_value(**params)
    except SecretStoreError:
        raise
    except Exception as e:
        raise SecretStoreError(f"AWS Secrets Manager: {_aws_reason(e)}") from None
    raw = resp.get("SecretString")
    if raw is None:
        raise SecretStoreError("AWS Secrets Manager: binary secrets are not supported")
    key = _ref(ref, "key", "Secret key", required=False)
    if not key:
        return FetchedSecret(secret=raw)
    try:
        value = json.loads(raw)
    except ValueError:
        raise SecretStoreError("AWS Secrets Manager: secret is not JSON, so no key can be read") from None
    return FetchedSecret(secret=_pick_key(value, key, "AWS Secrets Manager"))


def _aws_test(config: Dict[str, Any]) -> str:
    try:
        ident = _boto3_client("sts", **_aws_kwargs(config)).get_caller_identity()
    except SecretStoreError:
        raise
    except Exception as e:
        raise SecretStoreError(f"AWS identity check failed: {_aws_reason(e)}") from None
    return f"Using AWS identity {ident.get('Arn', 'unknown')}."


# ── CyberArk Central Credential Provider ─────────────────────────────────────

def _cyberark_fetch(config: Dict[str, Any], store_secret: str, ref: Dict[str, Any]) -> FetchedSecret:
    base = _https_url(config.get("url", ""), "CyberArk CCP URL")
    params = {"AppID": _ref(config, "app_id", "CyberArk AppID"),
              "Safe": _ref(ref, "safe", "Safe"), "Object": _ref(ref, "object", "Object")}
    client_cert = str(config.get("client_cert") or "")
    if bool(client_cert) != bool(store_secret):
        raise SecretStoreError("CyberArk client certificate and key must be set together")
    with _pem_files(config.get("ca_cert", ""), client_cert, store_secret) as (ca, cert, key):
        kwargs: Dict[str, Any] = {"verify": ca or True}
        if cert and key:
            kwargs["cert"] = (cert, key)
        with _http_client(**kwargs) as client:
            r = client.get(f"{base}/AIMWebService/api/Accounts", params=params, headers={"Accept": "application/json"})
    if r.status_code >= 400:
        raise _status_error("CyberArk CCP", r)
    body = r.json() or {}
    content = body.get("Content")
    if not isinstance(content, str) or not content:
        raise SecretStoreError("CyberArk CCP returned no credential content")
    return FetchedSecret(secret=content, username=str(body.get("UserName") or ""))


def _cyberark_test(config: Dict[str, Any], store_secret: str) -> str:
    _https_url(config.get("url", ""), "CyberArk CCP URL")
    _ref(config, "app_id", "CyberArk AppID")
    if bool(config.get("client_cert")) != bool(store_secret):
        raise SecretStoreError("CyberArk client certificate and key must be set together")
    return "Settings are valid. CyberArk has no credential-free check: test a profile to fetch its account."


# ── Public API ───────────────────────────────────────────────────────────────

_FETCH: Dict[str, Callable[..., FetchedSecret]] = {
    "hashicorp_vault": lambda c, s, r: _vault_fetch(c, s, r),
    "aws_secrets_manager": lambda c, s, r: _aws_fetch(c, r),
    "cyberark_ccp": lambda c, s, r: _cyberark_fetch(c, s, r),
}
_TEST: Dict[str, Callable[..., str]] = {
    "hashicorp_vault": lambda c, s: _vault_test(c, s),
    "aws_secrets_manager": lambda c, s: _aws_test(c),
    "cyberark_ccp": lambda c, s: _cyberark_test(c, s),
}


def _guard(fn: Callable[[], Any], provider: str) -> Any:
    try:
        return fn()
    except SecretStoreError:
        raise
    except httpx.HTTPError as e:
        raise SecretStoreError(f"{provider}: could not connect ({type(e).__name__})") from None
    except ValueError:
        raise SecretStoreError(f"{provider}: unexpected response") from None


def fetch_secret(store: Any, ref: Dict[str, Any]) -> FetchedSecret:
    if not getattr(store, "is_active", True):
        raise SecretStoreError(f"secret store {store.name!r} is disabled")
    fn = _FETCH.get(store.provider)
    if fn is None:
        raise SecretStoreError(f"unknown secret store provider {store.provider!r}")
    return _guard(lambda: fn(store.config or {}, store.get_secret(), ref or {}), store.provider)


def test_store(store: Any) -> str:
    fn = _TEST.get(store.provider)
    if fn is None:
        raise SecretStoreError(f"unknown secret store provider {store.provider!r}")
    return _guard(lambda: fn(store.config or {}, store.get_secret()), store.provider)


def resolve_profile_secret(profile: Any, store: Optional[Any]) -> Tuple[str, str]:
    """(username, secret) for a credential profile."""
    if profile.secret_source == "stored":
        secret = profile.get_secret()
        if not secret:
            raise SecretStoreError("profile has no stored secret")
        return profile.username, secret
    if store is None:
        raise SecretStoreError("profile's secret store no longer exists")
    fetched = fetch_secret(store, profile.secret_ref or {})
    username = profile.username or fetched.username
    if not username:
        raise SecretStoreError("no username: set one on the profile")
    return username, fetched.secret
