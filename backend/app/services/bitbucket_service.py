"""Read-only Bitbucket Cloud source-code integration.

Connects to one Bitbucket Cloud workspace with a workspace access token
(Repository: Read), imports every non-fork repository as a REPOSITORY asset,
and optionally scans each repository's main branch for exposed secrets.

Only Bitbucket Cloud (bitbucket.org) is supported. Bitbucket Data Center and
Server are not. The integration never writes to Bitbucket: no pull requests,
no webhooks, no comments.

Secret scanning shallow-clones the main branch into a temporary directory and
runs Gitleaks in redacted mode. When Gitleaks is not installed, a built-in
regex fallback is used. Raw secret values are never persisted; findings carry
the rule, file, line and a stable fingerprint only.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.bitbucket_integration import BitbucketIntegration
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

logger = logging.getLogger(__name__)

DISCOVERY_SOURCE = "bitbucket"
SECRET_DETECTOR = "bitbucket_secret_scanner"
TEMPLATE_PREFIX = "bitbucket-secret:"
API_BASE = "https://api.bitbucket.org/2.0"
WEB_BASE = "https://bitbucket.org"
GIT_HOST = "bitbucket.org"

CLONE_TIMEOUT_SECONDS = 300
GITLEAKS_TIMEOUT_SECONDS = 300
FALLBACK_MAX_FILE_BYTES = 1_000_000
FALLBACK_MAX_FILES = 5000

MSG_INVALID_URL = "Enter a valid Bitbucket workspace URL (https://bitbucket.org/your-workspace)."
MSG_AUTH_REJECTED = "Bitbucket rejected the supplied access token or Connected App credentials."

_WORKSPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")
_FULL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}/[a-z0-9][a-z0-9_.-]{0,127}$")
_VALID_HOSTS = {"bitbucket.org", "www.bitbucket.org"}


class BitbucketApiError(Exception):
    """Base error for Bitbucket API failures. Messages are safe to show users."""


class BitbucketAuthError(BitbucketApiError):
    pass


class BitbucketAccessError(BitbucketApiError):
    pass


def _access_message(workspace: str) -> str:
    return (
        "The Bitbucket credentials authenticated successfully but cannot access "
        f"workspace '{workspace}'. Verify the token was created in that workspace "
        "and has Repository: Read."
    )


# ── Workspace URL handling ───────────────────────────────────────────────────


def parse_workspace_url(value: str) -> Tuple[str, str]:
    """Return ``(workspace_slug, canonical_url)`` for a Bitbucket Cloud workspace URL.

    Accepts ``https://bitbucket.org/<workspace>`` with an optional trailing
    slash, ``www.`` prefix, or missing scheme. Anything else (other hosts,
    Data Center URLs, credentials, ports, extra path segments) is rejected.
    """
    raw = (value or "").strip()
    if not raw:
        raise ValueError(MSG_INVALID_URL)
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    if parsed.scheme != "https":
        raise ValueError(MSG_INVALID_URL)
    if parsed.username or parsed.password or parsed.port:
        raise ValueError(MSG_INVALID_URL)
    if (parsed.hostname or "").lower() not in _VALID_HOSTS:
        raise ValueError(MSG_INVALID_URL)
    if parsed.query or parsed.fragment or parsed.params:
        raise ValueError(MSG_INVALID_URL)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if len(segments) != 1:
        raise ValueError(MSG_INVALID_URL)
    workspace = segments[0].lower()
    if not _WORKSPACE_RE.match(workspace):
        raise ValueError(MSG_INVALID_URL)
    return workspace, f"{WEB_BASE}/{workspace}"


# ── API client ───────────────────────────────────────────────────────────────


class BitbucketClient:
    """Minimal async Bitbucket Cloud REST 2.0 client (read-only)."""

    def __init__(self, workspace: str, access_token: str, *, timeout: float = 30.0) -> None:
        if not _WORKSPACE_RE.match(workspace or ""):
            raise BitbucketApiError(MSG_INVALID_URL)
        if not access_token:
            raise BitbucketAuthError(MSG_AUTH_REJECTED)
        self.workspace = workspace
        self._token = access_token
        self._timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "User-Agent": "JudahSecurity-ASM/bitbucket-integration",
        }

    async def _get(self, client: httpx.AsyncClient, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if not url.startswith(API_BASE + "/"):
            raise BitbucketApiError("Refusing to follow a non-Bitbucket API URL.")
        for attempt in range(4):
            response = await client.get(url, params=params, headers=self._headers())
            if response.status_code == 429 and attempt < 3:
                try:
                    delay = min(float(response.headers.get("Retry-After", "")), 60.0)
                except ValueError:
                    delay = 2.0 * (2 ** attempt)
                await asyncio.sleep(delay)
                continue
            break
        if response.status_code == 401:
            raise BitbucketAuthError(MSG_AUTH_REJECTED)
        if response.status_code in (403, 404):
            raise BitbucketAccessError(_access_message(self.workspace))
        if response.status_code >= 400:
            raise BitbucketApiError(f"Bitbucket API returned HTTP {response.status_code}.")
        try:
            return response.json()
        except ValueError as exc:
            raise BitbucketApiError("Bitbucket API returned a non-JSON response.") from exc

    async def probe(self) -> Dict[str, Any]:
        """Fetch one page of repositories to confirm the token reaches the workspace."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            return await self._get(
                client, f"{API_BASE}/repositories/{self.workspace}", params={"pagelen": 1}
            )

    async def list_repositories(self, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        repositories: List[Dict[str, Any]] = []
        url: Optional[str] = f"{API_BASE}/repositories/{self.workspace}"
        params: Optional[Dict[str, Any]] = {"pagelen": 100}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            while url:
                page = await self._get(client, url, params=params)
                repositories.extend(item for item in page.get("values") or [] if isinstance(item, dict))
                if limit and len(repositories) >= limit:
                    return repositories[:limit]
                url = page.get("next")
                params = None  # `next` already carries the query string
        return repositories


async def test_connection(workspace_url: str, access_token: str) -> Dict[str, Any]:
    try:
        workspace, _ = parse_workspace_url(workspace_url)
    except ValueError as exc:
        return {"ok": False, "message": str(exc), "repositories_accessible": False}
    try:
        page = await BitbucketClient(workspace, access_token).probe()
    except BitbucketApiError as exc:
        return {"ok": False, "message": str(exc), "repositories_accessible": False}
    except httpx.HTTPError as exc:
        return {
            "ok": False,
            "message": f"Could not reach Bitbucket: {type(exc).__name__}",
            "repositories_accessible": False,
        }
    size = page.get("size")
    detail = f" {size} repositories visible." if isinstance(size, int) else ""
    return {
        "ok": True,
        "message": f"Connected to Bitbucket workspace '{workspace}'.{detail}",
        "repositories_accessible": True,
    }


# ── Repository normalisation ─────────────────────────────────────────────────


def is_fork(repo: Dict[str, Any]) -> bool:
    return bool(repo.get("parent"))


def repo_full_name(repo: Dict[str, Any]) -> Optional[str]:
    full_name = str(repo.get("full_name") or "").strip().lower()
    return full_name if _FULL_NAME_RE.match(full_name) else None


def repo_asset_value(full_name: str) -> str:
    return f"{WEB_BASE}/{full_name}"


def _main_branch(repo: Dict[str, Any]) -> Optional[str]:
    branch = repo.get("mainbranch")
    if isinstance(branch, dict) and branch.get("name"):
        return str(branch["name"])
    return None


def _repo_metadata(repo: Dict[str, Any], integration: BitbucketIntegration) -> Dict[str, Any]:
    project = repo.get("project") if isinstance(repo.get("project"), dict) else {}
    return {
        "integration_id": integration.id,
        "workspace": integration.workspace,
        "uuid": repo.get("uuid"),
        "slug": repo.get("slug"),
        "full_name": repo_full_name(repo),
        "is_private": bool(repo.get("is_private", True)),
        "main_branch": _main_branch(repo),
        "language": repo.get("language") or None,
        "size_bytes": repo.get("size"),
        "scm": repo.get("scm"),
        "project_key": project.get("key"),
        "project_name": project.get("name"),
        "created_on": repo.get("created_on"),
        "updated_on": repo.get("updated_on"),
    }


class _Stats:
    def __init__(self) -> None:
        self.repos_seen = 0
        self.repos_skipped_forks = 0
        self.assets_created = 0
        self.assets_updated = 0
        self.repos_scanned = 0
        self.repos_scan_skipped = 0
        self.repos_scan_failed = 0
        self.secrets_created = 0
        self.secrets_updated = 0
        self.secrets_resolved = 0

    def as_dict(self) -> Dict[str, int]:
        return vars(self).copy()


def _upsert_repository_asset(
    db: Session, integration: BitbucketIntegration, repo: Dict[str, Any], full_name: str, stats: _Stats
) -> Asset:
    value = repo_asset_value(full_name)
    is_public = not bool(repo.get("is_private", True))
    description = (str(repo.get("description") or "").strip() or None)
    asset = db.query(Asset).filter(
        Asset.organization_id == integration.organization_id,
        Asset.value == value,
    ).first()

    tags_to_add = ["source:bitbucket", "repository", "public" if is_public else "private"]
    if asset:
        metadata = dict(asset.metadata_ or {})
        previous = metadata.get("bitbucket") if isinstance(metadata.get("bitbucket"), dict) else {}
        merged = {**previous, **_repo_metadata(repo, integration)}
        metadata["bitbucket"] = merged
        asset.metadata_ = metadata
        asset.name = full_name[:255]
        asset.is_public = is_public
        asset.last_seen = datetime.utcnow()
        if description:
            asset.description = description
        tags = [t for t in (asset.tags or []) if t not in ("public", "private")]
        for tag in tags_to_add:
            if tag not in tags:
                tags.append(tag)
        asset.tags = tags
        stats.assets_updated += 1
        return asset

    asset = Asset(
        name=full_name[:255],
        asset_type=AssetType.REPOSITORY,
        value=value[:500],
        organization_id=integration.organization_id,
        status=AssetStatus.VERIFIED,
        description=description,
        discovery_source=DISCOVERY_SOURCE,
        discovery_chain=[{
            "step": 1,
            "source": "bitbucket_workspace",
            "value": integration.workspace_url,
            "found": value,
        }],
        association_reason=(
            f"Repository in Bitbucket workspace '{integration.workspace}', imported with a "
            "workspace access token supplied by the organization."
        ),
        association_confidence=100,
        tags=tags_to_add,
        metadata_={"bitbucket": _repo_metadata(repo, integration)},
        system_type="source_repository",
        is_public=is_public,
    )
    db.add(asset)
    db.flush()
    stats.assets_created += 1
    return asset


# ── Secret scanning ──────────────────────────────────────────────────────────


def _git_env(access_token: str, home: str) -> Dict[str, str]:
    """Environment for git that authenticates via a header, never argv or disk."""
    basic = base64.b64encode(f"x-token-auth:{access_token}".encode()).decode()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": home,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_COUNT": "4",
        "GIT_CONFIG_KEY_0": f"http.https://{GIT_HOST}/.extraHeader",
        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {basic}",
        "GIT_CONFIG_KEY_1": "core.symlinks",
        "GIT_CONFIG_VALUE_1": "false",
        "GIT_CONFIG_KEY_2": "protocol.allow",
        "GIT_CONFIG_VALUE_2": "never",
        "GIT_CONFIG_KEY_3": "protocol.https.allow",
        "GIT_CONFIG_VALUE_3": "always",
    }
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
                "SSL_CERT_FILE", "GIT_SSL_CAINFO"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _scrub(text: str, secret: str) -> str:
    if not text:
        return ""
    if secret:
        text = text.replace(secret, "[REDACTED]")
        text = text.replace(base64.b64encode(f"x-token-auth:{secret}".encode()).decode(), "[REDACTED]")
    return text[-500:]


def _clone_repository(full_name: str, branch: Optional[str], access_token: str, workdir: str) -> Tuple[str, Optional[str]]:
    """Shallow-clone ``full_name`` into ``workdir/src``. Returns ``(path, head_commit)``."""
    if not _FULL_NAME_RE.match(full_name):
        raise RuntimeError("Invalid repository name.")
    dest = os.path.join(workdir, "src")
    home = os.path.join(workdir, "home")
    os.makedirs(home, exist_ok=True)
    cmd = ["git", "clone", "--quiet", "--depth", "1", "--single-branch", "--no-tags"]
    if branch:
        cmd += ["--branch", branch]
    cmd += ["--", f"https://{GIT_HOST}/{full_name}.git", dest]
    env = _git_env(access_token, home)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS, env=env)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("git clone timed out") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {_scrub(proc.stderr, access_token).strip()}")
    head = None
    try:
        rev = subprocess.run(
            ["git", "-C", dest, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        if rev.returncode == 0:
            head = rev.stdout.strip() or None
    except subprocess.TimeoutExpired:
        pass
    # Only the working tree is scanned; drop .git so packed objects and the
    # clone's config never reach the scanner.
    shutil.rmtree(os.path.join(dest, ".git"), ignore_errors=True)
    return dest, head


def _relative_path(path: str, root: str) -> str:
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        rel = os.path.basename(path)
    if rel.startswith(".."):
        rel = os.path.basename(path)
    return rel.replace(os.sep, "/")


def _fingerprint(rel_file: str, rule_id: str, line: Any) -> str:
    return hashlib.sha256(f"{rel_file}:{rule_id}:{line}".encode()).hexdigest()[:32]


def _run_gitleaks(source_dir: str, report_path: str) -> List[Dict[str, Any]]:
    exe = shutil.which("gitleaks")
    if not exe:
        raise FileNotFoundError("gitleaks")
    cmd = [
        exe, "detect",
        "--source", source_dir,
        "--no-git",
        "--redact",
        "--no-banner",
        "--report-format", "json",
        "--report-path", report_path,
        "--exit-code", "0",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("gitleaks timed out") from exc
    raw = ""
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as handle:
            raw = handle.read().strip()
    if not raw:
        if proc.returncode not in (0, 1):
            raise RuntimeError(f"gitleaks failed: {(proc.stderr or '')[-300:]}")
        return []
    data = json.loads(raw)
    findings = data if isinstance(data, list) else [data]
    results = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        rule_id = str(item.get("RuleID") or "generic-secret")
        rel_file = _relative_path(str(item.get("File") or ""), source_dir)
        line = item.get("StartLine")
        results.append({
            "rule_id": rule_id,
            "description": str(item.get("Description") or rule_id),
            "file": rel_file,
            "line": line if isinstance(line, int) else None,
            "fingerprint": _fingerprint(rel_file, rule_id, line),
            "engine": "gitleaks",
        })
    return results


_SKIP_DIRS = {"node_modules", "vendor", ".git", "__pycache__", "dist", "build", ".venv", "venv"}


def _run_regex_fallback(source_dir: str) -> List[Dict[str, Any]]:
    """Pattern scan used when gitleaks is unavailable."""
    from app.services.github_secret_service import SECRET_PATTERNS

    placeholders = (
        "example", "placeholder", "your_", "xxx", "sample", "dummy", "fake",
        "changeme", "insert", "replace",
    )
    compiled = [(key, re.compile(cfg["pattern"]), cfg) for key, cfg in SECRET_PATTERNS.items()]
    results: List[Dict[str, Any]] = []
    files_seen = 0
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            files_seen += 1
            if files_seen > FALLBACK_MAX_FILES:
                return results
            try:
                if os.path.getsize(path) > FALLBACK_MAX_FILE_BYTES:
                    continue
                with open(path, "rb") as handle:
                    blob = handle.read()
            except OSError:
                continue
            if b"\x00" in blob[:8192]:
                continue
            content = blob.decode("utf-8", errors="ignore")
            rel_file = _relative_path(path, source_dir)
            for key, pattern, cfg in compiled:
                for match in pattern.finditer(content):
                    text = match.group().lower()
                    if any(p in text for p in placeholders) or len(set(text)) < 5:
                        continue
                    line = content[: match.start()].count("\n") + 1
                    results.append({
                        "rule_id": key,
                        "description": cfg["description"],
                        "file": rel_file,
                        "line": line,
                        "fingerprint": _fingerprint(rel_file, key, line),
                        "engine": "regex",
                        "severity": cfg["severity"],
                    })
    return results


def scan_repository_for_secrets(
    full_name: str, branch: Optional[str], access_token: str
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Clone and scan one repository. Blocking; run in a worker thread."""
    workdir = tempfile.mkdtemp(prefix="bb-scan-")
    try:
        source_dir, head = _clone_repository(full_name, branch, access_token, workdir)
        report_path = os.path.join(workdir, "gitleaks-report.json")
        try:
            findings = _run_gitleaks(source_dir, report_path)
        except FileNotFoundError:
            findings = _run_regex_fallback(source_dir)
        return findings, head
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


_CRITICAL_RULE_HINTS = (
    "private-key", "aws-access", "aws-secret", "gcp-service-account", "stripe-access-token",
    "stripe_secret_key", "aws_access_key", "aws_secret_key", "gcp_service_account",
    "private_key", "azure-ad-client-secret", "database",
)
_MEDIUM_RULE_HINTS = ("generic", "test", "jwt", "sidekiq", "hashicorp-tf-password")


def secret_severity(finding: Dict[str, Any]) -> Severity:
    if isinstance(finding.get("severity"), Severity):
        return finding["severity"]
    rule = str(finding.get("rule_id") or "").lower()
    if any(hint in rule for hint in _CRITICAL_RULE_HINTS):
        return Severity.CRITICAL
    if any(hint in rule for hint in _MEDIUM_RULE_HINTS):
        return Severity.MEDIUM
    return Severity.HIGH


_REMEDIATION = (
    "1. Rotate or revoke the exposed credential immediately; assume it is compromised.\n"
    "2. Remove the secret from the file and from repository history "
    "(git filter-repo or BFG), then force-push and ask collaborators to re-clone.\n"
    "3. Load the value from a secret manager or environment variable instead.\n"
    "4. Add a pre-commit secret scanner (e.g. gitleaks) to stop recurrences."
)


def _upsert_secret_findings(
    db: Session,
    asset: Asset,
    full_name: str,
    head: Optional[str],
    findings: List[Dict[str, Any]],
    stats: _Stats,
) -> None:
    now = datetime.utcnow()
    seen: Set[str] = set()
    ref = head or "HEAD"
    for finding in findings:
        template_id = f"{TEMPLATE_PREFIX}{finding['fingerprint']}"
        if template_id in seen:
            continue
        seen.add(template_id)
        file_path = finding.get("file") or ""
        line = finding.get("line")
        file_url = f"{WEB_BASE}/{full_name}/src/{ref}/{file_path}" + (f"#lines-{line}" if line else "")
        title = f"Exposed {finding['description']} in {full_name}"[:500]
        location = f"{file_path}:{line}" if line else file_path
        description = (
            f"A secret matching the '{finding['rule_id']}' rule was found in Bitbucket "
            f"repository {full_name}.\n\nFile: {location}\n"
            f"Commit: {head or 'unknown'}\n\nThe secret value is redacted and not stored."
        )
        metadata = {
            "source": DISCOVERY_SOURCE,
            "secret_type": finding["rule_id"],
            "repository": full_name,
            "file": file_path,
            "line": line,
            "commit": head,
            "engine": finding.get("engine"),
            "fingerprint": finding["fingerprint"],
        }
        existing = db.query(Vulnerability).filter(
            Vulnerability.asset_id == asset.id,
            Vulnerability.detected_by == SECRET_DETECTOR,
            Vulnerability.template_id == template_id,
        ).first()
        if existing:
            existing.last_detected = now
            existing.references = [file_url]
            existing.metadata_ = {**(existing.metadata_ or {}), **metadata}
            if existing.status == VulnerabilityStatus.RESOLVED:
                existing.status = VulnerabilityStatus.OPEN
                existing.resolved_at = None
            stats.secrets_updated += 1
            continue
        db.add(Vulnerability(
            title=title,
            description=description,
            severity=secret_severity(finding),
            cwe_id="CWE-798",
            references=[file_url],
            asset_id=asset.id,
            detected_by=SECRET_DETECTOR,
            template_id=template_id[:255],
            matcher_name=finding["rule_id"][:255],
            status=VulnerabilityStatus.OPEN,
            affected_component=location[:500],
            evidence=f"Rule: {finding['rule_id']} ({finding.get('engine')}); value redacted.",
            remediation=_REMEDIATION,
            first_detected=now,
            last_detected=now,
            tags=["source:bitbucket", "secret"],
            metadata_=metadata,
        ))
        stats.secrets_created += 1

    # Anything open from a previous scan of this repo that wasn't seen now is fixed.
    stale = db.query(Vulnerability).filter(
        Vulnerability.asset_id == asset.id,
        Vulnerability.detected_by == SECRET_DETECTOR,
        Vulnerability.status == VulnerabilityStatus.OPEN,
    ).all()
    for vuln in stale:
        if vuln.template_id not in seen:
            vuln.status = VulnerabilityStatus.RESOLVED
            vuln.resolved_at = now
            stats.secrets_resolved += 1


def _needs_scan(asset: Asset, repo: Dict[str, Any], max_size_mb: int) -> Tuple[bool, Optional[str]]:
    if not _main_branch(repo):
        return False, "empty repository"
    size = repo.get("size")
    if isinstance(size, (int, float)) and size > max_size_mb * 1024 * 1024:
        return False, f"larger than {max_size_mb} MB"
    meta = (asset.metadata_ or {}).get("bitbucket") or {}
    if (
        meta.get("secret_scan_status") == "ok"
        and meta.get("secret_scanned_updated_on")
        and meta.get("secret_scanned_updated_on") == repo.get("updated_on")
    ):
        return False, "unchanged since last scan"
    return True, None


def _set_scan_meta(asset: Asset, **values: Any) -> None:
    metadata = dict(asset.metadata_ or {})
    bitbucket = dict(metadata.get("bitbucket") or {})
    bitbucket.update(values)
    metadata["bitbucket"] = bitbucket
    asset.metadata_ = metadata


# ── Sync ─────────────────────────────────────────────────────────────────────

_running: Set[int] = set()


def is_sync_running(integration_id: int) -> bool:
    return integration_id in _running


async def sync_integration(db: Session, integration: BitbucketIntegration) -> Dict[str, Any]:
    if integration.id in _running:
        return {"ok": False, "message": "A sync for this workspace is already running."}
    _running.add(integration.id)
    stats = _Stats()
    try:
        token = integration.get_access_token() or ""
        repos = await BitbucketClient(integration.workspace, token).list_repositories()
        for repo in repos:
            full_name = repo_full_name(repo)
            if not full_name:
                continue
            if is_fork(repo):
                stats.repos_skipped_forks += 1
                continue
            stats.repos_seen += 1
            asset = _upsert_repository_asset(db, integration, repo, full_name, stats)
            db.commit()

            if not integration.scan_secrets:
                continue
            should_scan, reason = _needs_scan(asset, repo, integration.max_repo_size_mb or 500)
            if not should_scan:
                stats.repos_scan_skipped += 1
                if reason != "unchanged since last scan":
                    _set_scan_meta(asset, secret_scan_status="skipped", secret_scan_note=reason)
                    db.commit()
                continue
            try:
                findings, head = await asyncio.to_thread(
                    scan_repository_for_secrets, full_name, _main_branch(repo), token
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Bitbucket secret scan failed for %s: %s", full_name, exc)
                stats.repos_scan_failed += 1
                _set_scan_meta(
                    asset,
                    secret_scan_status="failed",
                    secret_scan_note=_scrub(str(exc), token),
                    last_secret_scan_at=datetime.utcnow().isoformat(),
                )
                db.commit()
                continue
            _upsert_secret_findings(db, asset, full_name, head, findings, stats)
            _set_scan_meta(
                asset,
                secret_scan_status="ok",
                secret_scan_note=None,
                secret_scanned_commit=head,
                secret_scanned_updated_on=repo.get("updated_on"),
                last_secret_scan_at=datetime.utcnow().isoformat(),
                open_secret_count=len({f["fingerprint"] for f in findings}),
            )
            stats.repos_scanned += 1
            db.commit()

        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = True
        integration.last_error = None
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        message = (
            f"Imported {stats.repos_seen} repositor{'y' if stats.repos_seen == 1 else 'ies'} "
            f"({stats.assets_created} new, {stats.repos_skipped_forks} forks skipped)"
        )
        if integration.scan_secrets:
            message += (
                f"; scanned {stats.repos_scanned}, {stats.secrets_created} new secret finding(s)"
            )
        return {"ok": True, "message": message + ".", **stats.as_dict()}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("Bitbucket sync failed for organization %s", integration.organization_id)
        safe = str(exc) if isinstance(exc, BitbucketApiError) else f"{type(exc).__name__}: {exc}"
        safe = _scrub(safe, integration.get_access_token() or "")
        integration.last_sync_at = datetime.utcnow()
        integration.last_sync_ok = False
        integration.last_error = safe[:1000]
        integration.last_sync_stats = stats.as_dict()
        db.commit()
        return {"ok": False, "message": f"Sync failed: {safe}", **stats.as_dict()}
    finally:
        _running.discard(integration.id)


async def sync_integration_by_id(integration_id: int) -> None:
    """Background entry point: run a sync with its own DB session."""
    from app.db.database import SessionLocal

    db = SessionLocal()
    try:
        integration = db.query(BitbucketIntegration).filter(BitbucketIntegration.id == integration_id).first()
        if integration and integration.is_active:
            result = await sync_integration(db, integration)
            logger.info("Bitbucket sync (%s): %s", integration.workspace, result.get("message"))
    finally:
        db.close()
