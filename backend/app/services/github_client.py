"""Minimal GitHub REST client for fix pull requests (contents, refs, pulls).

The token is used only in the Authorization header and never logged or
returned. Repository names are validated before they reach a URL.
"""

from __future__ import annotations

import base64
import re
from typing import Any, Dict, Optional
from urllib.parse import quote

import httpx

_REPO = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_BRANCH = re.compile(r"[A-Za-z0-9._/-]{1,200}\Z")


class GitHubError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def validate_repository(repository: str) -> str:
    repository = (repository or "").strip()
    if not _REPO.fullmatch(repository) or ".." in repository:
        raise GitHubError("Repository must look like owner/name")
    return repository


def validate_branch(branch: str) -> str:
    if not _BRANCH.fullmatch(branch or "") or ".." in branch or branch.startswith("/"):
        raise GitHubError("Invalid branch name")
    return branch


class GitHubClient:
    def __init__(self, token: str, *, api_url: str = "https://api.github.com",
                 transport: Optional[httpx.AsyncBaseTransport] = None):
        if not token:
            raise GitHubError("A GitHub token is required")
        self._client = httpx.AsyncClient(
            base_url=api_url.rstrip("/"), timeout=30, transport=transport,
            headers={"Authorization": f"Bearer {token}",
                     "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28",
                     "User-Agent": "judah-prowl-fixer"},
        )

    async def __aenter__(self) -> "GitHubClient":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self._client.aclose()

    async def _call(self, method: str, path: str, **kwargs) -> Any:
        response = await self._client.request(method, path, **kwargs)
        if response.status_code >= 400:
            try:
                message = str(response.json().get("message") or "")[:200]
            except ValueError:
                message = ""
            raise GitHubError(f"GitHub {method} {path.split('?')[0]} failed: "
                              f"{response.status_code} {message}", response.status_code)
        return response.json() if response.content else {}

    async def default_branch(self, repository: str) -> str:
        data = await self._call("GET", f"/repos/{validate_repository(repository)}")
        return str(data.get("default_branch") or "main")

    async def branch_sha(self, repository: str, branch: str) -> str:
        data = await self._call(
            "GET", f"/repos/{validate_repository(repository)}/git/ref/heads/{quote(validate_branch(branch), safe='/')}")
        return str((data.get("object") or {}).get("sha") or "")

    async def get_file(self, repository: str, path: str, ref: str) -> Optional[Dict[str, str]]:
        try:
            data = await self._call(
                "GET", f"/repos/{validate_repository(repository)}/contents/{quote(path, safe='/')}",
                params={"ref": ref})
        except GitHubError as exc:
            if exc.status == 404:
                return None
            raise
        if not isinstance(data, dict) or data.get("type") != "file" or data.get("encoding") != "base64":
            return None
        try:
            text = base64.b64decode(data.get("content") or "").decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        return {"path": path, "content": text, "sha": str(data.get("sha") or "")}

    async def create_branch(self, repository: str, branch: str, sha: str) -> None:
        await self._call("POST", f"/repos/{validate_repository(repository)}/git/refs",
                         json={"ref": f"refs/heads/{validate_branch(branch)}", "sha": sha})

    async def put_file(self, repository: str, path: str, content: str, *, branch: str,
                       message: str, sha: Optional[str] = None) -> None:
        body: Dict[str, Any] = {
            "message": message, "branch": validate_branch(branch),
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        if sha:
            body["sha"] = sha
        await self._call("PUT", f"/repos/{validate_repository(repository)}/contents/{quote(path, safe='/')}",
                         json=body)

    async def create_pull(self, repository: str, *, head: str, base: str, title: str,
                          body: str, draft: bool = True) -> Dict[str, Any]:
        return await self._call("POST", f"/repos/{validate_repository(repository)}/pulls", json={
            "head": validate_branch(head), "base": validate_branch(base),
            "title": title[:250], "body": body[:60000], "draft": draft,
        })
