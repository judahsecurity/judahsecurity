"""
Exposed VCS dump — turn a `.git`/`.svn` exposure into confirmed, high-value loot.

Our recon already *detects* an exposed `/.git` (a distiller pivot fetches
`/.git/config`), but detection alone undersells the finding: an exposed VCS
directory usually means the **entire source tree and its secret history** are
recoverable. This confirms the exposure and pulls the immediately high-value
artifacts — remote URL (often with embedded credentials), branch refs, and
commit metadata — so the finding lands as the critical it is, with evidence.

It is a *confirm + extract*, not a full working-tree reconstruction (that's
git-dumper's job and is heavy); the report notes when a full dump is warranted.
Injectable HTTP; parsing helpers are pure and unit-tested.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("agent.vcs_dump")

HttpFetch = Callable[[str, str, Dict[str, str], str], Dict[str, Any]]

_GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/index", "/.git/logs/HEAD",
              "/.git/packed-refs"]
_SVN_PATHS = ["/.svn/wc.db", "/.svn/entries"]

# Signatures that confirm a path is a real VCS artifact (not a 200 error page).
_SIGNATURES = {
    "/.git/HEAD": re.compile(r"^ref:\s+refs/", re.MULTILINE),
    "/.git/config": re.compile(r"\[core\]|\[remote ", re.IGNORECASE),
    "/.git/logs/HEAD": re.compile(r"[0-9a-f]{40}\s+[0-9a-f]{40}"),
    "/.git/index": re.compile(r"^DIRC"),
    "/.svn/entries": re.compile(r"dir|svn:"),
}

_CREDS_IN_URL = re.compile(r"https?://[^/\s:@]+:[^/\s@]+@[^\s/]+")


def _confirms(path: str, body: str) -> bool:
    sig = _SIGNATURES.get(path)
    if sig is None:
        return bool(body)
    return bool(sig.search(body or ""))


def extract_git_config(config_body: str) -> Dict[str, Any]:
    """Pull the remote URL(s) and any embedded credentials from a .git/config."""
    remotes = re.findall(r"url\s*=\s*(\S+)", config_body or "")
    creds = _CREDS_IN_URL.findall(config_body or "")
    return {"remotes": remotes, "credential_urls": creds}


def run_vcs_dump(base_url: str, fetch: Optional[HttpFetch] = None) -> Dict[str, Any]:
    """Confirm an exposed .git/.svn dir and extract high-value artifacts."""
    http = fetch or _default_http
    base = base_url.rstrip("/")
    accessible: List[str] = []
    artifacts: Dict[str, Any] = {}
    for path in _GIT_PATHS + _SVN_PATHS:
        resp = http("GET", base + path, {}, "")
        if resp.get("status") == 200 and _confirms(path, resp.get("body") or ""):
            accessible.append(path)
            if path == "/.git/config":
                artifacts["git_config"] = extract_git_config(resp.get("body") or "")
            elif path in ("/.git/HEAD", "/.git/packed-refs", "/.git/logs/HEAD"):
                artifacts[path] = (resp.get("body") or "")[:500]

    candidates: List[Dict[str, Any]] = []
    if accessible:
        creds = artifacts.get("git_config", {}).get("credential_urls", [])
        sev = "critical" if creds else "high"
        ev = f"accessible VCS artifacts: {', '.join(accessible)}"
        if creds:
            ev += "  ·  credentials embedded in remote URL(s)"
        candidates.append({
            "title": "Exposed version-control directory (source & history disclosure)",
            "vuln_type": "secrets_exposure", "severity": sev, "url": base + accessible[0],
            "evidence": ev, "artifacts": artifacts, "confirmed": True,
            "note": "run a full git-dumper reconstruction to recover the whole "
                    "tree and secret history under authorization",
        })
    return {"probe": "vcs_dump", "target": base,
            "accessible": accessible, "candidates": candidates}


def _default_http(method: str, url: str, headers: Dict[str, str], body: str) -> Dict[str, Any]:
    import scanners
    return scanners.run_send_http_request(
        method=method, url=url, headers_json=json.dumps(headers or {}),
        body=body, follow_redirects=False, bridge=None,
    )


__all__ = ["run_vcs_dump", "extract_git_config", "_confirms"]
