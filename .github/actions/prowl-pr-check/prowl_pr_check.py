#!/usr/bin/env python3
"""Upload a pull request's changed files to Judah and gate the job on the result.

Standard library only. Reads the PR from GITHUB_EVENT_PATH, diffs base...head,
posts changed file contents plus their patches, prints GitHub annotations and a
step summary, and exits 1 when the server's conclusion is "failure".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

MAX_FILES = 300
MAX_FILE_BYTES = 256_000
MAX_TOTAL_BYTES = 5_000_000
SKIP_PARTS = ("node_modules/", "vendor/", "dist/", "build/", ".git/")
SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
                 ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf")


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def pr_context() -> dict:
    event = {}
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            event = json.load(handle)
    pr = event.get("pull_request") or {}
    base = os.environ.get("PROWL_BASE_SHA") or (pr.get("base") or {}).get("sha") or ""
    head = os.environ.get("PROWL_HEAD_SHA") or (pr.get("head") or {}).get("sha") or "HEAD"
    if not base:
        sys.exit("No base commit: run on pull_request events or set PROWL_BASE_SHA")
    return {"base": base, "head": head, "number": pr.get("number"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "")}


def changed_files(base: str, head: str) -> list:
    names = git("diff", "--name-only", "--diff-filter=AMR", f"{base}...{head}").splitlines()
    files, total = [], 0
    for name in names:
        if (any(part in name for part in SKIP_PARTS) or name.endswith(SKIP_SUFFIXES)
                or not os.path.isfile(name)):
            continue
        size = os.path.getsize(name)
        if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES or len(files) >= MAX_FILES:
            print(f"::notice::Skipping {name} (size limit)")
            continue
        try:
            with open(name, encoding="utf-8") as handle:
                content = handle.read()
        except UnicodeDecodeError:
            continue
        total += size
        patch = git("diff", "--unified=0", f"{base}...{head}", "--", name)
        files.append({"path": name, "content": content, "patch": patch})
    return files


def post(url: str, key: str, payload: dict) -> dict:
    request = urllib.request.Request(
        url.rstrip("/") + "/pr-checks", data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": key},
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        sys.exit(f"Judah PR check failed: HTTP {exc.code} {detail}")


def escape(value: str) -> str:
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def report(result: dict) -> None:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "notice", "info": "notice"}
    for finding in result.get("findings") or []:
        print(f"::{level.get(finding.get('severity'), 'notice')} file={escape(finding.get('file', ''))},"
              f"line={finding.get('line', 1)},title={escape(finding.get('title', ''))}::"
              f"{escape(finding.get('rule_id', ''))} ({finding.get('cwe', '')}) — "
              f"advisory until Prowl reproduces it live")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    summary = result.get("summary") or {}
    lines = [
        f"## Judah PR check: {result.get('conclusion')}",
        "",
        f"{summary.get('findings', 0)} findings, {summary.get('routes', 0)} HTTP routes "
        f"extracted (engines: {', '.join(summary.get('engines') or [])}). "
        f"Source-only findings are capped at {summary.get('severity_cap', 'medium')}.",
        "",
    ]
    if result.get("findings"):
        lines += ["| Severity | Rule | Location | Route |", "|---|---|---|---|"]
        for f in result["findings"][:50]:
            route = f.get("route") or {}
            where = f"{f.get('file')}:{f.get('line')}"
            lines.append(f"| {f.get('severity')} | {f.get('title')} ({f.get('cwe')}) | `{where}` | "
                         f"{route.get('method', '')} {route.get('path', '')} |")
    lines += ["", f"_{result.get('next_step', '')}_", f"Check id: `{result.get('id')}`"]
    with open(summary_path, "a", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    api_url = os.environ.get("JUDAH_API_URL", "").strip()
    api_key = os.environ.get("JUDAH_API_KEY", "").strip()
    if not api_url or not api_key:
        sys.exit("JUDAH_API_URL and JUDAH_API_KEY are required")
    context = pr_context()
    payload = {
        "repository": context["repository"], "pull_request": context["number"],
        "head_sha": git("rev-parse", context["head"]).strip(), "base_sha": context["base"],
        "fail_on": os.environ.get("PROWL_FAIL_ON", "medium"),
        "files": changed_files(context["base"], context["head"]),
    }
    asset_id = os.environ.get("PROWL_ASSET_ID", "").strip()
    if asset_id:
        payload["asset_id"] = int(asset_id)
    result = post(api_url, api_key, payload)
    report(result)
    print(f"Judah PR check {result.get('id')}: {result.get('conclusion')} "
          f"({(result.get('summary') or {}).get('findings', 0)} findings)")
    return 1 if result.get("conclusion") == "failure" else 0


if __name__ == "__main__":
    sys.exit(main())
