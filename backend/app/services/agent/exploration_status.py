"""Value-free browser exploration summary for the Agent work record."""

from __future__ import annotations

from urllib.parse import urlsplit


def project_exploration(capability_map: dict | None) -> dict:
    cmap = capability_map if isinstance(capability_map, dict) else {}
    try:
        scope = urlsplit(str(cmap.get("scope") or cmap.get("target") or ""))
    except ValueError:
        scope = urlsplit("")
    expected_origin = (scope.scheme, scope.netloc.lower())

    def path_in_scope(value: object) -> str:
        if not isinstance(value, str) or not value:
            return ""
        try:
            parts = urlsplit(value)
        except ValueError:
            return ""
        if parts.scheme or parts.netloc:
            if (parts.scheme, parts.netloc.lower()) != expected_origin:
                return ""
        path = parts.path or "/"
        return path[:300] if path.startswith("/") and not path.startswith("//") else ""

    mapped_paths = list(dict.fromkeys(filter(None, (
        path_in_scope(value) for value in (cmap.get("pages_visited") or [])[:100]
    ))))
    actions = []
    for row in (cmap.get("action_checkpoints") or [])[:200]:
        if (not isinstance(row, dict)
                or row.get("source") != "scoped_browser_inspect_js"):
            continue
        kind = str(row.get("kind") or row.get("action") or "")[:40]
        if kind not in {"navigate", "navigate_link", "scroll", "tab", "summary", "disclosure", "menu"}:
            continue
        action_path = path_in_scope(row.get("after_path") or row.get("path") or row.get("before_path"))
        if not action_path:
            continue
        actions.append({
            "kind": kind,
            "path": action_path,
            "status": str(row.get("status") or "unknown")[:40],
            "request_count": max(0, min(int(row.get("request_count") or 0), 1000))
            if str(row.get("request_count") or "0").isdigit() else 0,
        })
    browser_paths = list(dict.fromkeys(
        row["path"] for row in actions if row["status"] == "completed"
    ))
    return {
        "pages_observed": len(browser_paths),
        "page_paths": browser_paths[:30],
        "mapped_pages": len(mapped_paths),
        "forms_observed": len(cmap.get("forms") or []),
        "links_observed": len(cmap.get("discovered_links") or []),
        "browser_actions": len(actions),
        "safe_interactions": sum(row["kind"] in {"navigate_link", "tab", "summary", "disclosure", "menu"}
                                 and row["status"] == "completed" for row in actions),
        "recent_actions": actions[-12:],
    }
