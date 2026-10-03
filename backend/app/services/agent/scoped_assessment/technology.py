"""Offline technology signals from a pinned, separately installed Wappalyzer engine."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path


WRAPPER = Path(__file__).with_name("wappalyzer_offline.cjs")


def detect_technologies(requests: list[dict], origin: str, path: str = "/") -> dict:
    """Classify observed script paths only; never give Wappalyzer a target socket."""
    root = os.getenv("AEGIS_WAPPALYZER_ROOT") or os.getenv("PROWL_WAPPALYZER_ROOT", "")
    if not root or not (Path(root) / "src" / "wappalyzer.js").is_file():
        return {"engine": "wappalyzer-offline", "status": "unavailable", "signals_used": ["scriptSrc"], "matches": []}
    scripts = []
    for row in requests:
        value = row.get("path")
        if (row.get("method") == "GET" and row.get("resource_type") == "script"
                and isinstance(value, str) and value.startswith("/") and not value.startswith("//")
                and len(value) <= 512 and "\\" not in value):
            scripts.append(origin + value)
    payload = json.dumps({"url": origin + path, "scriptSrc": scripts[:100]})
    try:
        completed = subprocess.run(
            ["node", str(WRAPPER)], input=payload, text=True, capture_output=True,
            timeout=5, check=True, env={"PATH": os.getenv("PATH", ""), "PROWL_WAPPALYZER_ROOT": root},
        )
        value = json.loads(completed.stdout)
        if not isinstance(value, list):
            raise ValueError("Invalid detector output")
        matches = [
            {"name": item["name"][:100], "confidence": int(item["confidence"]),
             "version": str(item.get("version", ""))[:30]}
            for item in value[:20]
            if isinstance(item, dict) and isinstance(item.get("name"), str)
            and isinstance(item.get("confidence"), (int, float))
        ]
        return {"engine": "wappalyzer-offline", "status": "ok", "signals_used": ["scriptSrc"], "matches": matches}
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"engine": "wappalyzer-offline", "status": "error", "signals_used": ["scriptSrc"], "matches": []}
