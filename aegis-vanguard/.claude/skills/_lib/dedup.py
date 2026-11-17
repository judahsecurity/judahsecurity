#!/usr/bin/env python3
"""Root-cause dedup for findings.json (used by /triage and /chain).

Clusters by (canonical class, normalized endpoint, parameter/sink), never by
title. Endpoint normalization: lowercase host, default port dropped, query and
fragment dropped, numeric / UUID / long-hex path segments -> {id}, trailing
slash dropped. For source findings (`path/file.py:120 symbol`) the line number
is dropped. Classes resolve through data/vuln_classes.json aliases.

    python3 .claude/skills/_lib/dedup.py <run-dir>/findings.json [--out <run-dir>/clusters.json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

CLASSES = Path(__file__).resolve().parents[3] / "data" / "vuln_classes.json"
_ID_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$", re.I
)
_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _aliases() -> tuple[dict, set]:
    try:
        data = json.loads(CLASSES.read_text())
    except (OSError, ValueError):
        return {}, set()
    aliases = dict(data.get("vanguard_aliases") or {})
    aliases.update({k: v for k, v in (data.get("coverage_to_class") or {}).items() if v})
    return aliases, set(data.get("classes") or {})


def canonical_class(value: str, aliases: dict | None = None, known: set | None = None) -> str:
    if aliases is None:
        aliases, known = _aliases()
    key = re.sub(r"[\s-]+", "_", (value or "").strip().lower())
    if key in (known or set()):
        return key
    return aliases.get(key, key or "unknown")


def normalize_endpoint(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parts = urlsplit(value)
        host = (parts.hostname or "").lower().rstrip(".")
        try:
            port = parts.port
        except ValueError:
            port = None
        if port and port != {"http": 80, "https": 443}.get(parts.scheme.lower()):
            host = f"{host}:{port}"
        path = parts.path
    else:
        # Source location or bare path: drop :line and query.
        value = re.sub(r":\d+(?::\d+)?(?=\s|$)", "", value.split("?", 1)[0].split("#", 1)[0])
        host, path = "", value
    segments = ["{id}" if _ID_SEGMENT.match(seg) else seg for seg in path.split("/")]
    path = "/".join(segments).rstrip("/") or "/"
    return f"{host}{path}" if host else path


def finding_key(row: dict, aliases: dict | None = None, known: set | None = None) -> tuple:
    cls = canonical_class(str(row.get("vuln_class") or row.get("class") or row.get("category")
                              or row.get("type") or ""), aliases, known)
    endpoint = normalize_endpoint(str(row.get("endpoint") or row.get("url")
                                      or row.get("location") or row.get("target") or ""))
    sink = str(row.get("parameter") or row.get("param") or row.get("sink") or "").strip().lower()
    return cls, endpoint, sink


def cluster(findings: list[dict]) -> list[dict]:
    aliases, known = _aliases()
    groups: dict[tuple, list[dict]] = {}
    for row in findings:
        groups.setdefault(finding_key(row, aliases, known), []).append(row)
    out = []
    for (cls, endpoint, sink), rows in groups.items():
        primary = max(rows, key=lambda r: (bool(r.get("confirmed")),
                                           _SEVERITY.get(str(r.get("severity", "")).lower(), -1)))
        out.append({
            "vuln_class": cls, "endpoint": endpoint, "parameter": sink,
            "primary": primary.get("id"),
            "duplicates": [r.get("id") for r in rows if r is not primary],
            "finding_ids": [r.get("id") for r in rows],
        })
    return sorted(out, key=lambda c: (c["vuln_class"], c["endpoint"], c["parameter"]))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("findings")
    p.add_argument("--out")
    args = p.parse_args()
    data = json.loads(Path(args.findings).read_text())
    rows = data.get("findings", []) if isinstance(data, dict) else data
    text = json.dumps(cluster(rows), indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
