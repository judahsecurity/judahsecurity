#!/usr/bin/env python3
"""Enforce an operator scope file for /recon, /pentest and /chain.

Scope file (one entry per line, `#` comments):

    app.example.com            exact host (any port)
    app.example.com:8443       exact host and port
    https://api.example.com    origin form; scheme ignored, port honoured if given
    *.example.com              wildcard: subdomains only (list the apex separately)
    !admin.example.com         exclusion; wins over every include

    python3 .claude/skills/_lib/scope.py check <scope-file> <url-or-host>...   # exit 1 if any out
    python3 .claude/skills/_lib/scope.py filter <scope-file> < hosts.txt       # print in-scope lines
    python3 .claude/skills/_lib/scope.py wildcards <scope-file>                # roots allowed for subdomain enum
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urlsplit


def _split(value: str) -> tuple[str, int | None]:
    value = value.strip()
    parts = urlsplit(value if "://" in value else "//" + value)
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None
    return host, port


def load(path: str | Path) -> dict:
    include, exclude = [], []
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        bucket = exclude if line.startswith("!") else include
        line = line.lstrip("!").strip()
        if line.startswith("*."):
            bucket.append(("wildcard", line[2:].lower().rstrip("."), None))
        else:
            host, port = _split(line)
            if host:
                bucket.append(("exact", host, port))
    if not include:
        raise SystemExit(f"scope file {path} has no include entries")
    return {"include": include, "exclude": exclude}


def _match(rule: tuple, host: str, port: int | None) -> bool:
    kind, value, rule_port = rule
    if kind == "wildcard":
        return host.endswith("." + value)
    return host == value and (rule_port is None or rule_port == port)


def in_scope(scope: dict, target: str) -> bool:
    host, port = _split(target)
    if not host:
        return False
    if any(_match(rule, host, port) for rule in scope["exclude"]):
        return False
    return any(_match(rule, host, port) for rule in scope["include"])


def wildcards(scope: dict) -> list[str]:
    return sorted({value for kind, value, _ in scope["include"] if kind == "wildcard"})


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["check", "filter", "wildcards"])
    p.add_argument("scope_file")
    p.add_argument("targets", nargs="*")
    args = p.parse_args()
    scope = load(args.scope_file)
    if args.action == "wildcards":
        print("\n".join(wildcards(scope)))
        return 0
    if args.action == "filter":
        for line in sys.stdin:
            if line.strip() and in_scope(scope, line.strip()):
                print(line.strip())
        return 0
    if not args.targets:
        p.error("check needs at least one target")
    bad = 0
    for target in args.targets:
        ok = in_scope(scope, target)
        bad += not ok
        print(f"{'IN ' if ok else 'OUT'} {target}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
