#!/usr/bin/env python3
"""Container entrypoint: make named-volume cache dirs writable, then drop to appuser."""
from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    try:
        os.chown(path, uid, gid)
    except OSError:
        return
    for child in path.rglob("*"):
        try:
            os.chown(child, uid, gid)
        except OSError:
            continue


def main() -> None:
    if len(sys.argv) < 2:
        sys.stderr.write("docker-entrypoint: missing command\n")
        sys.exit(1)

    cache = Path(os.environ.get("DELPHI_CACHE_DIR") or "/app/data/delphi_cache")
    try:
        cache.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    if os.geteuid() == 0:
        try:
            user = pwd.getpwnam("appuser")
            _chown_tree(cache, user.pw_uid, user.pw_gid)
            os.initgroups("appuser", user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)
            os.environ["HOME"] = user.pw_dir
            os.environ["USER"] = "appuser"
            os.environ["LOGNAME"] = "appuser"
        except Exception as exc:
            sys.stderr.write(f"docker-entrypoint: privilege drop failed ({exc}); continuing\n")

    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
