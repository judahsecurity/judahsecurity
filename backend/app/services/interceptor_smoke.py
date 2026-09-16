"""End-to-end smoke gate for an installed Interceptor worker."""

from __future__ import annotations

import argparse
import json
import time
from typing import Optional

from app.services import recon_jobs_service as jobs


def run_smoke(target: str, timeout_sec: float) -> dict:
    view = jobs.create_job(
        url=target,
        max_pages=8,
        interact=False,
        prefer=["ubuntu"],
        opts={
            "depth": 1,
            "max_pages": 8,
            "interact": False,
            "prefer_spider": False,
            "mode": "smoke",
        },
    )
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        current = jobs.get_job(view.id)
        if current and current.status in ("completed", "failed", "cancelled"):
            break
        time.sleep(2)
    else:
        raise RuntimeError(f"job {view.id} timed out after {timeout_sec:.0f}s")

    if current is None:
        raise RuntimeError(f"job {view.id} disappeared")
    if current.status != "completed":
        raise RuntimeError(
            f"job {view.id} ended as {current.status}: {current.error or 'unknown error'}"
        )
    normalized = (current.result or {}).get("normalized") or {}
    engine = str(normalized.get("engine") or "")
    pages = list(normalized.get("pages_visited") or [])
    if current.worker_kind != "ubuntu":
        raise RuntimeError(f"job used {current.worker_kind!r}, expected ubuntu")
    if not engine.startswith("interceptor"):
        raise RuntimeError(f"job engine was {engine!r}, expected real Interceptor")
    if not pages:
        raise RuntimeError("job completed without visiting a page")
    return {
        "ok": True,
        "job_id": current.id,
        "worker_id": current.worker_id,
        "engine": engine,
        "pages_visited": len(pages),
        "target": target,
    }


def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the real Interceptor worker end to end")
    parser.add_argument("--target", default="https://example.com")
    parser.add_argument("--timeout", type=float, default=240)
    args = parser.parse_args(argv)
    try:
        result = run_smoke(args.target, args.timeout)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
