"""
Interceptor worker poller — Mac desktop or Ubuntu browser host.

Runs outside the ASM backend container on a machine with:
  - Hacker-Valley-Media/Interceptor CLI installed
  - Chrome/Brave + Interceptor extension loaded
  - Network reachability to the ASM API

Usage (Mac):
  export ASM_API_BASE=https://aegis.example.com/api/v1
  export INTERCEPTOR_WORKER_TOKEN=...
  python -m app.services.interceptor_worker --kind mac

Usage (Ubuntu host with Xvfb + Interceptor):
  export DISPLAY=:99
  python -m app.services.interceptor_worker --kind ubuntu --worker-id ubuntu-ec2-1

One-shot (no poller) still works:
  python -m app.services.interceptor_recon https://target \\
    --post $ASM_API_BASE/recon/ingest --token $ASM_TOKEN --org 1
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _api_base() -> str:
    base = (
        os.environ.get("ASM_API_BASE")
        or os.environ.get("ASM_BASE_URL")
        or "http://127.0.0.1:8000/api/v1"
    ).rstrip("/")
    if base.endswith("/api/v1"):
        return base
    return base + "/api/v1"


def _token() -> str:
    return (
        os.environ.get("INTERCEPTOR_WORKER_TOKEN")
        or os.environ.get("ASM_TOKEN")
        or ""
    ).strip()


def _headers() -> Dict[str, str]:
    h = {"Content-Type": "application/json", "Accept": "application/json"}
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
        h["X-Worker-Token"] = tok
    return h


def _request(
    method: str,
    path: str,
    *,
    body: Optional[Dict[str, Any]] = None,
    query: Optional[Dict[str, str]] = None,
    timeout: float = 60.0,
) -> Dict[str, Any]:
    url = _api_base() + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8") or "{}"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"HTTP {e.code} {path}: {detail}") from e


def heartbeat(worker_id: str, worker_kind: str, meta: Optional[Dict[str, Any]] = None) -> None:
    _request(
        "POST",
        "/recon/workers/heartbeat",
        body={
            "worker_id": worker_id,
            "worker_kind": worker_kind,
            "hostname": socket.gethostname(),
            "meta": meta or {},
        },
        timeout=15,
    )


def claim_job(worker_id: str, worker_kind: str) -> Optional[Dict[str, Any]]:
    data = _request(
        "GET",
        "/recon/jobs/next",
        query={"worker": worker_kind, "worker_id": worker_id},
        timeout=30,
    )
    return data.get("job")


def complete_job(
    job_id: str,
    *,
    success: bool,
    recon: Optional[Dict[str, Any]] = None,
    auth_session: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
) -> None:
    _request(
        "POST",
        f"/recon/jobs/{job_id}/complete",
        body={
            "success": success,
            "recon": recon,
            "auth_session": auth_session,
            "error": error,
            "result": result,
        },
        timeout=120,
    )


async def run_one_job(job: Dict[str, Any]) -> None:
    from app.services.interceptor_recon import run_recon, to_normalized_dict
    from app.services.interceptor_service import apply_pentester_defaults
    from app.services.recon_envelope import envelope_from_normalized

    url = job.get("url") or ""
    opts = apply_pentester_defaults(dict(job.get("opts") or {}))
    if job.get("scope"):
        opts.setdefault("scope", job["scope"])
    opts.setdefault("max_pages", job.get("max_pages") or opts.get("max_pages") or 25)
    opts.setdefault("interact", bool(job.get("interact", True)))

    logger.info(
        "Running Interceptor pentester recon for %s (job %s depth=%s pages=%s)",
        url,
        job.get("id"),
        opts.get("depth"),
        opts.get("max_pages"),
    )
    result = await run_recon(url, opts)
    normalized = to_normalized_dict(result)
    envelope = envelope_from_normalized(
        normalized,
        note=f"worker={job.get('worker_kind')} id={job.get('worker_id')}",
    )
    complete_job(
        job["id"],
        success=bool(result.pages_visited),
        recon=normalized,
        auth_session=envelope.get("auth_session"),
        result=envelope,
        error=None if result.pages_visited else "; ".join(result.errors[:3]) or "no_pages",
    )


async def poll_loop(
    *,
    worker_kind: str,
    worker_id: str,
    poll_sec: float = 5.0,
    heartbeat_sec: float = 30.0,
) -> None:
    last_hb = 0.0
    logger.info(
        "Interceptor worker starting kind=%s id=%s api=%s",
        worker_kind,
        worker_id,
        _api_base(),
    )
    while True:
        now = time.time()
        if now - last_hb >= heartbeat_sec:
            try:
                heartbeat(worker_id, worker_kind, meta={"pid": os.getpid()})
                last_hb = now
            except Exception as e:
                logger.warning("heartbeat failed: %s", e)

        try:
            job = claim_job(worker_id, worker_kind)
        except Exception as e:
            logger.warning("claim failed: %s", e)
            await asyncio.sleep(poll_sec)
            continue

        if not job:
            await asyncio.sleep(poll_sec)
            continue

        try:
            await run_one_job(job)
        except Exception as e:
            logger.exception("job %s failed: %s", job.get("id"), e)
            try:
                complete_job(job["id"], success=False, error=str(e)[:500])
            except Exception:
                pass


def _main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="ASM Interceptor worker poller")
    parser.add_argument("--kind", choices=["mac", "ubuntu"], required=True)
    parser.add_argument(
        "--worker-id",
        default=None,
        help="Stable instance id (default: <kind>-<hostname>)",
    )
    parser.add_argument("--poll-sec", type=float, default=5.0)
    parser.add_argument("--heartbeat-sec", type=float, default=30.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    worker_id = args.worker_id or f"{args.kind}-{socket.gethostname()}"
    if not _token():
        logger.warning(
            "INTERCEPTOR_WORKER_TOKEN / ASM_TOKEN not set — API may reject worker calls"
        )

    try:
        asyncio.run(
            poll_loop(
                worker_kind=args.kind,
                worker_id=worker_id,
                poll_sec=args.poll_sec,
                heartbeat_sec=args.heartbeat_sec,
            )
        )
    except KeyboardInterrupt:
        logger.info("stopped")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
