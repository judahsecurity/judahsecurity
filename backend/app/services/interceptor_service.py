"""
Interceptor Service — harness entrypoint for the `execute_interceptor` tool.

Preference order:
  1. Online Mac Interceptor worker (job queue)
  2. Online Ubuntu Interceptor worker (job queue)
  3. Local ``interceptor`` CLI on this host (desktop / GUI worker colocated)
  4. Playwright ``deep_crawl`` fallback

Pentester crawl defaults (when the agent passes a bare URL):
  depth=3, max_pages=25, interact=true, max_clicks=14, prefer_spider=true
  — interaction-first Site Spider (katana in a real Chrome tab).

Config (env):
    INTERCEPTOR_BIN                      — path to local interceptor binary
    INTERCEPTOR_CMD_TIMEOUT              — per-verb timeout seconds (default: 45)
    INTERCEPTOR_PREFER_REMOTE_WORKERS    — default true
    RECON_JOB_TIMEOUT_SEC                — wait for remote workers (default 900)
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Assessment-grade crawl — enough to understand functionality, not page spam.
PENTESTER_DEFAULTS: Dict[str, Any] = {
    "depth": 3,
    "max_pages": 25,
    "interact": True,
    "max_clicks": 14,
    "prefer_spider": True,
    "mode": "assessment",
}


def apply_pentester_defaults(opts: Dict[str, Any]) -> Dict[str, Any]:
    """Fill missing crawl knobs so a bare URL still walks the app like a tester."""
    out = dict(opts or {})
    for key, value in PENTESTER_DEFAULTS.items():
        out.setdefault(key, value)
    try:
        pages = int(out.get("max_pages") or PENTESTER_DEFAULTS["max_pages"])
    except (TypeError, ValueError):
        pages = int(PENTESTER_DEFAULTS["max_pages"])
    out["max_pages"] = max(8, min(pages, 80))
    try:
        depth = int(out.get("depth") or PENTESTER_DEFAULTS["depth"])
    except (TypeError, ValueError):
        depth = int(PENTESTER_DEFAULTS["depth"])
    out["depth"] = max(1, min(depth, 6))
    if out.get("interact") is None:
        out["interact"] = True
    return out


def _parse_args(args: Any) -> Dict[str, Any]:
    """Accept a bare URL string or a JSON object of options."""
    if isinstance(args, dict):
        return apply_pentester_defaults(args)
    s = str(args or "").strip()
    if not s:
        return {}
    if s.startswith("{"):
        try:
            return apply_pentester_defaults(json.loads(s))
        except (json.JSONDecodeError, TypeError):
            return apply_pentester_defaults({"url": s})
    return apply_pentester_defaults({"url": s.split()[0]})


def _session_id_from_opts(opts: Dict[str, Any]) -> Optional[str]:
    return (
        str(opts.get("session_id") or opts.get("agent_session_id") or "").strip()
        or None
    )


async def queue_early_pentester_crawl(
    url: str,
    *,
    session_id: Optional[str] = None,
    organization_id: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Queue a pentester Interceptor job immediately (no wait).

    Returns {queued, job_id, online, note}. Safe to call when no workers are
    online — then queued=False and execute_interceptor will fall back later.
    """
    u = (url or "").strip()
    if not u:
        return {"queued": False, "job_id": None, "online": [], "note": "no_url"}
    if not u.startswith("http"):
        u = f"https://{u}"

    try:
        from app.services import recon_jobs_service as jobs
    except Exception as e:
        return {"queued": False, "job_id": None, "online": [], "note": f"jobs_unavailable:{e}"}

    # Reuse an in-flight job for this session+URL if kickoff ran twice.
    existing = jobs.find_active_job(session_id=session_id, url=u)
    if existing:
        await jobs.notify_session_ws(
            session_id,
            {
                "type": "thinking",
                "content": (
                    f"Interceptor crawl already in flight ({existing.id[:8]}… "
                    f"status={existing.status}) — agent will attach when ready."
                ),
            },
        )
        return {
            "queued": True,
            "job_id": existing.id,
            "online": jobs.online_kinds(),
            "note": f"reused_active:{existing.status}",
            "status": existing.status,
        }

    online = jobs.online_kinds()
    if not online:
        return {
            "queued": False,
            "job_id": None,
            "online": [],
            "note": "no_workers_online",
        }

    prefer = [p for p in jobs.DEFAULT_PREFER if p in online] or list(jobs.DEFAULT_PREFER)
    opts = apply_pentester_defaults({"url": u, "prefer": prefer})
    max_pages = int(opts.get("max_pages") or PENTESTER_DEFAULTS["max_pages"])
    crawl_opts = {
        k: v
        for k, v in opts.items()
        if k
        not in (
            "url",
            "target",
            "prefer",
            "prefer_remote",
            "session_id",
            "agent_session_id",
            "organization_id",
            "org_id",
            "job_id",
        )
    }
    try:
        org_id = int(organization_id) if organization_id is not None else None
    except (TypeError, ValueError):
        org_id = None

    view = jobs.create_job(
        url=u,
        organization_id=org_id,
        session_id=session_id,
        max_pages=max_pages,
        interact=bool(opts.get("interact", True)),
        prefer=prefer,
        opts=crawl_opts,
    )
    await jobs.notify_session_ws(
        session_id,
        {
            "type": "thinking",
            "content": (
                f"Early-queued Interceptor pentester crawl {view.id[:8]}… "
                f"depth={opts.get('depth')} max_pages={max_pages} "
                f"(prefer={prefer}, online={online}) — running while agent plans."
            ),
        },
    )
    return {
        "queued": True,
        "job_id": view.id,
        "online": online,
        "note": "queued",
        "status": view.status,
    }


async def run_interceptor(args: Any) -> Dict[str, Any]:
    """
    Run interaction-first recon via remote workers, local Interceptor, or deep_crawl.

    Returns the ASM tool envelope: {success, output, error, exit_code, capability_map?}.
    """
    opts = _parse_args(args)
    url = str(opts.get("url") or opts.get("target") or "").strip()
    if not url:
        return {
            "success": False,
            "output": (
                'No target. Pass a URL, e.g. execute_interceptor(args="https://target.com") '
                "or JSON (depth/max_pages/interact applied automatically)."
            ),
            "error": "no_target",
            "exit_code": 1,
        }
    if not url.startswith("http"):
        url = f"https://{url}"
        opts["url"] = url

    prefer_remote = os.environ.get("INTERCEPTOR_PREFER_REMOTE_WORKERS", "true").lower() not in (
        "0", "false", "no",
    )
    if "prefer_remote" in opts:
        prefer_remote = bool(opts.get("prefer_remote"))

    reasons: list[str] = []

    if prefer_remote:
        remote = await _try_remote_workers(url, opts)
        if remote is not None:
            return _with_next_steps(remote)
        reasons.append("No Mac/Ubuntu Interceptor workers completed the job (offline or timeout).")

    local = await _try_local_interceptor(url, opts)
    if local is not None:
        return _with_next_steps(local)
    reasons.append(
        "Local Interceptor CLI not reachable (needs Chrome/Brave + extension on this host)."
    )

    reason = (
        " ".join(reasons)
        + " Falling back to deep_crawl (same pentester interact/depth defaults)."
    )
    return _with_next_steps(await _fallback(opts, reason))


def _with_next_steps(result: Dict[str, Any]) -> Dict[str, Any]:
    """Remind the agent how to turn the crawl into an assessment."""
    if not isinstance(result, dict):
        return result
    cmap = result.get("capability_map") or {}
    ready = bool(cmap.get("ready_for_attack"))
    hint = (
        "\n\nNEXT (tester control loop): sync_engagement_brain → "
        'fireteam_dispatch(specialists="auto") → prove with compare_requests. '
        + (
            "Capability map is ready for attack."
            if ready
            else "Map may be thin — raise max_pages/depth or authenticate and re-crawl."
        )
    )
    out = result.get("output") or ""
    if "NEXT (tester control loop)" not in out:
        result["output"] = out + hint
    return result


async def _try_remote_workers(url: str, opts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        from app.services import recon_jobs_service as jobs
    except Exception as e:
        logger.warning("recon_jobs_service unavailable: %s", e)
        return None

    online = jobs.online_kinds()
    prefer = opts.get("prefer") or jobs.DEFAULT_PREFER
    if isinstance(prefer, str):
        prefer = [p.strip() for p in prefer.split(",") if p.strip()]
    prefer = [p for p in prefer if p in jobs.WORKER_KINDS]
    if not prefer:
        prefer = list(jobs.DEFAULT_PREFER)

    session_id = _session_id_from_opts(opts)
    org_id = opts.get("organization_id") or opts.get("org_id")
    try:
        org_id = int(org_id) if org_id is not None else None
    except (TypeError, ValueError):
        org_id = None

    # Attach to early-queued or in-flight crawl when possible.
    force_new = bool(opts.get("force_new") or opts.get("force_new_job"))
    reuse_id = str(opts.get("job_id") or "").strip() or None
    view = None
    if reuse_id and not force_new:
        view = jobs.get_job(reuse_id)
        if view and view.status in ("failed", "cancelled"):
            view = None
    if view is None and not force_new:
        view = jobs.find_active_job(session_id=session_id, url=url)
        # Completed early job: agent called execute_interceptor after crawl finished.
        if view is None and reuse_id:
            done_early = jobs.get_job(reuse_id)
            if done_early and done_early.status == "completed":
                view = done_early

    if view is None:
        if not any(p in online for p in prefer):
            logger.info("No Interceptor workers online for prefer=%s", prefer)
            return None

        crawl_opts = {
            k: v
            for k, v in opts.items()
            if k
            not in (
                "url",
                "target",
                "prefer",
                "prefer_remote",
                "session_id",
                "agent_session_id",
                "organization_id",
                "org_id",
                "job_id",
                "force_new",
                "force_new_job",
            )
        }
        max_pages = int(opts.get("max_pages") or PENTESTER_DEFAULTS["max_pages"])
        view = jobs.create_job(
            url=url,
            organization_id=org_id,
            session_id=session_id,
            scope=opts.get("scope"),
            max_pages=max_pages,
            interact=bool(opts.get("interact", True)),
            prefer=prefer,
            opts=crawl_opts,
        )
        await jobs.notify_session_ws(
            session_id,
            {
                "type": "thinking",
                "content": (
                    f"Queued Interceptor pentester crawl {view.id[:8]}… "
                    f"depth={opts.get('depth')} max_pages={max_pages} "
                    f"interact={opts.get('interact')} (prefer={prefer}, online={online})"
                ),
            },
        )
    else:
        await jobs.notify_session_ws(
            session_id,
            {
                "type": "thinking",
                "content": (
                    f"Attaching to Interceptor job {view.id[:8]}… "
                    f"status={view.status} (early queue / in-flight reuse)"
                ),
            },
        )

    timeout = float(os.environ.get("RECON_JOB_TIMEOUT_SEC", "900"))

    async def _progress(v):
        await jobs.notify_session_ws(
            session_id,
            {
                "type": "thinking",
                "content": (
                    f"Interceptor job {v.id[:8]} status={v.status} "
                    f"worker={v.worker_kind or '-'}"
                ),
            },
        )

    # Already finished (early queue completed during planning).
    if view.status == "completed" and isinstance(view.result, dict):
        done = view
    else:
        try:
            done = await jobs.wait_for_job(view.id, timeout_sec=timeout, on_progress=_progress)
        except TimeoutError:
            return None
        except Exception as e:
            logger.warning("wait_for_job failed: %s", e)
            return None

    if done.status != "completed" or not isinstance(done.result, dict):
        return None
    result = dict(done.result)
    if not result.get("capability_map") and result.get("normalized"):
        result = jobs.envelope_from_normalized(
            result["normalized"],
            auth_session=result.get("auth_session"),
            note=f"Completed by {done.worker_kind} worker {done.worker_id}",
        )
    result.setdefault("success", True)
    note = (
        f"[NOTE] Completed via {done.worker_kind} Interceptor worker "
        f"({done.worker_id}) — interaction-first pentester crawl.\n\n"
    )
    result["output"] = note + (result.get("output") or "")
    await jobs.push_map_updates(session_id, result)
    return result


async def _try_local_interceptor(url: str, opts: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        from app.services.interceptor_recon import (
            format_output,
            resolve_bin,
            run_recon,
            to_normalized_dict,
        )
        from app.services.recon_envelope import envelope_from_normalized
    except Exception as e:
        logger.warning("interceptor_recon unavailable: %s", e)
        return None

    if not resolve_bin():
        return None

    result = await run_recon(url, opts)
    if not result.pages_visited:
        return None

    normalized = to_normalized_dict(result)
    envelope = envelope_from_normalized(normalized)
    envelope["output"] = format_output(result) + "\n\n" + (envelope.get("output") or "")
    try:
        from app.services import recon_jobs_service as jobs

        await jobs.push_map_updates(_session_id_from_opts(opts), envelope)
    except Exception:
        pass
    return envelope


async def _fallback(opts: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """Run the hardened Playwright deep_crawl and prefix an explanatory note."""
    try:
        from app.services.deep_crawl_service import run_deep_crawl
    except Exception as e:
        return {
            "success": False,
            "output": reason + f"\n\n(deep_crawl fallback also unavailable: {e})",
            "error": "interceptor_unavailable",
            "exit_code": -1,
        }

    result = await run_deep_crawl(opts)
    note = f"[NOTE] {reason}\n\n"
    result["output"] = note + (result.get("output") or "")
    return result
