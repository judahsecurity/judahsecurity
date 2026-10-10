"""
Parallel recon workers (Copilot-style streams).

Spawn background streams that run while the main agent plans/thinks.
Completed briefs are drained into the next think prompt / execution trace
so results "come in" without serializing the whole turn on one tool.

Worker kinds (bounded — not DirBuster-scale):
  httpx_tech   — ProjectDiscovery-style HTTP + tech probe
  waf_probe    — wafw00f
  ferox_dirs   — depth-1 common dirs (app-dirs-common.txt)
  katana_urls  — shallow URL/JS crawl enrich
  archive_params — historical parameter URLs from ParamSpider (leads only)
  whatweb      — quick fingerprint
  nuclei_recon — informational Nuclei (tech / detect). Not CVE spray.

Packs:
  early        — httpx_tech + waf_probe + whatweb + archive_params
                 (auto on URL paste; interceptor queued separately)
  enrich       — ferox_dirs + katana_urls
  nuclei_recon — informational Nuclei only (explicit spawn)
  full         — early + enrich
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

WORKER_KINDS = (
    "httpx_tech",
    "waf_probe",
    "ferox_dirs",
    "katana_urls",
    "archive_params",
    "whatweb",
    "nuclei_recon",
)

PACKS: Dict[str, List[str]] = {
    "early": ["httpx_tech", "waf_probe", "whatweb", "archive_params"],
    "enrich": ["ferox_dirs", "katana_urls"],
    "nuclei_recon": ["nuclei_recon"],
    "full": [
        "httpx_tech",
        "waf_probe",
        "whatweb",
        "nuclei_recon",
        "ferox_dirs",
        "katana_urls",
        "archive_params",
    ],
}

# Soft ceilings so background streams cannot eat the whole turn budget.
_KIND_TIMEOUT_SEC: Dict[str, float] = {
    "httpx_tech": 90.0,
    "waf_probe": 60.0,
    "whatweb": 60.0,
    "ferox_dirs": 180.0,
    "katana_urls": 180.0,
    "archive_params": 120.0,
    "nuclei_recon": 120.0,
}

# Informational Nuclei only. Tags are OR'd; -etags keeps this off CVE/fuzz spray.
# Confirmation gate treats this arg shape as safe recon (like httpx), not a
# full execute_nuclei engagement scan.
NUCLEI_RECON_TAGS = "tech,detect"
NUCLEI_RECON_EXCLUDE_TAGS = "dos,fuzz"
_ALLOWED_RECON_SEVERITIES = {"info", "low"}
_ALLOWED_RECON_TAG_HINTS = {
    "tech",
    "exposure",
    "panel",
    "misconfig",
    "detect",
    "waf",
    "cms",
    "wordpress",
    "login",
}
_BLOCKED_RECON_TAGS = {"cve", "rce", "exploit"}


def nuclei_recon_args(url: str) -> str:
    """Bounded Nuclei CLI for the parallel recon worker."""
    return (
        f"-u {url} -jsonl -silent -rate-limit 20 -c 5 -timeout 5 -retries 0 "
        f"-severity info -tags {NUCLEI_RECON_TAGS} "
        f"-etags {NUCLEI_RECON_EXCLUDE_TAGS}"
    )


def is_bounded_nuclei_recon_args(args: str) -> bool:
    """True when execute_nuclei args are informational recon, not CVE spray."""
    raw = (args or "").strip()
    if not raw:
        return False
    lower = raw.lower()
    sev_m = re.search(r"-severity(?:\s+|=)([^\s]+)", lower)
    if not sev_m:
        return False
    sevs = {s.strip() for s in sev_m.group(1).split(",") if s.strip()}
    if not sevs or sevs - _ALLOWED_RECON_SEVERITIES:
        return False
    tags_m = re.search(r"-tags(?:\s+|=)([^\s]+)", lower)
    if not tags_m:
        return False
    tags = {t.strip() for t in tags_m.group(1).split(",") if t.strip()}
    if not tags or tags & _BLOCKED_RECON_TAGS:
        return False
    return bool(tags & _ALLOWED_RECON_TAG_HINTS)

_WORDLIST_CANDIDATES = (
    os.environ.get("ASM_APP_DIRS_WORDLIST") or "",
    "/opt/wordlists/app-dirs-common.txt",
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
        "..",
        "wordlists",
        "app-dirs-common.txt",
    ),
)


@dataclass
class WorkerRecord:
    id: str
    kind: str
    url: str
    status: str = "queued"  # queued|running|completed|failed|cancelled
    brief: str = ""
    observations: List[Dict[str, str]] = field(default_factory=list)
    error: Optional[str] = None
    started_at: float = field(default_factory=time.time)
    finished_at: Optional[float] = None
    drained: bool = False
    task: Optional[asyncio.Task] = field(default=None, repr=False)


# session_id → worker_id → record
_registry: Dict[str, Dict[str, WorkerRecord]] = {}
_reg_lock = asyncio.Lock()
_capture_context: ContextVar[tuple[str, List[Dict[str, str]]] | None] = ContextVar(
    "recon_capture_context", default=None,
)


def _normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    if not u.startswith("http"):
        u = f"https://{u}"
    return u.rstrip("/") or u


def _wordlist_path() -> str:
    for p in _WORDLIST_CANDIDATES:
        if p and os.path.isfile(p):
            return p
    return "/opt/wordlists/app-dirs-common.txt"


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def extract_recon_urls(kind: str, brief: str, target: str) -> List[str]:
    """Return bounded, same-origin crawl discoveries for deterministic ingestion.

    Worker briefs may contain error text or third-party URLs. Only the two
    URL-discovery workers are eligible, and only URLs on the worker's exact
    origin are promoted into the capability map.
    """
    if kind not in {"katana_urls", "ferox_dirs"}:
        return []
    origin = urlparse(_normalize_url(target))
    if not origin.hostname:
        return []
    seen: set[str] = set()
    urls: List[str] = []
    for raw in re.findall(r"https?://[^\s\"'<>]+", brief or ""):
        candidate = raw.rstrip("),.;]}")
        parsed = urlparse(candidate)
        if (
            parsed.scheme != origin.scheme
            or parsed.netloc.lower() != origin.netloc.lower()
            or parsed.username
            or parsed.password
        ):
            continue
        normalized = parsed._replace(netloc=parsed.netloc.lower(), fragment="").geturl()
        if normalized in seen:
            continue
        seen.add(normalized)
        urls.append(normalized)
        if len(urls) >= 200:
            break
    return urls


def scoped_archive_urls(urls: Sequence[str], target: str) -> List[str]:
    """Map archived paths to the assessed origin without broadening host/port scope.

    Archive records are leads, not evidence that an endpoint is live. Historical
    HTTP entries are kept as paths on the current HTTPS origin for later checks.
    """
    origin = urlparse(_normalize_url(target))
    if not origin.hostname:
        return []
    found: List[str] = []
    seen: set[str] = set()
    for raw in urls:
        try:
            parsed = urlparse(str(raw))
            archive_port = parsed.port
        except ValueError:
            continue
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.hostname != origin.hostname
            or parsed.username or parsed.password
            or archive_port not in (None, origin.port)
            or not parsed.query
        ):
            continue
        # Keep only parameter names. Archived values may be stale secrets or
        # payloads, and ParamSpider often substitutes them with FUZZ.
        query = urlencode([
            (name, "") for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        candidate = urlunparse((origin.scheme, origin.netloc, parsed.path or "/",
                                parsed.params, query, ""))
        if candidate not in seen:
            seen.add(candidate)
            found.append(candidate)
        if len(found) >= 40:
            break
    return found


async def _emit(thought: str) -> None:
    try:
        from app.services.agent.orchestrator import _status_callback_var

        cb = _status_callback_var.get(None)
        if not cb:
            return
        maybe = cb({"type": "thinking", "phase": "informational", "thought": thought[:500]})
        if asyncio.iscoroutine(maybe):
            await maybe
    except Exception:
        pass


def _truncate(text: str, limit: int = 3500) -> str:
    t = (text or "").strip()
    if len(t) <= limit:
        return t
    return t[: limit - 20] + "\n…[truncated]"


async def _run_mcp(
    tools_manager: Any,
    tool_name: str,
    args: str,
    *,
    user_id: Optional[int],
    org_id: Optional[int],
    session_id: Optional[str],
) -> Dict[str, Any]:
    """Execute an MCP tool with tenant context restored for the background task."""
    from app.services.agent.tools import set_tenant_context

    if user_id is not None and org_id is not None:
        set_tenant_context(int(user_id), int(org_id), session_id=session_id)
    if tools_manager is None:
        return {"success": False, "output": "tools_manager unavailable", "error": "no_tools"}
    try:
        tools_manager._fallback_target = _normalize_url(
            getattr(tools_manager, "_fallback_target", "") or ""
        ) or None
    except Exception:
        pass
    result = await tools_manager.execute(tool_name, {"args": args})
    capture = _capture_context.get()
    if capture and tool_name in ("execute_katana", "execute_feroxbuster"):
        target, observations = capture
        kind = "katana_urls" if tool_name == "execute_katana" else "ferox_dirs"
        discovered = result.get("observations")
        if not isinstance(discovered, list):
            discovered = [
                {"type": "HTTP_ENDPOINT", "target": item, "source": tool_name}
                for item in extract_recon_urls(kind, str(result.get("output") or ""), target)
            ]
        candidate_text = "\n".join(
            str(item.get("target") or "") for item in discovered
            if isinstance(item, dict) and item.get("type") == "HTTP_ENDPOINT"
        )
        seen = {item.get("target") for item in observations}
        for url in extract_recon_urls(kind, candidate_text, target):
            if url in seen or len(observations) >= 200:
                continue
            seen.add(url)
            observations.append({"type": "HTTP_ENDPOINT", "target": url,
                                 "source": tool_name})
    return result


async def _worker_body(
    kind: str,
    url: str,
    tools_manager: Any,
    *,
    user_id: Optional[int],
    org_id: Optional[int],
    session_id: Optional[str],
) -> str:
    host = _host_from_url(url)
    wl = _wordlist_path()

    if kind == "httpx_tech":
        args = f"-u {url} -silent -tech-detect -status-code -title -web-server -json"
        res = await _run_mcp(
            tools_manager, "execute_httpx", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _truncate(str(res.get("output") or res.get("error") or ""))
        ok = bool(res.get("success"))
        return f"[recon_worker:httpx_tech] success={ok}\n{out}"

    if kind == "waf_probe":
        args = f"-a {url}"
        res = await _run_mcp(
            tools_manager, "execute_wafw00f", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _truncate(str(res.get("output") or res.get("error") or ""), 2000)
        return f"[recon_worker:waf_probe] success={bool(res.get('success'))}\n{out}"

    if kind == "whatweb":
        args = f"{url} --color=never -a 1"
        res = await _run_mcp(
            tools_manager, "execute_whatweb", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _truncate(str(res.get("output") or res.get("error") or ""), 2500)
        return f"[recon_worker:whatweb] success={bool(res.get('success'))}\n{out}"

    if kind == "ferox_dirs":
        args = (
            f"-u {url} -w {wl} -d 1 -t 15 --rate-limit 40 "
            f"--silent -C 404,429"
        )
        res = await _run_mcp(
            tools_manager, "execute_feroxbuster", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _truncate(str(res.get("output") or res.get("error") or ""), 4000)
        return (
            f"[recon_worker:ferox_dirs] success={bool(res.get('success'))} "
            f"wordlist={wl}\n{out}\n"
            "HINT: call ingest_urls_into_map with interesting paths."
        )

    if kind == "katana_urls":
        args = (
            f"-u {url} -d 2 -jc -fx "
            f"-ef woff,css,png,svg,jpg,woff2,jpeg,gif,ico -silent"
        )
        res = await _run_mcp(
            tools_manager, "execute_katana", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _truncate(str(res.get("output") or res.get("error") or ""), 4000)
        return (
            f"[recon_worker:katana_urls] success={bool(res.get('success'))}\n{out}\n"
            "HINT: call ingest_urls_into_map to fold URLs into the capability map."
        )

    if kind == "archive_params":
        from app.services.paramspider_service import (
            ParamSpiderService,
            filter_scannable_domains,
        )

        domains, _ = filter_scannable_domains([urlparse(url).hostname or host])
        if not domains:
            return "[recon_worker:archive_params] success=True skipped non-domain target"
        service = ParamSpiderService()
        if not service.is_available():
            raise RuntimeError("ParamSpider unavailable in backend image")
        result = await service.scan_domain(domains[0], timeout=100)
        if not result.success:
            raise RuntimeError(result.error or "ParamSpider archive query failed")
        leads = scoped_archive_urls(result.urls, url)
        capture = _capture_context.get()
        if capture:
            _, observations = capture
            observations.extend(
                {"type": "HTTP_ENDPOINT", "target": lead, "source": "paramspider_archive"}
                for lead in leads
            )
        preview = "\n".join(leads[:20])
        return (
            f"[recon_worker:archive_params] success=True "
            f"same_origin_leads={len(leads)} error={result.error or 'none'}\n"
            f"{preview}\nHistorical URLs are leads only; verify live before testing."
        )

    if kind == "nuclei_recon":
        args = nuclei_recon_args(url)
        res = await _run_mcp(
            tools_manager, "execute_nuclei", args,
            user_id=user_id, org_id=org_id, session_id=session_id,
        )
        out = _nuclei_recon_brief(res)
        return (
            f"[recon_worker:nuclei_recon] success={bool(res.get('success'))}\n{out}\n"
            "HINT: informational Nuclei only (tech/detect). Follow Augur "
            "pivots (WordPress → REST enum / wpscan, panel → bounded dir brute). "
            "Full CVE nuclei remains coverage leftover — this is not a vuln scan."
        )

    return f"[recon_worker:{kind}] unknown kind (host={host})"


def _nuclei_recon_brief(res: Dict[str, Any]) -> str:
    """Prefer Augur-filtered Nuclei text so Joshua sees signals, not JSONL."""
    raw = str(res.get("output") or res.get("error") or "")
    if res.get("augur"):
        return _truncate(raw, 4500)
    try:
        from aegis_praetorium.augur import filter_nuclei

        return _truncate(filter_nuclei(raw).to_text(), 4500)
    except Exception:
        return _truncate(raw, 4500)


async def spawn_workers(
    *,
    url: str,
    session_id: str,
    kinds: Optional[Sequence[str]] = None,
    pack: Optional[str] = None,
    tools_manager: Any = None,
    user_id: Optional[int] = None,
    organization_id: Optional[int] = None,
    skip_kinds: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Fire-and-forget workers for this session. Returns metadata for each spawn.
    Dedupes: will not start a second running worker of the same kind+url.
    """
    target = _normalize_url(url)
    if not target:
        return []
    sid = (session_id or "").strip() or "default"
    skip = {k.strip() for k in (skip_kinds or []) if k}

    if pack:
        wanted = list(PACKS.get(pack, []))
    else:
        wanted = [k for k in (kinds or []) if k in WORKER_KINDS]
    if not wanted:
        wanted = list(PACKS["early"])
    wanted = [k for k in wanted if k in WORKER_KINDS and k not in skip]
    if not wanted:
        return []

    spawned: List[Dict[str, Any]] = []
    async with _reg_lock:
        bucket = _registry.setdefault(sid, {})

        # Dedupe active same kind+url
        active_keys = {
            (r.kind, _normalize_url(r.url))
            for r in bucket.values()
            if r.status in ("queued", "running")
        }

        for kind in wanted:
            if (kind, target) in active_keys:
                existing = next(
                    (
                        r
                        for r in bucket.values()
                        if r.kind == kind
                        and _normalize_url(r.url) == target
                        and r.status in ("queued", "running")
                    ),
                    None,
                )
                spawned.append(
                    {
                        "worker_id": existing.id if existing else None,
                        "kind": kind,
                        "status": existing.status if existing else "running",
                        "note": "reused_active",
                    }
                )
                continue

            wid = f"rw_{uuid.uuid4().hex[:10]}"
            rec = WorkerRecord(id=wid, kind=kind, url=target, status="queued")
            bucket[wid] = rec

            async def _run(record: WorkerRecord = rec, k: str = kind) -> None:
                from app.core.config import settings
                from app.services.agent.action_fingerprint import action_fingerprint
                from app.services.agent.action_ledger import active_run_id, append_action

                run_id = active_run_id.get()
                fingerprint = action_fingerprint(
                    run_id=run_id, tool_name=f"recon_worker:{k}", target=target,
                    tool_args={}, secret_key=settings.SECRET_KEY,
                )
                observations: List[Dict[str, str]] = []
                capture_token = _capture_context.set((target, observations))
                timeout = float(_KIND_TIMEOUT_SEC.get(k, 120.0))
                try:
                    append_action(run_id, record.id, "started", f"recon_worker:{k}",
                                  target=target, fingerprint=fingerprint)
                    record.status = "running"
                    await _emit(f"Recon stream [{k}] started on {target}")
                    brief = await asyncio.wait_for(
                        _worker_body(
                            k,
                            target,
                            tools_manager,
                            user_id=user_id,
                            org_id=organization_id,
                            session_id=sid,
                        ),
                        timeout=timeout,
                    )
                    record.brief = brief
                    record.observations = observations[:200]
                    record.status = "completed"
                    await _emit(f"Recon stream [{k}] completed")
                except asyncio.TimeoutError:
                    record.status = "failed"
                    record.error = f"timeout after {timeout}s"
                    record.brief = f"[recon_worker:{k}] FAILED: timeout after {timeout}s"
                    await _emit(f"Recon stream [{k}] timed out")
                except asyncio.CancelledError:
                    record.status = "cancelled"
                    record.error = "cancelled"
                    raise
                except Exception as e:
                    record.status = "failed"
                    record.error = str(e)[:300]
                    record.brief = f"[recon_worker:{k}] FAILED: {e}"
                    logger.warning("recon worker %s failed: %s", k, e)
                    await _emit(f"Recon stream [{k}] failed: {str(e)[:120]}")
                finally:
                    _capture_context.reset(capture_token)
                    record.finished_at = time.time()
                    append_action(
                        run_id, record.id,
                        "completed" if record.status == "completed" else
                        "interrupted" if record.status == "cancelled" else "failed",
                        f"recon_worker:{k}", target=target,
                        detail=record.error or "",
                        fingerprint=fingerprint,
                    )

            rec.task = asyncio.create_task(_run())
            spawned.append(
                {
                    "worker_id": wid,
                    "kind": kind,
                    "status": "queued",
                    "note": "spawned",
                    "url": target,
                }
            )

    if spawned:
        kinds_s = ", ".join(s["kind"] for s in spawned)
        await _emit(f"Spawned recon streams: {kinds_s}")
    return spawned


async def drain_completed(
    session_id: str,
    *,
    wait_sec: float = 0.0,
    include_failed: bool = True,
) -> List[Dict[str, Any]]:
    """
    Collect finished workers not yet drained.
    wait_sec>0 briefly waits for in-flight workers (Copilot-style soft join).
    """
    sid = (session_id or "").strip() or "default"
    if wait_sec > 0:
        deadline = time.time() + wait_sec
        while time.time() < deadline:
            async with _reg_lock:
                bucket = _registry.get(sid) or {}
                pending = [
                    r for r in bucket.values()
                    if r.status in ("queued", "running")
                ]
            if not pending:
                break
            await asyncio.sleep(0.4)

    out: List[Dict[str, Any]] = []
    async with _reg_lock:
        bucket = _registry.get(sid) or {}
        for rec in bucket.values():
            if rec.drained:
                continue
            if rec.status == "completed" or (include_failed and rec.status == "failed"):
                rec.drained = True
                out.append(
                    {
                        "worker_id": rec.id,
                        "kind": rec.kind,
                        "status": rec.status,
                        "brief": rec.brief,
                        "observations": rec.observations if rec.status == "completed" else [],
                        "urls": ([item["target"] for item in rec.observations]
                                 if rec.observations else extract_recon_urls(rec.kind, rec.brief, rec.url))
                        if rec.status == "completed" else [],
                        "url": rec.url,
                        "error": rec.error,
                    }
                )
    return out


async def list_workers(session_id: str) -> List[Dict[str, Any]]:
    sid = (session_id or "").strip() or "default"
    async with _reg_lock:
        bucket = _registry.get(sid) or {}
        return [
            {
                "worker_id": r.id,
                "kind": r.kind,
                "status": r.status,
                "url": r.url,
                "drained": r.drained,
                "error": r.error,
                "elapsed_sec": round(
                    (r.finished_at or time.time()) - r.started_at, 1
                ),
            }
            for r in bucket.values()
        ]


async def wait_workers(
    session_id: str,
    *,
    timeout_sec: float = 45.0,
    worker_ids: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Block until listed (or all) workers finish, then drain them."""
    sid = (session_id or "").strip() or "default"
    want = {w for w in (worker_ids or []) if w}
    deadline = time.time() + max(1.0, timeout_sec)

    while time.time() < deadline:
        async with _reg_lock:
            bucket = _registry.get(sid) or {}
            targets = [
                r
                for r in bucket.values()
                if (not want or r.id in want)
                and r.status in ("queued", "running")
            ]
        if not targets:
            break
        await asyncio.sleep(0.5)

    return await drain_completed(sid, wait_sec=0.0)


def format_briefs_for_prompt(briefs: Sequence[Dict[str, Any]]) -> str:
    if not briefs:
        return ""
    lines = ["## Parallel recon streams (completed)"]
    for b in briefs:
        lines.append(
            f"### {b.get('kind')} [{b.get('status')}] id={b.get('worker_id')}"
        )
        lines.append((b.get("brief") or "")[:4000])
        lines.append("")
    return "\n".join(lines)


def clear_session(session_id: str) -> None:
    """Best-effort cancel (used on session end if desired)."""
    sid = (session_id or "").strip() or "default"
    bucket = _registry.pop(sid, {})
    for r in bucket.values():
        if r.task and not r.task.done():
            r.task.cancel()
