"""
Lictor — Aegis Vanguard's pre/post tool-execution enforcer.

Named after the Roman lictors who walked before magistrates carrying the fasces,
Lictor is the deterministic guard layer that sits between the agent and every
security-tool invocation. It runs **PreToolUse** hooks (block, rewrite, or
allow a command before it spawns) and **PostToolUse** hooks (audit, sanitize
results).

Design goals:
- Single chokepoint for SSRF, scope, destructive-flag, and rate-limit
  enforcement across every tool every agent calls (platform agent + Aegis Vanguard).
- Hooks are pluggable: register additional pre/post hooks at startup.
- Hooks cannot be bypassed by the LLM — equivalent to Praetorian's PreToolUse
  / PostToolUse / Stop Claude Code lifecycle events.

Default hooks installed:
  PRE:
    - block_ssrf_targets        (cloud metadata + localhost across all tools)
    - block_destructive_flags   (per-tool flag denylist; sqlmap --os-shell, etc.)
    - inject_safe_defaults      (centralized --batch / --no-banner / etc.)
    - enforce_scope             (delegates to the registered ScopeResolver)
    - rate_limit                (per-(org, tool) token bucket)
  POST:
    - audit_log                 (structured log row per call)
    - clip_output               (defensive cap, separate from Augur filtering)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from aegis_praetorium.config import get_config
from aegis_praetorium.scope import get_scope_resolver

logger = logging.getLogger("aegis.lictor")


# ---------------------------------------------------------------------------
# Hook protocol
# ---------------------------------------------------------------------------


@dataclass
class HookContext:
    """Context passed to PreToolUse hooks."""

    tool_name: str
    args: str                      # raw CLI args string (or "" for kwarg-style invocations)
    parsed_args: List[str]         # shlex.split result (or all string kwarg values)
    command: List[str]             # full argv (binary + parsed_args)
    inspectable_text: Optional[str] = None  # text for SSRF / destructive scans
    org_id: Optional[int] = None
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def text(self) -> str:
        """Return inspectable text for SSRF / destructive-flag scans."""
        return self.inspectable_text if self.inspectable_text is not None else " ".join(self.command)


@dataclass
class HookResult:
    """Result returned by a PreToolUse hook."""

    allowed: bool = True
    reason: Optional[str] = None
    modified_command: Optional[List[str]] = None  # rewrite command before spawn
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostHookContext:
    """Context passed to PostToolUse hooks."""

    tool_name: str
    args: str
    command: List[str]
    result: Dict[str, Any]         # {success, output, error, exit_code}
    duration_ms: float
    org_id: Optional[int] = None
    user_id: Optional[int] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostHookResult:
    """Result returned by a PostToolUse hook."""

    modified_result: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


PreHook = Callable[[HookContext], HookResult]
PostHook = Callable[[PostHookContext], PostHookResult]


# ---------------------------------------------------------------------------
# Default hooks
# ---------------------------------------------------------------------------


# Cloud metadata + localhost patterns blocked for every tool.
_SSRF_PATTERNS = [
    "169.254.169.254",   # AWS / DigitalOcean / Hetzner metadata
    "metadata.google",   # GCP metadata
    "metadata.azure",    # Azure IMDS
    "100.100.100.200",   # Alibaba metadata
    "fd00:ec2::254",     # AWS IMDSv6
    "file://",
    "gopher://",
    "dict://",
    "ldap://localhost",
    "ftp://localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::1]",
    " ::1 ",
    "localhost",
]

# Per-tool destructive-flag denylist. Add flags as we discover them. Tool-name
# aliases for both naming conventions (platform: ``execute_X``, Aegis Vanguard: ``X``).
_DESTRUCTIVE_FLAGS: Dict[str, List[str]] = {
    "sqlmap": [
        "--os-shell", "--os-pwn", "--os-cmd", "--os-bof",
        "--file-write", "--file-dest", "--reg-add", "--reg-del", "--purge",
    ],
    "nmap": [
        "--script=vuln", "--script vuln",
        "--script=exploit", "--script exploit",
        "--script=brute", "--script brute",
        "--script=dos", "--script dos",
    ],
    "masscan": ["--banners"],
    "nuclei": ["-as", "-fuzz", "-dast"],
    "xsstrike": ["--blind"],
    "browser": ["evaluate_xss_payload"],
    "ffuf": ["-x http://", "-x https://"],
    "hydra": ["-e nsr"],  # empty/null/reverse sprays without explicit lists
    "commix": ["--os-shell", "--os-pwn"],
}

# Centralize tool defaults that used to be in individual handlers.
_SAFE_DEFAULTS: Dict[str, List[str]] = {
    "sqlmap": ["--batch"],
    "wpscan": ["--no-banner"],
    "nikto": ["-Tuning", "1234567"],
    "commix": ["--batch"],
    "hydra": ["-f"],
}


def _canonical_tool(tool_name: str) -> str:
    """Strip ``execute_`` / ``scan_`` prefixes so platform + Aegis Vanguard share lookups."""
    for prefix in ("execute_", "scan_", "run_"):
        if tool_name.startswith(prefix):
            return tool_name[len(prefix):]
    return tool_name


def _extract_targets(parsed_args: List[str]) -> List[str]:
    """Best-effort extraction of URL / hostname targets from a command line."""
    targets: List[str] = []
    flag_consumes_value = {
        "-u", "--url", "-host", "--host", "-target", "--target",
        "-d", "--domain", "-h",
    }
    skip_next = False
    for tok in parsed_args:
        if skip_next:
            targets.append(tok)
            skip_next = False
            continue
        if tok in flag_consumes_value:
            skip_next = True
            continue
        for f in flag_consumes_value:
            if tok.startswith(f + "="):
                targets.append(tok.split("=", 1)[1])
                break
        else:
            if tok.startswith(("http://", "https://")):
                targets.append(tok)
    return targets


def _hostname_from_target(target: str) -> Optional[str]:
    """Extract bare hostname from a URL or host:port string."""
    t = (target or "").strip()
    if not t:
        return None
    if t.startswith(("http://", "https://")):
        try:
            p = urlparse(t)
            return (p.hostname or "").lower() or None
        except Exception:
            return None
    return t.split("/")[0].split(":")[0].lower() or None


def block_ssrf_targets(ctx: HookContext) -> HookResult:
    """Block requests to cloud metadata endpoints and loopback across ALL tools."""
    haystack = ctx.text().lower()
    for needle in _SSRF_PATTERNS:
        if needle.lower() in haystack:
            logger.warning(
                "lictor.block_ssrf_targets: blocked %s — pattern=%s",
                ctx.tool_name, needle,
            )
            return HookResult(
                allowed=False,
                reason=(
                    f"Lictor blocked {ctx.tool_name}: SSRF guard hit pattern "
                    f"'{needle}'. Cloud metadata endpoints, loopback, and non-HTTP "
                    f"protocol handlers (file://, gopher://, dict://) are denied "
                    f"for every tool. Use an external in-scope target."
                ),
            )
    return HookResult(allowed=True)


def block_destructive_flags(ctx: HookContext) -> HookResult:
    """Per-tool denylist for high-risk CLI flags (sqlmap --os-shell, etc.)."""
    flags = _DESTRUCTIVE_FLAGS.get(_canonical_tool(ctx.tool_name))
    if not flags:
        return HookResult(allowed=True)
    haystack = " " + ctx.text() + " "
    for flag in flags:
        if f" {flag} " in haystack or f" {flag}=" in haystack:
            logger.warning(
                "lictor.block_destructive_flags: blocked %s — flag=%s",
                ctx.tool_name, flag,
            )
            return HookResult(
                allowed=False,
                reason=(
                    f"Lictor blocked {ctx.tool_name}: flag '{flag}' is in the "
                    f"destructive-action denylist. This action requires a "
                    f"scoped engagement and is gated by Lictor."
                ),
            )
    return HookResult(allowed=True)


def inject_safe_defaults(ctx: HookContext) -> HookResult:
    """Centrally inject non-interactive / quiet defaults (replaces per-handler hacks)."""
    extras = _SAFE_DEFAULTS.get(_canonical_tool(ctx.tool_name))
    if not extras:
        return HookResult(allowed=True)
    cmd = list(ctx.command)
    added: List[str] = []
    for e in extras:
        if e.startswith("-"):
            present = any(c == e or c.startswith(e + "=") for c in cmd)
        else:
            present = e in cmd
        if not present:
            cmd.extend(e.split())
            added.append(e)
    if added:
        logger.debug("lictor.inject_safe_defaults: %s += %s", ctx.tool_name, added)
        return HookResult(allowed=True, modified_command=cmd, metadata={"injected": added})
    return HookResult(allowed=True)


def enforce_scope(ctx: HookContext) -> HookResult:
    """Verify every URL/host target resolves to a hostname the registered
    ``ScopeResolver`` accepts. Soft-fails open if scope enforcement is disabled
    in config or no targets can be extracted from the command."""
    if not get_config().enforce_scope:
        return HookResult(allowed=True)
    targets = _extract_targets(ctx.parsed_args)
    if not targets:
        return HookResult(allowed=True)
    hostnames = {h for h in (_hostname_from_target(t) for t in targets) if h}
    if not hostnames:
        return HookResult(allowed=True)
    resolver = get_scope_resolver()
    out_of_scope = [h for h in hostnames if not resolver.is_in_scope(h, org_id=ctx.org_id)]
    if out_of_scope:
        logger.warning(
            "lictor.enforce_scope: blocked %s — out_of_scope=%s",
            ctx.tool_name, out_of_scope,
        )
        return HookResult(
            allowed=False,
            reason=(
                f"Lictor blocked {ctx.tool_name}: target(s) "
                f"{', '.join(sorted(out_of_scope))} are not in the registered "
                f"scope for this engagement. Add the asset first or choose an "
                f"in-scope target."
            ),
        )
    return HookResult(allowed=True)


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (per (org, tool))
# ---------------------------------------------------------------------------


class _TokenBucket:
    """Thread-safe token bucket. capacity tokens, refilled at refill_rate per second."""

    __slots__ = ("capacity", "refill_rate", "tokens", "last_refill", "_lock")

    def __init__(self, capacity: int, refill_rate: float) -> None:
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self._lock = Lock()

    def take(self, n: int = 1) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


_RATE_BUCKETS: Dict[Tuple[Optional[int], str], _TokenBucket] = {}
_RATE_BUCKETS_LOCK = Lock()


def rate_limit(ctx: HookContext) -> HookResult:
    """Per-(org, tool) token-bucket rate limit. Defaults: 30 calls / min / tool / org."""
    cfg = get_config()
    capacity = cfg.rate_capacity
    per_minute = cfg.rate_per_minute
    refill = max(per_minute, 1) / 60.0
    key = (ctx.org_id, ctx.tool_name)
    with _RATE_BUCKETS_LOCK:
        bucket = _RATE_BUCKETS.get(key)
        if bucket is None:
            bucket = _TokenBucket(capacity=capacity, refill_rate=refill)
            _RATE_BUCKETS[key] = bucket
    if bucket.take(1):
        return HookResult(allowed=True)
    logger.warning("lictor.rate_limit: throttled %s (org=%s)", ctx.tool_name, ctx.org_id)
    return HookResult(
        allowed=False,
        reason=(
            f"Lictor throttled {ctx.tool_name}: per-org rate limit "
            f"({per_minute}/min, burst {capacity}) exceeded. Wait or dispatch "
            f"as a background job."
        ),
    )


def audit_log(ctx: PostHookContext) -> PostHookResult:
    """Structured audit log row per tool call (post-execution)."""
    out_size = len((ctx.result or {}).get("output", "") or "")
    err_size = len((ctx.result or {}).get("error", "") or "") if (ctx.result or {}).get("error") else 0
    logger.info(
        "aegis.audit tool=%s org=%s user=%s session=%s exit=%s duration_ms=%.1f "
        "out_bytes=%d err_bytes=%d injected=%s",
        ctx.tool_name, ctx.org_id, ctx.user_id, ctx.session_id,
        (ctx.result or {}).get("exit_code"),
        ctx.duration_ms, out_size, err_size,
        ctx.metadata.get("injected"),
    )
    return PostHookResult()


# Rough cap per single tool invocation to defend against runaway output even
# if Augur is disabled. Augur's smart filter still runs upstream for typed outputs.
_HARD_OUTPUT_CAP = 4_000_000  # 4 MB safety lid


def clip_output(ctx: PostHookContext) -> PostHookResult:
    out = (ctx.result or {}).get("output") or ""
    if len(out) > _HARD_OUTPUT_CAP:
        clipped = out[:_HARD_OUTPUT_CAP] + (
            f"\n\n... (lictor: hard-capped at {_HARD_OUTPUT_CAP} bytes; total "
            f"{len(out)} bytes — refine your query)"
        )
        new_result = dict(ctx.result)
        new_result["output"] = clipped
        return PostHookResult(modified_result=new_result)
    return PostHookResult()


# ---------------------------------------------------------------------------
# Lictor — the chokepoint
# ---------------------------------------------------------------------------


class Lictor:
    """Pre/post tool-execution enforcer. The agent cannot bypass this layer."""

    def __init__(self) -> None:
        self._pre: List[PreHook] = []
        self._post: List[PostHook] = []
        self._install_defaults()

    def _install_defaults(self) -> None:
        # Order matters: cheap denies first, then mutators, then rate limit last.
        self.add_pre_hook(block_ssrf_targets)
        self.add_pre_hook(block_destructive_flags)
        self.add_pre_hook(inject_safe_defaults)
        self.add_pre_hook(enforce_scope)
        self.add_pre_hook(rate_limit)
        self.add_post_hook(audit_log)
        self.add_post_hook(clip_output)

    def add_pre_hook(self, hook: PreHook) -> None:
        self._pre.append(hook)

    def add_post_hook(self, hook: PostHook) -> None:
        self._post.append(hook)

    def run_pre(self, ctx: HookContext) -> HookResult:
        """Run every pre-hook in order. First deny short-circuits."""
        accumulated_meta: Dict[str, Any] = {}
        cmd = ctx.command
        for hook in self._pre:
            ctx.command = cmd
            ctx.metadata = {**ctx.metadata, **accumulated_meta}
            try:
                res = hook(ctx)
            except Exception as e:
                logger.exception("lictor pre-hook %s raised: %s", hook.__name__, e)
                continue
            if not res.allowed:
                return res
            if res.modified_command is not None:
                cmd = res.modified_command
            if res.metadata:
                accumulated_meta.update(res.metadata)
        return HookResult(allowed=True, modified_command=cmd, metadata=accumulated_meta)

    def run_post(self, ctx: PostHookContext) -> PostHookResult:
        """Run every post-hook in order. Last writer wins for modified_result."""
        result = ctx.result
        meta = dict(ctx.metadata or {})
        for hook in self._post:
            ctx.result = result
            ctx.metadata = meta
            try:
                res = hook(ctx)
            except Exception as e:
                logger.exception("lictor post-hook %s raised: %s", hook.__name__, e)
                continue
            if res.modified_result is not None:
                result = res.modified_result
            if res.metadata:
                meta.update(res.metadata)
        return PostHookResult(modified_result=result, metadata=meta)


_lictor: Optional[Lictor] = None
_lictor_lock = Lock()


def get_lictor() -> Lictor:
    global _lictor
    if _lictor is None:
        with _lictor_lock:
            if _lictor is None:
                _lictor = Lictor()
    return _lictor


__all__ = [
    "Lictor",
    "HookContext",
    "HookResult",
    "PostHookContext",
    "PostHookResult",
    "get_lictor",
]
