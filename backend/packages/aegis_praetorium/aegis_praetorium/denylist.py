"""
aegis_praetorium.denylist — "never touch" targets, checked before every tool call.

Scope enforcement answers "is this target registered for the org?". The
denylist answers a different question: "is this a target we must never send
traffic to, whatever the agent believes about scope?". It runs even when scope
enforcement and Rules of Engagement are off.

Rules come from two places:

  - Built-in defaults (government and military suffixes). An org can override a
    default only by naming the host explicitly in ``DenyPolicy.allow_hosts``
    (the platform feeds RoE ``scope_in`` here), which records written
    authorization instead of a silent toggle.
  - Org rules from the registered ``DenyPolicyProvider`` (RoE ``scope_out`` hosts
    and admin-written regex patterns). These cannot be overridden by allow_hosts.

Matching inspects every hostname and IPv4 literal that appears anywhere in the
tool's argument text, not only flag values, so a positional ``nmap host.gov``
or a JSON body that embeds a URL is still caught.

Dry run: ``PraetoriumConfig.denylist_dry_run`` turns every block into a logged
"would block". ``DenyPolicy.dry_run`` does the same for the org's own rules only;
it never relaxes the built-in defaults.

Stdlib only, like the rest of the package.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from threading import Lock
from typing import Iterable, List, Optional, Protocol, Sequence, Tuple, runtime_checkable

from aegis_praetorium.config import get_config

logger = logging.getLogger("aegis.denylist")

# Inspect at most this much argument text (regex cost bound for admin patterns).
_MAX_INSPECT_CHARS = 64_000
MAX_PATTERN_LENGTH = 300

_HOST_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63})"
    r"(?![A-Za-z0-9_-])"
)
_IPV4_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")


@dataclass(frozen=True)
class DenyRule:
    """One denylist entry.

    kind:
      ``host``  — hostname suffix (``example.com`` also covers ``a.example.com``),
                  ``*.example.com`` wildcard, exact IP, or CIDR.
      ``regex`` — case-insensitive regex searched in the argument text.
    """

    kind: str
    pattern: str
    reason: str = ""
    source: str = "org"          # "default" | "org"
    overridable: bool = False    # may allow_hosts lift it? (defaults only)


@dataclass(frozen=True)
class DenyPolicy:
    rules: Tuple[DenyRule, ...] = ()
    allow_hosts: Tuple[str, ...] = ()   # explicit authorization for overridable rules
    dry_run: bool = False               # org rules log instead of block
    include_defaults: bool = True


@dataclass
class DenyVerdict:
    blocked: bool = False
    dry_run_hits: List[str] = field(default_factory=list)
    rule: Optional[DenyRule] = None
    matched: str = ""
    reason: str = ""

    @property
    def would_block(self) -> bool:
        return bool(self.dry_run_hits)


_GOV_REASON = "Government or military domain: never tested without explicit written authorization."

DEFAULT_DENY_RULES: Tuple[DenyRule, ...] = tuple(
    DenyRule(kind="host", pattern=suffix, reason=_GOV_REASON, source="default", overridable=True)
    for suffix in (
        "gov", "mil", "fed.us", "gov.uk", "mod.uk", "police.uk", "gc.ca",
        "gov.au", "govt.nz", "gouv.fr", "bund.de", "gov.in", "nic.in",
        "go.jp", "gov.cn", "gov.br", "gob.mx", "gov.sg", "gov.za",
        "europa.eu", "int",
    )
)


@runtime_checkable
class DenyPolicyProvider(Protocol):
    def policy_for(self, org_id: Optional[int]) -> DenyPolicy: ...


class StaticDenyPolicyProvider:
    """Same policy for every org (Vanguard CLI, tests)."""

    def __init__(self, policy: Optional[DenyPolicy] = None) -> None:
        self._policy = policy or DenyPolicy()

    def policy_for(self, org_id: Optional[int]) -> DenyPolicy:
        return self._policy


_provider: DenyPolicyProvider = StaticDenyPolicyProvider()
_provider_lock = Lock()


def set_deny_policy_provider(provider: DenyPolicyProvider) -> None:
    global _provider
    with _provider_lock:
        _provider = provider


def get_deny_policy_provider() -> DenyPolicyProvider:
    return _provider


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


def extract_hosts(text: str) -> List[str]:
    """Every hostname and IPv4 literal found in ``text``, lowercased, deduped in order."""
    seen: dict = {}
    for m in _HOST_RE.finditer(text):
        seen.setdefault(m.group(1).lower().rstrip("."), None)
    for m in _IPV4_RE.finditer(text):
        try:
            ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        seen.setdefault(m.group(1), None)
    return list(seen)


def host_matches(host: str, rule: str) -> bool:
    """Hostname suffix, ``*.`` wildcard, exact IP, or CIDR match."""
    host = (host or "").strip().lower().rstrip(".")
    rule = (rule or "").strip().lower().rstrip(".")
    if not host or not rule:
        return False
    if "/" in rule:
        try:
            return ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    try:
        rule_ip = ipaddress.ip_address(rule)
    except ValueError:
        rule_ip = None
    if rule_ip is not None:
        return host == str(rule_ip)
    if rule.startswith("*."):
        rule = rule[2:]
    rule = rule.lstrip(".")
    return host == rule or host.endswith("." + rule)


def compile_pattern(pattern: str) -> re.Pattern:
    """Compile an admin regex; raises ``ValueError`` with a readable message."""
    if not pattern or not pattern.strip():
        raise ValueError("Pattern is empty")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(f"Pattern is longer than {MAX_PATTERN_LENGTH} characters")
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        raise ValueError(f"Invalid regex {pattern!r}: {e}") from e


def _rule_hit(rule: DenyRule, text: str, hosts: Sequence[str]) -> Optional[str]:
    if rule.kind == "host":
        for h in hosts:
            if host_matches(h, rule.pattern):
                return h
        return None
    if rule.kind == "regex":
        try:
            m = compile_pattern(rule.pattern).search(text)
        except ValueError as e:
            logger.warning("denylist: skipping bad pattern: %s", e)
            return None
        return m.group(0)[:200] if m else None
    return None


def evaluate(
    texts: Iterable[str],
    org_id: Optional[int] = None,
    policy: Optional[DenyPolicy] = None,
) -> DenyVerdict:
    """Check argument text against defaults + the org's policy. Never raises.

    ``policy`` overrides the registered provider (used for previews).
    """
    cfg = get_config()
    if not cfg.denylist_enabled:
        return DenyVerdict()
    text = "\n".join(t for t in texts if isinstance(t, str) and t)[:_MAX_INSPECT_CHARS]
    if not text:
        return DenyVerdict()

    if policy is None:
        try:
            policy = get_deny_policy_provider().policy_for(org_id)
        except Exception as e:  # provider failure must not drop the defaults
            logger.error("denylist: policy provider failed (%s); defaults only", e)
            policy = DenyPolicy()

    rules: List[DenyRule] = list(DEFAULT_DENY_RULES) if policy.include_defaults else []
    rules.extend(policy.rules)
    hosts = extract_hosts(text)
    verdict = DenyVerdict()

    for rule in rules:
        hit = _rule_hit(rule, text, hosts)
        if not hit:
            continue
        if (rule.overridable and rule.kind == "host"
                and any(host_matches(hit, a) for a in policy.allow_hosts)):
            continue
        dry = cfg.denylist_dry_run or (policy.dry_run and rule.source == "org")
        label = f"{rule.source}:{rule.kind}:{rule.pattern} matched {hit!r}"
        if dry:
            verdict.dry_run_hits.append(label)
            logger.warning("denylist dry-run: would block — %s", label)
            continue
        verdict.blocked = True
        verdict.rule = rule
        verdict.matched = hit
        why = f" {rule.reason}" if rule.reason else ""
        verdict.reason = (
            f"Denylist blocked this call: {hit!r} matches never-touch rule "
            f"{rule.pattern!r} ({rule.source}).{why} Do not retry against this "
            f"target or route around it with another tool."
        )
        return verdict
    return verdict


__all__ = [
    "DEFAULT_DENY_RULES",
    "DenyPolicy",
    "DenyPolicyProvider",
    "DenyRule",
    "DenyVerdict",
    "StaticDenyPolicyProvider",
    "compile_pattern",
    "evaluate",
    "extract_hosts",
    "get_deny_policy_provider",
    "host_matches",
    "set_deny_policy_provider",
]
