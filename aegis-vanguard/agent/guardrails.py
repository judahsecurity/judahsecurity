"""
Guardrails Engine for Aegis Vanguard Agent Framework

Multi-layered defense system that validates tool inputs and outputs
before execution. Blocks prompt injection, dangerous commands, and
out-of-scope operations at the execution layer (not just in prompts).
"""

import base64
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

logger = logging.getLogger("agent.guardrails")


@dataclass
class GuardrailViolation:
    rule: str
    description: str
    severity: str  # warning, block
    tool_name: str = ""
    argument: str = ""


BLOCKED_COMMANDS = [
    # Reverse shells
    r"bash\s+-i\s+>&\s*/dev/tcp",
    r"nc\s+.*\s+-e\s+/bin/(ba)?sh",
    r"python.*import\s+socket.*connect",
    r"perl\s+-e.*socket",
    r"ruby\s+-rsocket",
    r"mkfifo.*nc\s+",
    r"socat\s+.*exec:",
    # Fork bombs
    r":\(\)\{.*\|.*&\s*\}",
    r"fork\s*while\s*fork",
    # Destructive
    r"rm\s+-rf\s+/\s",
    r"rm\s+-rf\s+/\*",
    r"mkfs\.",
    r"dd\s+if=.*/dev/zero.*of=.*/dev/sd",
    r">\s*/dev/sd[a-z]",
    # Data exfiltration
    r"curl.*\|\s*bash",
    r"wget.*\|\s*sh",
    r"curl\s+.*-d\s+@/etc/(passwd|shadow)",
    r"tar\s+.*\|\s*(nc|curl|wget)",
    r"cat\s+/etc/(shadow|passwd).*\|\s*(curl|nc|wget)",
    # Crypto mining
    r"(xmrig|minerd|cgminer|bfgminer)",
    r"stratum\+tcp://",
    # Credential dumping (beyond validation)
    r"mimikatz",
    r"hashdump",
    r"secretsdump",
]

BLOCKED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in BLOCKED_COMMANDS]

SQLMAP_SAFE_FLAGS = {"--batch", "--level", "--risk", "--forms", "--output-dir"}
SQLMAP_BLOCKED_FLAGS = {"--os-shell", "--os-cmd", "--os-pwn", "--priv-esc", "--file-write", "--file-read"}


class GuardrailEngine:
    """Validates tool calls before execution."""

    def __init__(
        self,
        enabled: bool = True,
        scope_domains: Optional[List[str]] = None,
        max_risk: str = "high",
    ):
        self.enabled = enabled if os.environ.get("AEGIS_GUARDRAILS", "true").lower() != "false" else False
        self.scope_domains: Set[str] = set(scope_domains or [])
        self.max_risk = max_risk
        self._risk_levels = ["safe", "low", "medium", "high", "critical"]
        self.violations: List[GuardrailViolation] = []

    def check_tool_call(self, tool_name: str, arguments: dict, risk_level: str = "safe") -> Optional[GuardrailViolation]:
        if not self.enabled:
            return None

        risk_idx = self._risk_levels.index(risk_level) if risk_level in self._risk_levels else 0
        max_idx = self._risk_levels.index(self.max_risk) if self.max_risk in self._risk_levels else 3
        if risk_idx > max_idx:
            v = GuardrailViolation(
                rule="risk_level",
                description=f"Tool {tool_name} has risk '{risk_level}' exceeding max '{self.max_risk}'",
                severity="block",
                tool_name=tool_name,
            )
            self.violations.append(v)
            return v

        for key, val in arguments.items():
            if not isinstance(val, str):
                continue

            violation = self._check_blocked_commands(val, tool_name, key)
            if violation:
                return violation

            violation = self._check_encoded_payloads(val, tool_name, key)
            if violation:
                return violation

        if self.scope_domains:
            violation = self._check_scope(tool_name, arguments)
            if violation:
                return violation

        if tool_name in ("run_sqlmap", "sql_injection_test"):
            violation = self._check_sqlmap_safety(arguments)
            if violation:
                return violation

        return None

    def _check_blocked_commands(self, value: str, tool_name: str, arg_name: str) -> Optional[GuardrailViolation]:
        for pattern in BLOCKED_PATTERNS:
            if pattern.search(value):
                v = GuardrailViolation(
                    rule="blocked_command",
                    description=f"Blocked dangerous command pattern in {tool_name}.{arg_name}: {pattern.pattern}",
                    severity="block",
                    tool_name=tool_name,
                    argument=arg_name,
                )
                self.violations.append(v)
                logger.warning(f"GUARDRAIL BLOCK: {v.description}")
                return v
        return None

    def _check_encoded_payloads(self, value: str, tool_name: str, arg_name: str) -> Optional[GuardrailViolation]:
        for decoder, name in [(base64.b64decode, "base64"), (base64.b32decode, "base32")]:
            if len(value) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', value):
                try:
                    decoded = decoder(value).decode("utf-8", errors="ignore")
                    for pattern in BLOCKED_PATTERNS:
                        if pattern.search(decoded):
                            v = GuardrailViolation(
                                rule="encoded_payload",
                                description=f"Blocked {name}-encoded dangerous payload in {tool_name}.{arg_name}",
                                severity="block",
                                tool_name=tool_name,
                                argument=arg_name,
                            )
                            self.violations.append(v)
                            logger.warning(f"GUARDRAIL BLOCK: {v.description}")
                            return v
                except Exception:
                    pass
        return None

    def _check_scope(self, tool_name: str, arguments: dict) -> Optional[GuardrailViolation]:
        # Multi-URL tools: newline- or comma-separated list
        urls_blob = arguments.get("urls")
        if isinstance(urls_blob, str) and urls_blob.strip():
            for piece in re.split(r"[\n,]+", urls_blob):
                u = piece.strip()
                if not u.startswith("http"):
                    continue
                fake = {"url": u}
                v = self._check_scope(tool_name, fake)
                if v:
                    return v

        target_keys = ("target", "domain", "host", "target_url", "url", "hosts")
        for key in target_keys:
            val = arguments.get(key)
            if not val:
                continue
            targets = val if isinstance(val, list) else [val]
            for target in targets:
                if not isinstance(target, str):
                    continue
                target_clean = target.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
                in_scope = any(
                    target_clean == d or target_clean.endswith(f".{d}")
                    for d in self.scope_domains
                )
                if not in_scope:
                    v = GuardrailViolation(
                        rule="scope_violation",
                        description=f"Target '{target_clean}' not in scope {self.scope_domains}",
                        severity="block",
                        tool_name=tool_name,
                        argument=key,
                    )
                    self.violations.append(v)
                    logger.warning(f"GUARDRAIL BLOCK: {v.description}")
                    return v
        return None

    def _check_sqlmap_safety(self, arguments: dict) -> Optional[GuardrailViolation]:
        for key, val in arguments.items():
            if not isinstance(val, str):
                continue
            for flag in SQLMAP_BLOCKED_FLAGS:
                if flag in val:
                    v = GuardrailViolation(
                        rule="sqlmap_safety",
                        description=f"Blocked unsafe sqlmap flag: {flag}",
                        severity="block",
                        tool_name="run_sqlmap",
                        argument=key,
                    )
                    self.violations.append(v)
                    return v
        return None

    def check_prompt_injection(self, text: str) -> Optional[GuardrailViolation]:
        """Check for prompt injection attempts in user/agent text."""
        if not self.enabled:
            return None

        injection_patterns = [
            r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
            r"you\s+are\s+now\s+(a|an)\s+(unrestricted|unfiltered|evil)",
            r"(system|admin)\s*:\s*override",
            r"forget\s+(everything|all|your\s+instructions)",
            r"new\s+instructions?\s*:",
            r"jailbreak",
            r"DAN\s+mode",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                v = GuardrailViolation(
                    rule="prompt_injection",
                    description=f"Potential prompt injection detected: {pattern}",
                    severity="block",
                )
                self.violations.append(v)
                logger.warning(f"GUARDRAIL BLOCK: Prompt injection attempt detected")
                return v
        return None
