"""Server-owned out-of-band payloads for blind OS command injection.

A command whose output never reaches the response can still be proven if the
injected command performs a DNS lookup of a freshly registered collaborator.
Only a lookup is ever sent (``nslookup``); nothing writes, deletes, or opens a
shell. Registration, planting, polling, and correlation are owned by
``oob_callback_workflow`` and validated by ``proof_policy`` (kind
``oob_callback``), which also requires the planted request to carry this
module's lookup so a URL-fetch (SSRF) callback cannot pass as command injection.
"""

from __future__ import annotations

from .sqli_oob import observed_value

CMDI_SHELLS = ("posix_subshell", "posix_separator", "windows_separator")
LOOKUP_COMMAND = "nslookup"

_TEMPLATES = {
    "posix_subshell": "$(nslookup {{callback_host}})",
    "posix_separator": ";nslookup {{callback_host}};",
    "windows_separator": "&nslookup {{callback_host}}&",
}


def plan_oob_cmdi(url: str, *, parameter: str, shell: str) -> tuple[str, str]:
    """Return ``(field, template)`` for a ``query_template`` callback probe."""
    if shell not in CMDI_SHELLS:
        raise ValueError("unsupported_cmdi_shell")
    value = observed_value(url, parameter=parameter)
    return parameter, value + _TEMPLATES[shell]
