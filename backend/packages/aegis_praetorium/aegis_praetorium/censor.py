"""
Censor — Aegis Vanguard's tool-input validator (shared package).

Named after the Roman Censor (the magistrate who examined fitness, enforced
standards, and could strike a citizen from the rolls), Censor validates and
normalizes the arguments the LLM sends to every security tool *before* they
reach subprocess spawn. Equivalent to Praetorian's Zod-schema wrapper layer.

Used by:
  - the platform agent's MCP server (CLI-string-style ``args="..."`` invocations)
  - the Aegis Vanguard agent's tool registry (Python-kwarg-style invocations)

Tool-name lookups are normalized: ``execute_nuclei`` (platform) and
``scan_nuclei`` (Aegis Vanguard) both resolve to the canonical ``nuclei`` schema.

Tools without an explicit schema fall through to a permissive default that
still rejects shell metacharacters and length bombs.
"""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("aegis.censor")


# Hard ceilings (defense against accidental prompt explosions, not security).
_DEFAULT_MAX_ARG_LEN = 4096
_DEFAULT_MAX_TOKEN_COUNT = 200

# Shell-metacharacter set we never want unescaped in CLI args. shlex.split will
# turn these into single tokens, but they signal that the LLM is trying to do
# something we don't want (chaining, subshells, redirection).
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r]")
_BACKTICK_DOLLAR_PAREN = re.compile(r"(\$\(|`)")


# ---------------------------------------------------------------------------
# Schema dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FieldSchema:
    """Schema for a single tool argument."""

    type: str = "cli_string"      # cli_string | url | hostname | json | integer
    required: bool = True
    max_length: int = _DEFAULT_MAX_ARG_LEN
    pattern: Optional[str] = None              # extra regex to match
    forbidden_substrings: List[str] = field(default_factory=list)
    allowed_subcommands: Optional[List[str]] = None  # first-token allowlist
    allow_empty: bool = False
    description: str = ""

    _compiled_pattern: Optional[re.Pattern] = field(default=None, init=False, repr=False)

    def compiled(self) -> Optional[re.Pattern]:
        if self.pattern and self._compiled_pattern is None:
            self._compiled_pattern = re.compile(self.pattern)
        return self._compiled_pattern


@dataclass
class ToolSchema:
    """Per-tool input schema. Attach to MCPTool registrations via Censor.register."""

    tool_name: str
    fields: Dict[str, FieldSchema]
    custom: Optional[Callable[[Dict[str, Any]], Tuple[bool, Optional[str]]]] = None
    """Optional whole-payload validator returning (ok, error_message)."""


# ---------------------------------------------------------------------------
# Reusable atomic validators
# ---------------------------------------------------------------------------


def _check_cli_string(value: str, schema: FieldSchema) -> Optional[str]:
    if not value and not schema.allow_empty:
        return "value is empty"
    if len(value) > schema.max_length:
        return f"exceeds max length ({len(value)} > {schema.max_length})"
    if _SHELL_METACHARS.search(value):
        return (
            "contains shell metacharacters (; & | ` $ > < newline). Pass each "
            "flag as a separate token; do not chain commands."
        )
    if _BACKTICK_DOLLAR_PAREN.search(value):
        return "contains command-substitution syntax (`...` or $(...)) — refused"
    try:
        tokens = shlex.split(value) if value else []
    except ValueError as e:
        return f"unparseable shell quoting: {e}"
    if len(tokens) > _DEFAULT_MAX_TOKEN_COUNT:
        return f"too many tokens ({len(tokens)} > {_DEFAULT_MAX_TOKEN_COUNT})"
    if schema.allowed_subcommands and tokens:
        if tokens[0] not in schema.allowed_subcommands:
            return (
                f"first token '{tokens[0]}' is not in the allowed subcommand "
                f"list: {sorted(schema.allowed_subcommands)}"
            )
    for bad in schema.forbidden_substrings:
        if bad.lower() in value.lower():
            return f"contains forbidden substring '{bad}'"
    pat = schema.compiled()
    if pat and not pat.search(value):
        return f"does not match required pattern: {schema.pattern}"
    return None


def _check_url(value: str, schema: FieldSchema) -> Optional[str]:
    if not value:
        return None if schema.allow_empty else "url is empty"
    if not value.startswith(("http://", "https://")):
        return "url must start with http:// or https://"
    try:
        p = urlparse(value)
    except Exception as e:
        return f"unparseable url: {e}"
    if not p.hostname:
        return "url has no hostname"
    return _check_cli_string(value, schema)


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _check_hostname(value: str, schema: FieldSchema) -> Optional[str]:
    if not value:
        return None if schema.allow_empty else "hostname is empty"
    if not _HOSTNAME_RE.match(value):
        return f"'{value}' is not a valid hostname"
    return _check_cli_string(value, schema)


def _check_json(value: str, schema: FieldSchema) -> Optional[str]:
    if not value:
        return None if schema.allow_empty else "json payload is empty"
    if len(value) > schema.max_length:
        return f"json exceeds max length ({len(value)} > {schema.max_length})"
    import json as _json
    try:
        _json.loads(value)
    except _json.JSONDecodeError as e:
        return f"invalid json: {e}"
    return None


def _check_integer(value: Any, schema: FieldSchema) -> Optional[str]:
    if value is None:
        return None if not schema.required else "integer value is required"
    try:
        int(value)
    except (TypeError, ValueError):
        return f"'{value}' is not an integer"
    return None


_TYPE_DISPATCH: Dict[str, Callable[[Any, FieldSchema], Optional[str]]] = {
    "cli_string": _check_cli_string,
    "url": _check_url,
    "hostname": _check_hostname,
    "json": _check_json,
    "integer": _check_integer,
}


# ---------------------------------------------------------------------------
# Default schemas — covers the highest-risk tools first.
# ---------------------------------------------------------------------------


def _build_default_schemas() -> Dict[str, ToolSchema]:
    """Build the canonical schema map. Keys are normalized tool names (no
    ``execute_`` / ``scan_`` / ``run_`` prefix); :py:meth:`Censor.validate`
    strips those prefixes before lookup so both naming conventions work."""
    s: Dict[str, ToolSchema] = {}

    # Generic single-arg cli string used by most ProjectDiscovery tools.
    cli_only = lambda name, max_len=2048: ToolSchema(  # noqa: E731
        tool_name=name,
        fields={"args": FieldSchema(type="cli_string", max_length=max_len)},
    )

    for name in [
        "nuclei", "naabu", "httpx", "subfinder", "dnsx", "katana",
        "tldfinder", "waybackurls", "nmap", "masscan", "ffuf", "amass",
        "whatweb", "knockpy", "gau", "kiterunner", "arjun", "xsstrike",
        "gitleaks", "cmseek", "testssl", "sslyze", "nikto", "wafw00f",
    ]:
        s[name] = cli_only(name)

    # Structured Aegis Vanguard wrappers whose kwargs are NOT a raw CLI string.
    # Registered under their EXACT tool name so they win over the prefix-
    # normalized raw-CLI schema above: without this, `scan_nuclei` canonicalizes
    # to `nuclei` and is rejected for missing the CLI `args` field (it passes
    # structured target/templates instead), blocking nuclei for every hunter.
    # The raw `nuclei` / `nikto` CLI guards above are left untouched.
    s["scan_nuclei"] = ToolSchema(
        tool_name="scan_nuclei",
        fields={
            "target": FieldSchema(type="url", max_length=512),
            "templates": FieldSchema(type="cli_string", required=False, max_length=512),
            "severity": FieldSchema(type="cli_string", required=False, max_length=128),
            "timeout": FieldSchema(type="integer", required=False),
        },
    )
    s["scan_nikto"] = ToolSchema(
        tool_name="scan_nikto",
        fields={
            "target": FieldSchema(type="url", max_length=512),
            "timeout": FieldSchema(type="integer", required=False),
        },
    )

    s["wappalyzer"] = ToolSchema(
        tool_name="wappalyzer",
        fields={"args": FieldSchema(type="url", max_length=512)},
    )
    s["crtsh"] = ToolSchema(
        tool_name="crtsh",
        fields={"args": FieldSchema(type="hostname", max_length=253)},
    )

    # curl: cli_string + schema-level SSRF substrings (Lictor blocks too — defense in depth).
    s["curl"] = ToolSchema(
        tool_name="curl",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=2048,
                forbidden_substrings=[
                    "169.254.169.254", "metadata.google", "metadata.azure",
                    "127.0.0.1", "localhost", "[::1]", "file://", "gopher://",
                    "dict://",
                ],
            ),
        },
    )

    s["sqlmap"] = ToolSchema(
        tool_name="sqlmap",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=4096,
                pattern=r"-u\s+|--url\s*=|-r\s+|--data\s+|-g\s+",
                description="SQLMap requires at least -u/--url, -r request file, --data, or -g.",
            ),
        },
    )

    # Hermes / TruffleHog: subcommand-driven (git, github, s3, docker, etc.)
    s["hermes"] = ToolSchema(
        tool_name="hermes",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=2048,
                allowed_subcommands=[
                    "git", "github", "gitlab", "s3", "gcs", "azure", "docker",
                    "filesystem", "postman", "jira", "confluence", "jenkins",
                    "circleci", "travisci", "elasticsearch", "syslog",
                ],
            ),
        },
    )

    # Themis / Prowler: provider must be first token
    s["themis"] = ToolSchema(
        tool_name="themis",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=2048,
                allowed_subcommands=["aws", "azure", "gcp", "kubernetes"],
            ),
        },
    )

    # Atlas / pius and Argus / titus: subcommand-driven
    s["atlas"] = ToolSchema(
        tool_name="atlas",
        fields={"args": FieldSchema(type="cli_string", max_length=2048,
                                    allowed_subcommands=["run"])},
    )
    s["argus"] = ToolSchema(
        tool_name="argus",
        fields={"args": FieldSchema(type="cli_string", max_length=2048,
                                    allowed_subcommands=["scan"])},
    )

    # WPScan: require --url
    s["wpscan"] = ToolSchema(
        tool_name="wpscan",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=2048,
                pattern=r"--url\s+|--url=",
                description="WPScan requires --url <target>.",
            ),
        },
    )

    s["schemathesis"] = ToolSchema(
        tool_name="schemathesis",
        fields={"args": FieldSchema(type="cli_string", max_length=2048)},
    )
    s["janus"] = ToolSchema(
        tool_name="janus",
        fields={"args": FieldSchema(type="cli_string", max_length=2048)},
    )
    s["browser"] = ToolSchema(
        tool_name="browser",
        fields={"args": FieldSchema(type="json", max_length=8192)},
    )
    s["js_urls_for_secrets"] = ToolSchema(
        tool_name="js_urls_for_secrets",
        fields={
            "urls": FieldSchema(type="cli_string", max_length=16384),
            "max_urls": FieldSchema(type="integer", required=False),
        },
    )
    # Retire.js: same URL-list shape as the secrets scanner.
    s["retirejs"] = ToolSchema(
        tool_name="retirejs",
        fields={
            "urls": FieldSchema(type="cli_string", max_length=16384),
            "max_urls": FieldSchema(type="integer", required=False),
        },
    )
    # jwt_tool: first token is the JWT (which can be long); allow generous length.
    s["jwt"] = ToolSchema(
        tool_name="jwt",
        fields={"args": FieldSchema(type="cli_string", max_length=8192)},
    )
    # Interactsh OOB collaborator: subcommand-driven.
    s["interactsh"] = ToolSchema(
        tool_name="interactsh",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=512,
                allowed_subcommands=["register", "poll", "list", "stop"],
            ),
        },
    )
    # Semgrep SAST: path + config flags; allow longer rule/path lists.
    s["semgrep"] = ToolSchema(
        tool_name="semgrep",
        fields={"args": FieldSchema(type="cli_string", max_length=4096)},
    )
    # Trivy: first token must be a scan mode.
    s["trivy"] = ToolSchema(
        tool_name="trivy",
        fields={
            "args": FieldSchema(
                type="cli_string",
                max_length=2048,
                allowed_subcommands=[
                    "fs", "image", "config", "repo", "rootfs",
                    "sbom", "kubernetes", "k8s", "vm", "server",
                    "convert", "version",
                ],
            ),
        },
    )
    s["llm_red_team"] = ToolSchema(
        tool_name="llm_red_team",
        fields={
            "target_url": FieldSchema(type="url", max_length=512),
            "categories": FieldSchema(type="cli_string", required=False, max_length=512),
            "endpoint_url": FieldSchema(type="url", required=False, max_length=512),
            "message_field": FieldSchema(type="cli_string", required=False, max_length=64),
        },
    )

    # All ``*_help`` tools take no arguments — permissive empty schema.
    for name in list(s.keys()):
        s.setdefault(name + "_help", ToolSchema(tool_name=name + "_help", fields={}))

    return s


def _canonical_tool(tool_name: str) -> str:
    """Strip ``execute_`` / ``scan_`` / ``run_`` prefixes for schema lookup."""
    for prefix in ("execute_", "scan_", "run_"):
        if tool_name.startswith(prefix):
            return tool_name[len(prefix):]
    return tool_name


# ---------------------------------------------------------------------------
# Censor — the gatekeeper
# ---------------------------------------------------------------------------


@dataclass
class CensorVerdict:
    ok: bool
    error: Optional[str] = None
    normalized: Dict[str, Any] = field(default_factory=dict)


class Censor:
    """Validates and normalizes tool arguments before Lictor + subprocess."""

    def __init__(self) -> None:
        self._schemas: Dict[str, ToolSchema] = _build_default_schemas()

    def register(self, schema: ToolSchema) -> None:
        self._schemas[_canonical_tool(schema.tool_name)] = schema

    def get(self, tool_name: str) -> Optional[ToolSchema]:
        # Exact name wins over the prefix-stripped canonical fallback, so a
        # structured wrapper (scan_nuclei) can override its raw-CLI base (nuclei).
        return (self._schemas.get(tool_name)
                or self._schemas.get(_canonical_tool(tool_name)))

    def validate(self, tool_name: str, arguments: Dict[str, Any]) -> CensorVerdict:
        """Validate arguments against the registered schema (or permissive default)."""
        arguments = dict(arguments or {})
        schema = (self._schemas.get(tool_name)
                  or self._schemas.get(_canonical_tool(tool_name)))

        # Permissive default: still defend against the worst.
        if schema is None:
            for k, v in arguments.items():
                if isinstance(v, str):
                    err = _check_cli_string(v, FieldSchema(type="cli_string"))
                    if err:
                        return CensorVerdict(
                            ok=False,
                            error=(
                                f"Censor rejected {tool_name}.{k}: {err}. "
                                f"Pass arguments as plain strings without shell "
                                f"chaining (; & |) or substitution ($() ``)."
                            ),
                        )
            return CensorVerdict(ok=True, normalized=arguments)

        # Required-field check
        for fname, fschema in schema.fields.items():
            if fname not in arguments:
                if fschema.required:
                    return CensorVerdict(
                        ok=False,
                        error=(
                            f"Censor rejected {tool_name}: missing required "
                            f"field '{fname}' ({fschema.type}). "
                            f"{fschema.description or ''}".strip()
                        ),
                    )
                continue
            value = arguments[fname]
            if isinstance(value, (int, float)) and fschema.type != "integer":
                value = str(value)
            check = _TYPE_DISPATCH.get(fschema.type)
            if not check:
                logger.warning("censor: unknown type '%s' for %s.%s", fschema.type, tool_name, fname)
                continue
            err = check(value, fschema)
            if err:
                return CensorVerdict(
                    ok=False,
                    error=(
                        f"Censor rejected {tool_name}.{fname}: {err}. "
                        f"{fschema.description or ''}".strip()
                    ),
                )
            arguments[fname] = value

        # Whole-payload custom validator
        if schema.custom:
            try:
                ok, err = schema.custom(arguments)
                if not ok:
                    return CensorVerdict(
                        ok=False,
                        error=f"Censor rejected {tool_name}: {err}",
                    )
            except Exception as e:
                logger.exception("censor custom validator crashed: %s", e)

        return CensorVerdict(ok=True, normalized=arguments)


_censor: Optional[Censor] = None


def get_censor() -> Censor:
    global _censor
    if _censor is None:
        _censor = Censor()
    return _censor


__all__ = [
    "Censor",
    "CensorVerdict",
    "ToolSchema",
    "FieldSchema",
    "get_censor",
]
