"""YAML tool recipes: expose a simple CLI to the agent without writing Python.

Each ``recipes/*.yaml`` file describes one command-line tool. At startup the
recipe is registered everywhere a hand-written tool would need an edit:

  - MCP server registry (generic handler + optional ``<tool>_help``) and the
    binary map used by Lictor and the "unavailable tools" prompt note
  - agent tool registry (``ASMToolsManager._register_tools``)
  - ``TOOL_PHASE_MAP`` and the phase tool list in the system prompt
  - Lictor destructive-flag denylist and safe defaults
  - confirmation auto-approval and concurrent single-flight sharing (opt-in)

Recipes never bypass the guard layer: every call still goes through Censor,
the denylist, Lictor (SSRF, scope, flags, rate limit) and Augur like any other
``execute_*`` tool. A recipe cannot replace a hand-written tool of the same
name; collisions are skipped with a warning.

Schema (unknown keys are rejected so typos fail loudly)::

    name: execute_tlsx                 # required, ^execute_[a-z0-9_]+$
    binary: tlsx                       # required, bare executable name
    description: One line for the LLM  # required, <= 400 chars
    example: execute_tlsx(args="-u example.com -san")   # optional
    phases: [informational, exploitation, post_exploitation]  # default: all three
    timeout_seconds: 120               # default 300, max 1800
    fixed_args: [-silent]              # always prepended before the agent's args
    help_args: [-h]                    # registers <short>_help; null disables
    success_exit_codes: [0]
    deny_flags: [--brute]              # Lictor refuses calls containing these
    safe_defaults: [-no-color]         # Lictor appends when absent
    auto_approve: true                 # passive recon: skip the confirmation prompt
    shareable: true                    # identical concurrent calls share one run
"""

from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Tuple

import yaml

logger = logging.getLogger(__name__)

RECIPE_DIR = Path(__file__).parent / "recipes"
PHASES = ("informational", "exploitation", "post_exploitation")
MAX_TIMEOUT_SECONDS = 1800

_NAME_RE = re.compile(r"^execute_[a-z0-9_]{1,48}$")
_BINARY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_FLAG_RE = re.compile(r"^[^\s;&|`$<>]{1,128}$")
_KEYS = {
    "name", "binary", "description", "example", "phases", "timeout_seconds",
    "fixed_args", "help_args", "success_exit_codes", "deny_flags",
    "safe_defaults", "auto_approve", "shareable",
}


class RecipeError(ValueError):
    pass


@dataclass(frozen=True)
class ToolRecipe:
    name: str
    binary: str
    description: str
    example: str = ""
    phases: Tuple[str, ...] = PHASES
    timeout_seconds: int = 300
    fixed_args: Tuple[str, ...] = ()
    help_args: Optional[Tuple[str, ...]] = ("-h",)
    success_exit_codes: Tuple[int, ...] = (0,)
    deny_flags: Tuple[str, ...] = ()
    safe_defaults: Tuple[str, ...] = ()
    auto_approve: bool = False
    shareable: bool = False
    source: str = ""

    @property
    def short(self) -> str:
        return self.name[len("execute_"):]

    @property
    def help_name(self) -> Optional[str]:
        return f"{self.short}_help" if self.help_args is not None else None

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def prompt_line(self) -> str:
        line = f"- **{self.name}**: {self.description}"
        if self.example:
            line += f" Example: {self.example}"
        return line


def _str_list(raw: Any, field: str, *, pattern: re.Pattern = _FLAG_RE) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
        raise RecipeError(f"{field} must be a list of strings")
    for item in raw:
        if not pattern.match(item):
            raise RecipeError(f"{field} entry {item!r} has whitespace or shell metacharacters")
    return tuple(raw)


def parse_recipe(data: Any, source: str = "") -> ToolRecipe:
    """Validate one recipe mapping. Raises ``RecipeError`` with a readable reason."""
    if not isinstance(data, dict):
        raise RecipeError("recipe must be a mapping")
    unknown = set(data) - _KEYS
    if unknown:
        raise RecipeError(f"unknown keys: {', '.join(sorted(unknown))}")

    name = data.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise RecipeError("name must match ^execute_[a-z0-9_]+$")
    binary = data.get("binary")
    if not isinstance(binary, str) or not _BINARY_RE.match(binary):
        raise RecipeError("binary must be a bare executable name (no path or spaces)")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise RecipeError("description is required")
    if len(description) > 400:
        raise RecipeError("description must be at most 400 characters")
    example = data.get("example") or ""
    if not isinstance(example, str) or len(example) > 300:
        raise RecipeError("example must be a string of at most 300 characters")

    phases_raw = data.get("phases", list(PHASES))
    if (not isinstance(phases_raw, list) or not phases_raw
            or any(p not in PHASES for p in phases_raw)):
        raise RecipeError(f"phases must be a non-empty subset of {list(PHASES)}")

    timeout = data.get("timeout_seconds", 300)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= MAX_TIMEOUT_SECONDS:
        raise RecipeError(f"timeout_seconds must be an integer from 1 to {MAX_TIMEOUT_SECONDS}")

    if "help_args" in data and data["help_args"] is None:
        help_args: Optional[Tuple[str, ...]] = None
    else:
        help_args = _str_list(data.get("help_args", ["-h"]), "help_args")

    codes = data.get("success_exit_codes", [0])
    if (not isinstance(codes, list) or not codes
            or not all(isinstance(c, int) and not isinstance(c, bool) and 0 <= c <= 255 for c in codes)):
        raise RecipeError("success_exit_codes must be a list of integers 0-255")

    flags: Dict[str, bool] = {}
    for key in ("auto_approve", "shareable"):
        value = data.get(key, False)
        if not isinstance(value, bool):
            raise RecipeError(f"{key} must be true or false")
        flags[key] = value

    return ToolRecipe(
        name=name,
        binary=binary,
        description=" ".join(description.split()),
        example=example.strip(),
        phases=tuple(dict.fromkeys(phases_raw)),
        timeout_seconds=timeout,
        fixed_args=_str_list(data.get("fixed_args"), "fixed_args"),
        help_args=help_args,
        success_exit_codes=tuple(codes),
        deny_flags=_str_list(data.get("deny_flags"), "deny_flags"),
        safe_defaults=_str_list(data.get("safe_defaults"), "safe_defaults"),
        auto_approve=flags["auto_approve"],
        shareable=flags["shareable"],
        source=source,
    )


def load_recipes(directory: Path = RECIPE_DIR) -> Tuple[Dict[str, ToolRecipe], List[str]]:
    """Load every ``*.yaml``/``*.yml`` file. Bad files are skipped, not fatal.

    Returns ``(recipes_by_name, errors)``.
    """
    recipes: Dict[str, ToolRecipe] = {}
    errors: List[str] = []
    if not directory.is_dir():
        return recipes, errors
    files = sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")])
    for path in files:
        try:
            recipe = parse_recipe(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
        except (RecipeError, yaml.YAMLError, OSError) as e:
            errors.append(f"{path.name}: {e}")
            continue
        clash = recipe.name in recipes or (recipe.help_name and recipe.help_name in recipes)
        if clash:
            errors.append(f"{path.name}: duplicate tool name {recipe.name}")
            continue
        recipes[recipe.name] = recipe
    for err in errors:
        logger.warning("tool recipe skipped — %s", err)
    return recipes, errors


_cache: Optional[Dict[str, ToolRecipe]] = None
_cache_lock = Lock()


def get_recipes() -> Dict[str, ToolRecipe]:
    """Recipes from the bundled directory, loaded once per process."""
    global _cache
    if _cache is None:
        with _cache_lock:
            if _cache is None:
                _cache, _ = load_recipes()
    return _cache


def reset_cache() -> None:
    global _cache
    with _cache_lock:
        _cache = None


def help_tool_names() -> Dict[str, ToolRecipe]:
    return {r.help_name: r for r in get_recipes().values() if r.help_name}


def phase_map() -> Dict[str, List[str]]:
    """``TOOL_PHASE_MAP`` entries for recipe tools and their help tools."""
    out: Dict[str, List[str]] = {}
    for r in get_recipes().values():
        out[r.name] = list(r.phases)
        if r.help_name:
            out[r.help_name] = list(r.phases)
    return out


def prompt_section(phase: str, reserved: Optional[set] = None) -> str:
    """Tool list lines for installed recipe tools allowed in ``phase``."""
    reserved = reserved or set()
    lines = [
        r.prompt_line() for r in get_recipes().values()
        if phase in r.phases and r.name not in reserved and r.available()
    ]
    if not lines:
        return ""
    helps = [r.help_name for r in get_recipes().values()
             if r.help_name and phase in r.phases and r.name not in reserved and r.available()]
    text = "\n### Recipe tools (YAML-defined CLI wrappers; pass CLI flags in args)\n" + "\n".join(lines)
    if helps:
        text += "\n- " + ", ".join(f"**{h}**" for h in helps) + ": Get CLI usage for each recipe tool"
    return text + "\n"


def is_auto_approved(tool_name: str) -> bool:
    r = get_recipes().get(tool_name) or help_tool_names().get(tool_name)
    return bool(r and (r.auto_approve or tool_name == r.help_name))


def is_shareable(tool_name: str) -> bool:
    r = get_recipes().get(tool_name)
    return bool(r and r.shareable)


__all__ = [
    "PHASES",
    "RECIPE_DIR",
    "RecipeError",
    "ToolRecipe",
    "get_recipes",
    "help_tool_names",
    "is_auto_approved",
    "is_shareable",
    "load_recipes",
    "parse_recipe",
    "phase_map",
    "prompt_section",
    "reset_cache",
]
