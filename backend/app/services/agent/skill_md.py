"""Load Claude-style SKILL.md packs (frontmatter + body + optional references).

say_hello in the Claude skills drop is the format: YAML name/description, body
instructions, companion files loaded on demand. Judah uses the same shape under
skill_packs/ — not Codex, not operator Chrome, not unrestricted bash.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Optional

PACKS_DIR = Path(__file__).resolve().parent / "skill_packs"

_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.S)


def _parse_frontmatter(raw: str) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for line in (raw or "").splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        meta[key.strip()] = val.strip().strip("\"'")
    return meta


def load_skill_md(name: str) -> Optional[Dict[str, Any]]:
    path = PACKS_DIR / name / "SKILL.md"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER.match(text)
    if m:
        meta = _parse_frontmatter(m.group(1))
        body = m.group(2).strip()
    else:
        meta = {"name": name}
        body = text.strip()
    refs: Dict[str, str] = {}
    ref_dir = PACKS_DIR / name / "references"
    if ref_dir.is_dir():
        for p in sorted(ref_dir.glob("*.md")):
            refs[p.stem] = p.read_text(encoding="utf-8")[:8000]
    return {
        "name": meta.get("name") or name,
        "description": meta.get("description") or "",
        "body": body,
        "references": refs,
        "path": str(path),
    }


def skill_body(name: str) -> str:
    pack = load_skill_md(name)
    return (pack or {}).get("body") or ""


def list_skill_packs() -> list[str]:
    if not PACKS_DIR.is_dir():
        return []
    return sorted(p.name for p in PACKS_DIR.iterdir() if (p / "SKILL.md").is_file())
