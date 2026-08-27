"""Keep Claude Code SKILL.md files small (progressive disclosure)."""

from pathlib import Path

SKILLS_ROOT = Path(__file__).resolve().parents[1] / ".claude" / "skills"
MAX_SKILL_LINES = 150
MAX_REFERENCE_LINES = 200
REFERENCE_NAMES = {"schema.md", "gate.md", "researchers.md", "curiosity.md"}


def test_skill_md_under_line_cap():
    files = sorted(SKILLS_ROOT.glob("*/SKILL.md"))
    assert files, f"no SKILL.md under {SKILLS_ROOT}"
    over = []
    for path in files:
        n = len(path.read_text().splitlines())
        if n > MAX_SKILL_LINES:
            over.append(f"{path.relative_to(SKILLS_ROOT)}: {n} > {MAX_SKILL_LINES}")
    assert not over, "SKILL.md over cap:\n" + "\n".join(over)


def test_reference_md_under_line_cap():
    over = []
    for path in SKILLS_ROOT.glob("*/*.md"):
        if path.name not in REFERENCE_NAMES:
            continue
        n = len(path.read_text().splitlines())
        if n > MAX_REFERENCE_LINES:
            over.append(f"{path.relative_to(SKILLS_ROOT)}: {n} > {MAX_REFERENCE_LINES}")
    assert not over, "reference md over cap:\n" + "\n".join(over)
