#!/usr/bin/env python3
"""Fail the build when code we ship can change without a reviewed commit.

Scans tracked Dockerfiles, Compose files, GitHub workflows and shell scripts:

  image-digest    FROM / image: must pin an image digest (@sha256:...)
  go-version      go install must name an exact version, not @latest/@master
  pipe-to-shell   no curl/wget ... | sh or | bash
  git-clone-pin   git clone must be followed by a checkout of a full commit hash
  download-hash   a Dockerfile RUN step that downloads a file must verify a
                  SHA-256 (sha256sum -c / echo "<hash>  file" | sha256sum)
  action-sha      workflow `uses:` must pin a full 40-character commit SHA
  backdoor-ioc    known ARTEX backdoor implant strings must not appear anywhere

A line, or a RUN step, may opt out with a trailing comment
`supply-chain: allow <reason>`, which keeps every exception visible in review.

Exit code 0 when clean, 1 with a report otherwise.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOW = "supply-chain: allow"
# Strings from the backdoored upstream ARTEX build (FailSafe audit, 2026-11).
IOC_STRINGS = ("verify" + "Captcha", "tomic" + "dd", "congdong" + "linux")

FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", re.I)
IMAGE_RE = re.compile(r"^\s*image:\s*['\"]?([^'\"\s#]+)")
GO_INSTALL_RE = re.compile(r"go\s+install\s+(?:-\S+\s+)*(\S+)")
PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b")
USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
HEX40 = re.compile(r"\b[0-9a-f]{40}\b")
DOWNLOAD_RE = re.compile(r"\b(?:curl|wget)\b[^\n]*https?://")
HASH_CHECK_RE = re.compile(r"sha256sum\s+(?:-c|--check)|sha256sum\s+-c\s*-|\bsha256sum\b.*-c")


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [ROOT / line for line in out.stdout.splitlines() if line]


def is_dockerfile(path: Path) -> bool:
    return path.name.startswith("Dockerfile") or path.suffix == ".dockerfile"


def is_compose(path: Path) -> bool:
    return path.name.startswith(("docker-compose", "compose")) and path.suffix in {".yml", ".yaml"}


def is_workflow(path: Path) -> bool:
    return ".github/workflows" in path.as_posix() and path.suffix in {".yml", ".yaml"}


def run_steps(text: str) -> list[tuple[int, str]]:
    """Dockerfile RUN instructions joined across line continuations."""
    steps, current, start = [], [], 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not current:
            if not re.match(r"RUN\b", stripped, re.I):
                continue
            start = number
        current.append(line)
        if not stripped.endswith("\\"):
            steps.append((start, "\n".join(current)))
            current = []
    if current:
        steps.append((start, "\n".join(current)))
    return steps


def check_dockerfile(path: Path, text: str, stages: set[str]) -> list[str]:
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        match = FROM_RE.match(line)
        if not match or ALLOW in line:
            continue
        image = match.group(1)
        if image.lower() in stages or image == "scratch" or "@sha256:" in image:
            continue
        if image.startswith("${") and "@sha256:" in text:  # ARG-defined, checked at its ARG
            continue
        problems.append(f"{path}:{number}: image-digest: FROM {image} has no @sha256 digest")
    for number, step in run_steps(text):
        if ALLOW in step:
            continue
        flat = " ".join(part.rstrip("\\") for part in step.splitlines())
        for target in GO_INSTALL_RE.findall(flat):
            version = target.rsplit("@", 1)[1] if "@" in target else ""
            if not version or version in {"latest", "master", "main", "HEAD"}:
                problems.append(f"{path}:{number}: go-version: go install {target} is not an exact version")
        if PIPE_SHELL_RE.search(flat):
            problems.append(f"{path}:{number}: pipe-to-shell: downloaded script piped into a shell")
        if "git clone" in flat and not re.search(r"checkout\s+(?:--\S+\s+)*[0-9a-f]{40}\b", flat):
            problems.append(f"{path}:{number}: git-clone-pin: git clone without a commit checkout")
        if DOWNLOAD_RE.search(flat) and not HASH_CHECK_RE.search(flat):
            problems.append(f"{path}:{number}: download-hash: download without a SHA-256 check")
    return problems


def check_compose(path: Path, text: str) -> list[str]:
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        match = IMAGE_RE.match(line)
        if not match or ALLOW in line:
            continue
        image = match.group(1)
        if "@sha256:" in image or image.startswith("${"):
            continue
        problems.append(f"{path}:{number}: image-digest: image {image} has no @sha256 digest")
    return problems


def check_workflow(path: Path, text: str) -> list[str]:
    problems = []
    for number, line in enumerate(text.splitlines(), 1):
        match = USES_RE.match(line)
        if not match or ALLOW in line:
            continue
        ref = match.group(1)
        if ref.startswith(("./", "docker://")):
            continue
        if "@" not in ref or not HEX40.fullmatch(ref.rsplit("@", 1)[1]):
            problems.append(f"{path}:{number}: action-sha: {ref} is not pinned to a commit SHA")
    for number, line in enumerate(text.splitlines(), 1):
        if PIPE_SHELL_RE.search(line) and ALLOW not in line:
            problems.append(f"{path}:{number}: pipe-to-shell: downloaded script piped into a shell")
    return problems


def check_shell(path: Path, text: str) -> list[str]:
    return [
        f"{path}:{number}: pipe-to-shell: downloaded script piped into a shell"
        for number, line in enumerate(text.splitlines(), 1)
        if PIPE_SHELL_RE.search(line) and ALLOW not in line
    ]


def main() -> int:
    problems: list[str] = []
    this_file = Path(__file__).resolve()
    for path in tracked_files():
        if not path.is_file() or path.resolve() == this_file:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(ROOT)
        for needle in IOC_STRINGS:
            if needle.lower() in text.lower():
                problems.append(f"{rel}: backdoor-ioc: contains '{needle}'")
        if is_dockerfile(path):
            stages = {m.group(1).lower() for m in re.finditer(r"^\s*FROM\s+\S+\s+AS\s+(\S+)", text, re.I | re.M)}
            problems += check_dockerfile(rel, text, stages)
        elif is_compose(path):
            problems += check_compose(rel, text)
        elif is_workflow(path):
            problems += check_workflow(rel, text)
        elif path.suffix == ".sh":
            problems += check_shell(rel, text)
    if problems:
        print(f"supply-chain check: {len(problems)} problem(s)")
        print("\n".join(sorted(set(problems))))
        return 1
    print("supply-chain check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
