import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from xben_fix_buster_apt import patch_text, MARKER  # noqa: E402

BROKEN = (
    "\nFROM python:2.7.18-slim\n\n"
    "RUN apt-get update && apt-get install -y phantomjs\n\n"
    "ENV QT_QPA_PLATFORM=offscreen\n"
)


def test_patch_rewrites_the_apt_line():
    out, changed = patch_text(BROKEN)
    assert changed
    assert MARKER in out
    assert "Acquire::Check-Valid-Until=false" in out
    assert "phantomjs" in out
    # other lines preserved
    assert "FROM python:2.7.18-slim" in out
    assert "QT_QPA_PLATFORM" in out


def test_patch_is_idempotent():
    once, _ = patch_text(BROKEN)
    twice, changed = patch_text(once)
    assert not changed and twice == once


def test_unaffected_dockerfile_untouched():
    other = "FROM node:18\nRUN npm ci\n"
    out, changed = patch_text(other)
    assert not changed and out == other
