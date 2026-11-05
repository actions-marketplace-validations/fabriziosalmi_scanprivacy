"""House style for what the public reads: no em dash, no emoji.

These files are the project's own words (README, docs, policies, the landing
page). Text that the engine generates from a scanned site, such as a report, is
product output and is not held to this.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

PUBLIC = sorted(
    [
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CODE_OF_CONDUCT.md",
        ROOT / "CHANGELOG.md",
        ROOT / "data" / "baseline" / "README.md",
        ROOT / "src" / "scanprivacy" / "rules" / "README.md",
        ROOT / "site" / "index.html",
        *(ROOT / "docs").glob("*.md"),
    ]
)

EMOJI = re.compile("[\U0001f300-\U0001faff☀-➿️]")


@pytest.mark.parametrize("path", PUBLIC, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_em_dash_in_public_text(path: Path):
    text = path.read_text(encoding="utf-8")
    lines = [i + 1 for i, line in enumerate(text.split("\n")) if "—" in line]
    assert not lines, f"{path.name} has an em dash on lines {lines}"


@pytest.mark.parametrize("path", PUBLIC, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_emoji_in_public_text(path: Path):
    found = EMOJI.findall(path.read_text(encoding="utf-8"))
    assert not found, f"{path.name} contains emoji: {found[:5]}"
