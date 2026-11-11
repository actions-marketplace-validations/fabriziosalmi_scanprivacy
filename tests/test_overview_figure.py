"""The figure at the top of the README: well formed, readable in both colour schemes, and linked."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SVG = ROOT / "docs" / "img" / "overview.svg"
NS = {"s": "http://www.w3.org/2000/svg"}


def _luminance(hex_color: str) -> float:
    channels = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _contrast(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def _palettes() -> tuple[dict[str, str], dict[str, str]]:
    css = ET.parse(SVG).getroot().find("s:style", NS).text
    light = dict(re.findall(r"--([a-z]+): (#[0-9a-f]{6})", css.split("@media")[0]))
    dark = dict(re.findall(r"--([a-z]+): (#[0-9a-f]{6})", css.split("@media")[1]))
    return light, dark


def test_the_figure_is_well_formed_and_describes_itself():
    root = ET.parse(SVG).getroot()
    assert root.find("s:title", NS).text and root.find("s:desc", NS).text
    assert root.get("role") == "img"
    text = SVG.read_text(encoding="utf-8")
    assert "—" not in text and "–" not in text
    assert not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", text)
    assert "<script" not in text and "href=" not in text, "an image that loads nothing and runs nothing"


def test_every_text_is_readable_on_what_it_sits_on_in_both_schemes():
    light, dark = _palettes()
    # page backgrounds GitHub uses behind a README image: white, and its dark canvas
    for palette, page in ((light, "#ffffff"), (dark, "#0d1117")):
        for ink in ("ink", "text", "accent"):
            assert _contrast(palette[ink], palette["bg"]) >= 4.5, (ink, palette[ink])
        assert _contrast(palette["muted"], page) >= 4.5, ("note on the page", palette["muted"])
        assert _contrast(palette["rule"], page) >= 1.1, "the card edge is visible"


def test_the_readme_shows_it_with_a_description():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    match = re.search(r"!\[([^\]]+)\]\(docs/img/overview\.svg\)", readme)
    assert match and len(match.group(1)) > 40, "the image needs alt text that says what it shows"
    assert readme.index("overview.svg") < readme.index("```bash"), "it sits above the install steps"
