"""The colours of the site are readable, and they are the colours of the report.

Contrast is computed, not eyeballed: WCAG relative luminance, 4.5:1 for text
and 3:1 for the borders of controls. The site and the PDF report share one
palette; a hex value changed in one stylesheet and not the other fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SITE_CSS = (ROOT / "site" / "assets" / "site.css").read_text(encoding="utf-8")
REPORT_CSS = (ROOT / "src" / "scanprivacy" / "report" / "templates" / "base.css").read_text(encoding="utf-8")

PAIR = re.compile(r"--([\w-]+):\s*light-dark\((#[0-9a-fA-F]{6}),\s*(#[0-9a-fA-F]{6})\)")
# The first declaration of each token is the palette; later ones (for example the
# `prefers-contrast: more` override) are variations of it, not the palette.
TOKENS: dict[str, tuple[str, str]] = {}
for _m in PAIR.finditer(SITE_CSS):
    TOKENS.setdefault(_m.group(1), (_m.group(2).lower(), _m.group(3).lower()))

TEXT = ("ink", "text", "muted", "accent", "sev-critical", "sev-high", "sev-medium", "sev-low", "sev-info",
        "grade-a", "grade-b", "grade-c", "grade-d", "grade-f")


def _luminance(hex_color: str) -> float:
    r, g, b = (int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5))
    lin = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def ratio(a: str, b: str) -> float:
    hi, lo = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def test_the_palette_is_declared_for_both_schemes():
    assert {"paper", "wash", "ink", "text", "muted", "rule", "control", "accent"} <= set(TOKENS)


@pytest.mark.parametrize("scheme", [0, 1], ids=["light", "dark"])
@pytest.mark.parametrize("name", TEXT)
@pytest.mark.parametrize("surface", ["paper", "wash"])
def test_text_colours_reach_4_5_to_1_on_both_surfaces(name, surface, scheme):
    assert ratio(TOKENS[name][scheme], TOKENS[surface][scheme]) >= 4.5, (name, surface, scheme)


@pytest.mark.parametrize("scheme", [0, 1], ids=["light", "dark"])
def test_the_border_of_a_control_reaches_3_to_1(scheme):
    for surface in ("paper", "wash"):
        assert ratio(TOKENS["control"][scheme], TOKENS[surface][scheme]) >= 3.0


def test_the_report_uses_the_light_values_of_the_same_palette():
    report = {m.group(1): m.group(2).lower() for m in re.finditer(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", REPORT_CSS)}
    assert report, "the report stylesheet declares no palette"
    shared = set(report) & set(TOKENS)
    assert {"ink", "text", "muted", "rule", "accent", "sev-critical", "grade-b"} <= shared
    for name in shared:
        assert report[name] == TOKENS[name][0], f"--{name} differs between the site and the report"


def test_text_is_sized_in_rem_so_it_follows_the_users_setting():
    body = SITE_CSS.split("/* ---------- typography")[1]
    assert not re.search(r"font-size:\s*\d+(\.\d+)?px", body), "a font size is in px"
