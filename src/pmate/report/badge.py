"""A conformance badge, as a self-contained SVG.

Deliberately not a shields.io URL. A badge served from a third party makes every
visitor of the README disclose their IP address to that third party — which is
precisely the finding `PM-TRF-01` raises against everyone else. A tool that
breaks its own rule in its own README has no standing to raise it.

So the SVG is generated here, embedded in the repository, and loads nothing.
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from ..core.enums import Grade
from ..core.models import ScanResult

# Grade colours: the same ladder the verdict uses, so a reader who has seen one
# report recognises the badge without a legend.
_COLOUR = {
    Grade.A: "#2f7d32",
    Grade.B: "#5c8a1e",
    Grade.C: "#a07800",
    Grade.D: "#b5480f",
    Grade.F: "#a3001b",
    Grade.INCONCLUSIVE: "#6a6a6a",
}

_LABEL_BG = "#404448"
_FONT = "Verdana,DejaVu Sans,Geneva,sans-serif"
_CHAR_WIDTH = 6.6  # 11px Verdana, close enough for a badge and font-free
_PADDING = 10


def _width(text: str) -> int:
    return int(len(text) * _CHAR_WIDTH + 2 * _PADDING)


def render_badge(result: ScanResult, label: str = "privacy", detail: bool = True) -> str:
    """`detail` appends the finding count: "F · 30" says more than "F"."""
    grade = result.verdict.grade if result.verdict else Grade.INCONCLUSIVE
    value = grade.value
    if detail and result.findings:
        value = f"{grade.value} · {len(result.findings)}"

    label_width, value_width = _width(label), _width(value)
    total = label_width + value_width
    colour = _COLOUR.get(grade, _COLOUR[Grade.INCONCLUSIVE])
    accessible = f"{label}: {value}"

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{escape(accessible)}">
  <title>{escape(accessible)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="{_LABEL_BG}"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{colour}"/>
    <rect width="{total}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="{_FONT}" font-size="11">
    <text x="{label_width / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{escape(label)}</text>
    <text x="{label_width / 2:.0f}" y="14">{escape(label)}</text>
    <text x="{label_width + value_width / 2:.0f}" y="15" fill="#010101" fill-opacity=".3">{escape(value)}</text>
    <text x="{label_width + value_width / 2:.0f}" y="14">{escape(value)}</text>
  </g>
</svg>
"""
