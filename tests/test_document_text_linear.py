"""Turning a page into text must be linear in its size.

The two regexes that did it were quadratic on input a page can supply:
160 KB of repeated `<script>` or of bare `<` took 13 to 15 seconds, on the
event loop, before any size cap applied. A hostile target could stall the API
with one document.
"""

from __future__ import annotations

import random
import re
import time

from scanprivacy.observe.docs import _strip_blocks, _strip_tags, _to_text

_OLD_TAG = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
_OLD_HTML = re.compile(r"<[^>]+>")


def test_repeated_unclosed_script_is_not_quadratic():
    started = time.perf_counter()
    _to_text("<script>" * 20_000)
    assert time.perf_counter() - started < 1.0


def test_bare_angle_brackets_are_not_quadratic():
    started = time.perf_counter()
    _to_text("<" * 160_000)
    assert time.perf_counter() - started < 1.0


def test_unclosed_style_openers_are_not_quadratic():
    started = time.perf_counter()
    _to_text("<style>x" * 20_000)
    assert time.perf_counter() - started < 1.0


def test_a_normal_page_reads_the_same_as_before():
    page = (
        "<html><head><style>p{color:red}</style><script>var a = '<b>';</script></head>"
        "<body><h1>Informativa</h1><p>Titolare: Fabrizio &amp; Co.</p><SCRIPT>x()</SCRIPT></body></html>"
    )
    old = _OLD_HTML.sub(" ", _OLD_TAG.sub(" ", page))
    assert _strip_tags(_strip_blocks(page)) == old
    assert "var a" not in _to_text(page) and "color:red" not in _to_text(page)
    assert "Informativa" in _to_text(page)


def test_it_agrees_with_the_old_regexes_on_random_markup():
    rng = random.Random(7)
    tokens = ["<script>", "</script>", "<style>", "</style>", "<b>", "</b>", "x", " ", "<", ">", "\n", "<p class=a>"]
    for _ in range(3000):
        text = "".join(rng.choice(tokens) for _ in range(rng.randint(0, 14)))
        old = _OLD_HTML.sub(" ", _OLD_TAG.sub(" ", text))
        assert _strip_tags(_strip_blocks(text)) == old, repr(text)
