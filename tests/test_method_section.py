"""The section that says exactly what the engine did.

Every report ends with a method block: how many pages, what interaction, which
consent, whether robots.txt was honoured. It is the part a supplier reads when
they want to argue, and the part that makes the rest of the document checkable.

It was wrong in three ways at once, in three separate copies of the same code.

The label was derived from the key — `report.posture.extra_requests` printed as
"extra requests" — so an Italian report described its own method in English.
The sentence was resolved without parameters, so the page budget read literally
"at most {n} pages". And a single-page scan said "1 pages", in a document whose
credibility rests on looking carefully written.
"""

from __future__ import annotations

import pytest

from scanprivacy.i18n import Translator
from scanprivacy.report.render import posture_rows, scan_posture_rows

KEYS = (
    "report.posture.method",
    "report.posture.pages",
    "report.posture.interaction",
    "report.posture.consent",
    "report.posture.extra_requests",
    "report.posture.intrusive_tests",
    "report.posture.robots",
)


def _record(max_pages: int | None = 3, ua: str | None = "scanprivacy/0.1 (…)") -> dict:
    posture: dict = {"keys": list(KEYS), "per_host_rps": 1.0}
    if max_pages is not None:
        posture["max_pages"] = max_pages
    if ua:
        posture["user_agent"] = ua
    return {"posture": posture}


@pytest.mark.parametrize("lang", ["en", "it"])
def test_no_placeholder_survives_into_the_report(lang: str):
    for _, value in scan_posture_rows(_record(), Translator.for_locale(lang)):
        assert "{" not in value and "}" not in value, f"[{lang}] unresolved placeholder: {value}"
        assert "⟦" not in value, f"[{lang}] missing translation: {value}"


@pytest.mark.parametrize("lang", ["en", "it"])
def test_every_label_is_translated_rather_than_spelled_from_the_key(lang: str):
    for label, _ in scan_posture_rows(_record(), Translator.for_locale(lang)):
        assert "⟦" not in label, f"[{lang}] missing label: {label}"
        assert "_" not in label, f"[{lang}] {label!r} is a key, not a phrase"


def test_the_labels_actually_differ_between_languages():
    """Without this the test above passes on a function that never translates:
    "Method" and "Metodo" have to be two strings."""
    en = [label for label, _ in scan_posture_rows(_record(), Translator.for_locale("en"))]
    it = [label for label, _ in scan_posture_rows(_record(), Translator.for_locale("it"))]
    assert en != it


@pytest.mark.parametrize("lang", ["en", "it"])
def test_one_page_is_not_described_in_the_plural(lang: str):
    rows = dict(scan_posture_rows(_record(max_pages=1), Translator.for_locale(lang)))
    pages = next(v for k, v in rows.items() if k in ("Pages", "Pagine"))
    assert "1 pages" not in pages and "1 pagine" not in pages, pages


@pytest.mark.parametrize("lang", ["en", "it"])
def test_several_pages_state_the_number(lang: str):
    rows = dict(scan_posture_rows(_record(max_pages=5), Translator.for_locale(lang)))
    pages = next(v for k, v in rows.items() if k in ("Pages", "Pagine"))
    assert "5" in pages


def test_an_unrecorded_page_budget_is_omitted_rather_than_invented():
    """The method section exists to say precisely what was done. A budget the
    record does not carry is not something to fill in with a placeholder or a
    guess — this section of all sections cannot assert an unobserved fact."""
    labels = [label for label, _ in scan_posture_rows(_record(max_pages=None), Translator.for_locale("en"))]
    assert "Pages" not in labels
    assert "Method" in labels, "dropping one row must not drop the rest"


def test_the_user_agent_row_carries_a_translated_label():
    rows = dict(scan_posture_rows(_record(), Translator.for_locale("it")))
    assert "User-Agent" in rows
    assert rows["User-Agent"].startswith("scanprivacy/")


def test_the_fleet_report_uses_the_same_implementation():
    """It had its own copy of the bug. The estate PDF describes the same method
    and must describe it the same way."""
    from scanprivacy.report.fleet_pdf import FLEET_POSTURE_KEYS

    t = Translator.for_locale("it")
    rows = posture_rows(FLEET_POSTURE_KEYS, t, max_pages=3)
    assert rows, "the fleet method section rendered nothing"
    for label, value in rows:
        assert "_" not in label and "⟦" not in label, label
        assert "{" not in value, value
