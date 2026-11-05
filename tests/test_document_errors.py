"""Why a legal document could not be used, in the reader's language.

Four sentences were written inline in `observe/docs.py`, in Italian, and they
reach the report: an English PDF could tell its reader "nessuna risposta dal
server". In an engine whose premise is that findings carry no sentences — that
a scan holds canonical values and catalogue keys, and prose is assembled at
render time — those four were the exception nobody had noticed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scanprivacy.i18n.translator import Translator
from scanprivacy.report.pdf import _documents

CASES = [
    ({"error_key": "documents.error.no_response", "error_params": {}}, "no response", "nessuna risposta"),
    ({"error_key": "documents.error.http_status", "error_params": {"status": 404}}, "404", "404"),
    ({"error_key": "documents.error.too_short", "error_params": {"n": 42}}, "42", "42"),
    ({"error_key": "documents.error.not_recognisable", "error_params": {"kind": "privacy"}}, "privacy", "privacy"),
]


def _row(extra: dict) -> dict:
    return {"kind": "privacy", "url": "https://x.it/p", "ok": False, "status": 200, **extra}


@pytest.mark.parametrize("extra,en_needle,it_needle", CASES)
def test_each_reason_renders_in_the_language_asked_for(extra, en_needle, it_needle):
    for locale, needle in (("en", en_needle), ("it", it_needle)):
        rows = sum(_documents({"documents": [_row(extra)]}, Translator.for_locale(locale, strict=True)), [])
        text = rows[0]["error_text"]
        assert needle in text, f"{locale}: {text!r}"
        assert "⟦" not in text and "{" not in text


def test_an_english_report_contains_no_italian():
    """The defect stated as a property. Every reason, rendered in English, and
    none of the words the inline versions used."""
    italian = ("nessuna", "disponibile", "troppo breve", "riconoscibile", "caratteri")
    t = Translator.for_locale("en", strict=True)
    for extra, _, _ in CASES:
        rows = sum(_documents({"documents": [_row(extra)]}, t), [])
        text = rows[0]["error_text"].lower()
        leaked = [w for w in italian if w in text]
        assert leaked == [], f"Italian reached an English report: {leaked} in {text!r}"


def test_no_sentence_is_written_inline_in_the_observation_layer():
    """The guard against the same thing happening again. Prose belongs in a
    catalogue; a module that observes has no business composing it."""
    source = Path("src/scanprivacy/observe/docs.py").read_text(encoding="utf-8")
    # assignments to `.error` with a literal string, which is how the four got in
    offenders = re.findall(r"\.error\s*=\s*[\"'f][^\n]*", source)
    prose = [o for o in offenders if "type(" not in o and "__name__" not in o]
    assert prose == [], f"sentences written inline: {prose}"


def test_the_diagnostic_field_still_carries_exception_text():
    """`error` was not removed, only demoted. An exception's own words are a
    diagnostic for whoever operates the engine, and are not shown as prose."""
    from scanprivacy.observe.docs import DocumentEvidence

    ev = DocumentEvidence(kind="privacy", url="https://x.it/", status=None, ok=False)
    ev.error = "TimeoutError: navigation timeout"
    assert ev.error_key is None
    assert "TimeoutError" in ev.error


# ------------------------------------------------------ how a document was chosen


def test_the_discovery_reason_renders_in_both_languages():
    """`discovery` is how a reader checks the engine picked the document they
    would have picked. It reaches the report, so it has to be in their language
    to be checkable at all — and it was Italian, inline, like the errors."""
    obs = {"documents": [{
        "kind": "privacy", "url": "https://x.it/p", "ok": True, "status": 200,
        "discovery": "discovery.path_is_a_document,discovery.editorial_section",
    }]}
    seen = {}
    for locale in ("en", "it"):
        rows = sum(_documents(obs, Translator.for_locale(locale, strict=True)), [])
        text = rows[0]["discovery"]
        assert "⟦" not in text and "discovery." not in text, f"{locale}: {text!r}"
        seen[locale] = text
    assert seen["en"] != seen["it"], "the two languages produced the same string"
    assert "editorial" in seen["en"] and "editoriale" in seen["it"]


def test_an_empty_discovery_does_not_become_a_stray_separator():
    obs = {"documents": [{"kind": "privacy", "url": "https://x.it/p", "ok": True,
                          "status": 200, "discovery": ""}]}
    rows = sum(_documents(obs, Translator.for_locale("en", strict=True)), [])
    assert rows[0]["discovery"] == ""


def test_the_scorer_emits_keys_and_never_prose():
    """The guard: a reason added later as a sentence would reach the report in
    whatever language it was typed in, and only a reader of the other language
    would notice."""
    source = Path("src/scanprivacy/observe/discover.py").read_text(encoding="utf-8")
    appended = re.findall(r'why\.append\(\s*"([^"]+)"\s*\)', source)
    assert appended, "no reasons found — the test would pass vacuously"
    for reason in appended:
        assert reason.startswith("discovery."), f"a sentence, not a key: {reason!r}"


def test_how_a_document_was_found_is_always_catalogue_keys_never_prose():
    """The report translates each comma-separated part. A sentence here reached the
    reader as `[ui.percorso convenzionale]` in an English report, and a
    "link (score 11: ..." wrapper did the same to the keys inside it."""
    from scanprivacy.observe.discover import Candidate, fallback_candidates, linked_why

    reasons = [c.why for c in fallback_candidates("https://example.org/", "privacy")]
    reasons.append(linked_why(Candidate(kind="privacy", url="https://example.org/p", score=11,
                                         why="discovery.path_is_a_document,discovery.link_text_exact")))
    assert reasons
    for reason in reasons:
        for part in reason.split(","):
            assert part.startswith("discovery."), f"not a catalogue key: {part!r} in {reason!r}"

    from scanprivacy.i18n.translator import Translator, available_locales

    for locale in available_locales():
        t = Translator.for_locale(locale)
        for reason in reasons:
            text = ", ".join(t.t(k) for k in reason.split(",") if k)
            assert "⟦" not in text and "discovery." not in text, f"{locale}: {text!r}"


def test_evidence_stored_by_an_earlier_build_still_renders_without_placeholders():
    from scanprivacy.i18n.translator import Translator
    from scanprivacy.report.pdf import discovery_text

    legacy = [
        "link (score 11: discovery.path_is_a_document,discovery.link_text_exact)",
        "percorso convenzionale, nessun link trovato",
        "something nobody planned",
    ]
    for locale in ("en", "it"):
        t = Translator.for_locale(locale)
        for raw in legacy:
            text = discovery_text(raw, t)
            assert "⟦" not in text and "discovery." not in text, f"{locale}: {raw!r} -> {text!r}"
    en = Translator.for_locale("en")
    assert discovery_text(legacy[0], en) == "linked from the page, the path names a document, the link text matches exactly"
    assert discovery_text(legacy[1], en) == "a conventional path, no link to it was found"
    assert discovery_text(legacy[2], en) == "something nobody planned"
