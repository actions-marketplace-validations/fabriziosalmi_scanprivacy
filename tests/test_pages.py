"""Page selection and multi-page accumulation.

Determinism is the property under test here. If the same site yields a
different set of pages on two runs, `pmate diff` reports churn that never
happened and the evidence digests stop being comparable — the failure is silent
and it poisons everything downstream.
"""

from __future__ import annotations

import random

from pmate.analyze.context import build_context
from pmate.observe.browser import CookieSet, Observation, Request, StorageEntry
from pmate.observe.pages import normalise, select_pages

SITE = "https://www.example.it"


def _entry(links: list[str]) -> Observation:
    obs = Observation(url=SITE, final_url=f"{SITE}/", load_ok=True, status=200)
    obs.links = links
    return obs


# ---------------------------------------------------------------- normalise


def test_normalise_collapses_the_same_page_to_one_form():
    assert normalise(f"{SITE}/contatti#form") == f"{SITE}/contatti"
    assert normalise(f"{SITE}/contatti/") == f"{SITE}/contatti"
    assert normalise(f"{SITE}/CONTATTI") != normalise(f"{SITE}/contatti")  # paths are case-sensitive
    assert normalise(f"{SITE}/?utm_source=news") == f"{SITE}/"
    # a query that identifies a page is content, not noise, and is kept
    assert normalise(f"{SITE}/scheda?id=42") == f"{SITE}/scheda?id=42"


# ------------------------------------------------------------- what is kept


def test_third_party_links_are_never_followed():
    chosen = select_pages(_entry(["https://facebook.com/pagina", f"{SITE}/contatti"]), limit=5)
    assert [c.url for c in chosen] == [f"{SITE}/contatti"]


def test_downloads_and_media_are_not_pages():
    chosen = select_pages(
        _entry([f"{SITE}/bilancio.pdf", f"{SITE}/logo.png", f"{SITE}/feed.xml", f"{SITE}/contatti"]),
        limit=5,
    )
    assert [c.url for c in chosen] == [f"{SITE}/contatti"]


def test_state_changing_paths_are_refused():
    """A GET is unlikely to log anyone out, and 'unlikely' is not the standard
    this engine works to."""
    chosen = select_pages(
        _entry([f"{SITE}/logout", f"{SITE}/carrello/checkout", f"{SITE}/wp-admin", f"{SITE}/chi-siamo"]),
        limit=5,
    )
    assert [c.url for c in chosen] == [f"{SITE}/chi-siamo"]


def test_legal_documents_are_left_to_their_own_reader():
    chosen = select_pages(_entry([f"{SITE}/privacy", f"{SITE}/cookie-policy", f"{SITE}/servizi"]), limit=5)
    assert [c.url for c in chosen] == [f"{SITE}/servizi"]


def test_pagination_is_the_same_page_kind_twice():
    chosen = select_pages(_entry([f"{SITE}/news/page/2", f"{SITE}/news/2026/07"]), limit=5)
    assert chosen == []


# ------------------------------------------------------------------- choice


def test_one_page_per_kind_comes_first():
    """Variety finds more than depth: four articles teach less than a contact
    page, a form and a service page."""
    links = [
        f"{SITE}/news/uno",
        f"{SITE}/news/due",
        f"{SITE}/news/tre",
        f"{SITE}/contatti",
        f"{SITE}/servizi",
    ]
    kinds = [c.kind for c in select_pages(_entry(links), limit=3)]
    assert kinds == ["contact", "services", "content"]


def test_selection_is_deterministic_whatever_the_link_order():
    links = [
        f"{SITE}/contatti",
        f"{SITE}/chi-siamo",
        f"{SITE}/servizi/consulenza",
        f"{SITE}/news/articolo-lungo/dettaglio",
        f"{SITE}/registrazione",
        f"{SITE}/cerca",
    ]
    expected = [c.url for c in select_pages(_entry(links), limit=4)]
    for seed in range(5):
        shuffled = links[:]
        random.Random(seed).shuffle(shuffled)
        assert [c.url for c in select_pages(_entry(shuffled), limit=4)] == expected


def test_the_limit_is_respected_and_zero_means_entry_page_only():
    links = [f"{SITE}/p{i}" for i in range(20)]
    assert len(select_pages(_entry(links), limit=3)) == 3
    assert select_pages(_entry(links), limit=0) == []


def test_a_deep_page_is_picked_up_for_the_embeds_a_landing_page_never_shows():
    links = [f"{SITE}/contatti", f"{SITE}/news/2026/il-convegno/galleria"]
    chosen = select_pages(_entry(links), limit=2)
    assert f"{SITE}/news/2026/il-convegno/galleria" in [c.url for c in chosen]


# ------------------------------------------------------- accumulating facts


def _page(url: str, host: str, resource: str = "script") -> Observation:
    page = Observation(url=url, final_url=url, load_ok=True, status=200)
    page.requests = [Request(f"https://{host}/x", host, "GET", "/x", 200, None, resource, t_ms=10)]
    return page


def test_a_vendor_seen_on_two_pages_is_one_vendor_with_two_pages():
    """Counting the same fact once per page would inflate every number in the
    report."""
    home = _page(f"{SITE}/", "fonts.googleapis.com")
    contact = _page(f"{SITE}/contatti", "fonts.googleapis.com")
    ctx = build_context([home, contact])
    fonts = ctx.vendors["google-fonts"]
    assert len(ctx.third_party_vendors) == 1
    assert fonts.pages == [f"{SITE}/", f"{SITE}/contatti"]


def test_a_vendor_present_on_one_page_only_is_attributed_to_that_page():
    """The finding that a single-page scan cannot produce, and the reason the
    page attribution has to survive into the evidence."""
    home = _page(f"{SITE}/", "fonts.googleapis.com")
    about = _page(f"{SITE}/chi-siamo", "cdnjs.cloudflare.com")
    ctx = build_context([home, about])
    assert ctx.vendors["cdnjs"].pages == [f"{SITE}/chi-siamo"]
    assert ctx.vendors["google-fonts"].pages == [f"{SITE}/"]


def test_cookies_and_storage_are_deduplicated_across_pages():
    home = _page(f"{SITE}/", "fonts.googleapis.com")
    home.cookies = [CookieSet("_ga", ".example.it", "/", True, False, "Lax", 1.0, False)]
    home.storage = [StorageEntry("localStorage", "_ga_X", 8)]
    contact = _page(f"{SITE}/contatti", "fonts.googleapis.com")
    contact.cookies = [CookieSet("_ga", ".example.it", "/", True, False, "Lax", 1.0, False)]
    contact.storage = [StorageEntry("localStorage", "_ga_X", 8)]

    ctx = build_context([home, contact])
    assert len(ctx.cookies) == 1
    assert ctx.cookies[0].first_seen_page == f"{SITE}/"
    assert len(ctx.storage) == 1
    assert ctx.storage[0].first_seen_page == f"{SITE}/"


def test_a_page_that_failed_to_load_contributes_nothing():
    home = _page(f"{SITE}/", "fonts.googleapis.com")
    broken = Observation(url=f"{SITE}/giu", final_url=f"{SITE}/giu", load_ok=False, status=None)
    ctx = build_context([home, broken])
    assert len(ctx.observed_pages) == 1
    assert ctx.vendors["google-fonts"].pages == [f"{SITE}/"]


def test_consent_platform_found_on_any_page_counts_for_the_site():
    home = _page(f"{SITE}/", "fonts.googleapis.com")
    contact = _page(f"{SITE}/contatti", "fonts.googleapis.com")
    contact.cmp_detected = ["iubenda"]
    ctx = build_context([home, contact])
    assert ctx.has_cmp is True
    assert ctx.cmp_detected == ["iubenda"]


def test_a_single_observation_still_works():
    """The single-page call shape is the common one and must not need a list."""
    ctx = build_context(_page(f"{SITE}/", "fonts.googleapis.com"))
    assert len(ctx.observed_pages) == 1
    assert ctx.vendors["google-fonts"].pages == [f"{SITE}/"]


def test_normalise_keeps_identifying_parameters_and_drops_campaign_ones():
    """`?id=42` is a page; `?utm_source=news` is a visit. Dropping the whole
    query would merge distinct pages into one."""
    assert normalise(f"{SITE}/scheda?id=42&utm_source=news&gclid=abc") == f"{SITE}/scheda?id=42"
    # parameter order is not identity
    assert normalise(f"{SITE}/s?b=2&a=1") == normalise(f"{SITE}/s?a=1&b=2")


# --------------------------------------------------- why a page was chosen


def test_the_reason_a_page_was_chosen_is_a_key_not_a_phrase():
    """It is printed in the report, and the report is rendered in the reader's
    language. An English phrase stored in the evidence arrives in an Italian
    PDF as an English phrase — the same defect as an English report telling its
    reader "nessuna risposta dal server", pointed the other way."""
    chosen = select_pages(_entry([f"{SITE}/contatti", f"{SITE}/chi-siamo"]), 2)
    assert chosen, "the fixture selected no pages"
    for candidate in chosen:
        assert candidate.why.startswith("page_choice."), (
            f"{candidate.why!r} is a phrase, and phrases are translated"
        )


def test_every_selection_reason_reads_in_both_languages():
    from pmate.i18n import Translator
    from pmate.report.pdf import _why

    reasons = ["page_choice.entry", "page_choice.robots_skip"] + [
        c.why for c in select_pages(_entry([f"{SITE}/contatti", f"{SITE}/a/b/c/d"]), 4)
    ]
    for lang in ("en", "it"):
        t = Translator.for_locale(lang)
        for why in set(reasons):
            rendered = _why({"why": why, "kind": "contact"}, t)
            assert rendered and "⟦" not in rendered, f"[{lang}] {why} has no translation"
            assert not rendered.startswith("page_choice."), f"[{lang}] {why} was not resolved"


def test_evidence_written_before_the_reason_was_a_key_still_reads():
    """A JSON produced by an earlier version carries an English phrase. Passing
    it through beats printing a missing-key marker over the reader's report."""
    from pmate.i18n import Translator
    from pmate.report.pdf import _why

    assert _why({"why": "first contact page", "kind": "contact"}, Translator.for_locale("it")) == (
        "first contact page"
    )
