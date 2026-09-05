"""Recognising the Art. 13 elements a notice actually states.

Found by reading the notice the engine was complaining about. One page —
`fabriziosalmi.github.io/privacy` — is linked from 32 sites of one estate, and
the engine reported "purposes" missing from every one of them. The notice
states its purposes plainly, in both its languages, under the heading "What
data is processed, and why" / "Quali dati sono trattati e perché".

The pattern only knew the first person: "why we process", "perché li
trattiamo". A notice written impersonally — which is how most of them are
written, and how Italian legal prose is usually written — read as a notice that
never said why. 35 findings across 44 sites, all of them the same false one,
because one page is shared.

The other half of the job is not over-correcting. A bare purposive phrase ("in
order to", "al fine di") appears somewhere in nearly every notice; matching one
would make this element true everywhere and the finding worth nothing. What is
recognised is the shape of a statement *about* why, not any sentence that
happens to contain a reason — and the negatives below are what hold that line.
"""

from __future__ import annotations

import pytest

from scanprivacy.observe.docs import ART13_ELEMENTS

PURPOSES = ART13_ELEMENTS["purposes"]
RETENTION = ART13_ELEMENTS["retention"]
CONTACT = ART13_ELEMENTS["contact"]


STATES_ITS_PURPOSES = [
    # the real notice, both halves
    "What data is processed, and why. Your IP address and basic request data are processed",
    "Quali dati sono trattati e perché. Indirizzo IP e dati basilari della richiesta",
    # impersonal variants of the same idea
    "What personal data is collected, and why we keep it",
    "Why personal data is processed",
    "Why data is collected on this site",
    "Quali dati vengono trattati e perché",
    "Perché questi dati sono trattati",
    "Perché li trattiamo",
    "Perché vengono trattati",
    # the wordings that already worked, which must keep working
    "Finalità del trattamento",
    "Scopo del trattamento",
    "Scopi del trattamento",
    "Purposes of the processing",
    "Purpose of the collection",
    "What we collect",
    "Why we process your data",
    "Zwecke der Verarbeitung",
]

STATES_NO_PURPOSE = [
    # a notice that names a controller and rights and never says why
    "Data Controller: Example Srl, Milan. Contact: privacy@example.org. "
    "You have the right of access, rectification and erasure under Arts. 15-22 GDPR.",
    # purposive prose that is not a statement of purposes — the over-broadening trap
    "Cookies are set in order to remember your session. See the cookie policy.",
    "I dati sono conservati al fine di garantire la sicurezza del sito.",
    "We use a CDN to deliver pages quickly.",
    "Why you can trust us: we are audited annually.",
    "Perché scegliere il nostro servizio",
    # near misses that must not fire
    "What we do: we build open-source tools.",
    "Quali sono i tuoi diritti",
]


@pytest.mark.parametrize("text", STATES_ITS_PURPOSES)
def test_a_notice_that_says_why_is_recognised(text: str):
    assert PURPOSES.search(text), f"purposes not recognised in: {text!r}"


@pytest.mark.parametrize("text", STATES_NO_PURPOSE)
def test_prose_that_merely_contains_a_reason_is_not_a_statement_of_purposes(text: str):
    match = PURPOSES.search(text)
    assert match is None, (
        f"over-broad: matched {match.group(0)!r} in text that states no purposes: {text!r}"
    )


def test_the_shared_notice_of_the_estate_that_exposed_this():
    """The document itself, as served. Kept as a fixture rather than fetched:
    the point is the wording that defeated the pattern, and it should keep
    defeating the old one long after the page changes."""
    notice = (
        "Privacy & Legal Notice. Who publishes these sites (Data Controller): Fabrizio Salmi. "
        "Contact for any privacy request: privacy@example.org. "
        "What data is processed, and why. Your IP address and basic request data (user-agent, "
        "page requested) are processed transiently by the hosting provider in order to deliver "
        "the page and to protect it against abuse. Legal basis: legitimate interest."
    )
    assert PURPOSES.search(notice)


def test_the_italian_half_stands_on_its_own():
    """A reader who only sees the Italian section must not be short an element
    the English section happened to carry."""
    notice = (
        "Chi pubblica questi siti (Titolare del trattamento): Fabrizio Salmi. "
        "Quali dati sono trattati e perché. Indirizzo IP e dati basilari della richiesta "
        "sono trattati in modo transitorio dal fornitore di hosting per erogare la pagina."
    )
    assert PURPOSES.search(notice)


# ------------------------------------------- retention, Art. 13(2)(a)

STATES_ITS_RETENTION = [
    # the affirmative form, with words in between — "conserviamo per" did not
    # survive two words of ordinary Italian
    "Conservazione. Conserviamo i dati per il tempo necessario alle finalità indicate.",
    "Conservati per 12 mesi",
    "Periodo di conservazione",
    "Conservazione dei dati",
    "Data retention",
    "Speicherdauer",
    # the negative form. "The period is none" is a complete answer to the
    # article, and it is how a static site with no logs of its own answers it.
    "Non conserviamo questi dati",
    "We do not store this data",
    "We keep no personal data",
    "No personal data is stored",
    "we never retain your information",
]

STATES_NO_RETENTION = [
    # statements about cookies are not statements about a retention period, and
    # accepting them would close a real finding on a site that never answers it
    "Cookies & device storage. This site sets no cookies.",
    "No cookies, no device storage",
    "We do not store cookies on your device",
    "We keep no cookies",
    "Non impostiamo cookie",
    "Il sito usa localStorage per ricordare il tema",
    "I tuoi diritti: accesso, rettifica, cancellazione, portabilità",
]


@pytest.mark.parametrize("text", STATES_ITS_RETENTION)
def test_a_notice_that_answers_how_long_is_recognised(text: str):
    assert RETENTION.search(text), f"retention not recognised in: {text!r}"


@pytest.mark.parametrize("text", STATES_NO_RETENTION)
def test_a_statement_about_cookies_is_not_a_retention_period(text: str):
    match = RETENTION.search(text)
    assert match is None, (
        f"over-broad: matched {match.group(0)!r} in text that gives no retention "
        f"period: {text!r}"
    )


# --------------------------------------------- contact, Art. 13(1)(a)

HAS_A_CONTACT = [
    "Per qualsiasi richiesta scrivi a privacy@example.org",
    "PEC: titolare@pec.example.it",
    "posta elettronica certificata",
]

HAS_NO_CONTACT = [
    "Titolare del trattamento: Fabrizio Salmi, Genova, Italia",
    "Contattaci tramite il modulo di contatto sul sito",
    "Contact us through the form on our website",
]


@pytest.mark.parametrize("text", HAS_A_CONTACT)
def test_an_address_in_the_document_counts_however_it_is_written(text: str):
    assert CONTACT.search(text), f"contact not recognised in: {text!r}"


@pytest.mark.parametrize("text", HAS_NO_CONTACT)
def test_naming_the_controller_is_not_giving_a_contact(text: str):
    match = CONTACT.search(text)
    assert match is None, f"over-broad: matched {match.group(0)!r} in {text!r}"


# Cloudflare email obfuscation. The address is in the markup, hex-encoded in an
# attribute, and a script swaps it in on load — so stripping tags threw away the
# one thing Art. 13(1)(a) asks for, and a notice served through Cloudflare read
# as a notice with no contact address on a page where the reader sees one.
CLOUDFLARE_NOTICE = (
    '<p>Per richieste scrivi a <a href="/cdn-cgi/l/email-protection#a1b2">'
    '<span class="__cf_email__" data-cfemail="2046414252495a494f0e53414c4d49">'
    '[email&#160;protected]</span></a></p>'
)


def test_an_obfuscated_address_survives_text_extraction():
    """The fix belongs in the extraction, not the pattern: an element allowed to
    match markup could be satisfied by a `<meta>` tag no reader ever sees."""
    from scanprivacy.observe.docs import _to_text

    assert CONTACT.search(_to_text(CLOUDFLARE_NOTICE))


def test_it_is_recognised_but_never_decoded():
    """The encoding exists to keep harvesters off the address. A privacy tool
    that unwrapped it to print it in a report would be doing the harvester's
    work — and it does not need the value to answer what the article asks."""
    from scanprivacy.observe.docs import _to_text

    text = _to_text(CLOUDFLARE_NOTICE)
    assert "cf-protected-email" in text
    assert "@" not in text.replace("[email protected]", ""), (
        "an address was decoded out of the obfuscation"
    )


def test_a_notice_with_no_address_is_unaffected_by_the_marker():
    from scanprivacy.observe.docs import _to_text

    plain = "<p>Titolare: Fabrizio Salmi, Genova. Contattaci col modulo.</p>"
    assert CONTACT.search(_to_text(plain)) is None
