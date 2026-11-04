"""Reading the site's own legal documents.

This is where the engine stops being a tracker scanner and becomes a
conformance engine: it compares what the site *declares* with what the site
*does*. The gap between the two is the finding a data protection authority
actually acts on, and it is fully deterministic — no judgement needed to see
that a notice never names the processor whose script the page just loaded.
"""

from __future__ import annotations

import hashlib
import html
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import Browser

from ..config import DEFAULTS, UA, Settings
from ..knowledge.registry import Vendor, aliases_for, all_vendors
from .browser import new_context
from .discover import looks_like
from .rate import PerHostLimiter

# GDPR Art. 13 elements, as surface-detectable text. Bilingual IT/EN: the
# Italian expressions come first because they are the primary market.
ART13_ELEMENTS: dict[str, re.Pattern[str]] = {
    "controller": re.compile(
        r"titolare\s+del\s+trattamento|data\s+controller|verantwortlicher|"
        r"responsable\s+du\s+traitement|responsable\s+del\s+tratamiento",
        re.I,
    ),
    # Art. 13(1)(a), the controller's contact details.
    #
    # `cf-protected-email` is the marker `_to_text` leaves where Cloudflare had
    # obfuscated an address — see the note there. Matching on the extracted text
    # rather than the markup keeps every element reading the same source: a
    # pattern allowed to see attributes could be satisfied by a `<meta>` tag no
    # reader ever sees.
    "contact": re.compile(
        r"[\w.+-]+@[\w-]+\.[\w.]+|pec[:\s]|posta\s+elettronica\s+certificata|"
        r"cf-protected-email",
        re.I,
    ),
    "dpo": re.compile(
        r"\bdpo\b|\brpd\b|responsabile\s+(?:della\s+)?protezione\s+dei\s+dati|"
        r"data\s+protection\s+officer|datenschutzbeauftragte",
        re.I,
    ),
    # Art. 13(1)(c). The element is the *why*, and the wording that carries it is
    # very often impersonal: "What data is processed, and why", "Quali dati sono
    # trattati e perché". The pattern only recognised the first person — "why we
    # process", "perché li trattiamo" — and reported the element missing on a
    # notice that stated it plainly, across 35 sites of one estate, because they
    # all link the same page.
    #
    # Broadened to the impersonal forms, and no further. A bare purposive phrase
    # ("in order to", "al fine di") appears in almost any notice, so matching one
    # would make this element true everywhere and the finding worth nothing. What
    # is added here is the shape of a *statement about why*, not any sentence
    # that happens to contain a reason.
    "purposes": re.compile(
        r"finalit[àa]|scop[oi]\s+del\s+trattamento|"
        r"perch[ée]\s+(?:li\s+|questi\s+dati\s+)?(?:trattiamo|(?:sono|vengono)\s+trattati)|"
        r"quali\s+dati\s+[^.]{0,60}?\be\s+perch[ée]\b|"
        r"purposes?\s+of\s+(?:the\s+)?(?:processing|collection)|"
        r"what\s+we\s+(?:process|collect)|"
        r"what\s+(?:personal\s+)?(?:data|information)\s+[^.]{0,60}?\band\s+why\b|"
        r"why\s+we\s+(?:process|collect|use)|"
        r"why\s+(?:it\s+is|they\s+are|(?:personal\s+)?(?:data|information)\s+(?:is|are))\s+"
        r"(?:processed|collected|used)|"
        r"zwecke\s+der\s+verarbeitung",
        re.I,
    ),
    "legal_basis": re.compile(
        r"base\s+giuridica|basi\s+giuridiche|legal\s+bas[ei]s|art(?:icolo)?\.?\s*6|"
        r"legittimo\s+interesse|legitimate\s+interest|rechtsgrundlage",
        re.I,
    ),
    "recipients": re.compile(
        r"destinatari|responsabil[ei]\s+del\s+trattamento|processors?|recipients?|"
        r"sub-?responsabili|empf[äa]nger",
        re.I,
    ),
    "transfers": re.compile(
        r"paes[ei]\s+terz[oi]|trasferiment[oi]\s+(?:dei\s+dati\s+)?(?:all.estero|extra)|"
        r"third\s+countr|clausole\s+contrattuali\s+standard|standard\s+contractual\s+clauses|"
        r"\bscc\b|data\s+privacy\s+framework|\bdpf\b|drittland",
        re.I,
    ),
    # Art. 13(2)(a). Two wordings defeated this and both are ordinary.
    #
    # "Conserviamo i dati per il tempo necessario" did not match
    # `conserv(?:iamo|ati)\s+per` — two words in between were enough. And
    # "Non conserviamo questi dati" / "We do not store this data" is a complete
    # answer to the article, the period being none; the pattern only knew the
    # affirmative form, so a notice that answered the question by saying nothing
    # is kept was read as a notice that never answered it.
    #
    # The negative forms require the object to be *data*: "we do not store
    # cookies" and "no device storage" are statements about cookies, and
    # accepting them as a retention period would close a real finding.
    "retention": re.compile(
        r"period[oi]\s+di\s+conservazione|conservazione\s+dei\s+dati|retention|"
        r"conserv(?:iamo|ati|iamo\s+i\s+dati)[^.]{0,30}?\bper\b|"
        r"non\s+conserviamo[^.]{0,25}?\bdat[io]\b|"
        r"nessuna\s+conservazione|"
        r"we\s+(?:do\s+not|don.t|never)\s+(?:store|retain|keep)\s+"
        r"(?:this\s+|any\s+|your\s+|such\s+|personal\s+)*(?:data|information|logs?)|"
        r"no\s+(?:personal\s+)?(?:data|information)\s+(?:is|are)\s+(?:stored|retained|kept)|"
        r"we\s+(?:keep|store|retain)\s+no\s+(?:personal\s+)?(?:data|information)|"
        r"speicherdauer",
        re.I,
    ),
    "rights": re.compile(
        r"diritt[oi]\s+(?:di\s+accesso|dell.interessato)|rettifica|cancellazione|portabilit|"
        r"right\s+to\s+(?:access|erasure|rectification)|your\s+rights|betroffenenrechte",
        re.I,
    ),
    "complaint": re.compile(
        r"reclamo|garante\s+per\s+la\s+protezione|autorit[àa]\s+di\s+controllo|"
        r"supervisory\s+authority|lodge\s+a\s+complaint|aufsichtsbeh[öo]rde",
        re.I,
    ),
    "profiling": re.compile(
        r"profilazione|profiling|decision[ei]\s+automatizzat|automated\s+decision", re.I
    ),
    "last_updated": re.compile(
        r"ultim[oa]\s+aggiornamento|aggiornat[ao]\s+al|last\s+updated?|versione\s+del\s+\d|stand:",
        re.I,
    ),
}

# Elements whose absence is not, by itself, a breach: the DPO exists only in
# the cases of Art. 37, the profiling paragraph only where there is automated
# decision-making, and a revision date is good practice rather than law. They
# are still reported, but never counted as a missing obligation.
ART13_CONDITIONAL: frozenset[str] = frozenset({"dpo", "profiling", "last_updated"})


# Cookie-specific elements, relevant when a cookie/tracker was observed.
COOKIE_ELEMENTS: dict[str, re.Pattern[str]] = {
    "cookie_list": re.compile(
        r"durata|scadenza|expiry|expiration|\bgiorni\b|\bmesi\b|\bsession[ei]?\b|laufzeit", re.I
    ),
    "how_to_withdraw": re.compile(
        r"disabilitar|revoca|opt-?out|impostazioni\s+del\s+browser|browser\s+settings|"
        r"withdraw|widerruf",
        re.I,
    ),
}

_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.S | re.I)
_HTML_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


@dataclass(slots=True)
class DocumentEvidence:
    kind: str  # privacy | cookie | terms | accessibility | dpo
    url: str
    status: int | None
    ok: bool
    text_len: int = 0
    error: str | None = None
    """Free text, and only ever a diagnostic — an exception's own words. Never
    a sentence for a reader: see error_key."""
    error_key: str | None = None
    error_params: dict[str, Any] = field(default_factory=dict)
    """Why this document could not be used, as a catalogue key.

    These strings reach the report. Written inline they were Italian, in an
    engine whose entire premise is that findings carry no sentences — so an
    English report could tell its reader "nessuna risposta dal server". A key
    renders in whatever language the report is asked for, which is what every
    other string in this package already does."""
    discovery: str = ""  # how this URL was chosen, for auditability
    elements: dict[str, bool] = field(default_factory=dict)
    element_snippets: dict[str, str] = field(default_factory=dict)
    """For each element found, the passage that satisfied it — so the reader
    can check the engine read the document the way they would."""
    cookie_elements: dict[str, bool] = field(default_factory=dict)
    declared_vendors: list[str] = field(default_factory=list)  # vendor ids named in the text
    negated_vendors: list[str] = field(default_factory=list)
    """Named only inside a denial ("no advertising, no Google Ads"). Reporting
    these as declared would credit a notice for the opposite of what it says."""
    vendor_snippets: dict[str, str] = field(default_factory=dict)
    text_sha256: str = ""
    """Digest of the extracted text: pins the exact version of the document
    this analysis is about. Documents change; findings should not drift."""
    text: str = field(default="", repr=False)


# Cloudflare's email obfuscation. The address is in the markup, hex-encoded in
# an attribute, and a script swaps it in on load. Stripping tags therefore threw
# away the one thing Art. 13(1)(a) asks for, and a notice served through
# Cloudflare — which is a great many of them — read as a notice with no contact
# address, on a page where the reader plainly sees one.
#
# Substituted with a marker rather than decoded. The encoding exists to keep
# harvesters off the address, and a privacy tool that unwrapped it to print it
# into a report would be doing the harvester's work. Whether an address is there
# is the whole question; its value is not needed to answer it.
# The whole tag, not just the attribute: a marker substituted inside `<...>`
# is removed again two lines below with the tag around it.
_CF_EMAIL = re.compile(
    r'<[^<>]*(?:data-cfemail="[0-9a-fA-F]{8,}"|/cdn-cgi/l/email-protection)[^<>]*>'
)
CF_EMAIL_MARKER = " cf-protected-email "


def _to_text(html_source: str) -> str:
    txt = _CF_EMAIL.sub(CF_EMAIL_MARKER, html_source)
    txt = _TAG_RE.sub(" ", txt)
    txt = _HTML_RE.sub(" ", txt)
    # entities must be resolved before matching: a notice written with &amp;
    # or &egrave; would otherwise be read differently from how it displays.
    txt = html.unescape(txt)
    return _WS_RE.sub(" ", txt).strip()


# A vendor named inside a denial is not a declared recipient — it is the
# opposite. "no advertising, no Google Ads" must not count as disclosure.
_NEGATION = re.compile(
    r"\b(no|non|nessun[ao]?|senza|niente|né|nè|neither|nor|without|we\s+do\s+not|"
    r"non\s+utilizziamo|non\s+usiamo|non\s+sono\s+presenti|assenza\s+di)\b",
    re.I,
)


def _is_negated(text: str, match: re.Match[str], window: int = 90) -> bool:
    before = text[max(0, match.start() - window) : match.start()]
    # only the closest clause counts: a negation before a full stop is unrelated
    clause = re.split(r"[.;:!?]\s", before)[-1]
    return bool(_NEGATION.search(clause))


def _snippet(text: str, match: re.Match[str] | None, width: int = 110) -> str:
    if match is None:
        return ""
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    return ("… " if start else "") + text[start:end].strip() + (" …" if end < len(text) else "")


def _declared_vendors(text: str, vendors: list[Vendor]) -> tuple[list[str], list[str]]:
    """Which vendors the document names, and which it names only to deny.

    Word-boundary matching, not substring: an Italian notice mentioning
    "Vercelli" does not declare Vercel, and "metà" does not declare Meta.
    Returns (dichiarati, negati).
    """
    low = text.lower()
    declared: list[str] = []
    negated: list[str] = []
    for v in vendors:
        for alias in sorted(aliases_for(v.id)):
            if not alias:
                continue
            hit = None
            for m in re.finditer(rf"(?<!\w){re.escape(alias)}(?!\w)", low):
                if not _is_negated(low, m):
                    hit = m
                    break
                hit = hit or False  # seen, but only inside a denial
            if hit:
                declared.append(v.id)
                break
            if hit is False:
                negated.append(v.id)
                break
    return sorted(set(declared)), sorted(set(negated))


async def fetch_document(
    browser: Browser,
    url: str,
    kind: str,
    settings: Settings = DEFAULTS,
    user_agent: str | None = None,
    discovery: str = "",
    limiter: PerHostLimiter | None = None,
) -> DocumentEvidence:
    """Open one legal document the same way a visitor would, and read it.

    `limiter` is the scan's per-host budget. A document is a page load like any
    other, so it waits its turn: the promise is one load per second per host,
    not one load per second except for the legal documents.
    """

    ev = DocumentEvidence(kind=kind, url=url, status=None, ok=False, discovery=discovery)
    context = await new_context(browser, user_agent or UA, settings)
    page = await context.new_page()
    try:
        if limiter is not None:
            await limiter.wait(urlsplit(url).netloc)
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=settings.nav_timeout_ms)
        ev.status = resp.status if resp else None
        await page.wait_for_timeout(700)
        html = await page.content()
        text = _to_text(html)[: settings.document_max_bytes]
        ev.text = text
        ev.text_len = len(text)
        reachable = bool(resp and resp.status < 400 and ev.text_len > 200)
        if resp is None:
            ev.error_key = "documents.error.no_response"
        elif resp.status >= 400:
            ev.error_key = "documents.error.http_status"
            ev.error_params = {"status": resp.status}
        elif ev.text_len <= 200:
            ev.error_key = "documents.error.too_short"
            ev.error_params = {"n": ev.text_len}
        # A reachable page is not yet the document: verify it reads like one.
        # This is what keeps an article *about* privacy from being mistaken
        # for the privacy notice.
        ev.ok = reachable and looks_like(kind, text)
        if reachable and not ev.ok:
            ev.error_key = "documents.error.not_recognisable"
            ev.error_params = {"kind": kind}
        if ev.ok:
            ev.text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
            for k, pat in ART13_ELEMENTS.items():
                m = pat.search(text)
                ev.elements[k] = bool(m)
                if m:
                    ev.element_snippets[k] = _snippet(text, m)
            ev.cookie_elements = {k: bool(pat.search(text)) for k, pat in COOKIE_ELEMENTS.items()}
            ev.declared_vendors, ev.negated_vendors = _declared_vendors(text, all_vendors())
            for vendor in all_vendors():
                if vendor.id not in ev.declared_vendors:
                    continue
                for alias in sorted(aliases_for(vendor.id)):
                    m = re.search(rf"(?<!\w){re.escape(alias)}(?!\w)", text, re.I)
                    if m:
                        ev.vendor_snippets[vendor.id] = _snippet(text, m)
                        break
    except Exception as e:
        ev.error = f"{type(e).__name__}: {e}"
    finally:
        await context.close()
    return ev


async def fetch_documents(
    browser: Browser,
    links: list[tuple[str, str, str]],
    settings: Settings = DEFAULTS,
    user_agent: str | None = None,
    limiter: PerHostLimiter | None = None,
) -> list[DocumentEvidence]:
    """`links` is a list of (kind, url, discovery), already prioritised."""

    out: list[DocumentEvidence] = []
    for kind, url, why in links[: settings.max_documents]:
        out.append(
            await fetch_document(browser, url, kind, settings, user_agent, discovery=why, limiter=limiter)
        )
    return out


def doc_to_dict(ev: DocumentEvidence, include_text: bool = False) -> dict[str, Any]:
    d = {
        "kind": ev.kind,
        "url": ev.url,
        "status": ev.status,
        "ok": ev.ok,
        "text_len": ev.text_len,
        "error": ev.error,
        "error_key": ev.error_key,
        "error_params": ev.error_params,
        "discovery": ev.discovery,
        "text_sha256": ev.text_sha256,
        "elements": ev.elements,
        "element_snippets": ev.element_snippets,
        "cookie_elements": ev.cookie_elements,
        "declared_vendors": ev.declared_vendors,
        "negated_vendors": ev.negated_vendors,
        "vendor_snippets": ev.vendor_snippets,
    }
    if include_text:
        d["text"] = ev.text
    return d
