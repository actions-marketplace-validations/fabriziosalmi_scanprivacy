"""Finding the *actual* legal documents.

privacy-pa matched any link whose text or href contained "privacy". On a
municipality site that works. On federprivacy.org — an association whose every
article is about privacy — it picks up a webinar page and the whole conformance
reading collapses: the engine would read the wrong document, then declare
vendors "undisclosed" against a text that was never the notice.

So documents are *scored*, not matched: the URL path carries far more signal
than the link text, article-shaped paths are penalised, and what is fetched is
verified to actually read like the document it claims to be. When no link
qualifies, a small number of conventional paths are tried — plain GETs of
public URLs, robots.txt honoured, nothing an ordinary visitor could not do.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

# Path shapes that are the document itself, per kind.
PATH_STRONG: dict[str, re.Pattern[str]] = {
    "privacy": re.compile(
        r"/(privacy|privacy[-_]?policy|policy[-_]?privacy|informativa(?:[-_](?:privacy|sulla[-_]privacy))?|"
        r"privacy[-_]e[-_]cookie|datenschutz|politique[-_]de[-_]confidentialite|politica[-_]de[-_]privacidad)"
        r"(?:\.\w+)?/?$",
        re.I,
    ),
    "cookie": re.compile(r"/(cookie|cookies|cookie[-_]?policy|informativa[-_]cookie)(?:\.\w+)?/?$", re.I),
    "terms": re.compile(
        r"/(note[-_]legali|termini(?:[-_]e[-_]condizioni)?|condizioni[-_]d.?uso|terms(?:[-_]of[-_](?:use|service))?|"
        r"legal(?:[-_]notice)?|impressum|mentions[-_]legales|aviso[-_]legal)(?:\.\w+)?/?$",
        re.I,
    ),
    "accessibility": re.compile(
        r"/(accessibilit[àa]|dichiarazione[-_]di[-_]accessibilit[àa]|accessibility(?:[-_]statement)?)(?:\.\w+)?/?$",
        re.I,
    ),
}

PATH_WEAK: dict[str, re.Pattern[str]] = {
    "privacy": re.compile(r"privacy|informativa|datenschutz|confidentialit", re.I),
    "cookie": re.compile(r"cookie", re.I),
    "terms": re.compile(r"legal|termini|terms|condizioni|impressum", re.I),
    "accessibility": re.compile(r"accessibilit", re.I),
}

# Exact link texts, normalised. A footer link to the notice is short and says
# what it is; an article title is long and says something else.
TEXT_EXACT: dict[str, set[str]] = {
    "privacy": {
        "privacy", "privacy policy", "privacy & legal", "privacy e legal", "informativa",
        "informativa privacy", "informativa sulla privacy", "informativa sul trattamento dei dati",
        "privacy e cookie", "privacy & cookie", "privacy & cookie policy", "protezione dei dati",
        "trattamento dei dati personali", "datenschutz", "data protection",
    },
    "cookie": {"cookie", "cookies", "cookie policy", "informativa cookie", "gestione cookie", "preferenze cookie"},
    "terms": {
        "note legali", "termini", "termini e condizioni", "condizioni d'uso", "condizioni di utilizzo",
        "terms", "terms of use", "terms of service", "legal", "legal notice", "impressum",
    },
    "accessibility": {"accessibilità", "accessibilita", "dichiarazione di accessibilità", "accessibility"},
}

# Content sections: a link that lives here is a page *about* the topic.
EDITORIAL_PATH = re.compile(
    r"/(news|notizie|articol|blog|attivit|agenda|eventi|event|corsi|master|webinar|press|magazine|"
    r"approfondiment|documenti|pubblicazioni|forum|convegn)", re.I
)

# What each document must actually contain to be accepted as that document.
CONTENT_SIGNALS: dict[str, list[re.Pattern[str]]] = {
    "privacy": [
        re.compile(r"titolare\s+del\s+trattamento|data\s+controller|verantwortlicher", re.I),
        re.compile(r"regolamento\s*\(?ue\)?\s*2016/679|gdpr|dati\s+personali|personal\s+data", re.I),
        re.compile(r"diritt[oi]\s+(?:di\s+accesso|dell.interessato)|your\s+rights|rettifica|cancellazione", re.I),
        re.compile(r"finalit[àa]|purpose|base\s+giuridica|legal\s+basis", re.I),
    ],
    "cookie": [
        re.compile(r"cookie", re.I),
        re.compile(r"durata|scadenza|expiry|disabilitar|browser", re.I),
    ],
    "terms": [
        re.compile(r"condizioni|termini|terms|responsabilit|licen[zc]", re.I),
    ],
    "accessibility": [
        re.compile(r"accessibilit", re.I),
    ],
}

FALLBACK_PATHS: dict[str, tuple[str, ...]] = {
    "privacy": ("/privacy", "/privacy-policy", "/informativa-privacy", "/privacy.html", "/privacy-e-cookie"),
    "cookie": ("/cookie-policy", "/cookie", "/informativa-cookie"),
    "terms": ("/note-legali", "/termini-e-condizioni", "/terms", "/legal"),
}

MIN_SCORE = 3


@dataclass(slots=True)
class Candidate:
    kind: str
    url: str
    score: int
    why: str


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().strip("»«•|-–—").strip().lower()


def score_link(kind: str, text: str, href: str) -> tuple[int, str]:
    path = urlsplit(href).path or "/"
    t = _norm(text)
    score = 0
    why = []

    if PATH_STRONG[kind].search(path):
        score += 7
        why.append("discovery.path_is_a_document")
    elif PATH_WEAK[kind].search(path):
        score += 2
        why.append("discovery.path_related")

    if t in TEXT_EXACT[kind]:
        score += 4
        why.append("discovery.link_text_exact")
    elif PATH_WEAK[kind].search(t) and len(t) <= 32:
        score += 1
        why.append("discovery.link_text_short_related")

    if EDITORIAL_PATH.search(path):
        score -= 7
        why.append("discovery.editorial_section")
    depth = len([s for s in path.split("/") if s])
    if depth >= 3:
        score -= 3
        why.append("discovery.deep_path")
    if len(t) > 45:
        score -= 3
        why.append("discovery.long_text")

    # Catalogue keys, joined. This string reaches the report — it is how a
    # reader checks that the engine picked the document they would have picked
    # — so it renders in their language like everything else.
    return score, ",".join(why)


def pick_documents(obs, kinds: tuple[str, ...] = ("privacy", "cookie", "terms", "accessibility")) -> list[Candidate]:
    """Best candidate per kind, above the acceptance threshold."""
    best: dict[str, Candidate] = {}
    for link in obs.legal_links:
        for kind in kinds:
            if kind not in PATH_STRONG:
                continue
            if link.kind != kind and not PATH_STRONG[kind].search(urlsplit(link.href).path or ""):
                continue
            if link.href.startswith("mailto:") or urlsplit(link.href).scheme not in ("http", "https"):
                continue
            score, why = score_link(kind, link.text, link.href)
            if score < MIN_SCORE:
                continue
            cur = best.get(kind)
            if cur is None or score > cur.score:
                best[kind] = Candidate(kind=kind, url=link.href, score=score, why=why)
    return [best[k] for k in kinds if k in best]


# `why` is a comma-separated list of catalogue keys, never prose: the report
# translates each one, and a literal sentence here reached the reader as
# "[ui.percorso convenzionale]" in an English report.
FALLBACK_WHY = "discovery.conventional_path,discovery.no_link_found"


def linked_why(candidate: "Candidate") -> str:
    """Why a document was chosen from the links on the page, as catalogue keys."""
    return ",".join(k for k in ("discovery.linked", candidate.why) if k)


def fallback_candidates(base_url: str, kind: str, limit: int = 3) -> list[Candidate]:
    return [
        Candidate(kind=kind, url=urljoin(base_url, p), score=0, why=FALLBACK_WHY)
        for p in FALLBACK_PATHS.get(kind, ())[:limit]
    ]


def looks_like(kind: str, text: str) -> bool:
    """Does the fetched text actually read like the document it claims to be?"""
    signals = CONTENT_SIGNALS.get(kind, [])
    if not signals:
        return True
    hits = sum(1 for pat in signals if pat.search(text))
    needed = 2 if len(signals) >= 2 else 1
    return hits >= needed
