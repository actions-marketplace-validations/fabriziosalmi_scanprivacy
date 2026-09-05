"""Choosing which pages of a site to observe.

One page is not a site. A tracker that only runs on the contact form, an embed
that only appears on an article, a cookie set only in the members' area: none of
them exist as far as a single-page scan is concerned, and all of them are real.

Two constraints shape the selection:

- **Deterministic.** The same site must yield the same pages, or two scans stop
  being comparable and `pmate diff` starts reporting churn that never happened.
  Every ordering here is total: kind, then depth, then URL.
- **Representative, not exhaustive.** A handful of pages of *different kinds* —
  the entry, a contact page, a service page, a leaf article — surfaces far more
  than ten pages of the same news index. Crawling deeper is somebody else's
  budget and somebody else's server.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urldefrag, urlencode, urlsplit, urlunsplit

from ..knowledge.registry import is_first_party

# Page kinds, in the order they are worth spending a page load on. The regexes
# are multilingual because the sites are: a scan of a German site must find
# "kontakt" the way it finds "contatti".
KINDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "contact",
        re.compile(r"/(contatt|contact|kontakt|contacto|contato|nous-contacter|scriveteci)", re.I),
    ),
    (
        "form",
        re.compile(
            r"/(modul|form|preventiv|quote|richiest|iscri|signup|sign-up|register|registrazione|"
            r"newsletter|segnalazion|reclam)",
            re.I,
        ),
    ),
    (
        "services",
        re.compile(r"/(serviz|services|prodott|products|solution|soluzion|offerta|catalog)", re.I),
    ),
    (
        "about",
        re.compile(
            r"/(chi-siamo|chisiamo|about|azienda|company|uber-uns|ueber-uns|quienes-somos|"
            r"sobre|equipe|team|storia)",
            re.I,
        ),
    ),
    ("content", re.compile(r"/(news|notizie|blog|articol|magazine|press|attualit|post|eventi)", re.I)),
    ("account", re.compile(r"/(login|accedi|area-riservata|account|signin|sign-in|myaccount)", re.I)),
    ("search", re.compile(r"/(cerca|search|ricerca|suche|busca)", re.I)),
)

# Documents with their own reader: fetching them here would double the work and
# double the requests.
LEGAL_PATH = re.compile(
    r"/(privacy|cookie|informativa|datenschutz|note-legali|termini|terms|legal|impressum|"
    r"mentions-legales|aviso-legal|accessibilit)",
    re.I,
)

# Not pages: downloads, media, feeds. A GET on a 40 MB PDF teaches nothing about
# third parties and is rude.
NON_PAGE_SUFFIX = re.compile(
    r"\.(pdf|zip|rar|7z|tar|gz|docx?|xlsx?|pptx?|csv|jpe?g|png|gif|webp|avif|svg|ico|mp[34]|"
    r"m4[av]|mov|avi|webm|wav|ogg|woff2?|ttf|eot|xml|rss|atom|json|txt)$",
    re.I,
)

# Anything that changes state, however unlikely a GET is to trigger it. The
# posture is "do what a visitor's browser does when it opens a page", and a
# visitor does not open /logout by accident.
DESTRUCTIVE_PATH = re.compile(
    r"/(logout|signout|sign-out|esci|disconnect|delete|remove|unsubscribe|cancella|"
    r"disiscri|reset|checkout|carrello|cart|payment|pagamento|admin|wp-admin)",
    re.I,
)

# Campaign parameters identify a *visit*, not a page: two URLs that differ only
# by utm_source are the same page and must normalise to the same string.
# Filtering happens per parameter, not per query: dropping the whole query would
# collapse `?id=42` — which does identify a page — onto the bare path.
TRACKING_PARAMS = frozenset(
    {
        "gclid", "fbclid", "msclkid", "dclid", "twclid", "igshid", "mc_cid", "mc_eid",
        "_ga", "_gl", "ref", "referrer", "source", "yclid", "wbraid", "gbraid",
    }
)
TRACKING_PARAM_PREFIX = ("utm_", "pk_", "mtm_", "hsa_")
PAGINATION_PATH = re.compile(r"/(page|pagina|seite)/\d+/?$|/\d{4}/\d{2}(/\d{2})?/?$", re.I)


@dataclass(frozen=True, slots=True)
class PageCandidate:
    url: str
    kind: str
    depth: int
    why: str
    """Why this page was chosen, as a catalogue key.

    A phrase here would be an English phrase, and it is printed in the report —
    which is rendered in the reader's language. Keys are resolved at render
    time, like every other sentence the engine produces."""


def normalise(url: str) -> str:
    """One canonical form per page, so the same page is never visited twice.

    Fragments dropped, trailing slash normalised, query kept only when it is not
    obviously navigational noise — `?id=42` identifies a page, `?utm_source=x`
    does not.
    """
    url, _ = urldefrag(url)
    parts = urlsplit(url)
    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    kept = [
        (name, value)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
        if name.lower() not in TRACKING_PARAMS
        and not name.lower().startswith(TRACKING_PARAM_PREFIX)
    ]
    query = urlencode(sorted(kept))  # sorted: parameter order is not identity
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def _kind(path: str) -> str:
    for name, pattern in KINDS:
        if pattern.search(path):
            return name
    return "other"


def same_deployment(host: str, site_host: str) -> bool:
    """Is this the *same site*, rather than merely the same organisation?

    `is_first_party` compares registrable domains, which is the right question
    for "did the visitor's data leave the site" and the wrong one for "which
    pages does this scan cover". `www.cyberapi.io` and `threats.cyberapi.io`
    share an owner and nothing else: different deployment, different repository,
    usually a different person on the other end of the ticket. Following the
    link put jsDelivr findings under `www.cyberapi.io: D`, and sent the reader
    to a codebase that has no jsDelivr in it.

    The apex and its `www.` are the one pair that really is a single
    deployment — usually the same server, and typically one redirecting to the
    other — so they stay together.
    """
    return _apex(host) == _apex(site_host)


def _apex(host: str) -> str:
    host = host.lower().strip(".")
    return host[4:] if host.startswith("www.") else host


def _is_candidate(url: str, site_host: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return False
    if not same_deployment(parts.netloc, site_host):
        return False
    path = parts.path or "/"
    if NON_PAGE_SUFFIX.search(path) or DESTRUCTIVE_PATH.search(path):
        return False
    if LEGAL_PATH.search(path) or PAGINATION_PATH.search(path):
        return False
    return True


def select_pages(observation, limit: int, site_host: str | None = None) -> list[PageCandidate]:
    """Pages to visit *after* the entry page, at most `limit` of them.

    Links come from the entry page only. Following links from every page would
    turn a conformance check into a crawl, and a crawl needs a conversation with
    the site owner that a scan does not.
    """
    if limit <= 0:
        return []
    host = site_host or observation.host
    entry = normalise(observation.final_url or observation.url)

    seen: dict[str, PageCandidate] = {}
    for link in observation.links:
        url = normalise(link)
        if url == entry or url in seen or not _is_candidate(url, host):
            continue
        path = urlsplit(url).path or "/"
        seen[url] = PageCandidate(
            url=url,
            kind=_kind(path),
            depth=len([segment for segment in path.split("/") if segment]),
            why="",
        )

    order = {name: index for index, (name, _) in enumerate(KINDS)}
    order["other"] = len(KINDS)

    def sort_key(candidate: PageCandidate) -> tuple[int, int, str]:
        return (order[candidate.kind], candidate.depth, candidate.url)

    chosen: list[PageCandidate] = []
    taken_kinds: set[str] = set()

    # one page per kind first: variety finds more than depth
    for candidate in sorted(seen.values(), key=sort_key):
        if len(chosen) >= limit:
            break
        if candidate.kind == "other" or candidate.kind in taken_kinds:
            continue
        taken_kinds.add(candidate.kind)
        chosen.append(
            PageCandidate(candidate.url, candidate.kind, candidate.depth, "page_choice.first_of_kind")
        )

    # then a leaf page: articles carry the embeds a landing page never shows
    if len(chosen) < limit:
        deep = [c for c in seen.values() if c.depth >= 2 and c.url not in {p.url for p in chosen}]
        for candidate in sorted(deep, key=lambda c: (-c.depth, c.url))[: limit - len(chosen)]:
            chosen.append(PageCandidate(candidate.url, candidate.kind, candidate.depth, "page_choice.deep"))

    # then fill with whatever is closest to the root: the main navigation
    if len(chosen) < limit:
        rest = [c for c in seen.values() if c.url not in {p.url for p in chosen}]
        for candidate in sorted(rest, key=sort_key)[: limit - len(chosen)]:
            chosen.append(PageCandidate(candidate.url, candidate.kind, candidate.depth, "page_choice.navigation"))

    return chosen[:limit]


def sibling_hosts(observation, site_host: str | None = None) -> list[str]:
    """Hosts the entry page links to that belong to the same organisation but
    not to the same deployment.

    Returned so the caller can say so. Dropping them silently would trade a
    finding attributed to the wrong host for a hole in the evidence nobody can
    see, and this engine records the pages it chose not to visit for exactly
    that reason.
    """
    host = site_host or observation.host
    out: list[str] = []
    for link in observation.links:
        parts = urlsplit(normalise(link))
        netloc = parts.netloc.lower()
        if parts.scheme not in ("http", "https") or not netloc:
            continue
        if same_deployment(netloc, host) or not is_first_party(netloc, host):
            continue
        if netloc not in out:
            out.append(netloc)
    return sorted(out)
