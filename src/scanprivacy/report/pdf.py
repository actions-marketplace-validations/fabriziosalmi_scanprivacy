"""PDF rendering: Jinja2 + WeasyPrint.

The PDF is the artefact that gets attached to an email, forwarded to a supplier
or filed. It therefore carries the whole evidence, not a summary: requests with
timings, cookies, storage, headers, certificate, documents with their digests,
and the reproduction instructions. A reader must be able to check every claim
without asking us for anything.

The template contains no prose of its own — every string comes from the locale
catalogue through `t`, so the same template renders any language.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from ..core.models import ScanResult
from ..i18n.translator import DEFAULT_LOCALE, Translator
from .render import scan_posture_rows, render_scan

TEMPLATES = Path(__file__).resolve().parent / "templates"

MAX_REQUEST_ROWS = 120

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES)),
    autoescape=select_autoescape(["html", "xml"]),
    trim_blocks=True,
    lstrip_blocks=True,
)

_BACKTICK = re.compile(r"`([^`]+)`")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<!\*)\*([^*\n]+)\*(?!\*)")


def _mdinline(value: Any) -> Markup:
    """Rule and catalogue texts use the same inline markdown the terminal report
    uses; the PDF renders it rather than printing the markers."""
    if value is None:
        return Markup("")
    out = str(escape(str(value)))
    out = _BACKTICK.sub(r"<code>\1</code>", out)
    out = _BOLD.sub(r"<strong>\1</strong>", out)
    out = _ITALIC.sub(r"<em>\1</em>", out)
    return Markup(out)


_env.filters["md"] = _mdinline


def _cookie_rows(observation: dict[str, Any], graph: dict[str, Any], t: Translator) -> list[dict]:
    classes = {
        n["label"]: n["attrs"].get("data_class")
        for n in graph.get("nodes", [])
        if n["type"] == "cookie"
    }
    rows = []
    for cookie in (observation.get("browser") or {}).get("cookies") or []:
        data_class = classes.get(cookie.get("name"))
        rows.append(
            {
                **cookie,
                "class_display": t.label(data_class, "DataClass") if data_class else "—",
                "lifetime": t.t(
                    "report.labels.session" if cookie.get("session") else "report.labels.persistent"
                ),
            }
        )
    return rows


def _storage_rows(observation: dict[str, Any], graph: dict[str, Any], t: Translator) -> list[dict]:
    classes = {
        n["label"]: n["attrs"].get("data_class")
        for n in graph.get("nodes", [])
        if n["type"] == "storage"
    }
    rows = []
    for entry in (observation.get("browser") or {}).get("storage") or []:
        data_class = classes.get(entry.get("key"))
        rows.append({**entry, "class_display": t.label(data_class, "DataClass") if data_class else "—"})
    return rows


def _documents(observation: dict[str, Any], t: Translator) -> tuple[list[dict], list[dict]]:
    read, attempted = [], []
    for doc in observation.get("documents") or []:
        row = dict(doc)
        row["kind_display"] = t.label(doc.get("kind", "privacy"), "DocumentKind")
        # The reason a document could not be used, in the reader's language.
        # `error` stays available as a diagnostic but is never shown as prose:
        # it holds an exception's own words, which are not written for anyone.
        key = doc.get("error_key")
        row["error_text"] = t.t(key, **(doc.get("error_params") or {})) if key else None
        # How this URL was chosen: a comma-separated list of catalogue keys.
        # A reader uses it to check the engine picked the document they would
        # have picked, so it has to be in their language to be checkable.
        row["discovery"] = discovery_text(doc.get("discovery") or "", t)
        row["elements_present"] = [
            t.t(f"art13.{k}") for k, present in (doc.get("elements") or {}).items() if present
        ]
        row["elements_missing"] = [
            t.t(f"art13.{k}") for k, present in (doc.get("elements") or {}).items() if not present
        ]
        row["snippets"] = [
            (t.t(f"art13.{k}"), snippet) for k, snippet in (doc.get("element_snippets") or {}).items()
        ]
        (read if doc.get("ok") else attempted).append(row)
    return read, attempted


def _why(planned: dict[str, Any], t: Translator) -> str:
    """Resolve the selection reason, tolerating evidence written before it was
    a key. An older JSON carries an English phrase; printing it back is worse
    than nothing only if we pretend it is a translation, so it is passed
    through unchanged rather than rendered as a missing-key marker."""
    why = planned.get("why", "")
    if not why:
        return ""
    kind = planned.get("kind", "other")
    return t.maybe(why, kind=t.t(f"page_kind.{kind}")) or why


def _page_rows(observation: dict[str, Any], t: Translator) -> list[dict[str, Any]]:
    """One row per page the engine planned to visit, including the ones it did
    not: a page skipped by robots.txt is part of the method, not an omission."""
    rows = []
    observed = {page.get("final_url") or page.get("url"): page for page in observation.get("pages") or []}
    for planned in observation.get("page_plan") or []:
        page = observed.get(planned["url"]) or {}
        rows.append(
            {
                "url": planned["url"],
                "kind": t.t(f"page_kind.{planned.get('kind', 'other')}"),
                "why": _why(planned, t),
                "status": page.get("status"),
                "requests": len(page.get("requests") or []),
                "cookies": len(page.get("cookies") or []),
                "observed": bool(page.get("load_ok")),
            }
        )
    return rows


def _transfer_rows(screening: dict[str, Any], t: Translator) -> list[dict[str, Any]]:
    rows = []
    for entry in screening.get("transfers") or []:
        rows.append(
            {
                **entry,
                "product": entry.get("product"),
                "vendor": entry.get("vendor")
                or (t.t(f"remediation.{entry['vendor_key']}") if entry.get("vendor_key") else None),
                "basis_display": (
                    t.t(f"remediation.transfer_basis.{entry['transfer_basis']}")
                    if entry.get("transfer_basis")
                    else ""
                ),
                "data_display": [t.label(d, "DataType") for d in entry.get("data_types", [])],
                "alternative_display": [
                    t.t(f"remediation.alternative.{a}") for a in entry.get("alternatives", [])
                ],
            }
        )
    return rows


def build_context(result: ScanResult, locale: str = DEFAULT_LOCALE) -> dict[str, Any]:
    t = Translator.for_locale(locale)
    scan = render_scan(result, t)
    data = scan.raw
    observation = data.get("observation") or {}
    browser = observation.get("browser") or {}
    requests = browser.get("requests") or []
    read, attempted = _documents(observation, t)
    record = data.get("record") or {}

    return {
        "t": t,
        "scan": scan,
        "raw": data,
        "record": record,
        # Resolved here rather than in the template: Jinja was deriving the
        # label from the key, which is an English word in every language.
        "posture_rows": scan_posture_rows(record, t),
        "rerun": t.items(record.get("rerun_key", "record.rerun"), **(record.get("rerun_params") or {})),
        "requests": requests[:MAX_REQUEST_ROWS],
        "requests_total": len(requests),
        "cookies": _cookie_rows(observation, data.get("graph") or {}, t),
        "storage": _storage_rows(observation, data.get("graph") or {}, t),
        "headers": browser.get("response_headers") or {},
        "tls": observation.get("tls"),
        "documents": read,
        "documents_attempted": attempted,
        "pages": _page_rows(observation, t),
        "screening": (data.get("screening") or {}).get("dpia") or {},
        "transfers": _transfer_rows(data.get("screening") or {}, t),
        "transfer_questions": t.items("dpia.questions"),
    }


def render_html(result: ScanResult, locale: str = DEFAULT_LOCALE) -> str:
    return _env.get_template("report.html").render(**build_context(result, locale))


def check_resource(url: str) -> None:
    """Raise `ValueError` unless a report may load `url`: only `data:` URLs and
    files under the report templates.

    The report is rendered from text that came from a scanned site, and
    WeasyPrint fetches whatever a document points at (it has had SSRF advisories
    for exactly that). A report needs nothing from the network, so nothing else
    is allowed.
    """
    parts = urlsplit(url)
    allowed = parts.scheme == "data" or (
        parts.scheme == "file" and Path(unquote(parts.path)).resolve().is_relative_to(TEMPLATES.resolve())
    )
    if not allowed:
        raise ValueError(f"refusing to fetch {url!r}: a report loads no remote resources")


_LEGACY_LINK = re.compile(r"^link \(score \d+:\s*(.*?)\)?$")
_LEGACY_PROSE = {"percorso convenzionale": "discovery.conventional_path", "nessun link trovato": "discovery.no_link_found"}


def discovery_text(raw: str, t) -> str:
    """How a document was found, in the reader's language.

    The value is a comma-separated list of catalogue keys. Evidence stored by an
    earlier build holds prose instead (`link (score 11: discovery.x,discovery.y)`,
    or an Italian sentence), and a report regenerated from that file must not show
    a missing-key placeholder: legacy forms are mapped, and anything else is shown
    as it was recorded.
    """
    legacy = _LEGACY_LINK.match(raw.strip())
    if legacy:
        raw = f"discovery.linked,{legacy.group(1)}"
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return ", ".join(
        t.t(_LEGACY_PROSE.get(part, part)) if _LEGACY_PROSE.get(part, part).startswith("discovery.") else part
        for part in parts
    )


def local_only_fetcher():
    """A WeasyPrint URL fetcher that applies `check_resource` to every request."""
    from weasyprint.urls import URLFetcher  # lazy: pulls in cairo/pango

    class LocalOnlyFetcher(URLFetcher):
        def fetch(self, url, headers=None):
            check_resource(url)
            return super().fetch(url, headers)

    return LocalOnlyFetcher(allowed_protocols=("data", "file"))


def render_pdf(result: ScanResult, out: Path, locale: str = DEFAULT_LOCALE) -> Path:
    from weasyprint import HTML  # lazy: pulls in cairo/pango

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(
        string=render_html(result, locale), base_url=str(TEMPLATES), url_fetcher=local_only_fetcher()
    ).write_pdf(str(out))
    return out
