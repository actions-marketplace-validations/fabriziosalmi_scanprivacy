"""The site is built from the repository, and has to be right before anyone sees it."""

from __future__ import annotations

import importlib.util
import json
import re
import struct
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import pytest

pytest.importorskip("markdown")

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("site_build", ROOT / "site" / "build.py")
site_build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(site_build)


class _Page(HTMLParser):
    """What a page declares: its links, headings and landmarks."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []
        self.srcs: list[str] = []
        self.h1 = 0
        self.mains = 0
        self.meta: dict[str, str] = {}
        self.lang = ""
        self.ids: set[str] = set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.lang = a.get("lang", "")
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        if tag in ("link",) and a.get("href"):
            self.hrefs.append(a["href"])
        if tag in ("script", "img") and a.get("src"):
            self.srcs.append(a["src"])
        if tag == "h1":
            self.h1 += 1
        if tag == "main":
            self.mains += 1
        if tag == "meta" and a.get("name"):
            self.meta[a["name"]] = a.get("content", "")
        if a.get("id"):
            self.ids.add(a["id"])


def _parse(path: Path) -> _Page:
    page = _Page()
    page.feed(path.read_text(encoding="utf-8"))
    return page


def _example(tmp_path: Path, grade: str = "B") -> Path:
    example = tmp_path / "example"
    example.mkdir()
    (example / "report.md").write_text(
        "# Privacy assessment of a site\n\nBody.\n\n## Findings in detail\n\n### \U0001f535 No Content-Security-Policy\n\ntext\n",
        encoding="utf-8",
    )
    (example / "report.pdf").write_bytes(b"%PDF-1.4")
    (example / "evidence.json").write_text(
        json.dumps(
            {
                "url": "https://example.org/",
                "started_at": "2026-11-04T20:00:00+00:00",
                "site": {"domain": "example.org"},
                "verdict": {"grade": grade, "counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}},
                "findings": [{"id": "PM-SEC-03", "severity": "low"}],
            }
        ),
        encoding="utf-8",
    )
    return example


@pytest.fixture
def built(tmp_path):
    out = tmp_path / "site"
    site_build.build(out, _example(tmp_path))
    return out


def _resolve(out: Path, page: Path, href: str) -> Path | None:
    """Where a link lands in the built tree, as a browser would resolve it from
    `page`; None for an external one."""
    if href.startswith(("http://", "https://", "mailto:", "#")):
        return None
    base = "/" + page.relative_to(out).as_posix()
    path = urlsplit(urljoin(base, href)).path
    target = out / path.lstrip("/")
    return target / "index.html" if (path.endswith("/") or target.is_dir()) else target


def test_every_doc_becomes_a_page(built):
    docs = {p.stem for p in (ROOT / "docs").glob("*.md")}
    assert docs, "no docs to publish"
    for stem in docs:
        assert (built / "docs" / f"{stem}.html").is_file()
    for name in ("index.html", "404.html", "robots.txt", ".nojekyll", "assets/site.css", "assets/site.js", "assets/favicon.svg"):
        assert (built / name).is_file(), name


def test_every_internal_link_and_asset_resolves(built):
    pages = [p for p in built.rglob("*.html")]
    assert len(pages) >= 8
    for page in pages:
        parsed = _parse(page)
        for ref in parsed.hrefs + parsed.srcs:
            target = _resolve(built, page, ref)
            if target is not None:
                assert target.is_file(), f"{page.relative_to(built)} links to {ref}, which is not in the built site"


def test_every_page_has_one_h1_one_main_a_language_and_both_colour_schemes(built):
    for page in built.rglob("*.html"):
        parsed = _parse(page)
        name = str(page.relative_to(built))
        assert parsed.h1 == 1, f"{name} has {parsed.h1} h1"
        assert parsed.mains == 1, f"{name} has {parsed.mains} main landmarks"
        assert parsed.lang == "en", name
        assert parsed.meta.get("color-scheme") == "light dark", name
        assert "main" in parsed.ids, f"{name} has no skip-link target"


def test_the_fonts_the_stylesheet_names_are_published_with_their_licences(built):
    css = (built / "assets" / "site.css").read_text(encoding="utf-8")
    for name in re.findall(r"url\(fonts/([\w.-]+\.woff2)\)", css):
        assert (built / "assets" / "fonts" / name).is_file(), name
    assert (built / "assets" / "fonts" / "OFL-Inter.txt").is_file()
    assert (built / "assets" / "fonts" / "OFL-JetBrainsMono.txt").is_file()


def test_links_between_docs_work_on_the_site(built):
    for page in (built / "docs").glob("*.html"):
        for target in re.findall(r'href="([^"#:/][^"#:]*)"', page.read_text(encoding="utf-8")):
            assert target.endswith(".html"), f"{page.name} links to {target}, which is not a built page"
            assert (page.parent / target).is_file(), f"{page.name} links to missing {target}"


def test_a_link_out_of_docs_goes_to_the_repository(built):
    text = (built / "docs" / "index.html").read_text(encoding="utf-8")
    assert "github.com/fabriziosalmi/scanprivacy/blob/main/README.md" in text
    assert 'href="../README.md"' not in text


def test_tables_scroll_inside_a_labelled_focusable_region(built):
    text = (built / "docs" / "api.html").read_text(encoding="utf-8")
    assert text.count("<table>") == text.count('class="table-wrap"') >= 1
    assert 'role="region"' in text and 'tabindex="0"' in text


def test_the_rules_page_shows_severity_as_a_word_in_a_pill(built):
    text = (built / "docs" / "rules.html").read_text(encoding="utf-8")
    assert 'class="sev sev-critical">Critical<' in text
    assert "<td>critical</td>" not in text


def test_the_landing_page_summarises_the_example_when_there_is_one(built):
    text = (built / "index.html").read_text(encoding="utf-8")
    assert "{{" not in text and "<!--" not in text
    assert 'class="specimen"' in text and "example.org" in text
    assert 'class="grade grade-B"' in text
    assert "No Content-Security-Policy" in text


def test_without_an_example_the_landing_page_has_no_specimen_and_no_dead_link(tmp_path):
    out = tmp_path / "site"
    site_build.build(out)
    text = (out / "index.html").read_text(encoding="utf-8")
    assert "{{" not in text and "/example/" not in text and "specimen" not in text
    assert not (out / "example").exists()
    assert not list(out.rglob("evidence.json")) and not list(out.rglob("*.pdf"))


def test_the_example_report_is_published_with_its_files_and_no_emoji_in_headings(tmp_path):
    out = tmp_path / "site"
    written = site_build.build(out, _example(tmp_path))
    assert {"example/index.html", "example/report.pdf", "example/evidence.json"} <= set(written)
    text = (out / "example" / "index.html").read_text(encoding="utf-8")
    assert "Privacy assessment of a site" in text
    assert "\U0001f535" not in text, "a decorative emoji reached a heading"


def test_an_unreadable_example_is_left_out_rather_than_breaking_the_build(tmp_path):
    example = tmp_path / "example"
    example.mkdir()
    (example / "report.md").write_text("# x\n", encoding="utf-8")
    (example / "evidence.json").write_text("not json", encoding="utf-8")
    out = tmp_path / "site"
    site_build.build(out, example)
    assert "specimen" not in (out / "index.html").read_text(encoding="utf-8")


# ------------------------------------------------- policy, sharing and discovery


def _html_files(out: Path) -> list[Path]:
    return sorted(out.rglob("*.html"))


def test_every_page_carries_a_content_security_policy_and_a_referrer_policy(built):
    for path in _html_files(built):
        text = path.read_text(encoding="utf-8")
        assert 'http-equiv="Content-Security-Policy"' in text, path
        assert 'name="referrer" content="no-referrer"' in text, path


def test_no_page_needs_what_the_policy_forbids(built):
    """The policy allows only the site's own files, so a page that used an inline style, an
    inline script or an event handler would silently lose it in the browser."""
    for path in _html_files(built):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r'\sstyle="', text), f"{path}: inline style attribute"
        assert "<style" not in text, f"{path}: style element"
        assert not re.search(r"<script(?![^>]*\ssrc=)", text), f"{path}: inline script"
        assert not re.search(r'\son[a-z]+="', text), f"{path}: event handler attribute"
    assert "style" not in (built / "assets" / "site.js").read_text(encoding="utf-8").replace("sr-only", "")


def test_the_policy_would_catch_an_inline_style(built):
    """The guard's own guard."""
    assert re.search(r'\sstyle="', '<td style="text-align: right;">1</td>')
    assert site_build._no_inline_style('<td style="text-align: right;">1</td>') == '<td class="align-right">1</td>'


def test_a_shared_link_has_a_preview_image_of_the_right_size(built):
    png = (built / "assets" / "og.png").read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    width, height = struct.unpack(">II", png[16:24])
    assert (width, height) == (1200, 630)
    assert len(png) < 200_000
    text = (built / "index.html").read_text(encoding="utf-8")
    assert 'property="og:image" content="https://scanprivacy.org/assets/og.png"' in text
    assert 'name="twitter:card" content="summary_large_image"' in text


def test_the_sitemap_lists_exactly_the_pages_that_were_built(built):
    listed = set(re.findall(r"<loc>https://scanprivacy.org/([^<]*)</loc>", (built / "sitemap.xml").read_text(encoding="utf-8")))
    built_pages = {
        str(p.relative_to(built)).removesuffix("index.html") for p in _html_files(built) if p.name != "404.html"
    }
    assert listed == built_pages
    assert "Sitemap: https://scanprivacy.org/sitemap.xml" in (built / "robots.txt").read_text(encoding="utf-8")


def test_every_page_links_the_shared_privacy_notice(built):
    """The engine reports a site with no reachable privacy notice as critical; this site is scanned by it."""
    for path in _html_files(built):
        page = _parse(path)
        assert "https://fabriziosalmi.github.io/privacy" in page.hrefs, path
