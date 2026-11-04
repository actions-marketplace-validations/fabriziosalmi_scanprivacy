"""The site is built from the repository, and has to be right before anyone sees it."""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

pytest.importorskip("markdown")

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("site_build", ROOT / "site" / "build.py")
site_build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(site_build)


@pytest.fixture
def built(tmp_path):
    out = tmp_path / "site"
    site_build.build(out)
    return out


def test_every_doc_becomes_a_page(built):
    docs = {p.stem for p in (ROOT / "docs").glob("*.md")}
    assert docs, "no docs to publish"
    for stem in docs:
        assert (built / "docs" / f"{stem}.html").is_file()
    assert (built / "index.html").is_file() and (built / "robots.txt").is_file()
    assert (built / ".nojekyll").is_file()


def test_links_between_docs_work_on_the_site(built):
    for page in (built / "docs").glob("*.html"):
        for target in re.findall(r'href="([^"#:/][^"#:]*)"', page.read_text(encoding="utf-8")):
            if target.startswith("http"):
                continue
            assert target.endswith(".html"), f"{page.name} links to {target}, which is not a built page"
            assert (page.parent / target).is_file(), f"{page.name} links to missing {target}"


def test_a_link_out_of_docs_goes_to_the_repository(built):
    text = (built / "docs" / "index.html").read_text(encoding="utf-8")
    assert "github.com/fabriziosalmi/scanprivacy/blob/main/README.md" in text
    assert 'href="../README.md"' not in text


def test_the_landing_page_has_no_leftover_marker_without_an_example(built):
    text = (built / "index.html").read_text(encoding="utf-8")
    assert "<!--EXAMPLE-->" not in text
    assert "/example/" not in text


def test_an_example_report_is_published_and_linked_when_there_is_one(tmp_path):
    example = tmp_path / "example"
    example.mkdir()
    (example / "report.md").write_text("# Privacy assessment of a site\n\nBody.\n", encoding="utf-8")
    (example / "report.pdf").write_bytes(b"%PDF-1.4")
    (example / "evidence.json").write_text("{}", encoding="utf-8")
    out = tmp_path / "site"
    written = site_build.build(out, example)
    assert {"example/index.html", "example/report.pdf", "example/evidence.json"} <= set(written)
    assert "/example/" in (out / "index.html").read_text(encoding="utf-8")
    assert "Privacy assessment of a site" in (out / "example" / "index.html").read_text(encoding="utf-8")


def test_no_scan_result_is_built_into_the_site_without_an_example(built):
    assert not list(built.rglob("evidence.json")) and not list(built.rglob("*.pdf"))
