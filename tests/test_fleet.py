"""Aggregation across a set of sites, and the batch run that feeds it.

This is the artefact an estate owner is actually shown — the one that says
"four problems, repeated" instead of "231 findings" — and until now it had no
test at all: 253 statements across batch.py, analyze/fleet.py and
report/fleet_markdown.py at zero coverage, while the engine core sat above 90%.

The property that matters here is not arithmetic. It is that an aggregate ranks
by **sites affected** rather than by finding count, and that it does not let a
single noisy site, or a site's own hosting note, look like an estate-wide
problem. An aggregate that overstates costs the credibility of every number
next to it.
"""

from __future__ import annotations

import json

import pytest

from scanprivacy.analyze.fleet import summarise
from scanprivacy.batch import _slug, read_targets, run_batch
from scanprivacy.report.fleet_markdown import render_fleet


def _result(
    url: str,
    grade: str = "C",
    findings: list[tuple[str, str]] | None = None,
    vendors: list[tuple[str, bool]] | None = None,
    status: str = "ok",
) -> dict:
    """A stored scan, shaped the way run_batch writes it."""
    rules = findings or []
    return {
        "scan_id": _slug(url),
        "url": url,
        "final_url": url,
        "status": status,
        "site": {"domain": url.split("//")[-1].strip("/")},
        "verdict": {"grade": grade, "conformant": grade == "A", "counts": {}, "blocking": []},
        "findings": [
            {
                "id": rule,
                "rule_id": rule,
                "severity": severity,
                "confidence": "certain",
                "subject_kind": "site",
                "subject_node": "site",
                "params": {},
                "evidence": {},
                "owner": "cto",
                "priority": "P2",
                "quick_win": severity in ("critical", "high"),
            }
            for rule, severity in rules
        ],
        "inventory": [
            {
                "vendor_id": vid,
                "vendor": "Example Inc.",
                "product": vid,
                "transfer": "non_eea",
                "declared": declared,
                "hosts": [f"{vid}.example"],
            }
            for vid, declared in (vendors or [])
        ],
        "observation": {"pages": [{"url": url}]},
    }


# ------------------------------------------------------------- ranking rule


def test_rules_are_ranked_by_sites_affected_not_by_finding_count():
    """One site with twelve instances of a rule is one site's problem. Twelve
    sites with one instance each is the estate's. Ranking by raw count inverts
    the two and points the owner at the wrong work."""
    noisy = _result("https://noisy.example", findings=[("PM-COK-04", "low")] * 12)
    spread = [
        _result(f"https://s{i}.example", findings=[("PM-SEC-02", "medium")]) for i in range(5)
    ]
    summary = summarise([noisy, *spread])

    first = summary.by_rule[0]
    assert first.rule_id == "PM-SEC-02", "the widespread rule must come first"
    assert first.sites == 5
    noisy_entry = next(r for r in summary.by_rule if r.rule_id == "PM-COK-04")
    assert noisy_entry.sites == 1
    assert noisy_entry.findings >= 12, "the count is still reported, just not what orders it"


def test_a_site_whose_only_finding_is_informational_is_not_counted_as_actionable():
    """Reporting "0 clean sites" because every site carries a note about its own
    hosting provider is technically true and useless."""
    results = [
        _result("https://a.example", grade="C", findings=[("PM-TRF-02", "info")]),
        _result("https://b.example", grade="D", findings=[("PM-SEC-01", "medium")]),
    ]
    summary = summarise(results)
    assert summary.sites_with_any_finding == 2
    assert summary.sites_with_actionable == 1


def test_a_site_with_nothing_at_all_is_reported_as_clean():
    summary = summarise([_result("https://clean.example", grade="A")])
    assert summary.clean_sites == ["clean.example"] or "clean.example" in str(summary.clean_sites)


# ------------------------------------------------------------ vendor spread


def test_a_vendor_undeclared_on_some_sites_reports_where():
    """"Present on 4 sites, undeclared on 3" is the sentence that starts a
    remediation. "Present on 4" alone is not."""
    results = [
        _result("https://a.example", vendors=[("google-fonts", False)]),
        _result("https://b.example", vendors=[("google-fonts", False)]),
        _result("https://c.example", vendors=[("google-fonts", True)]),
    ]
    vendor = next(v for v in summarise(results).by_vendor if v.vendor_id == "google-fonts")
    assert vendor.sites == 3
    assert vendor.undeclared_on == 2


# -------------------------------------------------------------- the failures


def test_a_failed_target_is_counted_and_not_silently_dropped():
    """A site that could not be scanned is not a site with no problems, and an
    aggregate that quietly omits it reports a cleaner estate than it measured."""
    summary = summarise([
        _result("https://ok.example", grade="C", findings=[("PM-SEC-01", "medium")]),
        _result("https://gone.example", grade="INCONCLUSIVE", status="unreachable"),
    ])
    assert summary.targets == 2
    domains = {t.domain for t in summary.targets_detail}
    assert "gone.example" in domains


def test_an_empty_estate_does_not_divide_by_zero():
    summary = summarise([])
    assert summary.targets == 0
    for locale in ("en", "it"):
        assert render_fleet(summary, locale)


# ------------------------------------------------------------- the rendering


@pytest.mark.parametrize("locale", ["en", "it"])
def test_the_fleet_report_renders_in_both_languages_without_gaps(locale):
    """Same property the per-site report is held to: no unresolved catalogue
    key ever reaches a reader."""
    results = [
        _result("https://a.example", grade="D", findings=[("PM-SEC-01", "medium")],
                vendors=[("google-fonts", False)]),
        _result("https://b.example", grade="C", findings=[("PM-SEC-01", "medium")]),
    ]
    text = render_fleet(summarise(results), locale)
    assert "⟦" not in text, "unresolved catalogue key in the fleet report"
    assert "{" not in text.replace("{{", ""), "unsubstituted placeholder"
    assert "a.example" in text


def test_rule_titles_in_the_fleet_report_carry_no_per_site_placeholder():
    """A per-site title says "Google Fonts contacted before consent". Across an
    estate there is no single product to name, and a title still holding
    {product} is how that shows up."""
    results = [_result(f"https://s{i}.example", findings=[("PM-TRF-01", "high")]) for i in range(3)]
    for locale in ("en", "it"):
        text = render_fleet(summarise(results), locale)
        assert "{product}" not in text and "{vendor}" not in text


# ----------------------------------------------------------------- the batch


def test_targets_are_read_from_a_file_and_from_a_list(tmp_path):
    listing = tmp_path / "targets.txt"
    listing.write_text(
        "https://a.example\n"
        "# a comment\n"
        "\n"
        "  https://b.example  \n",
        encoding="utf-8",
    )
    assert read_targets(listing) == ["https://a.example", "https://b.example"]
    assert read_targets(["https://c.example"]) == ["https://c.example"]


def test_a_slug_is_stable_and_distinguishes_paths():
    """Fleet rows were once all labelled "github.io" because the slug dropped
    the path. Thirty-three identical labels is not a report."""
    a = _slug("https://user.github.io/project-one/")
    b = _slug("https://user.github.io/project-two/")
    assert a != b
    assert a == _slug("https://user.github.io/project-one/")


@pytest.mark.parametrize("bad", ["", "   ", "not a url"])
def test_read_targets_does_not_invent_entries(tmp_path, bad):
    listing = tmp_path / "t.txt"
    listing.write_text(bad, encoding="utf-8")
    assert all(t.strip() for t in read_targets(listing))


def test_a_batch_resumes_from_what_is_already_on_disk(tmp_path, monkeypatch):
    """A run over 44 sites that dies at 40 must not start again from zero. The
    cached target reports as cached rather than being silently re-scanned."""
    import asyncio

    out = tmp_path / "out"
    out.mkdir()
    url = "https://cached.example"
    (out / f"{_slug(url)}.json").write_text(json.dumps(_result(url)), encoding="utf-8")

    seen: list[tuple[str, str | None]] = []

    async def run():
        return await run_batch(
            [url], out, concurrency=1, on_result=lambda u, r, e: seen.append((u, e))
        )

    results, summary = asyncio.run(run())
    assert seen == [(url, "cached")], "a cached target must not be re-observed"
    assert summary.targets == 1


def test_the_fleet_pdf_is_produced_and_is_a_pdf(tmp_path):
    """The artefact an estate owner is actually handed. A markdown test does
    not cover it: the PDF path goes through a separate template and WeasyPrint,
    and has broken on its own before — a silent str.replace no-op once left an
    entire section out of the document and nobody noticed until it was read."""
    from scanprivacy.report.fleet_pdf import render_fleet_pdf

    results = [
        _result("https://a.example", grade="D", findings=[("PM-SEC-01", "medium")],
                vendors=[("google-fonts", False)]),
        _result("https://b.example", grade="C", findings=[("PM-SEC-01", "medium")]),
    ]
    summary = summarise(results)

    for locale in ("en", "it"):
        out = tmp_path / f"fleet.{locale}.pdf"
        render_fleet_pdf(summary, out, locale)
        blob = out.read_bytes()
        assert blob.startswith(b"%PDF-"), "not a PDF"
        assert len(blob) > 2000, "a PDF this small rendered nothing"
        assert b"\xe2\x9f\xa6" not in blob, "unresolved catalogue key reached the PDF"
