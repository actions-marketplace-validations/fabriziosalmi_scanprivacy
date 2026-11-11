"""`--repeat N`: the rules that decide what a repeated scan reports, held offline.

No browser here. The loads are built by hand, so each rule can be broken on purpose:
disable it and the test that names it has to fail.
"""

from __future__ import annotations

import asyncio
import copy
import json

import pytest

from scanprivacy import repeat as repeat_module
from scanprivacy.analyze.verdict import grade
from scanprivacy.core.enums import Grade
from scanprivacy.core.models import finding_from_dict, scan_from_dict
from scanprivacy.i18n.translator import Translator
from scanprivacy.report.markdown import render
from scanprivacy.report.record import canonical_digest
from scanprivacy.repeat import MAX_REPEAT, aggregate, scan_repeated, verify_repeat


def load(findings: list[tuple[str, str]], *, ok: bool = True, seed: str = "a"):
    """One complete load: findings as (id, severity), with the digests a real scan carries."""
    flist = [{"id": i, "rule_id": i.split(":")[0], "severity": sev} for i, sev in findings]
    observation = {"seed": seed, "findings": [i for i, _ in findings]}
    verdict = grade([finding_from_dict(f) for f in flist], observed_ok=ok)
    from dataclasses import asdict

    result = scan_from_dict(
        {
            "scan_id": f"{seed}-{len(findings)}",
            "url": "https://x.example/",
            "final_url": "https://x.example/",
            "started_at": "2026-11-05T10:00:00+00:00",
            "status": "ok",
            "observation": observation,
            "findings": flist,
            "verdict": asdict(verdict),
        }
    )
    # the digests a real scan carries, computed from what the result itself serialises
    published = result.to_dict()
    result.record = {
        "evidence_digest": {"sha256": canonical_digest(published["observation"])},
        "findings_digest": {"sha256": canonical_digest(published["findings"])},
        "digests": {},
    }
    return result


def _dump(result) -> dict:
    return json.loads(json.dumps(result.to_dict(), default=str))


B = [("PM-SEC-01", "medium")]
B_PLUS_TRACKER = [("PM-SEC-01", "medium"), ("PM-TRF-01:ads", "high")]


# ------------------------------------------------------------------- what is reported


def test_the_reported_grade_is_the_worst_completed_load_not_the_intersection():
    """A tracker in one load out of three did receive the visitor's data in that load. The
    intersection would erase it and print a grade no load ever produced."""
    loads = [load(B, seed="1"), load(B_PLUS_TRACKER, seed="2"), load(B, seed="3")]
    reported = aggregate(loads, 3)
    assert reported.verdict.grade == Grade.D
    assert reported.repeat["grades"] == ["C", "D", "C"]
    assert reported.repeat["reported_run"] == 1


def test_among_equal_grades_the_load_with_more_findings_is_reported_then_the_earliest():
    low = [("PM-SEC-03", "low")]
    low_two = [("PM-SEC-03", "low"), ("PM-X-01", "low")]
    assert aggregate([load(low, seed="1"), load(low_two, seed="2")], 2).repeat["reported_run"] == 1
    assert aggregate([load(low, seed="1"), load(low, seed="2")], 2).repeat["reported_run"] == 0


def test_stability_counts_how_many_completed_loads_showed_each_finding():
    reported = aggregate([load(B, seed="1"), load(B_PLUS_TRACKER, seed="2"), load(B, seed="3")], 3)
    rows = {f["id"]: (f["seen"], f["of"]) for f in reported.repeat["findings"]}
    assert rows == {"PM-SEC-01": (3, 3), "PM-TRF-01:ads": (1, 3)}
    assert [f["id"] for f in reported.repeat["findings"]] == ["PM-TRF-01:ads", "PM-SEC-01"], "worst severity first"


def test_a_load_that_did_not_complete_is_not_an_absence():
    """Counting a failed load as 'finding absent' would make every finding look unstable the
    first time a page timed out."""
    loads = [load(B, seed="1"), load([], ok=False, seed="2"), load(B, seed="3")]
    reported = aggregate(loads, 3)
    assert reported.repeat["completed"] == 2
    assert reported.repeat["grades"] == ["C", "INCONCLUSIVE", "C"]
    assert {(f["seen"], f["of"]) for f in reported.repeat["findings"]} == {(2, 2)}


def test_when_no_load_completed_the_result_is_the_first_one_and_stays_inconclusive():
    reported = aggregate([load([], ok=False, seed="1"), load([], ok=False, seed="2")], 2)
    assert reported.verdict.grade == Grade.INCONCLUSIVE
    assert reported.repeat["completed"] == 0
    assert reported.repeat["reported_run"] == 0
    assert reported.repeat["findings"] == []


# ------------------------------------------------------------------------ verifiable


def _published(loads, n):
    return _dump(aggregate(loads, n))


def test_a_repeated_result_verifies_and_a_single_one_has_no_repeat_block():
    data = _published([load(B, seed="1"), load(B_PLUS_TRACKER, seed="2")], 2)
    assert verify_repeat(data) == {
        "runs_intact": True, "digest_matches": True, "grades_match": True, "stability_matches": True,
    }
    assert "repeat" not in _dump(load(B)), "a single scan's JSON is unchanged"
    assert verify_repeat(_dump(load(B))) is None


@pytest.mark.parametrize(
    "tamper,broken",
    [
        (lambda d: d["repeat"]["runs"][1]["result"]["observation"].update(seed="changed"), "runs_intact"),
        (lambda d: d["observation"].update(seed="changed"), "runs_intact"),
        (lambda d: d["repeat"].update(requested=9), "digest_matches"),
        (lambda d: d["repeat"]["findings"][0].update(seen=2), "stability_matches"),
        (lambda d: d["repeat"]["runs"][0].update(grade="A"), "grades_match"),
    ],
    ids=["a-stored-load", "the-reported-load", "the-count-asked-for", "a-stability-row", "a-declared-grade"],
)
def test_changing_any_part_of_a_repeated_result_is_caught(tamper, broken):
    data = _published([load(B_PLUS_TRACKER, seed="1"), load(B, seed="2")], 2)
    assert all(verify_repeat(data).values())
    tampered = copy.deepcopy(data)
    tamper(tampered)
    assert verify_repeat(tampered)[broken] is False


# ---------------------------------------------------------------------------- running


def test_the_number_of_loads_is_bounded():
    for n in (0, 1, MAX_REPEAT + 1):
        with pytest.raises(ValueError):
            asyncio.run(scan_repeated("https://x.example/", n))


def test_every_load_shares_one_limiter_and_is_a_whole_scan(monkeypatch):
    """One page load per second per host has to hold across the loads, not only inside each."""
    limiters, calls = [], []

    async def fake_scan(url, settings, read_documents=True, context=None, limiter=None):
        limiters.append(limiter)
        calls.append(url)
        return load(B, seed=str(len(calls)))

    monkeypatch.setattr(repeat_module, "scan", fake_scan)
    result = asyncio.run(scan_repeated("https://x.example/", 3))
    assert len(calls) == 3
    assert limiters[0] is not None and all(item is limiters[0] for item in limiters)
    assert result.repeat["requested"] == 3


# --------------------------------------------------------------------------- reporting


def test_the_report_says_what_was_unstable_in_both_languages():
    reported = aggregate([load(B, seed="1"), load(B_PLUS_TRACKER, seed="2"), load(B, seed="3")], 3)
    en = render(reported, "en")
    assert "## Stability across 3 loads" in en
    assert "3 of 3 loads completed" in en and "C, D, C" in en
    assert "PM-TRF-01:ads" in en and "1 of 3" in en
    assert "1 findings did not appear in every completed load" in en
    it = render(reported, "it")
    assert "## Stabilità su 3 caricamenti" in it and "1 su 3" in it


def test_a_report_of_a_stable_site_says_so_and_a_single_scan_has_no_section():
    stable = aggregate([load(B, seed="1"), load(B, seed="2")], 2)
    assert "Every finding appeared in every completed load." in render(stable, "en")
    assert "Stability across" not in render(load(B), "en")


def test_the_report_says_when_loads_did_not_complete():
    reported = aggregate([load(B, seed="1"), load([], ok=False, seed="2")], 2)
    assert "1 loads did not complete and are not counted as absences." in render(reported, "en")


def test_every_new_string_exists_in_both_catalogues():
    for locale in ("en", "it"):
        t = Translator.for_locale(locale, strict=True)
        for key, params in (
            ("report.stability.heading", {"n": 2}),
            ("report.stability.intro", {"completed": 1, "requested": 2, "grades": "A"}),
            ("report.stability.all_stable", {}),
            ("report.stability.some_unstable", {"n": 1}),
            ("report.stability.incomplete", {"n": 1}),
            ("report.stability.seen", {}),
            ("report.stability.seen_value", {"seen": 1, "of": 2}),
            ("cli.verify_repeat", {"value": "x"}),
        ):
            assert t.t(key, **params)


# -------------------------------------------------------------------------------- CLI


def test_the_command_line_takes_a_bounded_count():
    from scanprivacy.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["scan", "https://x.example/"]).repeat == 1
    assert parser.parse_args(["scan", "https://x.example/", "--repeat", "5"]).repeat == 5
    for bad in ("0", "11", "x"):
        with pytest.raises(SystemExit):
            parser.parse_args(["scan", "https://x.example/", "--repeat", bad])


def test_verify_fails_the_command_when_a_stored_load_was_changed(tmp_path, capsys):
    from scanprivacy.cli import main

    data = _published([load(B_PLUS_TRACKER, seed="1"), load(B, seed="2")], 2)
    # the loads are built by hand, so the top-level record is complete but ruleset digests are absent:
    # only the repeat line is under test here
    good = tmp_path / "good.json"
    good.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(good)]) == 0
    assert "repeated loads intact: yes" in capsys.readouterr().out

    data["repeat"]["runs"][1]["result"]["observation"]["seed"] = "changed"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    assert main(["verify", str(bad)]) == 1
    assert "repeated loads intact: NO" in capsys.readouterr().out


def test_the_pdf_template_carries_the_section_only_for_a_repeated_scan():
    """The HTML the PDF is made from, which needs no Pango. Built from the full synthetic result the
    i18n tests use, because the template reads parts of a real record that a hand-made load lacks."""
    import importlib.util
    from pathlib import Path

    from scanprivacy.report.pdf import render_html

    spec = importlib.util.spec_from_file_location("i18n_helpers", Path(__file__).with_name("test_i18n.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    first, second = module._synthetic_result(), module._synthetic_result()
    dropped = second.sorted_findings[0].id
    second.findings = [f for f in second.findings if f.id != dropped]
    html = render_html(aggregate([first, second], 2), "en")
    assert "Stability across 2 loads" in html and dropped in html and "1 of 2" in html
    assert "Stability across" not in render_html(module._synthetic_result(), "en")
