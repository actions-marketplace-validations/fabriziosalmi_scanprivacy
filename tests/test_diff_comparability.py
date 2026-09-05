"""Whether two scans can be compared at all.

`pmate diff` produces the most quotable number this engine makes: "we resolved
twelve findings". It reached that number by comparing finding ids and nothing
else — so changing a rule moved every finding that rule used to produce into
the *resolved* column, and the report said somebody had fixed something when
what actually happened was a commit here.

That is this project's own cardinal error aimed at its loudest output: a
statement about a change nobody observed, handed to a steering committee.

The record has carried configuration digests since the beginning; the
comparison simply was not reading them. A missing digest counts as unknown
rather than as agreement, because an absent digest is not evidence of sameness.
"""

from __future__ import annotations

import pytest

from pmate.analyze.diff import diff
from pmate.i18n import Translator

RULESET_A = "a" * 64
RULESET_B = "b" * 64
KNOWLEDGE = "c" * 64
CATALOGUES = "d" * 64


def _scan(ruleset: str | None, findings: list[str], *, at: str = "2026-07-01T10:00:00+00:00") -> dict:
    scan = {
        "started_at": at,
        "final_url": "https://x.it/",
        "verdict": {"grade": "C"},
        "findings": [{"id": i, "severity": "high"} for i in findings],
    }
    if ruleset:
        scan["record"] = {
            "digests": {
                "ruleset": ruleset,
                "knowledge": KNOWLEDGE,
                "catalogues": CATALOGUES,
            }
        }
    return scan


def test_the_same_engine_says_nothing():
    """The comparison is sound; a warning here would be noise that trains the
    reader to ignore the one that matters."""
    result = diff(_scan(RULESET_A, ["PM-SEC-01"]), _scan(RULESET_A, []))
    assert result["configuration"]["status"] == "same"
    assert result["configuration"]["note_key"] is None


def test_a_changed_ruleset_is_reported_and_named():
    result = diff(_scan(RULESET_A, ["PM-SEC-01"]), _scan(RULESET_B, []))
    configuration = result["configuration"]
    assert configuration["status"] == "changed"
    assert configuration["changed"] == ["ruleset"]
    assert configuration["note_key"] == "diff.configuration_changed"


def test_the_finding_still_appears_as_resolved():
    """The warning is a warning, not a suppression. The comparison still
    reports what it found; the reader is told how to read it."""
    result = diff(_scan(RULESET_A, ["PM-SEC-01"]), _scan(RULESET_B, []))
    assert [f["id"] for f in result["resolved"]] == ["PM-SEC-01"]


def test_an_undigested_scan_is_unknown_not_comparable():
    """Silence about the engine is not a claim that it was the same one."""
    for before, after in (
        (_scan(None, ["PM-SEC-01"]), _scan(RULESET_A, [])),
        (_scan(RULESET_A, ["PM-SEC-01"]), _scan(None, [])),
    ):
        configuration = diff(before, after)["configuration"]
        assert configuration["status"] == "unknown"
        assert configuration["note_key"] == "diff.configuration_unknown"


def test_a_knowledge_change_counts_too():
    """Adding a vendor changes which hosts are attributed to whom. That moves
    findings just as surely as editing a rule does."""
    before = _scan(RULESET_A, ["PM-DIS-01:x"])
    after = _scan(RULESET_A, [])
    after["record"]["digests"]["knowledge"] = "e" * 64
    assert diff(before, after)["configuration"]["changed"] == ["knowledge"]


@pytest.mark.parametrize("lang", ["en", "it"])
def test_the_warning_reads_in_both_languages(lang: str):
    t = Translator.for_locale(lang)
    for key in ("diff.configuration_changed", "diff.configuration_unknown"):
        text = t.t(key, changed="ruleset")
        assert "⟦" not in text, f"[{lang}] {key} has no translation"
        assert len(text) > 100, f"[{lang}] {key} states the problem without explaining it"
    assert "{changed}" not in t.t("diff.configuration_changed", changed="ruleset")


def test_the_real_baseline_is_flagged_against_the_current_engine():
    """The case that prompted this. The kept estate baseline was produced in
    July; today's fixes changed rules and knowledge, so a diff against a fresh
    scan would list re-attributed findings as resolved.

    Skipped where the baseline is not on disk — it is an operator's own data and
    deliberately not tracked, so this cannot be a required check.
    """
    import json
    from pathlib import Path

    from pmate.report.record import build_record

    baseline = Path("data/baseline/2026-07-29/audiolibri.org.json")
    if not baseline.exists():
        pytest.skip("no kept baseline on this machine")

    before = json.loads(baseline.read_text(encoding="utf-8"))
    from pmate.config import DEFAULTS
    from pmate.observe.browser import Observation

    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    after = {
        "started_at": "2026-09-05T10:00:00+00:00",
        "findings": [],
        "record": build_record(
            url="https://x.it/", observation={}, settings=DEFAULTS, user_agent="t", findings=[]
        ),
    }
    assert diff(before, after)["configuration"]["status"] == "changed", (
        "a July baseline compares as identical to today's engine"
    )
