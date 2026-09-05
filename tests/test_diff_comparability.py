"""Whether two scans can be compared at all.

`scanprivacy diff` produces the most quotable number this engine makes: "we resolved
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

from scanprivacy.analyze.diff import diff
from scanprivacy.i18n import Translator

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


def test_a_kept_baseline_carries_digests_the_comparison_can_read():
    """Against real kept data, not a fixture.

    This started out pinned to `data/baseline/2026-07-29/`, which was deleted
    once it had served its purpose — leaving a test that could never run again
    and skipped forever with a reassuring message. It now takes whichever dated
    baseline is on this machine.

    What it asserts is the weaker thing that is always true: a kept snapshot
    carries the digests, so a comparison against it reports `same` or `changed`
    and never `unknown`. Whether the engine has moved since is a fact about the
    day, not something a test can require. The `changed` path itself is covered
    above, on fixtures.

    Skipped where no baseline is on disk — it is an operator's own data and
    deliberately untracked, so this cannot be a required check in CI.
    """
    import json
    from pathlib import Path

    from scanprivacy.config import DEFAULTS
    from scanprivacy.report.record import build_record

    kept = sorted(Path("data/baseline").glob("*/*.json")) if Path("data/baseline").is_dir() else []
    kept = [p for p in kept if p.name != "fleet.json"]
    if not kept:
        pytest.skip("no kept baseline on this machine")

    before = json.loads(kept[0].read_text(encoding="utf-8"))
    after = {
        "started_at": "2026-09-05T10:00:00+00:00",
        "findings": [],
        "record": build_record(
            url="https://x.it/", observation={}, settings=DEFAULTS, user_agent="t", findings=[]
        ),
    }
    status = diff(before, after)["configuration"]["status"]
    assert status in ("same", "changed"), (
        f"{kept[0]} does not carry configuration digests the comparison can read "
        f"(status={status!r})"
    )
