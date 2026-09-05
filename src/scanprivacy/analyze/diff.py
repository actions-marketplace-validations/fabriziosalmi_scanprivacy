"""Comparing two scans of the same target.

A single scan says what is wrong. Two scans say whether anyone did anything —
and that is the question every steering committee actually asks. Findings that
survive carry their age; findings that disappear are evidence that a fix landed;
findings that come back are the interesting ones, because they mean the fix was
undone by a deploy or by a supplier.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4, "INCONCLUSIVE": 5}


def _index(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {f["id"]: f for f in findings}


def _days_between(a: str | None, b: str | None) -> int | None:
    if not a or not b:
        return None
    try:
        first = datetime.fromisoformat(a.replace("Z", "+00:00"))
        second = datetime.fromisoformat(b.replace("Z", "+00:00"))
    except ValueError:
        return None
    return abs((second - first).days)


def _rank(grade: str | None) -> int:
    return _GRADE_RANK.get(grade or "", 6)


def _configuration(scan: dict[str, Any]) -> dict[str, str | None]:
    digests = ((scan.get("record") or {}).get("digests")) or {}
    return {
        "ruleset": digests.get("ruleset"),
        "knowledge": digests.get("knowledge"),
        "catalogues": digests.get("catalogues"),
    }


def _comparability(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Were these two scans produced by the same engine?

    Without this the comparison silently answers a different question than the
    one asked. Change a rule and every finding it used to produce shows up under
    "resolved" — which reads as somebody fixed something, and nobody did. That
    is this project's own cardinal error aimed at its most quotable output: a
    steering committee is shown a number that describes a code change and calls
    it remediation.

    The record already carries configuration digests; the comparison simply was
    not looking at them. A scan too old to carry any is `unknown` rather than
    `comparable`, because absence of a digest is not evidence of sameness.
    """
    old, new = _configuration(before), _configuration(after)
    if not any(old.values()) or not any(new.values()):
        return {"status": "unknown", "changed": [], "note_key": "diff.configuration_unknown"}
    changed = sorted(k for k in old if old[k] != new[k])
    if not changed:
        return {"status": "same", "changed": [], "note_key": None}
    return {
        "status": "changed",
        "changed": changed,
        "before": old,
        "after": new,
        "note_key": "diff.configuration_changed",
    }


def diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """`before` and `after` are two `ScanResult.to_dict()` payloads."""
    old, new = _index(before.get("findings", [])), _index(after.get("findings", []))

    resolved = [old[k] for k in old.keys() - new.keys()]
    appeared = [new[k] for k in new.keys() - old.keys()]
    persisting = []
    for key in old.keys() & new.keys():
        finding = dict(new[key])
        finding["first_seen"] = old[key].get("first_seen") or before.get("started_at")
        finding["last_seen"] = after.get("started_at")
        finding["age_days"] = _days_between(finding["first_seen"], finding["last_seen"])
        persisting.append(finding)

    def counts(items: list[dict[str, Any]]) -> dict[str, int]:
        return {s: sum(1 for f in items if f.get("severity") == s) for s in _SEVERITIES}

    grade_before = (before.get("verdict") or {}).get("grade")
    grade_after = (after.get("verdict") or {}).get("grade")
    return {
        "target": after.get("final_url") or after.get("url"),
        "from": before.get("started_at"),
        "to": after.get("started_at"),
        "days_elapsed": _days_between(before.get("started_at"), after.get("started_at")),
        "verdict": {
            "before": grade_before,
            "after": grade_after,
            "improved": _rank(grade_after) < _rank(grade_before),
        },
        "counts": {
            "resolved": counts(resolved),
            "new": counts(appeared),
            "persisting": counts(persisting),
        },
        "resolved": sorted(resolved, key=lambda f: f["id"]),
        "new": sorted(appeared, key=lambda f: f["id"]),
        "persisting": sorted(persisting, key=lambda f: (-(f.get("age_days") or 0), f["id"])),
        "configuration": _comparability(before, after),
        "note_key": "diff.note",
    }
