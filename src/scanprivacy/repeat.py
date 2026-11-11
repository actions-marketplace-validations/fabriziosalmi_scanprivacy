"""`scan --repeat N`: the same page loaded N times, and what stayed the same.

A single load is a photograph: two loads of one page can differ (ad rotation, an A/B test, a CDN
edge). The README says so; this module measures it instead of only saying it.

Rules, each of which is a decision and not a default:

- Every load is a complete scan in a fresh browser. Nothing is shared between loads except the
  per-host limiter, so "one page load per second per host" stays true across the whole run.
- The grade reported is the grade of the worst completed load. Not the findings common to every
  load: a tracker seen in two loads out of five did receive the visitor's data in those two, and
  an intersection would erase it and print a grade no load ever produced. Every load's own grade
  is listed beside it.
- A load that did not finish (the page did not load, a rule could not be evaluated) is not an
  absence. It leaves the denominator, so "seen in 3 of 4" means 4 loads completed. If none did,
  the result is the first load's, INCONCLUSIVE, unchanged.
- The reported result is one whole load, so `scanprivacy verify` keeps working on it. The other
  loads are kept in full inside `repeat`, whose own digest `verify` recomputes.
"""

from __future__ import annotations

from typing import Any

from .config import DEFAULTS, Settings
from .core.enums import Grade
from .core.models import ScanResult
from .observe.rate import PerHostLimiter
from .report.record import canonical_digest
from .scanner import scan

MAX_REPEAT = 10

_GRADE_RANK = {Grade.A.value: 0, Grade.B.value: 1, Grade.C.value: 2, Grade.D.value: 3, Grade.F.value: 4}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def grade_of(result: ScanResult) -> str:
    return result.verdict.grade.value if result.verdict else Grade.INCONCLUSIVE.value


def completed(result: ScanResult) -> bool:
    return grade_of(result) in _GRADE_RANK


def _digest(result: dict[str, Any], key: str) -> str | None:
    return ((result.get("record") or {}).get(key) or {}).get("sha256")


def block_digest(requested: int, runs: list[dict[str, Any]]) -> str:
    """What `repeat["digest"]` covers: how many loads were asked for, and for each load whether it
    completed and the digests of its evidence and findings. Anyone can recompute it from the file."""
    return canonical_digest(
        {
            "requested": requested,
            "runs": [
                {
                    "index": r["index"],
                    "grade": r["grade"],
                    "evidence_digest": r["evidence_digest"],
                    "findings_digest": r["findings_digest"],
                }
                for r in runs
            ],
        }
    )


def stability(finding_lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """For every finding id seen in any completed load, in how many of them it appeared.

    The id is the one `scanprivacy diff` already matches on, so "the same finding" means the
    same thing in both places.
    """
    seen: dict[str, dict[str, Any]] = {}
    for findings in finding_lists:
        for finding in findings:
            entry = seen.setdefault(
                finding["id"],
                {"id": finding["id"], "rule_id": finding.get("rule_id"), "severity": finding["severity"], "seen": 0},
            )
            entry["seen"] += 1
    total = len(finding_lists)
    out = [{**entry, "of": total} for entry in seen.values()]
    return sorted(out, key=lambda e: (_SEVERITY_RANK.get(e["severity"], 9), e["id"]))


def aggregate(results: list[ScanResult], requested: int) -> ScanResult:
    """Fold N complete results into the one that is reported, plus the `repeat` block.

    Pure: no browser, no clock. Everything above is decided here, so it can be tested offline.
    """
    done = [i for i, r in enumerate(results) if completed(r)]
    if not done:
        base = results[0]
        index = 0
    else:
        # worst grade; among equals the one with more findings; among those the earliest
        index = min(done, key=lambda i: (-_GRADE_RANK[grade_of(results[i])], -len(results[i].findings), i))
        base = results[index]

    dicts = [r.to_dict() for r in results]
    runs = []
    for i, (result, as_dict) in enumerate(zip(results, dicts)):
        runs.append(
            {
                "index": i,
                "scan_id": result.scan_id,
                "started_at": result.started_at,
                "grade": grade_of(result),
                "evidence_digest": _digest(as_dict, "evidence_digest"),
                "findings_digest": _digest(as_dict, "findings_digest"),
                # the reported load is the top-level result; storing it twice would only add size
                "result": None if i == index else as_dict,
            }
        )

    base.repeat = {
        "requested": requested,
        "completed": len(done),
        "reported_run": index,
        "reported_because": "worst_completed_load",
        "grades": [r["grade"] for r in runs],
        "findings": stability([dicts[i]["findings"] for i in done]),
        "runs": runs,
        "digest": block_digest(requested, runs),
    }
    return base


async def scan_repeated(
    url: str,
    n: int,
    settings: Settings = DEFAULTS,
    read_documents: bool = True,
    context: dict[str, Any] | None = None,
) -> ScanResult:
    if not 2 <= n <= MAX_REPEAT:
        raise ValueError(f"--repeat takes a number from 2 to {MAX_REPEAT}, not {n}")
    limiter = PerHostLimiter(settings.per_host_rps)
    results = [
        await scan(url, settings, read_documents=read_documents, context=context, limiter=limiter)
        for _ in range(n)
    ]
    return aggregate(results, n)


def verify_repeat(scan_json: dict[str, Any]) -> dict[str, bool] | None:
    """Recompute what `scanprivacy verify` can check about a repeated scan; None for a single one.

    Four things, none of them taken on trust from the block itself: every load's own evidence and
    findings digests (for the reported load, the top-level result), the block digest, the grade each
    load declares against its own verdict, and the stability table against the findings of the
    completed loads.
    """
    from .report.record import verify_record

    block = scan_json.get("repeat")
    if not block:
        return None
    runs = block.get("runs") or []
    loads = [scan_json if r.get("result") is None else r["result"] for r in runs]

    runs_intact = bool(runs)
    grades_match = True
    for run, load in zip(runs, loads):
        checked = verify_record(load)
        runs_intact = (
            runs_intact
            and checked["evidence_intact"]
            and checked["findings_intact"] is not False
            and run.get("evidence_digest") == checked["recomputed"]
            and run.get("findings_digest") == checked["recomputed_findings"]
        )
        grades_match = grades_match and run.get("grade") == ((load.get("verdict") or {}).get("grade") or Grade.INCONCLUSIVE.value)

    done = [load["findings"] for run, load in zip(runs, loads) if run.get("grade") in _GRADE_RANK]
    return {
        "runs_intact": bool(runs_intact),
        "digest_matches": block.get("digest") == block_digest(block.get("requested"), runs),
        "grades_match": grades_match,
        "stability_matches": block.get("findings") == stability(done),
    }
