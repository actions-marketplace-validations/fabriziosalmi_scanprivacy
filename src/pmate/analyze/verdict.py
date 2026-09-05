"""Fail-closed grading, in the register of AGSSH-STD-001.

Nothing is green unless it was observed to be green. A target that could not be
loaded is INCONCLUSIVE, never conformant: an unreachable site is not a clean
site, and saying otherwise is the one error this engine must not make.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from ..core.enums import Grade, Severity
from ..core.models import Finding, Verdict


def grade(findings: Iterable[Finding], observed_ok: bool, note_key: str = "") -> Verdict:
    findings = list(findings)
    counts = Counter(f.severity.value for f in findings)
    counted = {severity.value: counts.get(severity.value, 0) for severity in Severity}

    if not observed_ok:
        return Verdict(
            conformant=False,
            grade=Grade.INCONCLUSIVE,
            counts=counted,
            blocking=("verdict.inconclusive_blocking",),
            note_key=note_key or "verdict.inconclusive_note",
        )

    if counted[Severity.CRITICAL]:
        result = Grade.F
    elif counted[Severity.HIGH]:
        result = Grade.D
    elif counted[Severity.MEDIUM]:
        result = Grade.C
    elif counted[Severity.LOW]:
        result = Grade.B
    else:
        result = Grade.A

    conformant = result in (Grade.A, Grade.B, Grade.C)
    return Verdict(
        conformant=conformant,
        grade=result,
        counts=counted,
        blocking=tuple(f.id for f in findings if f.severity.blocking),
        note_key=note_key
        or ("verdict.conformant_note" if conformant else "verdict.not_conformant_note"),
    )
