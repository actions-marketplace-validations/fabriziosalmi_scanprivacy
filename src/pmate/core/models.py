"""The data model. Language-neutral by construction.

A `ScanResult` contains facts, canonical values and catalogue keys — never a
sentence. Sentences are produced by `report.render` at the moment a report is
asked for, in the language it is asked for. The practical consequence is the
one that matters: one scan, any number of languages, no re-observation. A
supplier in Munich and a DPO in Genoa read the same evidence, each in their own
language, and the digests prove it is the same evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from .enums import (
    Confidence,
    Effort,
    FindingStatus,
    Grade,
    Owner,
    Priority,
    ScanStatus,
    Severity,
    SubjectKind,
)


@dataclass(frozen=True, slots=True)
class VerificationStep:
    """One step a reader can follow to reproduce the finding without this tool.

    Stored as a catalogue key plus its parameters, so the instructions come out
    in the reader's language and stay identical in substance.
    """

    key: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RemediationRef:
    """Where the fix text comes from, and what to substitute into it."""

    source: str  # "rule" — written for this rule | "vendor" — a shared pattern
    key: str  # rule id, or vendor id
    effort: Effort = Effort.MEDIUM
    pattern: str | None = None  # vendor-sourced only
    alternatives: tuple[str, ...] = ()
    extra_steps: tuple[str, ...] = ()
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    id: str
    rule_id: str
    severity: Severity
    confidence: Confidence
    subject_kind: SubjectKind
    subject_node: str
    """Graph node the finding hangs from — the evidence, not the finding."""

    params: dict[str, Any] = field(default_factory=dict)
    """Substituted into the rule's title and description at render time."""
    evidence: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()  # reference keys
    controls: dict[str, tuple[str, ...]] = field(default_factory=dict)

    owner: Owner = Owner.CTO
    secondary_owners: tuple[Owner, ...] = ()
    domains: tuple[str, ...] = ()
    priority: Priority = Priority.P3
    quick_win: bool = False

    verification: tuple[VerificationStep, ...] = ()
    remediation: RemediationRef | None = None

    # lifecycle — a scan is a photograph, remediation is a film
    status: FindingStatus = FindingStatus.OPEN
    first_seen: str | None = None
    last_seen: str | None = None
    age_days: int | None = None
    ticket_ref: str | None = None
    waiver: dict[str, Any] | None = None

    @property
    def rank(self) -> int:
        return self.severity.rank


_EFFORT_BONUS = {Effort.LOW: 15, Effort.MEDIUM: 5, Effort.HIGH: 0}
_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 70,
    Severity.MEDIUM: 40,
    Severity.LOW: 20,
    Severity.INFO: 5,
}


def priority_for(severity: Severity, effort: Effort, confidence: Confidence) -> tuple[Priority, bool]:
    """Backlog order, not legal gravity.

    Severity says how bad it is; priority says what to do on Monday. A high
    severity finding that takes ten minutes outranks one that needs a
    procurement cycle — and is flagged as a quick win, which is the only thing
    that reliably gets a first fix shipped.
    """
    score = _SEVERITY_WEIGHT.get(severity, 5) + _EFFORT_BONUS.get(effort, 0)
    if confidence is Confidence.CERTAIN:
        score += 10
    if score >= 100:
        priority = Priority.P1
    elif score >= 75:
        priority = Priority.P2
    elif score >= 45:
        priority = Priority.P3
    elif score >= 25:
        priority = Priority.P4
    else:
        priority = Priority.P5
    quick_win = severity in (Severity.CRITICAL, Severity.HIGH) and effort is Effort.LOW
    return priority, quick_win


@dataclass(slots=True)
class Verdict:
    """Fail-closed grading, in the AGSSH register: nothing is green unless it
    was observed to be green. An unreachable target is not a clean target."""

    conformant: bool
    grade: Grade
    counts: dict[str, int] = field(default_factory=dict)
    blocking: tuple[str, ...] = ()  # finding ids, not titles
    note_key: str = ""


@dataclass(slots=True)
class ScanResult:
    scan_id: str
    url: str
    final_url: str
    started_at: str
    finished_at: str
    status: ScanStatus
    error: str | None = None
    site: dict[str, Any] = field(default_factory=dict)
    observation: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    graph: "Graph | None" = None
    verdict: Verdict | None = None
    inventory: list[dict[str, Any]] = field(default_factory=list)
    record: dict[str, Any] = field(default_factory=dict)
    screening: dict[str, Any] = field(default_factory=dict)
    """Impact-assessment screening and transfer prompts: work products for a
    DPO, derived from the same observation and never a determination."""
    context: dict[str, Any] = field(default_factory=dict)
    """Who the scan is for and under which regime to read it: tenant, project,
    labels, sector, NIS2 status. Empty for an anonymous one-off scan."""

    @property
    def sorted_findings(self) -> list[Finding]:
        # severity, then priority, then id: within a severity band the more
        # urgent items come first, or the index reads as shuffled
        return sorted(self.findings, key=lambda f: (f.rank, f.priority.value, f.id))

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "final_url": self.final_url,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "status": self.status,
            "error": self.error,
            "site": self.site,
            "context": self.context,
            "inventory": self.inventory,
            "record": self.record,
            "screening": self.screening,
            "verdict": asdict(self.verdict) if self.verdict else None,
            "findings": [asdict(f) for f in self.sorted_findings],
            "graph": self.graph.to_dict() if self.graph else {"nodes": [], "edges": []},
            "observation": self.observation,
        }


from .graph import Edge, Graph, Node  # noqa: E402  (cycle-free: Graph does not import models)


# --------------------------------------------------------------- rehydration


def _enum(cls, value, default):
    if isinstance(value, cls):
        return value
    try:
        return cls(value)
    except (ValueError, TypeError):
        return default


def finding_from_dict(data: dict[str, Any]) -> Finding:
    remediation = data.get("remediation")
    return Finding(
        id=data["id"],
        rule_id=data["rule_id"],
        severity=_enum(Severity, data.get("severity"), Severity.INFO),
        confidence=_enum(Confidence, data.get("confidence"), Confidence.PROBABLE),
        subject_kind=_enum(SubjectKind, data.get("subject_kind"), SubjectKind.SITE),
        subject_node=data.get("subject_node", ""),
        params=data.get("params", {}) or {},
        evidence=data.get("evidence", {}) or {},
        references=tuple(data.get("references", []) or []),
        controls={k: tuple(v) for k, v in (data.get("controls") or {}).items()},
        owner=_enum(Owner, data.get("owner"), Owner.CTO),
        secondary_owners=tuple(_enum(Owner, o, Owner.CTO) for o in data.get("secondary_owners", []) or []),
        domains=tuple(data.get("domains", []) or []),
        priority=_enum(Priority, data.get("priority"), Priority.P3),
        quick_win=bool(data.get("quick_win", False)),
        verification=tuple(
            VerificationStep(key=s["key"], params=s.get("params", {}) or {})
            for s in data.get("verification", []) or []
        ),
        remediation=(
            RemediationRef(
                source=remediation.get("source", "rule"),
                key=remediation.get("key", data["rule_id"]),
                effort=_enum(Effort, remediation.get("effort"), Effort.MEDIUM),
                pattern=remediation.get("pattern"),
                alternatives=tuple(remediation.get("alternatives", []) or []),
                extra_steps=tuple(remediation.get("extra_steps", []) or []),
                params=remediation.get("params", {}) or {},
            )
            if remediation
            else None
        ),
        status=_enum(FindingStatus, data.get("status"), FindingStatus.OPEN),
        first_seen=data.get("first_seen"),
        last_seen=data.get("last_seen"),
        age_days=data.get("age_days"),
        ticket_ref=data.get("ticket_ref"),
        waiver=data.get("waiver"),
    )


def scan_from_dict(data: dict[str, Any]) -> ScanResult:
    """Rebuild a result from its published JSON.

    Needed because every downstream artefact — SARIF, badge, comparison,
    a report in another language — must be derivable from the stored evidence
    alone. If a consumer had to re-scan to produce them, the digests would stop
    meaning anything.
    """
    verdict_data = data.get("verdict")
    graph = Graph()
    for node in (data.get("graph") or {}).get("nodes", []):
        graph.node(node["id"], node["type"], node["label"], **(node.get("attrs") or {}))
    for edge in (data.get("graph") or {}).get("edges", []):
        graph.edge(edge["src"], edge["dst"], edge["type"], **(edge.get("attrs") or {}))

    return ScanResult(
        scan_id=data["scan_id"],
        url=data["url"],
        final_url=data.get("final_url", data["url"]),
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at", ""),
        status=_enum(ScanStatus, data.get("status"), ScanStatus.ERROR),
        error=data.get("error"),
        site=data.get("site", {}) or {},
        observation=data.get("observation", {}) or {},
        findings=[finding_from_dict(f) for f in data.get("findings", []) or []],
        graph=graph,
        verdict=(
            Verdict(
                conformant=bool(verdict_data.get("conformant")),
                grade=_enum(Grade, verdict_data.get("grade"), Grade.INCONCLUSIVE),
                counts=verdict_data.get("counts", {}) or {},
                blocking=tuple(verdict_data.get("blocking", []) or []),
                note_key=verdict_data.get("note_key", ""),
            )
            if verdict_data
            else None
        ),
        inventory=data.get("inventory", []) or [],
        record=data.get("record", {}) or {},
        screening=data.get("screening", {}) or {},
        context=data.get("context", {}) or {},
    )
