"""Turning facts into sentences, in one language, in one place.

Everything upstream of this module is language-neutral. Everything downstream —
Markdown, PDF, the API's human-readable views — consumes what this module
produces. That is what makes "the same scan in five languages" a rendering
option rather than a re-observation, and it is the only reason the digests in
the reproducibility record stay meaningful across translations.
"""

from __future__ import annotations

from collections.abc import Iterable

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..core.models import Finding, RemediationRef, ScanResult, VerificationStep
from ..i18n.translator import Translator


def _resolve(value: Any, t: Translator) -> Any:
    """Canonical values and catalogue keys become display strings; the rest is
    passed through untouched."""
    if isinstance(value, StrEnum):
        return t.label(value)
    if isinstance(value, dict) and set(value) == {"__key__"}:
        return t.t(value["__key__"])
    if isinstance(value, dict):
        return {k: _resolve(v, t) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_resolve(v, t) for v in value]
    return value


def _params(params: dict[str, Any], t: Translator) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in params.items():
        resolved = _resolve(value, t)
        out[name] = ", ".join(str(v) for v in resolved) if isinstance(resolved, list) else resolved
    return out


@dataclass(slots=True)
class RenderedRemediation:
    summary: str
    steps: list[str]
    effort: str
    alternatives: list[str]


@dataclass(slots=True)
class RenderedFinding:
    id: str
    rule_id: str
    title: str
    description: str
    severity: str
    severity_value: str
    priority: str
    confidence: str
    owner: str
    owner_value: str
    secondary_owners: list[str]
    domains: list[str]
    quick_win: bool
    references: list[str]
    controls: list[tuple[str, list[str]]]
    evidence: list[tuple[str, Any]]
    verification: list[str]
    remediation: RenderedRemediation | None


def render_verification(steps: tuple[VerificationStep, ...], t: Translator) -> list[str]:
    """A step may point at a single string or at a list of strings; both flatten
    into one ordered set of instructions."""
    out: list[str] = []
    clean_window = t.t("verification.clean_window")
    for step in steps:
        params = {"clean_window": clean_window, **step.params}
        out.extend(rendered for rendered in t.items(step.key, **params) if rendered)
    return out


def render_remediation(remediation: RemediationRef | None, t: Translator) -> RenderedRemediation | None:
    if remediation is None:
        return None
    params = _params(remediation.params, t)
    if remediation.source == "vendor" and remediation.pattern:
        base = f"remediation.pattern.{remediation.pattern}"
        summary = t.t(f"{base}.summary", **params)
        steps = t.items(f"{base}.steps", **params)
    else:
        summary = t.rule(remediation.key, "remediation.summary", **params)
        steps = t.rule_list(remediation.key, "remediation.steps", **params)

    steps = list(steps)
    for extra in remediation.extra_steps:
        steps.append(t.t(f"remediation.extra.{extra}", **params))
    hint_key = remediation.params.get("platform_hint_key")
    if hint_key:
        hint = t.maybe(hint_key)
        if hint:
            steps.append(f"{remediation.params.get('platform_name')}: {hint}")

    # Prepended, not appended. Where the hosting makes the ordinary fix
    # impossible, that is the first thing the reader needs — after three steps
    # about a setting their platform does not have, they have already gone
    # looking for it.
    constraint_key = remediation.params.get("platform_constraint_key")
    if constraint_key:
        constraint = t.maybe(constraint_key)
        if constraint:
            steps.insert(0, constraint)

    return RenderedRemediation(
        summary=summary,
        steps=steps,
        effort=t.label(remediation.effort),
        alternatives=[t.t(f"remediation.alternative.{a}") for a in remediation.alternatives],
    )


def posture_rows(
    keys: Iterable[str],
    t: Translator,
    *,
    max_pages: int | None = None,
    per_host_rps: float | None = None,
    user_agent: str | None = None,
) -> list[tuple[str, str]]:
    """The method section: one (label, sentence) pair per posture key.

    One implementation for the scan report, the PDF and the fleet summary,
    because it had been written three times and was wrong three times in the
    same ways. The label was derived from the key — `report.posture.
    extra_requests` printed as "extra requests" — so an Italian report described
    its own method in English. The sentence was resolved with no parameters, so
    the page budget read "at most {n} pages". And a one-page scan said "1
    pages", which is what `Translator.plural` exists to prevent.

    A key whose catalogue entry is a plural form is only usable when the count
    is known. Where it is not, the row is dropped rather than printed with a
    placeholder: a method section that describes a budget nobody recorded is a
    statement about something unobserved, in the one section that exists to say
    exactly what was done.
    """
    rows: list[tuple[str, str]] = []
    for key in keys:
        label = t.t(f"report.posture_label.{key.split('.')[-1]}")
        if t.maybe(f"{key}.other") is not None:
            if not isinstance(max_pages, int):
                continue
            rows.append((label, t.plural(key, max_pages)))
        else:
            rows.append((label, t.t(key, n=max_pages, rps=per_host_rps)))
    if user_agent:
        rows.append((t.t("report.posture_label.user_agent"), user_agent))
    return rows


def vantage_line(record: dict[str, Any] | None, t: Translator) -> str:
    """Where the scan was run from, as one readable sentence.

    Printed even when undetermined, and especially then: a method section that
    silently omits the observation point lets a reader assume it does not
    matter, and it is the difference between two scans of one site disagreeing
    about the site and disagreeing about the observer."""
    vantage = (record or {}).get("vantage") or {}
    source = vantage.get("source")
    if source == "declared":
        return f"{vantage.get('declared')} — {t.t('record.vantage.declared')}"
    if source == "looked_up":
        place = " / ".join(
            str(vantage[k]) for k in ("country", "region", "city", "org") if vantage.get(k)
        )
        via = t.t("record.vantage.looked_up", endpoint=vantage.get("endpoint", ""))
        return f"{place} — {via}" if place else via
    reason = t.t(vantage.get("reason_key") or "record.vantage.not_configured")
    detail = vantage.get("detail")
    return f"{reason} ({detail})" if detail else reason


def scan_posture_rows(record: dict[str, Any] | None, t: Translator) -> list[tuple[str, str]]:
    posture = (record or {}).get("posture") or {}
    rows = posture_rows(
        posture.get("keys", []),
        t,
        max_pages=posture.get("max_pages"),
        per_host_rps=posture.get("per_host_rps"),
        user_agent=posture.get("user_agent"),
    )
    rows.append((t.t("record.vantage.label"), vantage_line(record, t)))
    return rows


def render_evidence(evidence: dict[str, Any], t: Translator) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for machine_key, value in evidence.items():
        if value in (None, "", [], {}):
            continue
        label = t.t(f"evidence.{machine_key}")
        resolved = _resolve(value, t)
        if isinstance(resolved, list):
            # a list of catalogue keys (missing Art. 13 elements, cookie policy
            # elements) resolves item by item
            resolved = [t.maybe(str(item)) or item for item in resolved]
        elif isinstance(resolved, str) and resolved.startswith(
            ("art13.", "cookie_policy.", "constraint.")
        ):
            resolved = t.t(resolved)
        out.append((label, resolved))
    return out


def render_finding(finding: Finding, t: Translator) -> RenderedFinding:
    params = _params(finding.params, t)
    return RenderedFinding(
        id=finding.id,
        rule_id=finding.rule_id,
        title=t.rule(finding.rule_id, "title", **params),
        description=t.rule(finding.rule_id, "description", **params),
        severity=t.label(finding.severity),
        severity_value=finding.severity.value,
        priority=finding.priority.value,
        confidence=t.label(finding.confidence),
        owner=t.label(finding.owner),
        owner_value=finding.owner.value,
        secondary_owners=[t.label(o) for o in finding.secondary_owners],
        domains=list(finding.domains),
        quick_win=finding.quick_win,
        references=t.references(finding.references),
        controls=[
            (framework.replace("_", " ").upper(), t.references(keys))
            for framework, keys in finding.controls.items()
        ],
        evidence=render_evidence(finding.evidence, t),
        verification=render_verification(finding.verification, t),
        remediation=render_remediation(finding.remediation, t),
    )


# ------------------------------------------------------------- whole report


@dataclass(slots=True)
class RenderedScan:
    mode: str = "passive"
    """`passive` or `refusal_pass`. The refusal report must announce what it is
    on its first line: a document that interacts with the page while calling
    itself a passive observation is the one mistake this mode was designed to
    avoid."""
    refusal: dict[str, Any] = field(default_factory=dict)
    scan_id: str = ""
    url: str = ""
    final_url: str = ""
    domain: str = ""
    started_at: str = ""
    grade: str = ""
    conformant: bool = False
    verdict_note: str = ""
    counts_by_severity: list[tuple[str, int]] = field(default_factory=list)
    counts_by_priority: list[tuple[str, int]] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)
    stability: dict[str, Any] = field(default_factory=dict)
    """Set for a scan made with --repeat: the heading, the sentences and the findings that did not appear in every completed load."""
    findings: list[RenderedFinding] = field(default_factory=list)
    quick_wins: list[RenderedFinding] = field(default_factory=list)
    by_owner: list[dict[str, Any]] = field(default_factory=list)
    inventory: list[dict[str, Any]] = field(default_factory=list)
    site: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)


_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_PRIORITY_ORDER = ("P1", "P2", "P3", "P4", "P5")


def _refusal_summary(result: ScanResult, t: Translator, attempt: dict[str, Any]) -> list[str]:
    """What this document measured, said before anything else.

    A reader must not have to reach the method section to learn that the engine
    interacted with the page, or which refusal it performed.
    """
    out = [t.t("consent_pass.intro")]
    outcome = attempt.get("outcome", "")
    if outcome:
        out.append(t.t(f"consent_pass.outcome.{outcome}") + ".")
    if not attempt.get("performed"):
        return out

    tracking = sum(1 for f in result.findings if f.rule_id in ("PM-REJ-02", "PM-REJ-03"))
    vendors = sum(1 for f in result.findings if f.rule_id == "PM-REJ-01")
    if vendors or tracking:
        out.append(
            t.t("consent_pass.summary.survived", vendors=vendors, tracking=tracking)
        )
    else:
        out.append(t.t("consent_pass.summary.honoured"))
    return out


def _summary(result: ScanResult, t: Translator) -> list[str]:
    """Three or four sentences for whoever reads only the first page.

    Built from counts, never from a judgement: the numbers are the argument and
    each is checkable further down the document. Plural forms come from the
    catalogue — "1 keys" in the opening paragraph costs the document its
    credibility before the reader reaches the findings.
    """
    site = result.site or {}
    inventory = result.inventory or []
    verdict = result.verdict
    counts = verdict.counts if verdict else {}

    third_parties = len(inventory)
    outside = sum(1 for v in inventory if v.get("transfer") != "eea")
    undeclared = sum(1 for v in inventory if not v.get("declared"))
    consent_required = sum(1 for v in inventory if v.get("consent_class") == "required")

    # A page that never loaded has no requests and no storage to report: saying "none observed"
    # would read as a clean result, so the two "none" sentences are left out.
    observed = site.get("pages_observed", 1) != 0

    out: list[str] = []
    if third_parties:
        sentence = t.t("report.summary.third_parties", n=third_parties)
        if outside:
            sentence += t.t(
                "report.summary.third_parties_transfers_all"
                if outside == third_parties
                else "report.summary.third_parties_transfers",
                n=outside,
            )
        if undeclared:
            sentence += t.t("report.summary.third_parties_undeclared", n=undeclared)
        out.append(sentence.strip() + ".")
    elif observed:
        out.append(t.t("report.summary.third_parties_none"))

    tracking = sum(1 for f in result.findings if f.rule_id in ("PM-COK-01", "PM-STO-01"))
    cookies, storage = site.get("cookies", 0), site.get("storage", 0)
    if cookies or storage:
        sentence = (
            f"{t.t('report.summary.storage_intro')} "
            f"{t.plural('report.summary.cookies', cookies)}"
            f"{t.t('report.summary.storage_join')}"
            f"{t.plural('report.summary.storage_keys', storage)}"
        )
        if tracking:
            sentence += t.plural("report.summary.storage_tracking", tracking)
        out.append(sentence.strip() + ".")
    elif observed:
        out.append(t.t("report.summary.storage_none"))

    cmp_list = site.get("cmp") or []
    if cmp_list:
        out.append(t.t("report.summary.consent_present", names=", ".join(cmp_list)))
    elif consent_required:
        out.append(t.t("report.summary.consent_missing", n=consent_required))

    quick = sum(1 for f in result.findings if f.quick_win)
    sentence = t.t(
        "report.summary.verdict",
        grade=verdict.grade.value if verdict else "?",
        total=len(result.findings),
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
    )
    if quick:
        sentence += t.t("report.summary.verdict_quick", n=quick)
    out.append(sentence.strip() + ".")
    return out


def _by_owner(findings: list[RenderedFinding], t: Translator) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for finding in findings:
        bucket = buckets.setdefault(
            finding.owner_value,
            {"owner": finding.owner, "total": 0, "serious": 0, "quick": 0, "domains": set()},
        )
        bucket["total"] += 1
        if finding.severity_value in ("critical", "high"):
            bucket["serious"] += 1
        if finding.quick_win:
            bucket["quick"] += 1
        bucket["domains"].update(finding.domains)
    out = []
    for bucket in buckets.values():
        bucket["domains"] = ", ".join(sorted(bucket["domains"]))
        out.append(bucket)
    return sorted(out, key=lambda b: (-b["serious"], -b["total"]))


def _inventory(result: ScanResult, t: Translator) -> list[dict[str, Any]]:
    rows = []
    for entry in result.inventory:
        row = dict(entry)
        row["vendor_display"] = entry.get("vendor") or t.t(
            f"remediation.{entry.get('vendor_key', 'unknown_third_party')}"
        )
        row["transfer_display"] = t.label(entry.get("transfer", "non_eea"), "TransferScope")
        row["consent_display"] = t.label(entry.get("consent_class", "uncertain"), "ConsentClass")
        row["basis_display"] = (
            t.t(f"remediation.transfer_basis.{entry['transfer_basis']}")
            if entry.get("transfer_basis")
            else ""
        )
        row["detected_display"] = t.label(entry.get("detected_via", "request"), "Detection")
        rows.append(row)
    return rows


def _stability(result: ScanResult, t: Translator, titles: dict[str, str]) -> dict[str, Any]:
    """The repeat block as text. Only the findings that did not appear in every completed load get
    a row: those are the information; the stable ones are the report itself."""
    block = result.repeat or {}
    if not block:
        return {}
    requested, completed = block["requested"], block["completed"]
    unstable = [f for f in block.get("findings", []) if f["seen"] < f["of"]]
    notes = []
    if completed < requested:
        notes.append(t.t("report.stability.incomplete", n=requested - completed))
    notes.append(
        t.t("report.stability.some_unstable", n=len(unstable)) if unstable else t.t("report.stability.all_stable")
    )
    return {
        "heading": t.t("report.stability.heading", n=requested),
        "intro": t.t(
            "report.stability.intro", completed=completed, requested=requested, grades=", ".join(block["grades"])
        ),
        "notes": notes,
        "head": (t.t("report.labels.finding"), t.t("report.labels.severity"), t.t("report.stability.seen")),
        "rows": [
            (
                f"{f['id']}: {titles[f['id']]}" if f["id"] in titles else f["id"],
                t.label(f["severity"], "Severity"),
                t.t("report.stability.seen_value", seen=f["seen"], of=f["of"]),
            )
            for f in unstable
        ],
    }


def render_scan(result: ScanResult, t: Translator) -> RenderedScan:
    findings = [render_finding(f, t) for f in result.sorted_findings]
    verdict = result.verdict
    counts = verdict.counts if verdict else {}
    priorities = {p: sum(1 for f in result.findings if f.priority.value == p) for p in _PRIORITY_ORDER}
    mode = (result.context or {}).get("mode", "passive")
    attempt = (result.record.get("posture") or {}).get("refusal") or {}
    if attempt:
        attempt = {
            **attempt,
            "outcome_display": t.t(f"consent_pass.outcome.{attempt.get('outcome', '')}"),
        }
    return RenderedScan(
        mode=mode,
        refusal=attempt,
        scan_id=result.scan_id,
        url=result.url,
        final_url=result.final_url,
        domain=(result.site or {}).get("domain", result.url),
        started_at=result.started_at,
        grade=verdict.grade.value if verdict else "?",
        conformant=bool(verdict and verdict.conformant),
        verdict_note=t.t(verdict.note_key) if verdict and verdict.note_key else "",
        counts_by_severity=[
            (t.label(s, "Severity"), counts.get(s, 0)) for s in _SEVERITY_ORDER
        ],
        counts_by_priority=[(p, priorities[p]) for p in _PRIORITY_ORDER],
        stability=_stability(result, t, {f.id: f.title for f in findings}),
        summary=(
            _refusal_summary(result, t, attempt) if mode == "refusal_pass" else _summary(result, t)
        ),
        findings=findings,
        quick_wins=[f for f in findings if f.quick_win],
        by_owner=_by_owner(findings, t),
        inventory=_inventory(result, t),
        site=result.site or {},
        raw=result.to_dict(),
    )
