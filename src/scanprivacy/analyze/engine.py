"""Rule evaluation: context + rules -> findings.

The engine loads logic, never prose. It emits findings that carry canonical
values, catalogue keys and parameters — the sentences are assembled later, in
whatever language the report is asked for.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import RULES_DIR
from ..core.enums import Confidence, Effort, Severity, SubjectKind
from ..core.models import Finding, RemediationRef, priority_for
from ..knowledge.registry import mapping_for
from .context import Context
from .predicates import evaluate_condition
from .subjects import Subject, build
from .verify import steps_for


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    severity: Severity
    confidence: Confidence
    subject: SubjectKind
    condition: dict[str, Any]
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    remediation_source: str = "rule"
    remediation_effort: Effort = Effort.MEDIUM
    pass_: str = "passive"
    """Which observation a rule belongs to. `passive` rules describe what the
    site does to a visitor who has not decided; `refusal` rules describe what it
    does to one who said no. Mixing them in one document would make both weaker
    — and the refusal pass interacts with the page, which the passive one never
    does."""


_RULES_CACHE: dict[tuple, tuple[Rule, ...]] = {}


def load_rules(directory: Path = RULES_DIR, pass_: str = "passive") -> list[Rule]:
    """The rules in `directory` for one pass.

    Parsed once per distinct state of the files: this ran on every scan and on
    every unauthenticated `/healthz` probe. The key includes each file's mtime,
    so editing a rule is still picked up. A fresh list is returned each time.
    """
    files = sorted(directory.glob("PM-*.yml"))
    key = (str(directory), pass_, tuple((p.name, p.stat().st_mtime_ns) for p in files))
    if key not in _RULES_CACHE:
        _RULES_CACHE[key] = tuple(_parse_rules(files, pass_))
    return list(_RULES_CACHE[key])


def _parse_rules(files: list[Path], pass_: str) -> list[Rule]:
    rules: list[Rule] = []
    for path in files:
        body = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if body.get("pass", "passive") != pass_:
            continue
        remediation = body.get("remediation", {}) or {}
        rules.append(
            Rule(
                id=body["id"],
                severity=Severity(body["severity"]),
                confidence=Confidence(body.get("confidence", "certain")),
                subject=SubjectKind(body.get("subject", "site")),
                condition=body.get("condition", {}) or {},
                references=tuple(body.get("references", []) or []),
                tags=tuple(body.get("tags", []) or []),
                remediation_source=remediation.get("source", "rule"),
                remediation_effort=Effort(remediation.get("effort", "medium")),
                pass_=body.get("pass", "passive"),
            )
        )
    return rules


def _remediation(rule: Rule, ctx: Context, subject: Subject) -> RemediationRef:
    params = dict(subject.params)
    if ctx.platform_id:
        params["platform_hint_key"] = f"platform.{ctx.platform_id}.hint"
        params["platform_name"] = ctx.platform_name
    # Only for rules a response header alone can satisfy — see `_extra_evidence`.
    if "header_missing" in rule.condition and ctx.fixed_header_platform:
        params["platform_constraint_key"] = (
            f"remediation.constraint.{ctx.fixed_header_platform}"
        )
    if rule.remediation_source == "vendor" and subject.kind is SubjectKind.VENDOR:
        vendor = subject.payload.vendor
        return RemediationRef(
            source="vendor",
            key=vendor.id,
            pattern=vendor.remediation.pattern,
            effort=rule.remediation_effort,
            alternatives=vendor.remediation.alternatives,
            extra_steps=vendor.remediation.extra_steps,
            params=params,
        )
    return RemediationRef(
        source="rule", key=rule.id, effort=rule.remediation_effort, params=params
    )


def _confidence(rule: Rule, ctx: Context) -> Confidence:
    """The rule's confidence, unless the observation behind it is weaker.

    A refusal rule says "this ran even after the visitor said no". That is a
    fact only if the refusal itself happened, and a refusal performed through a
    path transcribed from a vendor's documentation and never exercised is not
    established: the call may exist, return cleanly and do nothing, and from
    outside the page that is indistinguishable from a site ignoring it. Stating
    it as `certain` would put an accusation on an unproven premise — and the
    catalogue is eight documented entries to one verified.
    """
    refusal = getattr(ctx, "refusal", None)
    if rule.pass_ != "refusal" or refusal is None:
        return rule.confidence
    # Default False, not True: a refusal record that does not say how far its
    # path is proven — an older evidence file, a partial double — has not
    # established anything, and the weaker claim is the safe direction.
    if not getattr(refusal, "path_proven", False):
        return Confidence.PROBABLE
    return rule.confidence


def _extra_evidence(rule: Rule, ctx: Context, subject: Subject) -> dict[str, Any]:
    """Evidence that belongs to the rule rather than to the subject."""
    extra: dict[str, Any] = {}
    condition = rule.condition
    if "art13_missing_any" in condition:
        extra["missing_elements"] = [f"art13.{k}" for k in ctx.art13_missing("privacy")]
        conditional = [f"art13.{k}" for k in ctx.art13_missing_conditional("privacy")]
        if conditional:
            extra["conditional_elements"] = conditional
        doc = ctx.docs_by_kind.get("privacy")
        if doc:
            extra["document"] = doc.url
    if "consent_required_vendors_present" in condition:
        extra["consent_required_vendors"] = [
            f"{v.vendor.product} ({', '.join(v.hosts[:3]) or v.detection.value})"
            for v in ctx.consent_required_vendors
        ]
    if "csp_absent" in condition and ctx.csp_report_only:
        # Present and enforcing nothing is a different situation from absent,
        # and the reader is the one who has to tell them apart.
        extra["csp_report_only"] = ctx.csp_report_only[:300]
    if "cmp_present" in condition:
        extra["cmp_detected"] = ctx.cmp_detected
    if "tls_classification" in condition and ctx.tls:
        extra["issuer"] = ctx.tls.issuer_org or ctx.tls.issuer_cn
        extra["expiry"] = ctx.tls.not_after
    if "header_missing" in condition or "header_regex_not_matching" in condition:
        extra["observed_headers"] = sorted(ctx.obs.response_headers.keys())
        # A response header is the only way to satisfy this rule, and some
        # hosting serves a fixed set nobody using it can add to. The finding
        # stays — it is true, and the exposure is real — but a reader has to be
        # told it cannot be closed where the site currently lives, or the
        # instruction to "set the header" sends them to look for a setting that
        # does not exist. Rules with a `<meta>` equivalent (CSP,
        # Referrer-Policy) are deliberately not covered: those *are* fixable on
        # such a platform, and claiming otherwise would excuse a real finding.
        platform = ctx.fixed_header_platform
        if platform:
            extra["platform_constraint"] = f"constraint.response_headers_fixed.{platform}"
    if "missing_document" in condition or "document_link_absent" in condition:
        extra["legal_links_found"] = [
            f"{link.kind}: {link.href}"
            for page in ctx.observed_pages
            for link in page.legal_links
        ][:12]
    if "dpia_criteria_min" in condition:
        from .dpia import screen

        screening = screen(ctx)
        extra["criteria_met"] = [f"dpia.criteria.{c.key}" for c in screening.met]
        extra["criteria_not_assessable"] = [
            f"dpia.criteria.{c.key}" for c in screening.not_assessable
        ]
        observed = [item for c in screening.met for item in c.evidence]
        if observed:
            extra["observed_signals"] = sorted(set(observed))
    if "cookie_section_incomplete" in condition:
        doc = ctx.docs_by_kind.get("cookie") or ctx.docs_by_kind.get("privacy")
        if doc:
            extra["document"] = doc.url
            extra["cookie_elements_present"] = [
                f"cookie_policy.{k}" for k, present in doc.cookie_elements.items() if present
            ]
    return extra


def evaluate(ctx: Context, rules: list[Rule] | None = None) -> list[Finding]:
    """Findings from an observation — and nothing at all without one.

    The register is fail-closed: nothing is graded green unless it was observed
    to be green. The converse binds just as hard, and was not being honoured.
    When the page never loaded there are no response headers, so every rule
    phrased as "this header is absent" fired, and the report asserted that a
    site carried no HSTS, no Referrer-Policy and no CSP on the strength of a
    response that was never received. It even offered `curl -sSI <target>` as
    the way to confirm it.

    Absence of observation is not observation of absence. With no page load the
    honest output is the empty set, and the verdict — already INCONCLUSIVE via
    `observed_ok` — is what carries the meaning.
    """
    if not ctx.obs.load_ok:
        return []

    findings: list[Finding] = []
    for rule in rules if rules is not None else load_rules():
        if not rule.condition:
            continue
        for subject in build(rule.subject, ctx):
            if not evaluate_condition(ctx, subject, rule.condition):
                continue
            remediation = _remediation(rule, ctx, subject)
            confidence = _confidence(rule, ctx)
            priority, quick_win = priority_for(rule.severity, remediation.effort, confidence)
            mapping = mapping_for(rule.id)
            findings.append(
                Finding(
                    id=rule.id if rule.subject is SubjectKind.SITE else f"{rule.id}:{subject.slug}",
                    rule_id=rule.id,
                    severity=rule.severity,
                    confidence=confidence,
                    subject_kind=subject.kind,
                    subject_node=subject.node_id,
                    params=subject.params,
                    evidence={**subject.evidence, **_extra_evidence(rule, ctx, subject)},
                    references=rule.references,
                    controls=mapping.controls,
                    owner=mapping.owner,
                    secondary_owners=mapping.secondary_owners,
                    domains=mapping.domains,
                    priority=priority,
                    quick_win=quick_win,
                    verification=steps_for(rule.id, ctx, subject),
                    remediation=remediation,
                )
            )
    return findings
