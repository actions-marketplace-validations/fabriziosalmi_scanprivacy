"""How to reproduce a finding without this tool.

The point of a conformance report is not to be believed. Every finding carries
the steps a sceptic — the site owner, their supplier, an authority — can follow
with a browser and a terminal to see the same thing, or to prove us wrong. A
finding nobody can check independently is worth nothing, and the first thing a
supplier says is "your scanner is wrong".

Steps are catalogue keys plus parameters, so the instructions come out in the
reader's language and stay identical in substance.
"""

from __future__ import annotations

from ..core.enums import Detection, SubjectKind
from ..core.models import VerificationStep
from .context import Context
from .subjects import Subject


def _document_url(ctx: Context, kind: str = "privacy") -> str | None:
    doc = ctx.docs_by_kind.get(kind)
    return doc.url if doc else None


def steps_for(rule_id: str, ctx: Context, subject: Subject) -> tuple[VerificationStep, ...]:
    url = ctx.obs.final_url or ctx.obs.url
    host = ctx.site_host
    evidence = subject.evidence
    steps: list[VerificationStep] = []

    if subject.kind is SubjectKind.VENDOR:
        hosts = evidence.get("hosts") or []
        target = hosts[0] if hosts else ""
        if evidence.get("detected_via") is Detection.HEADER:
            steps.append(VerificationStep("verification.vendor_header", {"url": url}))
        else:
            steps.append(VerificationStep("verification.vendor_request", {"url": url, "host": target}))
            samples = evidence.get("observed_requests") or []
            if samples:
                steps.append(VerificationStep("verification.vendor_request_sample", {"url": samples[0]}))
            steps.append(VerificationStep("verification.vendor_request_cli", {"url": url, "host": target}))
        doc = _document_url(ctx)
        if doc:
            steps.append(VerificationStep("verification.vendor_document", {"url": doc}))

    elif subject.kind is SubjectKind.COOKIE:
        steps.append(
            VerificationStep(
                "verification.cookie",
                {"url": url, "domain": evidence.get("domain"), "name": evidence.get("name")},
            )
        )

    elif subject.kind is SubjectKind.STORAGE:
        steps.append(
            VerificationStep(
                "verification.storage",
                {"url": url, "kind": evidence.get("kind"), "key": evidence.get("key")},
            )
        )

    elif subject.kind is SubjectKind.FORM:
        steps.append(
            VerificationStep("verification.form", {"url": url, "action": evidence.get("action")})
        )

    # rule-specific site-level checks
    if rule_id.startswith("PM-SEC"):
        steps.append(VerificationStep("verification.headers", {"url": url}))
    elif rule_id == "PM-COST-01":
        steps.append(VerificationStep("verification.tls", {"host": host}))
    elif rule_id in ("PM-DOC-01", "PM-DOC-02", "PM-DOC-03"):
        doc = _document_url(ctx) or _document_url(ctx, "cookie")
        if doc:
            steps.append(VerificationStep("verification.documents_found", {"url": doc}))
        else:
            steps.append(VerificationStep("verification.documents_missing", {"url": url}))
    elif rule_id in ("PM-CNS-02", "PM-CNS-03"):
        steps.append(VerificationStep("verification.consent", {"url": url}))
    elif rule_id == "PM-AI-01":
        steps.append(VerificationStep("verification.ai", {"url": url}))

    steps.append(VerificationStep("verification.closing", {}))
    return tuple(steps)
