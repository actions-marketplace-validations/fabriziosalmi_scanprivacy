"""SARIF 2.1.0 export.

The point is not the file format. It is that a privacy finding becomes an item
in the same queue a developer already works from — GitHub's Security tab —
instead of a PDF somebody has to remember to read.

Three properties make the difference between a tolerated integration and a
useful one:

- **stable fingerprints**, so an alert that persists stays the same alert and an
  alert whose cause is removed closes by itself. The remediation lifecycle we
  model ends up tracked by the platform, at no cost.
- **real locations** where a source root is available: the file and line that
  loads the third party, not "your website".
- **the fix in the message**, because an alert nobody can act on gets muted.

Severity mapping is deliberate. SARIF `level` drives the icon; GitHub reads
`security-severity` for its own High/Medium/Low banding, and the two must agree
or the queue becomes unreadable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from ..core.enums import Severity
from ..core.models import ScanResult
from ..i18n.translator import DEFAULT_LOCALE, Translator
from .anchor import SourceAnchor, SourceIndex
from .render import RenderedFinding, render_finding

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
INFORMATION_URI = "https://github.com/fabriziosalmi/scanprivacy"

# level drives the icon, security-severity drives GitHub's own banding
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}
# `precision` tells the platform how much to trust the result; it maps onto the
# same distinction the reports make between observed and inferred findings.
_PRECISION = {"certain": "very-high", "probable": "medium"}


def fingerprint(finding_id: str) -> str:
    """Stable across runs and across languages: the identity of a finding is its
    rule plus its subject, never its rendered text."""
    return hashlib.sha256(f"scanprivacy/v1/{finding_id}".encode("utf-8")).hexdigest()[:32]


def _rule_name(rule_id: str, title: str) -> str:
    """SARIF `name` should be an identifier-ish label; GitHub shows it in lists."""
    cleaned = "".join(word.capitalize() for word in title.replace("{", "").replace("}", "").split()[:6])
    return f"{rule_id.replace('-', '')}{cleaned[:60]}" if cleaned else rule_id.replace("-", "")


def _rule_help_markdown(rendered: RenderedFinding, t: Translator) -> str:
    parts = [rendered.description, ""]
    if rendered.references:
        parts.append(f"**{t.t('report.labels.legal_references')}**")
        parts.extend(f"- {reference}" for reference in rendered.references)
        parts.append("")
    if rendered.controls:
        parts.append(f"**{t.t('report.labels.control_mapping')}**")
        for framework, items in rendered.controls:
            parts.append(f"- {framework}: {', '.join(items)}")
        parts.append("")
    if rendered.verification:
        parts.append(f"**{t.t('report.labels.verification')}**")
        parts.extend(f"{i}. {step}" for i, step in enumerate(rendered.verification, start=1))
    return "\n".join(parts).strip()


def _message(rendered: RenderedFinding, t: Translator, anchor: SourceAnchor | None) -> str:
    """What the developer reads in the alert. Title, then the fix, then the
    steps — anything longer than this gets skimmed."""
    lines = [rendered.title]
    if rendered.remediation:
        lines.append("")
        lines.append(
            f"{t.t('report.labels.remediation', effort=rendered.remediation.effort)}: "
            f"{rendered.remediation.summary}"
        )
        lines.extend(f"  {i}. {step}" for i, step in enumerate(rendered.remediation.steps, start=1))
        if rendered.remediation.alternatives:
            lines.append(
                f"  {t.t('report.labels.alternatives')}: {', '.join(rendered.remediation.alternatives)}"
            )
    if anchor is not None:
        lines.append("")
        relation = "loaded at" if anchor.kind == "inclusion" else "named at"
        lines.append(f"`{anchor.token}` {relation} {anchor.path}:{anchor.line}")
        if anchor.kind == "mention":
            lines.append(
                "  (the line names the host but does not appear to load it — the inclusion may be elsewhere)"
            )
    return "\n".join(lines)


def _location(anchor: SourceAnchor | None, fallback: str, url: str) -> dict[str, Any]:
    if anchor is not None:
        return {
            "physicalLocation": {
                "artifactLocation": {"uri": anchor.path, "uriBaseId": "%SRCROOT%"},
                "region": {
                    "startLine": anchor.line,
                    "snippet": {"text": anchor.snippet},
                },
            },
            "message": {
                "text": (
                    f"{anchor.token} — {url}"
                    if anchor.kind == "inclusion"
                    else f"{anchor.token} named here; the inclusion may be elsewhere — {url}"
                )
            },
        }
    # No source match: anchor to the declared file so the alert still lands
    # somewhere a human can open, and say plainly that it is not the cause.
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": fallback, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 1},
        },
        "message": {"text": f"observed on {url}; no matching line found in the source tree"},
    }


def build_sarif(
    result: ScanResult,
    locale: str = DEFAULT_LOCALE,
    source_root: Path | None = None,
    anchor_file: str = "README.md",
) -> dict[str, Any]:
    t = Translator.for_locale(locale)
    index = SourceIndex(source_root) if source_root else None

    rules: list[dict[str, Any]] = []
    rule_index: dict[str, int] = {}
    results: list[dict[str, Any]] = []
    anchored = 0

    for finding in result.sorted_findings:
        rendered = render_finding(finding, t)
        if finding.rule_id not in rule_index:
            rule_index[finding.rule_id] = len(rules)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": _rule_name(finding.rule_id, t.rule(finding.rule_id, "title")),
                    "shortDescription": {"text": t.rule(finding.rule_id, "title")},
                    "fullDescription": {"text": t.rule(finding.rule_id, "description")},
                    "help": {
                        "text": rendered.description,
                        "markdown": _rule_help_markdown(rendered, t),
                    },
                    "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                    "properties": {
                        "tags": ["privacy", "gdpr", "compliance", *finding.domains],
                        "security-severity": _SECURITY_SEVERITY[finding.severity],
                        "precision": _PRECISION.get(finding.confidence.value, "medium"),
                        "problem.severity": _LEVEL[finding.severity],
                        "references": list(finding.references),
                    },
                }
            )

        anchor = index.anchor_for(finding) if index else None
        if anchor is not None:
            anchored += 1
        results.append(
            {
                "ruleId": finding.rule_id,
                "ruleIndex": rule_index[finding.rule_id],
                "level": _LEVEL[finding.severity],
                "message": {"text": _message(rendered, t, anchor)},
                "locations": [_location(anchor, anchor_file, result.final_url)],
                # Renamed with the project. Code scanning correlates alerts
                # across runs by this key, so changing it recreates every alert
                # — which is why it carries a version. Nothing has consumed it
                # yet: the action is unpublished and the repository is private,
                # so now is the only free moment to do this.
                "partialFingerprints": {"scanprivacyFindingId/v1": fingerprint(finding.id)},
                "properties": {
                    "findingId": finding.id,
                    "priority": finding.priority.value,
                    "owner": finding.owner.value,
                    "quickWin": finding.quick_win,
                    "domains": list(finding.domains),
                    "confidence": finding.confidence.value,
                    "subject": finding.subject_kind.value,
                    "url": result.final_url,
                    "anchorKind": anchor.kind if anchor else "none",
                },
            }
        )

    record = result.record or {}
    digests = record.get("digests") or {}
    verdict = result.verdict
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "scanprivacy",
                        "informationUri": INFORMATION_URI,
                        "semanticVersion": (record.get("engine") or {}).get("engine", "scanprivacy").split()[-1],
                        "rules": rules,
                    }
                },
                # groups runs of the same target so GitHub can close alerts that
                # disappeared instead of piling up duplicates
                "automationDetails": {"id": f"scanprivacy/{result.site.get('domain', result.url)}"},
                "invocations": [
                    {
                        "executionSuccessful": result.status.value == "ok",
                        "startTimeUtc": result.started_at,
                        "endTimeUtc": result.finished_at,
                    }
                ],
                "results": results,
                "properties": {
                    "scanId": result.scan_id,
                    "url": result.final_url,
                    "grade": verdict.grade.value if verdict else None,
                    "conformant": bool(verdict and verdict.conformant),
                    "evidenceDigest": (record.get("evidence_digest") or {}).get("sha256"),
                    "rulesetDigest": digests.get("ruleset"),
                    "knowledgeDigest": digests.get("knowledge"),
                    "sourceAnchored": anchored,
                    "sourceFilesSearched": index.file_count if index else 0,
                },
            }
        ],
    }
