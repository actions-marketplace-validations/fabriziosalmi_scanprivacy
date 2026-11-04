"""Markdown rendering. The JSON graph stays the source of truth; this is the
human projection, in whatever language it was asked for."""

from __future__ import annotations

from ..core.models import ScanResult
from ..i18n.translator import DEFAULT_LOCALE, Translator
from .render import RenderedScan, scan_posture_rows, render_scan

_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪️"}


def render(result: ScanResult, locale: str = DEFAULT_LOCALE, include_graph: bool = True) -> str:
    t = Translator.for_locale(locale)
    scan = render_scan(result, t)
    lines: list[str] = []
    add = lines.append

    title_key = "consent_pass.title" if scan.mode == "refusal_pass" else "report.title"
    add(f"# {t.t(title_key, domain=scan.domain)}")
    add("")
    add(f"**{t.t('report.subtitle_url')}**: {scan.final_url}  ")
    add(f"**{t.t('report.subtitle_scan')}**: `{scan.scan_id}`  ")
    if scan.mode == "refusal_pass":
        add(f"{t.t('consent_pass.posture.method_refusal')}  ")
    else:
        add(f"{t.t('report.subtitle_observed', timestamp=scan.started_at[:19].replace('T', ' '))}  ")
    verdict_text = (
        t.t("report.verdict_conformant") if scan.conformant else t.t("report.verdict_not_conformant")
    )
    add(f"**{scan.grade}** — {verdict_text}  ")
    add(f"{scan.verdict_note}")
    add("")

    for sentence in scan.summary:
        add(sentence.replace("<strong>", "**").replace("</strong>", "**"))
        add("")

    if scan.mode == "refusal_pass" and scan.refusal:
        add(f"| | |")
        add("|---|---|")
        add(f"| {t.t('consent_pass.labels.outcome')} | {scan.refusal.get('outcome_display')} |")
        if scan.refusal.get("platform_name"):
            add(f"| {t.t('consent_pass.labels.platform')} | {scan.refusal['platform_name']} |")
            add(f"| {t.t('consent_pass.labels.action')} | `{scan.refusal.get('action')}` |")
            add(f"| {t.t('consent_pass.labels.documentation')} | {scan.refusal.get('documentation')} |")
            # The reader is entitled to know how far the path used has been
            # proven. Eight of nine catalogue entries have never been run
            # against a live installation.
            verification = scan.refusal.get("verification")
            if verification:
                add(
                    f"| {t.t('consent_pass.labels.verification')} "
                    f"| {t.t(f'consent_pass.verification.{verification}')} |"
                )
        add("")

    add(f"| {t.t('report.labels.severity')} | {t.t('report.labels.findings_count')} |")
    add("|---|---:|")
    for label, count in scan.counts_by_severity:
        add(f"| {label} | {count} |")
    add("")

    if scan.by_owner:
        add(f"## {t.t('report.headings.responsibility')}")
        add("")
        add(
            f"| {t.t('report.labels.owner')} | {t.t('report.labels.findings_count')} "
            f"| {t.t('report.labels.of_which_serious')} | {t.t('report.labels.quick_wins')} "
            f"| {t.t('report.labels.areas')} |"
        )
        add("|---|---:|---:|---:|---|")
        for bucket in scan.by_owner:
            add(
                f"| {bucket['owner']} | {bucket['total']} | {bucket['serious']} "
                f"| {bucket['quick']} | {bucket['domains']} |"
            )
        add("")

    add(f"## {t.t('report.headings.findings')}")
    add("")
    if not scan.findings:
        add(t.t("report.headings.no_findings"))
        add("")
    for finding in scan.findings:
        add(f"### {_ICON.get(finding.severity_value, '•')} {finding.title}")
        add("")
        meta = [
            f"`{finding.id}`",
            f"**{finding.severity}**",
            finding.priority,
            f"{t.t('report.labels.owner')}: **{finding.owner}**",
            f"{t.t('report.labels.confidence')}: {finding.confidence}",
        ]
        if finding.quick_win:
            meta.append(f"**{t.t('report.labels.quick_wins')}**")
        add(" · ".join(meta))
        add("")
        add(finding.description)
        add("")
        if finding.references:
            add(f"**{t.t('report.labels.legal_references')}**: " + "; ".join(finding.references))
            add("")
        if finding.controls:
            mapped = " · ".join(f"{name}: {', '.join(items)}" for name, items in finding.controls)
            add(f"**{t.t('report.labels.control_mapping')}**: {mapped}")
            add("")
        if finding.evidence:
            add(f"<details><summary>{t.t('report.labels.evidence')}</summary>")
            add("")
            for label, value in finding.evidence:
                if isinstance(value, list):
                    add(f"- **{label}**:")
                    for item in value[:8]:
                        add(f"  - `{item}`")
                else:
                    add(f"- **{label}**: `{value}`")
            add("")
            add("</details>")
            add("")
        if finding.verification:
            add(f"<details><summary>{t.t('report.labels.verification')}</summary>")
            add("")
            for step in finding.verification:
                add(f"1. {step}")
            add("")
            add("</details>")
            add("")
        if finding.remediation:
            rem = finding.remediation
            add(f"**{t.t('report.labels.remediation', effort=rem.effort)}** — {rem.summary}")
            add("")
            for step in rem.steps:
                add(f"1. {step}")
            if rem.alternatives:
                add("")
                add(f"**{t.t('report.labels.alternatives')}**: " + ", ".join(rem.alternatives))
            add("")

    if scan.inventory:
        add(f"## {t.t('report.headings.inventory')}")
        add("")
        add(
            f"| {t.t('report.labels.service')} | {t.t('report.labels.entity')} "
            f"| {t.t('report.labels.jurisdiction')} | {t.t('report.labels.transfer')} "
            f"| {t.t('report.labels.consent')} | {t.t('report.labels.declared')} |"
        )
        add("|---|---|---|---|---|---|")
        for row in scan.inventory:
            declared = t.t("report.labels.yes") if row["declared"] else f"**{t.t('report.labels.no')}**"
            add(
                f"| {row['product']} | {row['vendor_display']} | {row['jurisdiction']} "
                f"| {row['transfer_display']} | {row['consent_display']} | {declared} |"
            )
        add("")

    plan = (result.observation or {}).get("page_plan") or []
    if len(plan) > 1:
        observed = {
            page.get("final_url") or page.get("url"): page
            for page in (result.observation or {}).get("pages") or []
        }
        add(f"## {t.t('report.headings.pages')}")
        add("")
        add(t.t("report.legend.pages"))
        add("")
        add(
            f"| # | {t.t('report.labels.url')} | {t.t('report.labels.page_kind')} "
            f"| {t.t('report.labels.status')} | {t.t('report.labels.requests_count')} |"
        )
        add("|---:|---|---|---:|---:|")
        for index, planned in enumerate(plan, start=1):
            page = observed.get(planned["url"]) or {}
            add(
                f"| {index} | {planned['url']} | {t.t('page_kind.' + planned.get('kind', 'other'))} "
                f"| {page.get('status') or '—'} | {len(page.get('requests') or [])} |"
            )
        add("")

    record = result.record or {}
    if record:
        add(f"## {t.t('report.headings.reproducibility')}")
        add("")
        add(t.t("report.legend.reproducibility"))
        add("")
        add("| | |")
        add("|---|---|")
        for key, value in (record.get("engine") or {}).items():
            add(f"| {t.t(f'record.engine.{key}')} | {value} |")
        digests = record.get("digests") or {}
        add(f"| {t.t('report.labels.ruleset_digest')} | `{digests.get('ruleset')}` |")
        add(f"| {t.t('report.labels.knowledge_digest')} | `{digests.get('knowledge')}` |")
        add(f"| {t.t('report.labels.evidence_digest')} | `{(record.get('evidence_digest') or {}).get('sha256')}` |")
        add("")
        add("```bash")
        for step in t.items(record.get("rerun_key", "record.rerun"), **(record.get("rerun_params") or {})):
            add(step)
        add("```")
        add("")

    if include_graph and result.graph:
        from ..core.graph import to_mermaid

        add(f"## {t.t('report.headings.evidence')}")
        add("")
        add("```mermaid")
        add(to_mermaid(result.graph, labels={f"finding:{f.id}": f.title for f in scan.findings}))
        add("```")
        add("")

    add(f"## {t.t('report.headings.method')}")
    add("")
    for label, value in scan_posture_rows(record, t):
        add(f"- **{label}**: {value}")
    add("")
    add(f"**{t.t('report.limits.title')}** {t.t('report.limits.body')}")
    # A partial observation that presents itself as complete is the failure
    # this engine exists to avoid. If a read did not finish, the reader is told
    # which one, rather than being handed a silence that looks like an answer.
    pages = (result.observation or {}).get("pages") or []
    probes = sorted({f for page in pages for f in (page.get("probe_failures") or [])})
    if probes:
        add("")
        add(t.t("report.limits.partial", probes=", ".join(probes)))
    add("")
    add(t.t("report.limits.disclaimer"))
    return "\n".join(lines)
