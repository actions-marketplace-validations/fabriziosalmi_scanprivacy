"""The fleet summary, in the reader's language.

Ranked by sites affected, never by finding count: an owner reading this needs
to know which single decision, taken once, is repeated across the estate.
"""

from __future__ import annotations

from ..analyze.fleet import FleetSummary
from ..i18n.translator import DEFAULT_LOCALE, Translator


def render_fleet(summary: FleetSummary, locale: str = DEFAULT_LOCALE, limit: int = 12) -> str:
    t = Translator.for_locale(locale)
    lines: list[str] = []
    add = lines.append

    add(f"# {t.t('fleet.title')}")
    add("")
    add(
        t.t(
            "fleet.headline",
            scanned=summary.scanned,
            targets=summary.targets,
            failed=summary.failed,
            affected=summary.sites_with_any_finding,
            actionable=summary.sites_with_actionable,
            clean=len(summary.clean_sites),
        )
    )
    add("")

    add(f"| {t.t('report.labels.severity')} | {t.t('fleet.labels.sites')} |")
    add("|---|---:|")
    for grade, count in summary.grades.items():
        add(f"| {grade} | {count} |")
    add("")

    if summary.by_rule:
        add(f"## {t.t('fleet.headings.repeated')}")
        add("")
        add(t.t("fleet.legend.repeated"))
        add("")
        add(
            f"| {t.t('report.labels.finding')} | {t.t('report.labels.severity')} "
            f"| {t.t('fleet.labels.sites')} | {t.t('fleet.labels.examples')} |"
        )
        add("|---|---|---:|---|")
        for entry in summary.by_rule[:limit]:
            title = (
                t.rule(entry.rule_id, "title_generic")
                if t.rule_has(entry.rule_id, "title_generic")
                else t.rule(entry.rule_id, "title")
            )
            add(
                f"| `{entry.rule_id}` {title} | {t.label(entry.severity, 'Severity')} "
                f"| {entry.sites} | {', '.join(entry.examples[:3])} |"
            )
        add("")

    if summary.by_vendor:
        add(f"## {t.t('fleet.headings.vendors')}")
        add("")
        add(t.t("fleet.legend.vendors"))
        add("")
        add(
            f"| {t.t('report.labels.service')} | {t.t('fleet.labels.sites')} "
            f"| {t.t('fleet.labels.undeclared_on')} | {t.t('report.labels.transfer')} |"
        )
        add("|---|---:|---:|---|")
        for entry in summary.by_vendor[:limit]:
            add(
                f"| {entry.product} | {entry.sites} | {entry.undeclared_on} "
                f"| {t.label(entry.transfer, 'TransferScope')} |"
            )
        add("")

    add(f"## {t.t('fleet.headings.targets')}")
    add("")
    add(
        f"| {t.t('fleet.labels.site')} | {t.t('report.labels.severity')} "
        f"| {t.t('report.labels.findings_count')} | {t.t('report.labels.third_parties')} "
        f"| {t.t('fleet.labels.pages')} |"
    )
    add("|---|---|---:|---:|---:|")
    for target in sorted(
        summary.targets_detail, key=lambda d: (-d.critical, -d.high, -d.findings, d.domain)
    ):
        grade = target.grade if target.status == "ok" else f"{target.grade} ({target.status})"
        add(
            f"| {target.domain} | {grade} | {target.findings} "
            f"| {target.third_parties} | {target.pages} |"
        )
    add("")

    if summary.clean_sites:
        add(f"## {t.t('fleet.headings.clean')}")
        add("")
        add(", ".join(sorted(summary.clean_sites)))
        add("")
    return "\n".join(lines)
