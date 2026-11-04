"""The fleet report as a PDF.

Same template engine, same stylesheet, same rule as everywhere else: the
template carries no prose of its own, so the estate summary renders in any
language the catalogues cover.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..analyze.fleet import FleetSummary
from ..i18n.translator import DEFAULT_LOCALE, Translator
from .pdf import _env
from .render import posture_rows

TEMPLATES = Path(__file__).resolve().parent / "templates"

# The passive posture applies unchanged: a fleet run is many passive scans, not
# a different method. Only the shared courtesy budget is specific to it.
FLEET_POSTURE_KEYS = (
    "report.posture.method",
    "report.posture.pages",
    "report.posture.interaction",
    "report.posture.consent",
    "report.posture.intrusive_tests",
    "report.posture.robots",
)


def build_context(summary: FleetSummary, locale: str = DEFAULT_LOCALE, limit: int = 20) -> dict[str, Any]:
    t = Translator.for_locale(locale)
    rules = []
    for entry in summary.by_rule[:limit]:
        title = (
            t.rule(entry.rule_id, "title_generic")
            if t.rule_has(entry.rule_id, "title_generic")
            else t.rule(entry.rule_id, "title")
        )
        # slots dataclass: asdict, not __dict__
        rules.append({**asdict(entry), "title": title})

    return {
        "t": t,
        "summary": summary,
        "rules": rules,
        "targets": sorted(
            summary.targets_detail,
            key=lambda d: (-d.critical, -d.high, -d.findings, d.domain),
        ),
        "severity_rows": [(s, n) for s, n in summary.severity_totals.items() if n],
        "owner_rows": list(summary.by_owner.items()),
        "posture_rows": posture_rows(FLEET_POSTURE_KEYS, t, max_pages=summary.max_pages),
        "generated_at": datetime.now(timezone.utc).isoformat()[:19].replace("T", " "),
        "headline": t.t(
            "fleet.headline",
            scanned=summary.scanned,
            targets=summary.targets,
            failed=summary.failed,
            affected=summary.sites_with_any_finding,
            actionable=summary.sites_with_actionable,
            clean=len(summary.clean_sites),
        ),
    }


def render_fleet_html(summary: FleetSummary, locale: str = DEFAULT_LOCALE) -> str:
    return _env.get_template("fleet.html").render(**build_context(summary, locale))


def render_fleet_pdf(summary: FleetSummary, out: Path, locale: str = DEFAULT_LOCALE) -> Path:
    from weasyprint import HTML

    from .pdf import local_only_fetcher

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(
        string=render_fleet_html(summary, locale), base_url=str(TEMPLATES), url_fetcher=local_only_fetcher()
    ).write_pdf(str(out))
    return out
