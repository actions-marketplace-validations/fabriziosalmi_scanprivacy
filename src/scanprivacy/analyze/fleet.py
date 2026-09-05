"""Aggregating a fleet of scans.

A single report tells an owner what to fix. A fleet tells them what they keep
doing: the same font CDN on thirty sites is one decision made once and repeated,
not thirty problems. That reframing is the whole value of scanning a fleet, and
it is why the aggregate counts **sites affected** rather than findings — one
site with five copies of a form must not outweigh five sites with one each.

Nothing here reaches the network. It reads results that already exist, so a
fleet summary can be recomputed from published evidence without re-scanning.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from urllib.parse import urlsplit
from dataclasses import dataclass, field
from typing import Any

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_GRADES = ("A", "B", "C", "D", "F", "INCONCLUSIVE")


@dataclass(slots=True)
class RulePrevalence:
    rule_id: str
    sites: int
    findings: int
    severity: str
    examples: list[str] = field(default_factory=list)


@dataclass(slots=True)
class VendorPrevalence:
    vendor_id: str
    product: str
    sites: int
    undeclared_on: int
    transfer: str
    examples: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TargetSummary:
    url: str
    domain: str
    grade: str
    findings: int
    critical: int
    high: int
    third_parties: int
    pages: int
    status: str
    scan_id: str = ""
    error: str | None = None


@dataclass(slots=True)
class FleetSummary:
    targets: int = 0
    scanned: int = 0
    failed: int = 0
    grades: dict[str, int] = field(default_factory=dict)
    severity_totals: dict[str, int] = field(default_factory=dict)
    sites_with_any_finding: int = 0
    sites_with_actionable: int = 0
    """Sites carrying something above `info`. A site whose only finding is an
    informational note about its own hosting provider is not a site with a
    problem, and reporting it as one costs the whole aggregate its credibility."""
    clean_sites: list[str] = field(default_factory=list)
    by_rule: list[RulePrevalence] = field(default_factory=list)
    by_vendor: list[VendorPrevalence] = field(default_factory=list)
    by_owner: dict[str, int] = field(default_factory=dict)
    targets_detail: list[TargetSummary] = field(default_factory=list)
    max_pages: int | None = None
    """The per-site page budget the run used, read back from the results.

    The estate report describes its own method, and that description includes
    how many pages of each site were looked at. Without this the fleet PDF said
    "at most {n} pages"; stating a budget nobody recorded would be worse."""
    quick_wins: int = 0

    def to_dict(self) -> dict[str, Any]:
        from dataclasses import asdict

        return {
            "targets": self.targets,
            "scanned": self.scanned,
            "failed": self.failed,
            "grades": self.grades,
            "severity_totals": self.severity_totals,
            "sites_with_any_finding": self.sites_with_any_finding,
            "sites_with_actionable": self.sites_with_actionable,
            "clean_sites": self.clean_sites,
            "quick_wins": self.quick_wins,
            "by_rule": [asdict(r) for r in self.by_rule],
            "by_vendor": [asdict(v) for v in self.by_vendor],
            "by_owner": self.by_owner,
            "targets_detail": [asdict(t) for t in self.targets_detail],
            "max_pages": self.max_pages,
        }


def summarise(results: list[dict[str, Any]]) -> FleetSummary:
    """`results` are `ScanResult.to_dict()` payloads, one per target."""
    summary = FleetSummary(targets=len(results))
    for result in results:
        budget = ((result.get("record") or {}).get("posture") or {}).get("max_pages")
        if isinstance(budget, int):
            summary.max_pages = budget
            break

    grades: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    owners: Counter[str] = Counter()
    rule_sites: dict[str, set[str]] = defaultdict(set)
    rule_findings: Counter[str] = Counter()
    rule_severity: dict[str, str] = {}
    vendor_sites: dict[str, set[str]] = defaultdict(set)
    vendor_undeclared: dict[str, set[str]] = defaultdict(set)
    vendor_meta: dict[str, tuple[str, str]] = {}

    for result in results:
        site = result.get("site") or {}
        verdict = result.get("verdict") or {}
        # The registrable domain is not an identity for project pages: thirty
        # sites under one github.io host would all be labelled the same. Host
        # plus path is what tells them apart, and it is what the owner reads.
        final = result.get("final_url") or result.get("url", "")
        parts = urlsplit(final)
        path = (parts.path or "/").strip("/")
        domain = f"{parts.netloc}/{path}" if path else parts.netloc
        status = result.get("status", "error")
        findings = result.get("findings") or []

        detail = TargetSummary(
            url=result.get("final_url") or result.get("url", ""),
            domain=domain,
            grade=verdict.get("grade", "INCONCLUSIVE"),
            findings=len(findings),
            critical=(verdict.get("counts") or {}).get("critical", 0),
            high=(verdict.get("counts") or {}).get("high", 0),
            third_parties=site.get("third_parties", 0),
            pages=site.get("pages_observed", 1),
            status=status,
            scan_id=result.get("scan_id", ""),
            error=result.get("error"),
        )
        summary.targets_detail.append(detail)

        if status != "ok":
            summary.failed += 1
            grades[detail.grade] += 1
            continue

        summary.scanned += 1
        grades[detail.grade] += 1
        if findings:
            summary.sites_with_any_finding += 1
            if any(f.get("severity") != "info" for f in findings):
                summary.sites_with_actionable += 1
        else:
            summary.clean_sites.append(domain)

        for finding in findings:
            severities[finding.get("severity", "info")] += 1
            owners[finding.get("owner", "cto")] += 1
            if finding.get("quick_win"):
                summary.quick_wins += 1
            rule_id = finding.get("rule_id", "")
            rule_sites[rule_id].add(domain)
            rule_findings[rule_id] += 1
            rule_severity.setdefault(rule_id, finding.get("severity", "info"))

        for entry in result.get("inventory") or []:
            vendor_id = entry.get("product") or entry.get("vendor_key") or "unknown"
            key = entry.get("vendor_key") or entry.get("product") or "unknown"
            vendor_sites[key].add(domain)
            vendor_meta[key] = (vendor_id, entry.get("transfer", "non_eea"))
            if not entry.get("declared"):
                vendor_undeclared[key].add(domain)

    summary.grades = {grade: grades.get(grade, 0) for grade in _GRADES if grades.get(grade)}
    summary.severity_totals = {s: severities.get(s, 0) for s in _SEVERITIES}
    summary.by_owner = dict(owners.most_common())

    # ranked by how many sites carry it, never by how many findings it produced:
    # one site with five copies must not outrank five sites with one each
    summary.by_rule = sorted(
        (
            RulePrevalence(
                rule_id=rule_id,
                sites=len(sites),
                findings=rule_findings[rule_id],
                severity=rule_severity.get(rule_id, "info"),
                examples=sorted(sites)[:5],
            )
            for rule_id, sites in rule_sites.items()
        ),
        key=lambda r: (-r.sites, r.rule_id),
    )
    summary.by_vendor = sorted(
        (
            VendorPrevalence(
                vendor_id=key,
                product=vendor_meta.get(key, (key, ""))[0],
                sites=len(sites),
                undeclared_on=len(vendor_undeclared.get(key, set())),
                transfer=vendor_meta.get(key, ("", "non_eea"))[1],
                examples=sorted(sites)[:5],
            )
            for key, sites in vendor_sites.items()
        ),
        key=lambda v: (-v.sites, v.vendor_id),
    )
    return summary
