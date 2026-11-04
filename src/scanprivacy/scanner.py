"""Orchestration: URL in, ScanResult out.

    observe -> read the site's own documents -> TLS -> facts -> rules ->
    graph -> verdict -> reproducibility record

Everything is passive. The engine never submits a form, never authenticates,
never repeats a request to force an error, and honours robots.txt for every URL
it fetches itself. The result it returns carries no sentences: it is the same
object whatever language the report will eventually be written in.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from playwright.async_api import async_playwright

from .analyze.context import build_context
from .analyze.dpia import screen, transfer_assessments
from .analyze.engine import evaluate, load_rules
from .analyze.graph import build_graph
from .analyze.verdict import grade
from .config import DEFAULTS, UA, UA_FALLBACK, Settings
from .core.enums import ScanStatus
from .core.models import ScanResult
from .observe.browser import obs_to_dict, observe_url, launch_browser
from .observe.discover import fallback_candidates, linked_why, pick_documents
from .observe.docs import doc_to_dict, fetch_document, fetch_documents
from .observe.consent import run_refusal_pass
from .observe.pages import select_pages, sibling_hosts
from .observe.egress import EgressProxy
from .observe.rate import PerHostLimiter
from .observe.robots import RobotsCache
from .observe.tls import probe, tls_to_dict
from .report.record import build_record

DOCUMENT_PRIORITY = ("privacy", "cookie", "terms", "accessibility")

# The method, as keys: the report states it in the reader's language.
POSTURE_KEYS = (
    "report.posture.method",
    "report.posture.pages",
    "report.posture.interaction",
    "report.posture.consent",
    "report.posture.extra_requests",
    "report.posture.intrusive_tests",
    "report.posture.robots",
)


async def _collect_documents(browser, obs, robots, settings, limiter) -> list:
    """Scored link selection, then conventional paths for what is still missing.

    The fallback matters: claiming "no privacy notice" because the footer link
    was worded unusually would be the worst error this engine can make.
    """
    candidates = pick_documents(obs, DOCUMENT_PRIORITY)
    picked = [(c.kind, c.url, linked_why(c)) for c in candidates]

    documents = []
    if picked:
        allowed = [
            (kind, url, why)
            for kind, url, why in picked
            if not settings.respect_robots or await robots.allowed(url)
        ]
        documents = await fetch_documents(browser, allowed, settings, limiter=limiter)

    still_missing = [k for k in ("privacy", "cookie") if not any(d.kind == k and d.ok for d in documents)]
    for kind in still_missing:
        for candidate in fallback_candidates(obs.final_url or obs.url, kind):
            if settings.respect_robots and not await robots.allowed(candidate.url):
                continue
            evidence = await fetch_document(
                browser, candidate.url, kind, settings, discovery=candidate.why, limiter=limiter
            )
            documents.append(evidence)
            if evidence.ok:
                break
    return documents


def _grade_evaluated(findings, observed_ok: bool, ctx) -> Any:
    """Grade, unless a rule could not be evaluated.

    A predicate that raised means some rule did not run. Reporting the grade the
    remaining rules give would read as a clean result for a check that never
    happened, so the verdict is INCONCLUSIVE and says why.
    """
    if observed_ok and ctx.rule_errors:
        return grade(
            findings,
            observed_ok=False,
            note_key="verdict.rule_error_note",
            blocking_key="verdict.rule_error_blocking",
        )
    return grade(findings, observed_ok=observed_ok)


async def scan(
    url: str,
    settings: Settings = DEFAULTS,
    scan_id: str | None = None,
    read_documents: bool = True,
    context: dict[str, Any] | None = None,
    limiter: PerHostLimiter | None = None,
) -> ScanResult:
    """`limiter` is shared across a fleet run: forty targets on one host must
    share one budget, or the courtesy the method promises is not kept.

    With `settings.guard_requests` (the API), every connection the scan makes
    goes through a local proxy that refuses non-public addresses; see
    `observe/egress.py`."""
    egress = await EgressProxy().start() if settings.guard_requests else None
    try:
        return await _scan(url, settings, scan_id, read_documents, context, limiter, egress)
    finally:
        if egress is not None:
            await egress.stop()


def _launch_options(egress: EgressProxy | None) -> dict[str, Any]:
    return {"proxy": egress.playwright_proxy()} if egress is not None else {}


async def _scan(
    url: str,
    settings: Settings,
    scan_id: str | None,
    read_documents: bool,
    context: dict[str, Any] | None,
    limiter: PerHostLimiter | None,
    egress: EgressProxy | None,
) -> ScanResult:
    scan_id = scan_id or uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc).isoformat()
    result = ScanResult(
        scan_id=scan_id,
        url=url,
        final_url=url,
        started_at=started,
        finished_at=started,
        status=ScanStatus.ERROR,
        context=context or {},
    )

    robots = RobotsCache(proxy=egress.url if egress is not None else None)
    if settings.respect_robots and not await robots.allowed(url):
        result.status = ScanStatus.ROBOTS_SKIP
        result.error = "verdict.robots_skip"
        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.verdict = grade([], observed_ok=False, note_key="verdict.robots_skip")
        return result

    limiter = limiter or PerHostLimiter(settings.per_host_rps)
    browser_version: str | None = None
    # The report states the identity that actually reached the site, not the one
    # we set out to use. If the fallback below is enabled and fires, this is what
    # changes; reporting `UA` regardless would describe a request we never made.
    ua_used = UA
    async with async_playwright() as pw:
        browser = await launch_browser(pw, **_launch_options(egress))
        browser._scanprivacy_egress = egress
        browser_version = f"Chromium {browser.version}"
        try:
            await limiter.wait(urlsplit(url).netloc)
            entry = await observe_url(browser, url, settings)
            if not entry.load_ok and entry.error and settings.ua_fallback_on_block:
                # Some WAFs reject an unusual UA outright. One retry with a plain
                # browser string: we are a browser, we just say so differently.
                # Opt-in, because the retry drops the contact address the site
                # owner would need in order to object — and whether that trade is
                # acceptable is the operator's call, not this function's.
                await limiter.wait(urlsplit(url).netloc)
                retried = await observe_url(browser, url, settings, user_agent=UA_FALLBACK)
                if retried.load_ok:
                    entry, ua_used = retried, UA_FALLBACK

            pages = [entry]
            page_plan: list[dict[str, Any]] = [
                {"url": entry.final_url or entry.url, "kind": "entry", "why": "page_choice.entry"}
            ]
            if entry.load_ok and settings.max_pages > 1:
                for candidate in select_pages(entry, settings.max_pages - 1):
                    if settings.respect_robots and not await robots.allowed(candidate.url):
                        page_plan.append(
                            {"url": candidate.url, "kind": candidate.kind, "why": "page_choice.robots_skip"}
                        )
                        continue
                    await limiter.wait(urlsplit(candidate.url).netloc)
                    page = await observe_url(browser, candidate.url, settings)
                    pages.append(page)
                    page_plan.append(
                        {"url": candidate.url, "kind": candidate.kind, "why": candidate.why}
                    )

                # Same organisation, different deployment. Not visiting them is
                # the correction — findings from `api.example.org` reported under
                # `www.example.org` send the reader to the wrong codebase — but
                # a reader has to be told the surface exists, or the omission is
                # invisible and looks like coverage.
                for sibling in sibling_hosts(entry):
                    page_plan.append(
                        {
                            "url": sibling,
                            "kind": "other",
                            "why": "page_choice.other_host",
                        }
                    )

            obs = entry
            documents = []
            if entry.load_ok and read_documents:
                documents = await _collect_documents(browser, entry, robots, settings, limiter)
        finally:
            await browser.close()

    tls = None
    host = obs.host or urlsplit(url).netloc
    if host and (obs.final_url or url).startswith("https"):
        tls = await probe(host, guarded=settings.guard_requests)

    ctx = build_context(pages, documents, tls)
    findings = evaluate(ctx, load_rules())

    result.final_url = obs.final_url
    result.status = ScanStatus.OK if obs.load_ok else ScanStatus.UNREACHABLE
    result.error = obs.error
    result.site = {
        "host": ctx.site_host,
        "domain": ctx.site_domain,
        "title": obs.title,
        "lang": obs.lang,
        "platform": ctx.platform_name,
        "platform_id": ctx.platform_id,
        "cmp": ctx.cmp_detected,
        "third_parties": len(ctx.third_party_vendors),
        "cookies": len(ctx.cookies),
        "storage": len(ctx.storage),
        "pages_observed": len(ctx.observed_pages),
        "pages_planned": len(page_plan),
        "documents_read": [d.kind for d in documents if d.ok],
    }
    result.findings = findings
    result.graph = build_graph(ctx, findings)
    result.verdict = _grade_evaluated(findings, obs.load_ok, ctx)
    result.observation = {
        **({"rule_errors": sorted(set(ctx.rule_errors))} if ctx.rule_errors else {}),
        **({"blocked_requests": list(egress.blocked)} if egress is not None and egress.blocked else {}),
        # the entry page keeps its own key: header, TLS and document evidence
        # all describe the origin, and consumers built against the single-page
        # shape keep working
        "browser": obs_to_dict(entry),
        "pages": [
            {
                **{k: v for k, v in obs_to_dict(page).items() if k != "html"},
                "kind": plan["kind"],
                "selected_because": plan["why"],
            }
            for page, plan in zip(pages, page_plan)
        ],
        "page_plan": page_plan,
        "documents": [doc_to_dict(d) for d in documents],
        "tls": tls_to_dict(tls) if tls else None,
    }
    result.inventory = [
        {
            "vendor": fact.vendor.vendor,
            "vendor_key": fact.vendor.vendor_key,
            "product": fact.vendor.product,
            "category": fact.vendor.category,
            "jurisdiction": fact.vendor.jurisdiction,
            "hosts": fact.hosts,
            "detected_via": fact.detection,
            "transfer": fact.transfer,
            "transfer_basis": fact.vendor.transfer_basis,
            "consent_class": fact.vendor.consent_class,
            "storage_access": fact.vendor.storage_access,
            "data_types": list(fact.vendor.data_types),
            "declared": fact.declared,
            "declared_in": fact.declared_in,
        }
        for fact in sorted(
            ctx.third_party_vendors, key=lambda f: (f.transfer.value == "eea", f.vendor.id)
        )
    ]
    result.screening = {
        "dpia": screen(ctx).to_dict(),
        "transfers": [asdict(entry) for entry in transfer_assessments(ctx)],
    }
    result.record = build_record(
        url=url,
        observation=result.observation,
        settings=settings,
        user_agent=ua_used,
        browser_version=browser_version,
        findings=result.to_dict()["findings"],
    )
    result.record["posture"] = {
        "keys": list(POSTURE_KEYS),
        "user_agent": ua_used,
        "pages": [p["url"] for p in page_plan],
        "max_pages": settings.max_pages,
        "per_host_rps": settings.per_host_rps,
    }
    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result



# The refusal pass is a separate mode with a separate method and a separate
# document. The passive scan above is untouched by it, and its report does not
# gain a word: the two answer different questions, and mixing them would make
# both weaker.
REFUSAL_POSTURE_KEYS = (
    "consent_pass.posture.method_refusal",
    "consent_pass.posture.interaction_refusal",
    "consent_pass.posture.platform_limit",
    "report.posture.extra_requests",
    "report.posture.intrusive_tests",
    "report.posture.robots",
    "consent_pass.posture.meaning",
)


async def refusal_scan(
    url: str,
    settings: Settings = DEFAULTS,
    scan_id: str | None = None,
    context: dict[str, Any] | None = None,
) -> ScanResult:
    """Observe, refuse through a documented path, reload, compare.

    Only the refusal rule set is evaluated. A passive finding has no business in
    this document: it was already produced by the passive scan, against a method
    that never touched the page.
    """
    scan_id = scan_id or uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc).isoformat()
    result = ScanResult(
        scan_id=scan_id,
        url=url,
        final_url=url,
        started_at=started,
        finished_at=started,
        status=ScanStatus.ERROR,
        context={**(context or {}), "mode": "refusal_pass"},
    )

    robots = RobotsCache()
    if settings.respect_robots and not await robots.allowed(url):
        result.status = ScanStatus.ROBOTS_SKIP
        result.error = "verdict.robots_skip"
        result.finished_at = datetime.now(timezone.utc).isoformat()
        result.verdict = grade([], observed_ok=False, note_key="verdict.robots_skip")
        return result

    browser_version: str | None = None
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        browser_version = f"Chromium {browser.version}"
        try:
            consent_pass = await run_refusal_pass(
                browser, url, settings, limiter=PerHostLimiter(settings.per_host_rps)
            )
        finally:
            await browser.close()

    before = consent_pass.before
    after = consent_pass.after or before

    tls = None
    host = before.host or urlsplit(url).netloc
    if host and (before.final_url or url).startswith("https"):
        tls = await probe(host)

    # facts are read from the state *after* the refusal; the state before is
    # attached so a finding can say a vendor was there and survived
    ctx = build_context([after], [], tls)
    ctx.refusal = consent_pass.attempt
    ctx.before = build_context([before], [], tls)

    findings = evaluate(ctx, load_rules(pass_="refusal"))

    result.final_url = before.final_url
    result.status = ScanStatus.OK if before.load_ok else ScanStatus.UNREACHABLE
    result.error = before.error
    result.site = {
        "host": ctx.site_host,
        "domain": ctx.site_domain,
        "title": before.title,
        "lang": before.lang,
        "platform": ctx.platform_name,
        "cmp": ctx.before.cmp_detected,
        "third_parties": len(ctx.third_party_vendors),
        "cookies": len(ctx.cookies),
        "storage": len(ctx.storage),
        "third_parties_before": len(ctx.before.third_party_vendors),
        "cookies_before": len(ctx.before.cookies),
        "storage_before": len(ctx.before.storage),
        "documents_read": [],
    }
    result.findings = findings
    result.graph = build_graph(ctx, findings)
    # Fail-closed, applied to this pass's own question.
    #
    # A refusal pass asks one thing: what survives when the visitor says no. If
    # no refusal happened — no mechanism found, the platform unrecognised, the
    # control ambiguous, the documented call failed — that question has no
    # answer, and zero findings is what "we never asked" looks like. Grading it
    # A meant handing out a clean verdict for something never observed, in the
    # mode built to be the strictest thing this engine does.
    #
    # The passive scan still covers a site with no consent mechanism, through
    # PM-CNS-02. This pass declines to pretend it measured something.
    refusal_happened = consent_pass.attempt.performed
    if before.load_ok and refusal_happened:
        result.verdict = _grade_evaluated(findings, True, ctx)
    else:
        result.verdict = grade(
            findings,
            observed_ok=False,
            note_key=f"consent_pass.outcome.{consent_pass.attempt.outcome}",
        )
    result.observation = {
        "browser": obs_to_dict(after),
        "consent_pass": consent_pass.to_dict(),
        "documents": [],
        "tls": tls_to_dict(tls) if tls else None,
    }
    result.inventory = [
        {
            "vendor": fact.vendor.vendor,
            "vendor_key": fact.vendor.vendor_key,
            "product": fact.vendor.product,
            "category": fact.vendor.category,
            "jurisdiction": fact.vendor.jurisdiction,
            "hosts": fact.hosts,
            "detected_via": fact.detection,
            "transfer": fact.transfer,
            "transfer_basis": fact.vendor.transfer_basis,
            "consent_class": fact.vendor.consent_class,
            "storage_access": fact.vendor.storage_access,
            "data_types": list(fact.vendor.data_types),
            "declared": fact.declared,
            "declared_in": fact.declared_in,
        }
        for fact in sorted(ctx.third_party_vendors, key=lambda f: f.vendor.id)
    ]
    result.record = build_record(
        url=url,
        observation=result.observation,
        settings=settings,
        user_agent=UA,
        browser_version=browser_version,
        findings=result.to_dict()["findings"],
    )
    result.record["posture"] = {
        "keys": list(REFUSAL_POSTURE_KEYS),
        "user_agent": UA,
        "refusal": asdict(consent_pass.attempt),
    }
    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result
