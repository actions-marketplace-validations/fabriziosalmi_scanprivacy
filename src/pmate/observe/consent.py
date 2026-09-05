"""The refusal pass: what a site does after the visitor says no.

This is the one part of the engine that touches the page. Everything else
observes a visitor who has not decided; here the engine exercises a choice the
site itself offers, and then looks at whether the site honoured it.

Why refusal and not acceptance. What happens after "Accept" is roughly what
everyone expects to happen. What happens after "Reject" is where the banner
turns out to be theatre, and it is the one thing passive observation can never
see: before any choice, "tracking is running" and "tracking is running because
consent was ignored" look identical.

The rules this module works to, in order:

1. **Never guess.** Only platforms in `knowledge/consent.yml`, only through the
   refusal path their own vendor documents. No searching for a button whose
   text resembles "Reject", no clicking the second control in a banner, no
   trying three things until one works. Clicking blindly on somebody else's
   site is how a scanner empties a cart or logs a user out.
2. **One action.** One documented call or one click on one unambiguous element.
   No retries, no fallbacks, no navigation.
3. **Say exactly what was done.** The platform, the method, the verbatim
   expression and the vendor's documentation URL all reach the report. A reader
   must be able to confirm we used the supported path.
4. **An unrecognised platform is a result, not a failure to hide.** The report
   states that a consent mechanism was present and that this engine did not
   interact with it, and why.
"""

from __future__ import annotations

import logging

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..config import DEFAULTS, KNOWLEDGE_DIR, UA, Settings
from .browser import Observation, new_context, observe_in_context

logger = logging.getLogger("pmate.consent")

CATALOGUE = KNOWLEDGE_DIR / "consent.yml"

# Outcomes, as canonical values: the report renders them in the reader's tongue.
NOT_ATTEMPTED_NO_CMP = "no_consent_mechanism"
NOT_ATTEMPTED_UNKNOWN = "platform_not_recognised"
NOT_ATTEMPTED_NOT_READY = "platform_not_ready"
NOT_ATTEMPTED_AMBIGUOUS = "control_ambiguous"
REFUSED = "refused"
FAILED = "refusal_failed"


@dataclass(frozen=True, slots=True)
class ConsentPlatform:
    id: str
    name: str
    detect: str
    method: str  # api | dom
    documentation: str
    expression: str = ""
    selector: str = ""
    note: str = ""
    verification: str = "documented"
    """`field_verified` when this exact path has been exercised against a real
    installation, `documented` when it was transcribed from the vendor's
    documentation and never run.

    Defaults to the weaker claim: a catalogue entry added without thinking
    about this should understate what we know, not overstate it."""


def load_catalogue(path: Path = CATALOGUE) -> list[ConsentPlatform]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [
        ConsentPlatform(
            id=entry["id"],
            name=entry["name"],
            detect=entry["detect"],
            method=entry["method"],
            documentation=entry["documentation"],
            expression=entry.get("expression", ""),
            selector=entry.get("selector", ""),
            note=entry.get("note", ""),
            verification=entry.get("verification", "documented"),
        )
        for entry in raw.get("platforms", [])
    ]


@dataclass(slots=True)
class RefusalAttempt:
    """Exactly what the engine did, for the record."""

    outcome: str
    platform_id: str | None = None
    platform_name: str | None = None
    method: str | None = None
    action: str = ""  # the verbatim expression or selector
    documentation: str | None = None
    note: str = ""
    verification: str = ""
    """How well the path used is known to work — carried through to the report,
    because a refusal made through an unproven path cannot support a finding
    stated as a fact."""
    detail: str = ""
    detected_markers: list[str] = field(default_factory=list)

    @property
    def performed(self) -> bool:
        return self.outcome == REFUSED

    @property
    def path_proven(self) -> bool:
        """Has this refusal path actually been observed to work?

        A documented call may exist, return cleanly and do nothing at all; from
        outside the page there is no way to tell that apart from a refusal the
        site then ignored. Findings built on it are indications, not facts."""
        return self.verification == "field_verified"


@dataclass(slots=True)
class ConsentPass:
    before: Observation
    after: Observation | None
    attempt: RefusalAttempt

    def to_dict(self) -> dict[str, Any]:
        from .browser import obs_to_dict

        return {
            "attempt": asdict(self.attempt),
            "before": obs_to_dict(self.before),
            "after": obs_to_dict(self.after) if self.after else None,
        }


async def _identify(page, platforms: list[ConsentPlatform]) -> ConsentPlatform | None:
    """The first platform whose own readiness expression says it is ready.

    Readiness, not mere presence: a platform whose script has loaded but whose
    API is not yet attached would swallow the call silently, and the report
    would claim a refusal that never happened.
    """
    for platform in platforms:
        try:
            if await page.evaluate(f"() => !!({platform.detect})"):
                return platform
        except Exception:
            # A detection expression that raises is our defect, not the site's.
            # Left silent, the run reports "platform not recognised" about a
            # site running a platform we do claim to support, and the entry in
            # consent.yml looks correct forever.
            logger.exception("detection expression for %s raised", platform.id)
            continue
    return None


async def refuse(page, platform: ConsentPlatform) -> RefusalAttempt:
    base = RefusalAttempt(
        outcome=FAILED,
        platform_id=platform.id,
        platform_name=platform.name,
        method=platform.method,
        documentation=platform.documentation,
        note=platform.note,
        verification=platform.verification,
    )

    if platform.method == "api":
        base.action = platform.expression
        try:
            await page.evaluate(f"() => {{ {platform.expression}; }}")
        except Exception as exc:
            base.detail = f"{type(exc).__name__}: {exc}"[:300]
            return base
        base.outcome = REFUSED
        return base

    if platform.method == "dom":
        base.action = platform.selector
        try:
            elements = await page.query_selector_all(platform.selector)
            visible = [element for element in elements if await element.is_visible()]
        except Exception as exc:
            base.detail = f"{type(exc).__name__}: {exc}"[:300]
            return base
        if len(visible) != 1:
            # Ambiguity is a stop condition, not something to resolve by
            # picking the first match: the wrong control on somebody else's
            # site can do anything.
            base.outcome = NOT_ATTEMPTED_AMBIGUOUS
            base.detail = f"{len(visible)} visible elements match the documented selector"
            return base
        try:
            await visible[0].click(timeout=5000)
        except Exception as exc:
            base.detail = f"{type(exc).__name__}: {exc}"[:300]
            return base
        base.outcome = REFUSED
        return base

    base.detail = f"unsupported method: {platform.method}"
    return base


async def run_refusal_pass(
    browser,
    url: str,
    settings: Settings = DEFAULTS,
    user_agent: str | None = None,
) -> ConsentPass:
    """Observe, refuse, reload in the same context, observe again.

    The reload matters: most platforms apply a refusal to the *next* page load.
    Re-observing without it would measure the scripts that were already running,
    not the ones the site chooses to run for someone who said no.
    """
    platforms = load_catalogue()
    context = await new_context(browser, user_agent or UA)
    try:
        before = await observe_in_context(context, url, settings)
        markers = list(before.cmp_detected) + (["TCF API"] if before.tcf_api_present else [])

        if not before.load_ok:
            return ConsentPass(before, None, RefusalAttempt(outcome=NOT_ATTEMPTED_NO_CMP, detail="page not loaded"))
        if not markers:
            return ConsentPass(
                before, None, RefusalAttempt(outcome=NOT_ATTEMPTED_NO_CMP, detected_markers=markers)
            )

        page = await context.new_page()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=settings.nav_timeout_ms)
            await page.wait_for_timeout(settings.wait_after_load_ms)
            platform = await _identify(page, platforms)
            if platform is None:
                attempt = RefusalAttempt(
                    outcome=NOT_ATTEMPTED_UNKNOWN,
                    detected_markers=markers,
                    detail="a consent mechanism is present but no documented refusal path is known for it",
                )
                return ConsentPass(before, None, attempt)
            attempt = await refuse(page, platform)
            attempt.detected_markers = markers
        finally:
            await page.close()

        if not attempt.performed:
            return ConsentPass(before, None, attempt)

        # the choice must survive a reload, or it was not a choice
        after = await observe_in_context(context, url, settings)
        return ConsentPass(before, after, attempt)
    finally:
        await context.close()
