"""A finding that can never be closed teaches people to ignore findings.

GitHub Pages serves a fixed set of response headers and provides no way to add
one. `PM-SEC-01` (HSTS) is therefore *true* on every site hosted there and
simultaneously impossible to act on, and the report used to state the first half
and not the second — sending the reader to look for a setting the platform does
not have, and leaving a finding open forever.

The correction is narrow on purpose. The finding stays, because the exposure is
real and suppressing it would be the fail-closed posture inverted. What changes
is that the report says why it cannot be closed here and gives a fix that can
actually be performed. And it applies only to rules a response header alone can
satisfy: CSP and Referrer-Policy have a `<meta>` equivalent that works fine on
GitHub Pages, so excusing those would excuse a real, fixable finding.
"""

from __future__ import annotations

from pmate.analyze.context import build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.i18n import Translator
from pmate.knowledge.registry import vendor_for
from pmate.observe.browser import Observation
from pmate.report.render import render_finding

GITHUB_PAGES_HEADERS = {
    "content-type": "text/html",
    "server": "GitHub.com",
    "x-github-request-id": "AAAA:BBBB:CCCC",
}


def _site(headers: dict[str, str], **meta: str) -> Observation:
    obs = Observation(
        url="https://example.github.io/",
        final_url="https://example.github.io/",
        load_ok=True,
        status=200,
    )
    obs.response_headers = dict(headers)
    for key, value in meta.items():
        setattr(obs, key, value)
    return obs


def _finding(ctx, rule_id: str):
    return next((f for f in evaluate(ctx, load_rules()) if f.rule_id == rule_id), None)


# ------------------------------------------------------------ the vendor fact


def test_the_constraint_is_a_fact_about_the_vendor_not_a_literal_in_the_engine():
    """It belongs in vendors.yml because it changes when GitHub changes, not
    when the analysis code does."""
    assert vendor_for("example.github.io").response_headers_fixed is True
    assert vendor_for("www.cloudflare.com").response_headers_fixed is False


def test_the_platform_is_recognised_from_its_response_headers():
    ctx = build_context([_site(GITHUB_PAGES_HEADERS)])
    assert ctx.fixed_header_platform == "github-pages"
    assert ctx.headers_configurable is False


def test_ordinary_hosting_carries_no_constraint():
    ctx = build_context([_site({"content-type": "text/html", "server": "nginx"})])
    assert ctx.fixed_header_platform is None
    assert ctx.headers_configurable is True


# --------------------------------------------------------------- the finding


def test_the_hsts_finding_still_fires_on_a_platform_that_cannot_fix_it():
    """The half that was already right, and must stay right. Suppressing a true
    finding because it is inconvenient to close is fail-closed inverted."""
    assert _finding(build_context([_site(GITHUB_PAGES_HEADERS)]), "PM-SEC-01") is not None


def test_the_finding_says_why_it_cannot_be_closed_here():
    finding = _finding(build_context([_site(GITHUB_PAGES_HEADERS)]), "PM-SEC-01")
    assert finding.evidence.get("platform_constraint") == (
        "constraint.response_headers_fixed.github-pages"
    )


def test_the_same_finding_elsewhere_carries_no_excuse():
    ctx = build_context([_site({"content-type": "text/html", "server": "nginx"})])
    finding = _finding(ctx, "PM-SEC-01")
    assert finding is not None
    assert "platform_constraint" not in finding.evidence


def test_a_rule_with_a_meta_equivalent_is_not_excused():
    """CSP and Referrer-Policy can both be set from the document, which works
    on GitHub Pages. Attaching the constraint to those would tell a reader that
    a fixable finding is unfixable."""
    ctx = build_context([_site(GITHUB_PAGES_HEADERS)])
    for rule_id in ("PM-SEC-02", "PM-SEC-03"):
        finding = _finding(ctx, rule_id)
        assert finding is not None, f"{rule_id} did not fire"
        assert "platform_constraint" not in finding.evidence, (
            f"{rule_id} is satisfiable with a <meta> element on this platform"
        )


# --------------------------------------------------------------- the reading


def test_the_reader_is_told_before_the_steps_they_cannot_follow():
    """Appended, this arrives after three instructions about a setting that does
    not exist — by which point the reader has already gone looking for it."""
    for lang in ("en", "it"):
        finding = _finding(build_context([_site(GITHUB_PAGES_HEADERS)]), "PM-SEC-01")
        rendered = render_finding(finding, Translator.for_locale(lang))

        assert rendered.remediation.steps, f"[{lang}] no remediation steps at all"
        first = rendered.remediation.steps[0]
        assert "GitHub Pages" in first, f"[{lang}] the constraint is not the first thing said"
        assert not first.startswith("constraint."), f"[{lang}] the key was not translated"

        labels = dict(rendered.evidence)
        assert any("GitHub Pages" in str(v) for v in labels.values()), (
            f"[{lang}] the evidence still shows an untranslated key"
        )


def test_the_constraint_names_a_fix_that_can_actually_be_performed():
    finding = _finding(build_context([_site(GITHUB_PAGES_HEADERS)]), "PM-SEC-01")
    rendered = render_finding(finding, Translator.for_locale("en"))
    first = rendered.remediation.steps[0]
    assert "CDN" in first or "proxy" in first, (
        "stating the constraint without naming a way out leaves the reader where they were"
    )
