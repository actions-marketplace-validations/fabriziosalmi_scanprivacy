"""Impact-assessment screening and transfer prompts.

The property under test is restraint. A screening that counts criteria it never
observed lets someone conclude "no assessment needed" from evidence that never
covered the question — which is worse than producing no screening at all.
"""

from __future__ import annotations

from pmate.analyze.context import build_context
from pmate.analyze.dpia import CRITERIA, screen, transfer_assessments
from pmate.analyze.engine import evaluate, load_rules
from pmate.observe.browser import CookieSet, Observation, Request


def _page(url: str = "https://x.it/") -> Observation:
    page = Observation(url=url, final_url=url, load_ok=True, status=200)
    page.response_headers = {"content-type": "text/html"}
    return page


def _request(host: str, resource: str = "script") -> Request:
    return Request(f"https://{host}/x", host, "GET", "/x", 200, None, resource, t_ms=10)


# ------------------------------------------------------------- what is seen


def test_the_four_invisible_criteria_are_never_counted_as_met():
    """Scale, vulnerable subjects, special categories and legal effects cannot
    be seen from outside. Counting them — either way — would be a fabrication."""
    page = _page()
    page.requests = [_request("www.googletagmanager.com"), _request("static.hotjar.com")]
    screening = screen(build_context([page]))

    invisible = {key for key, observable in CRITERIA if not observable}
    assert invisible == {"automated_decision", "sensitive_data", "large_scale", "vulnerable_subjects", "prevents_rights"}
    for criterion in screening.criteria:
        if criterion.key in invisible:
            assert criterion.met is False
            assert criterion.observable is False
    assert {c.key for c in screening.not_assessable} == invisible


def test_a_profiling_vendor_meets_the_evaluation_criterion():
    page = _page()
    page.requests = [_request("connect.facebook.net")]
    screening = screen(build_context([page]))
    met = {c.key for c in screening.met}
    assert "evaluation_scoring" in met


def test_a_session_recorder_meets_systematic_monitoring():
    page = _page()
    page.requests = [_request("static.hotjar.com")]
    met = {c.key for c in screen(build_context([page])).met}
    assert "systematic_monitoring" in met


def test_a_tag_manager_meets_matching_and_combining():
    page = _page()
    page.requests = [_request("www.googletagmanager.com")]
    met = {c.key for c in screen(build_context([page])).met}
    assert "matching_combining" in met


def test_an_ai_component_meets_innovative_technology():
    page = _page()
    page.ai_markers = ["ai-chat-widget"]
    met = {c.key for c in screen(build_context([page])).met}
    assert "innovative_technology" in met


def test_a_plain_site_meets_nothing():
    page = _page()
    page.requests = [_request("x.it", "document")]
    screening = screen(build_context([page]))
    assert screening.met == []
    assert screening.threshold_reached is False


# ------------------------------------------------------------- the threshold


def test_the_rule_fires_only_at_two_criteria():
    """The EDPB's own rule of thumb, and the reason the rule is a screening
    rather than a verdict."""
    one = _page()
    one.requests = [_request("static.hotjar.com")]
    assert "PM-DPIA-01" not in {f.rule_id for f in evaluate(build_context([one]), load_rules())}

    two = _page()
    two.requests = [_request("static.hotjar.com"), _request("connect.facebook.net")]
    findings = evaluate(build_context([two]), load_rules())
    dpia = [f for f in findings if f.rule_id == "PM-DPIA-01"]
    assert dpia
    assert dpia[0].confidence.value == "probable"  # never stated as certain


def test_the_finding_names_what_it_could_not_assess():
    """The honest half: a reader must see which questions remain theirs."""
    page = _page()
    page.requests = [_request("static.hotjar.com"), _request("connect.facebook.net")]
    finding = next(
        f for f in evaluate(build_context([page]), load_rules()) if f.rule_id == "PM-DPIA-01"
    )
    assert finding.evidence["criteria_met"]
    assert len(finding.evidence["criteria_not_assessable"]) == 5
    assert all(k.startswith("dpia.criteria.") for k in finding.evidence["criteria_not_assessable"])


def test_the_screening_renders_in_both_languages():
    from pmate.i18n.translator import Translator
    from pmate.report.render import render_finding

    page = _page()
    page.requests = [_request("static.hotjar.com"), _request("connect.facebook.net")]
    finding = next(
        f for f in evaluate(build_context([page]), load_rules()) if f.rule_id == "PM-DPIA-01"
    )
    for locale in ("en", "it"):
        rendered = render_finding(finding, Translator.for_locale(locale, strict=True))
        assert "⟦" not in rendered.description
        labels = [label for label, _ in rendered.evidence]
        assert any("valutabili" in label or "assessable" in label for label in labels)


# --------------------------------------------------------------- transfers


def test_every_non_eea_recipient_gets_a_prompt():
    page = _page()
    page.requests = [_request("fonts.googleapis.com"), _request("login.spid.gov.it", "document")]
    assessments = transfer_assessments(build_context([page]))
    ids = {a.vendor_id for a in assessments}
    assert "google-fonts" in ids
    assert "spid" not in ids  # processed inside the EEA: nothing to assess


def test_a_prompt_carries_the_equivalent_that_removes_the_transfer():
    """The cheapest transfer impact assessment is the transfer you do not make."""
    page = _page()
    page.requests = [_request("www.google-analytics.com")]
    assessment = next(
        a for a in transfer_assessments(build_context([page])) if a.vendor_id == "google-analytics"
    )
    assert assessment.alternatives
    assert assessment.data_types
    assert assessment.declared is False


def test_the_screening_survives_a_round_trip_through_json():
    import json

    from pmate.core.models import scan_from_dict

    from tests.test_integrations import _result  # reuse the built result fixture

    result = _result()
    result.screening = {"dpia": screen(build_context([_page()])).to_dict(), "transfers": []}
    rebuilt = scan_from_dict(json.loads(json.dumps(result.to_dict(), default=str)))
    assert rebuilt.screening["dpia"]["criteria"]


def test_evidence_is_only_shown_for_criteria_actually_met():
    """Signals listed next to a "not met" row read as a finding the engine then
    declines to draw. Silence is the honest option there."""
    page = _page()
    page.requests = [_request("www.paypal.com"), _request("i.ytimg.com", "image")]
    for criterion in screen(build_context([page])).criteria:
        if not criterion.met:
            assert criterion.evidence == [], criterion.key
