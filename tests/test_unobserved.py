"""What the engine may say about a target it never saw.

The register is fail-closed in one direction already: nothing is graded green
unless it was observed to be green. This file pins the other direction, which
is the one that was broken — nothing is graded red unless it was observed to be
red.

The distinction is not academic. A conformance report that lists findings about
a page it never loaded is not a strict report; it is a fabricated one, and a
reader has no way to tell which of the two they are holding.
"""

from __future__ import annotations

from pmate.analyze.context import build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.analyze.verdict import grade
from pmate.core.enums import Grade
from pmate.observe.browser import Observation


def _unreachable() -> Observation:
    """Exactly what the browser produces for a target that never answered."""
    return Observation(url="https://nothing.invalid/", final_url="https://nothing.invalid/",
                       load_ok=False, status=None)


def _loaded() -> Observation:
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {"content-type": "text/html"}
    return obs


def test_an_unobserved_target_produces_no_findings_at_all():
    """Before this guard: `pmate scan not-a-url` reported PM-DOC-01 (critical),
    PM-SEC-01, PM-SEC-02 and PM-SEC-03 with load_ok=False, status=None and zero
    response headers read."""
    findings = evaluate(build_context([_unreachable()]), load_rules())
    assert findings == []


def test_header_rules_in_particular_do_not_fire_without_a_response():
    """These are the ones that read worst: the report said "the page response
    carries no Strict-Transport-Security header" when there was no response."""
    fired = {f.rule_id for f in evaluate(build_context([_unreachable()]), load_rules())}
    assert not {"PM-SEC-01", "PM-SEC-02", "PM-SEC-03"} & fired


def test_the_documentary_rule_does_not_fire_either():
    """Not finding a privacy notice on a page that never loaded says nothing
    about whether the site publishes one."""
    fired = {f.rule_id for f in evaluate(build_context([_unreachable()]), load_rules())}
    assert "PM-DOC-01" not in fired


def test_silence_is_not_read_as_conformance():
    """The point of returning nothing is that the verdict carries the meaning.
    An empty finding set from an unreachable target must not grade as clean —
    that would trade a fabricated report for a falsely reassuring one."""
    verdict = grade([], observed_ok=False)
    assert verdict.grade is Grade.INCONCLUSIVE
    assert verdict.conformant is False

    # and the same empty set, when the page *was* observed, is a real pass
    assert grade([], observed_ok=True).conformant is True


def test_an_observed_page_still_produces_its_findings():
    """The guard must not silence real observation: a page that loaded and
    genuinely lacks the headers still says so."""
    fired = {f.rule_id for f in evaluate(build_context([_loaded()]), load_rules())}
    assert {"PM-SEC-01", "PM-SEC-02", "PM-SEC-03"} <= fired


# ------------------------------------------------- a broken rule is visible


def test_a_predicate_that_raises_does_not_fire_but_does_warn(caplog):
    """Not firing is right — an engine that cannot evaluate a rule must not
    assert anything. Doing it silently is not: the only visible consequence
    would be a finding that quietly stops appearing, and the report reads as
    clean. That is this project's recurring failure mode."""
    import logging

    from pmate.analyze import predicates
    from pmate.analyze.subjects import Subject
    from pmate.core.enums import SubjectKind

    def explode(ctx, subject, arg):
        raise RuntimeError("knowledge base out of shape")

    predicates.REGISTRY["_test_explodes"] = explode
    subject = Subject(kind=SubjectKind.SITE, slug="site", node_id="site")
    try:
        with caplog.at_level(logging.WARNING, logger="pmate.rules"):
            fired = predicates.evaluate_condition(
                build_context([_loaded()]), subject, {"_test_explodes": True}
            )
        assert fired is False
        assert "_test_explodes" in caplog.text
    finally:
        predicates.REGISTRY.pop("_test_explodes", None)


def test_an_unknown_predicate_warns_as_well(caplog):
    """A rule referring to a predicate this build does not have is a rule that
    silently covers nothing."""
    import logging

    from pmate.analyze import predicates
    from pmate.analyze.subjects import Subject
    from pmate.core.enums import SubjectKind

    subject = Subject(kind=SubjectKind.SITE, slug="site", node_id="site")
    with caplog.at_level(logging.WARNING, logger="pmate.rules"):
        assert predicates.evaluate_condition(
            build_context([_loaded()]), subject, {"no_such_predicate": True}
        ) is False
    assert "no_such_predicate" in caplog.text
