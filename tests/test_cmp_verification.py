"""How far the refusal path used has actually been proven.

The catalogue in `knowledge/consent.yml` holds nine consent platforms. One —
Cookiebot — has been exercised against a real installation and observed to do
what the vendor describes. The other eight were transcribed from vendor
documentation and never run: iubenda's production build did not expose
`_iub.cs.api.reject` at all, which is how this was noticed.

That difference matters because of what the refusal findings say. "This service
kept running after the visitor refused" is a fact if the refusal happened. When
the path is only documented, the call may exist, return cleanly, and do
nothing — and from outside the page that is indistinguishable from a site that
ignored the refusal. Stating it as `certain` puts an accusation on a premise
nobody has checked.

So the report says which kind of path was used, and findings built on an
unproven one are indications rather than facts.
"""

from __future__ import annotations

import pytest
import yaml

from scanprivacy.config import KNOWLEDGE_DIR
from scanprivacy.core.enums import Confidence
from scanprivacy.i18n import Translator
from scanprivacy.observe.consent import RefusalAttempt, load_catalogue

CATALOGUE = KNOWLEDGE_DIR / "consent.yml"
LEVELS = {"documented", "field_verified"}


# ------------------------------------------------------------- the catalogue


def test_every_platform_declares_how_far_it_is_proven():
    for platform in load_catalogue():
        assert platform.verification in LEVELS, (
            f"{platform.id} declares {platform.verification!r}"
        )


def test_an_entry_that_forgets_to_say_understates_rather_than_overstates():
    """A platform added without thinking about this must not silently claim to
    be verified."""
    raw = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    entry = dict(raw["platforms"][0])
    entry.pop("verification", None)
    from scanprivacy.observe.consent import ConsentPlatform

    made = ConsentPlatform(
        id=entry["id"],
        name=entry["name"],
        detect=entry["detect"],
        method=entry["method"],
        documentation=entry["documentation"],
    )
    assert made.verification == "documented"


def test_the_claim_matches_what_the_tests_actually_exercise():
    """The one entry marked field-verified is the one with a fixture proving it.

    If a second platform gets a fixture, this fails and asks for the catalogue
    to be updated — which is the point. A claim of verification that nothing
    verifies is exactly the kind of assertion this engine exists to refuse.
    """
    verified = {p.id for p in load_catalogue() if p.verification == "field_verified"}
    assert verified == {"cookiebot"}, (
        f"{verified} claim field verification; only cookiebot has a fixture proving it"
    )


# -------------------------------------------------------------- the finding


def _attempt(verification: str) -> RefusalAttempt:
    return RefusalAttempt(outcome="refused", platform_id="x", verification=verification)


def test_a_proven_path_supports_a_fact():
    assert _attempt("field_verified").path_proven is True


def test_an_unproven_path_does_not():
    assert _attempt("documented").path_proven is False
    assert _attempt("").path_proven is False


def test_refusal_findings_are_stated_as_indications_on_an_unproven_path():
    from scanprivacy.analyze.engine import _confidence, load_rules

    class _Ctx:
        refusal = _attempt("documented")

    rules = [r for r in load_rules(pass_="refusal") if r.confidence is Confidence.CERTAIN]
    assert rules, "no refusal rule claims certainty — this test would pass vacuously"
    for rule in rules:
        assert _confidence(rule, _Ctx()) is Confidence.PROBABLE, rule.id


def test_a_proven_path_keeps_the_rules_own_confidence():
    from scanprivacy.analyze.engine import _confidence, load_rules

    class _Ctx:
        refusal = _attempt("field_verified")

    for rule in load_rules(pass_="refusal"):
        assert _confidence(rule, _Ctx()) is rule.confidence, rule.id


def test_the_passive_pass_is_untouched():
    """Nothing about a documented refusal path weakens what was directly
    observed on an ordinary scan."""
    from scanprivacy.analyze.engine import _confidence, load_rules

    class _Ctx:
        refusal = _attempt("documented")

    passive = [r for r in load_rules() if r.pass_ != "refusal"]
    assert passive
    for rule in passive:
        assert _confidence(rule, _Ctx()) is rule.confidence, rule.id


# --------------------------------------------------------------- the reading


@pytest.mark.parametrize("lang", ["en", "it"])
def test_the_reader_is_told_in_their_own_language(lang: str):
    t = Translator.for_locale(lang)
    assert t.t("consent_pass.labels.verification")
    for level in LEVELS:
        text = t.t(f"consent_pass.verification.{level}")
        assert "⟦" not in text, f"[{lang}] {level} has no translation"
    documented = t.t("consent_pass.verification.documented")
    assert len(documented) > 120, (
        f"[{lang}] the weaker claim has to explain itself, not just be labelled"
    )
