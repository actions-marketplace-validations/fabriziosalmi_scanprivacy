"""A read that did not complete is not a thing that was not there.

Fourteen handlers in the observation layer used to convert a failed probe into
the value that means "nothing found": an empty storage list, no forms, no
iframes, `tcf_api_present = False`. Every rule downstream then read that as an
observation, and the report presented it as one.

This is the same defect as the `<meta>` CSP regression — an invalid selector
swallowed by `except Exception`, reported as 39 sites with no policy — stated
as a property rather than fixed at one call site.
"""

from __future__ import annotations

from pmate.core.models import ScanResult
from pmate.core.enums import ScanStatus
from pmate.i18n.translator import Translator
from pmate.observe.browser import Observation
from pmate.report.markdown import render


def _observation() -> Observation:
    return Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)


def test_a_failed_probe_is_recorded_with_its_cause():
    obs = _observation()
    obs.probe_failed("web_storage", TimeoutError("navigation timeout"))
    assert obs.probe_failures == ["web_storage: TimeoutError"]


def test_the_consent_framework_probe_has_three_states_not_two():
    """`False` is a claim about the site. A probe that threw makes no claim,
    and the difference decides whether a finding is honest."""
    assert _observation().tcf_api_present is None  # not established

    seen = _observation()
    seen.tcf_api_present = True
    assert seen.tcf_api_present is True

    absent = _observation()
    absent.tcf_api_present = False  # observed, and genuinely not there
    assert absent.tcf_api_present is False


def test_an_incomplete_observation_says_so_in_the_report():
    """Recording the failure and not showing it would fix nothing: the reader
    is the one who has to know the silence is not an answer."""
    result = ScanResult(
        scan_id="t", url="https://x.it/", final_url="https://x.it/",
        started_at="", finished_at="", status=ScanStatus.OK,
        site={"domain": "x.it"},
        observation={"pages": [{"url": "https://x.it/", "probe_failures": ["web_storage: TimeoutError"]}]},
    )
    for locale in ("en", "it"):
        text = render(result, locale)
        assert "web_storage: TimeoutError" in text
        assert "⟦" not in text, "unresolved catalogue key"


def test_a_complete_observation_adds_no_such_notice():
    """The notice must mean something. Printing it always would make it noise."""
    result = ScanResult(
        scan_id="t", url="https://x.it/", final_url="https://x.it/",
        started_at="", finished_at="", status=ScanStatus.OK,
        site={"domain": "x.it"},
        observation={"pages": [{"url": "https://x.it/", "probe_failures": []}]},
    )
    text = render(result, "en")
    assert "did not complete" not in text


def test_failures_from_every_page_reach_the_reader():
    """A multi-page scan whose third page failed to enumerate storage is still
    a partial observation, even if the first two were clean."""
    result = ScanResult(
        scan_id="t", url="https://x.it/", final_url="https://x.it/",
        started_at="", finished_at="", status=ScanStatus.OK,
        site={"domain": "x.it"},
        observation={"pages": [
            {"url": "https://x.it/", "probe_failures": []},
            {"url": "https://x.it/a", "probe_failures": []},
            {"url": "https://x.it/b", "probe_failures": ["iframes: Error"]},
        ]},
    )
    assert "iframes: Error" in render(result, "en")
