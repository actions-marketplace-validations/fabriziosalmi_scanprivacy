"""A page that did not load must not be summarised as "nothing observed"."""

from __future__ import annotations

from scanprivacy.core.enums import ScanStatus
from scanprivacy.core.models import ScanResult
from scanprivacy.i18n.translator import Translator
from scanprivacy.report.render import _summary


def _result(pages_observed: int) -> ScanResult:
    return ScanResult(
        scan_id="t", url="https://x.example/", final_url="https://x.example/",
        started_at="2026-01-01T00:00:00Z", finished_at="2026-01-01T00:00:01Z",
        status=ScanStatus.OK,
        site={"pages_observed": pages_observed, "cookies": 0, "storage": 0},
    )


def test_a_page_that_loaded_with_no_third_party_says_so():
    text = " ".join(_summary(_result(1), Translator.for_locale("en")))
    assert "No request to any third party was observed" in text
    assert "No cookie" in text


def test_a_page_that_never_loaded_does_not_claim_that_nothing_was_observed():
    text = " ".join(_summary(_result(0), Translator.for_locale("en")))
    assert "No request to any third party" not in text
    assert "No cookie" not in text
