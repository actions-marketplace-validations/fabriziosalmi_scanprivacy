"""What happens the first time someone runs this after installing it.

`pip install` brings the Playwright library, not the browser it drives. Those
are separate steps and nothing in the install says so, so the first command a
new user types fails. Whether it fails as an instruction or as a twenty-line
traceback ending in somebody else's error class decides whether they run the
second command.
"""

from __future__ import annotations

import asyncio

import pytest

from pmate.observe.browser import BrowserUnavailable, launch_browser


class _Chromium:
    def __init__(self, error: Exception | None = None, result: str = "browser"):
        self._error = error
        self._result = result
        self.kwargs: dict = {}

    async def launch(self, **kwargs):
        self.kwargs = kwargs
        if self._error:
            raise self._error
        return self._result


class _Playwright:
    def __init__(self, chromium):
        self.chromium = chromium


def _playwright_error(message: str) -> Exception:
    from playwright.async_api import Error

    return Error(message)


# -------------------------------------------------------- the missing browser


@pytest.mark.parametrize(
    "message",
    [
        "BrowserType.launch: Executable doesn't exist at /home/x/.cache/ms-playwright/chromium/headless_shell",
        "Looks like Playwright was just installed or updated.\nPlease run the following command to download new browsers:\n    playwright install",
    ],
)
def test_a_missing_browser_becomes_an_instruction(message):
    """Both shapes Playwright uses. Matching only one would leave the other as
    a traceback, which is the case this exists to remove."""
    pw = _Playwright(_Chromium(error=_playwright_error(message)))
    with pytest.raises(BrowserUnavailable) as unavailable:
        asyncio.run(launch_browser(pw))

    text = str(unavailable.value)
    assert "python -m playwright install chromium" in text, "the remedy must be copy-pasteable"
    assert len(text.splitlines()) <= 3, "an instruction nobody reads is not an instruction"


def test_the_original_cause_is_kept_for_whoever_needs_it():
    """The user gets one line; the chain keeps the rest. Discarding it would
    make a genuine launch problem undiagnosable."""
    original = _playwright_error("BrowserType.launch: Executable doesn't exist at /x")
    pw = _Playwright(_Chromium(error=original))
    with pytest.raises(BrowserUnavailable) as unavailable:
        asyncio.run(launch_browser(pw))
    assert unavailable.value.__cause__ is original


def test_a_different_launch_failure_is_not_disguised_as_a_missing_browser():
    """Telling somebody to install a browser they already have wastes their
    afternoon and hides the real fault."""
    pw = _Playwright(_Chromium(error=_playwright_error("BrowserType.launch: Target page crashed")))
    with pytest.raises(BrowserUnavailable) as unavailable:
        asyncio.run(launch_browser(pw))
    assert "playwright install" not in str(unavailable.value)
    assert "Target page crashed" in str(unavailable.value)


def test_a_successful_launch_is_returned_unchanged():
    chromium = _Chromium()
    assert asyncio.run(launch_browser(_Playwright(chromium))) == "browser"
    assert chromium.kwargs == {"headless": True}


# ------------------------------------------------------------- the exit code


def test_the_cli_reports_it_on_stderr_and_exits_3(capsys):
    """Exit 0 would tell a CI job the scan passed. Exit 1 is the finding gate,
    so a distinct code keeps "no browser" from reading as "findings found"."""
    import argparse

    from pmate.cli import _run

    def explode(args):
        raise BrowserUnavailable("the Chromium build this engine drives is not installed.")

    assert _run(explode, argparse.Namespace()) == 3
    captured = capsys.readouterr()
    assert captured.out == "", "the message belongs on stderr"
    assert "pmate:" in captured.err


def test_other_exceptions_keep_their_traceback():
    """Only the one predictable, user-fixable failure is caught. A swallowed
    bug in this engine is worse than an ugly one."""
    import argparse

    from pmate.cli import _run

    def explode(args):
        raise ValueError("a real bug")

    with pytest.raises(ValueError):
        _run(explode, argparse.Namespace())


def test_every_launch_in_the_package_goes_through_the_helper():
    """Three call sites each catching their own version of this is three
    chances to phrase it badly, and one of them will be missed."""
    import pathlib

    offenders = []
    for path in pathlib.Path("src").rglob("*.py"):
        if "__pycache__" in str(path) or path.name == "browser.py":
            continue
        if "chromium.launch" in path.read_text(encoding="utf-8"):
            offenders.append(str(path))
    assert offenders == [], f"these launch Chromium directly: {offenders}"
