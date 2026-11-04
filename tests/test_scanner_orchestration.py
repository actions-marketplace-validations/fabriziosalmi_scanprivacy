"""The orchestration around the observation, against a local server.

Two things live here that nothing else covered.

**robots.txt.** The constraint this project was given before any code existed —
"mai chiamate non legit" — and the one an unhappy site owner will check first.
It had no test at all, which meant the guarantee rested on nobody having broken
it yet.

**The refusal pass end to end.** `refusal_scan` orchestrates observe → refuse →
reload → compare and decides what reaches the document. The refusal *mechanics*
were tested; the orchestration around them was not, including the rule it
exists to enforce: a refusal document carries refusal findings and no others.
"""

from __future__ import annotations

import asyncio
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scanprivacy.config import DEFAULTS
from scanprivacy.core.enums import Grade, ScanStatus
from scanprivacy.scanner import refusal_scan, scan

pytest.importorskip("playwright.async_api", reason="playwright is not installed")


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>fixture</title>
<script>window.Cookiebot = { decline: function () { document.cookie = 'CookieConsent=deny; path=/'; } };</script>
</head><body>
<h1>fixture</h1>
<a href="/contatti">contatti</a>
<a href="/private/secret">private</a>
<a href="/privacy">privacy</a>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, robots: str = "User-agent: *\nAllow: /\n", **kwargs):
        self._robots = robots
        super().__init__(*args, **kwargs)

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 — http.server's interface
        if self.path.startswith("/robots.txt"):
            body, ctype = self._robots.encode(), "text/plain"
        else:
            body, ctype = PAGE.encode(), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(robots: str = "User-agent: *\nAllow: /\n"):
    server = HTTPServer(("127.0.0.1", 0), partial(_Handler, robots=robots))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/"


@pytest.fixture
def site():
    made = []

    def start(robots: str = "User-agent: *\nAllow: /\n"):
        server, url = _serve(robots)
        made.append(server)
        return url

    yield start
    for server in made:
        server.shutdown()


# ------------------------------------------------------------------- robots


def test_a_disallowed_target_is_not_observed_at_all(site):
    """The constraint stated before this project had any code. A scan that
    ignores the site's own stated wishes is a poor advertisement for the thing
    it is selling — and it is the first thing an unhappy owner checks."""
    url = site("User-agent: *\nDisallow: /\n")
    result = asyncio.run(scan(url, DEFAULTS, read_documents=False))

    assert result.status is ScanStatus.ROBOTS_SKIP
    assert result.findings == [], "a target that was never loaded cannot have findings"
    assert result.verdict is not None
    assert result.verdict.grade is Grade.INCONCLUSIVE
    assert result.verdict.conformant is False, "skipped is not clean"


def test_a_disallowed_target_records_why_rather_than_looking_like_an_error(site):
    """"We chose not to" and "we could not" are different outcomes, and a
    reader has to be able to tell them apart."""
    url = site("User-agent: *\nDisallow: /\n")
    result = asyncio.run(scan(url, DEFAULTS, read_documents=False))
    assert result.error == "verdict.robots_skip"
    assert result.verdict.note_key == "verdict.robots_skip"


def test_an_allowed_target_is_observed_normally(site):
    """The other half: the guard must not refuse everything."""
    result = asyncio.run(scan(site(), DEFAULTS, read_documents=False))
    assert result.status is ScanStatus.OK
    assert (result.observation or {}).get("pages")


def test_a_disallowed_subpath_is_skipped_and_the_skip_is_recorded(site):
    """Selection may still pick a page robots forbids. It is dropped, and the
    plan says so — a page silently missing from a multi-page scan is a hole in
    the evidence nobody can see."""
    from dataclasses import replace

    url = site("User-agent: *\nDisallow: /private/\n")
    result = asyncio.run(scan(url, replace(DEFAULTS, max_pages=5), read_documents=False))

    plan = (result.observation or {}).get("page_plan") or []
    skipped = [entry for entry in plan if "robots" in str(entry.get("why", ""))]
    observed = [p["url"] for p in (result.observation or {}).get("pages") or []]

    assert not any("/private/" in u for u in observed), "a forbidden page was loaded"
    # Unconditional: the fixture links /private/secret, so selection must have
    # considered it, and the plan must say it was dropped. A conditional here let
    # the assertion pass without ever running.
    assert any("/private/" in str(entry.get("url", "")) for entry in plan), "the forbidden page was never considered"
    assert skipped, "the page was dropped without saying why"


def test_robots_can_be_switched_off_only_deliberately(site):
    """`respect_robots` is a setting, not a default. The default must be to
    respect it, or the guarantee is a matter of how the caller happened to
    configure things."""
    assert DEFAULTS.respect_robots is True

    from dataclasses import replace

    url = site("User-agent: *\nDisallow: /\n")
    result = asyncio.run(
        scan(url, replace(DEFAULTS, respect_robots=False), read_documents=False)
    )
    assert result.status is ScanStatus.OK, "the override did not take effect"


# ------------------------------------------------------- the refusal document


def test_the_refusal_scan_produces_a_document_of_its_own(site):
    result = asyncio.run(refusal_scan(site(), DEFAULTS))
    assert result.status is ScanStatus.OK
    attempt = (result.record.get("posture") or {}).get("refusal") or {}
    assert attempt.get("outcome"), "the document must say what was attempted"


def test_only_refusal_rules_reach_the_refusal_document(site):
    """A passive finding has no business here: it was already produced by the
    passive scan, against a method that never touched the page. Mixing them
    would let a reader attribute a passive finding to a mode that clicked."""
    result = asyncio.run(refusal_scan(site(), DEFAULTS))
    non_refusal = [f.rule_id for f in result.findings if not f.rule_id.startswith("PM-REJ")]
    assert non_refusal == [], f"passive findings leaked into the refusal document: {non_refusal}"


def test_the_refusal_document_names_the_platform_and_its_documentation(site):
    """A reader must be able to confirm the supported path was used."""
    result = asyncio.run(refusal_scan(site(), DEFAULTS))
    attempt = (result.record.get("posture") or {}).get("refusal") or {}
    if attempt.get("outcome") == "refused":
        assert attempt.get("platform_name")
        assert str(attempt.get("documentation", "")).startswith("https://")
        assert attempt.get("action"), "the verbatim expression or selector belongs in the record"


def test_a_refusal_scan_of_a_disallowed_target_refuses_too(site):
    """The mode that touches the page must honour robots at least as strictly
    as the one that does not."""
    url = site("User-agent: *\nDisallow: /\n")
    result = asyncio.run(refusal_scan(url, DEFAULTS))
    # The exact status, not merely "not OK": a scan that failed for an
    # unrelated reason would satisfy the weaker assertion and prove nothing.
    assert result.status is ScanStatus.ROBOTS_SKIP
    assert result.error == "verdict.robots_skip"
    assert result.findings == []
    assert ((result.record.get("posture") or {}).get("refusal") or {}).get("outcome") is None, (
        "nothing may be attempted against a target that asked not to be visited"
    )
