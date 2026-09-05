"""The refusal pass, proved against fixtures instead of against other people's
sites.

Two pages are served locally: one whose consent platform honours a refusal, one
whose platform records it and keeps tracking anyway. The second is the finding
this whole mode exists to produce, and a fixture proves it deterministically —
without a third party's server, without depending on what some site happens to
deploy today, and in a way that keeps working as a regression test.
"""

from __future__ import annotations

import asyncio
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from scanprivacy.observe.consent import (
    NOT_ATTEMPTED_NO_CMP,
    NOT_ATTEMPTED_UNKNOWN,
    REFUSED,
    load_catalogue,
    run_refusal_pass,
)

playwright = pytest.importorskip("playwright.async_api", reason="playwright is not installed")

# A page carrying a consent platform the catalogue knows (the Cookiebot API
# shape) and a "tracker" that loads from a distinct path so it can be spotted in
# the request list. `honours` decides whether refusing actually stops it.
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>fixture</title>
<script>
  window.__refused = false;
  window.Cookiebot = {{ decline: function () {{
      window.__refused = true;
      document.cookie = 'CookieConsent=deny; path=/';
      if ({honours}) {{
        // a platform that honours a refusal also clears what it set before it:
        // an identifier left on the device after "no" is still an identifier
        document.cookie = '_ga=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT';
      }}
  }} }};
</script></head><body>
<h1>fixture</h1>
<script>
  var refused = document.cookie.indexOf('CookieConsent=deny') !== -1;
  var honours = {honours};
  if (!honours || !refused) {{
    var s = document.createElement('script');
    s.src = '/tracker.js';
    document.head.appendChild(s);
    document.cookie = '_ga=GA1.2.fixture; path=/';
  }}
</script>
</body></html>"""

UNKNOWN_CMP_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>fixture</title>
</head><body>
<div id="cookieconsent">We use cookies. <button>Reject</button></div>
<script>var s=document.createElement('script');s.src='/tracker.js';document.head.appendChild(s);</script>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, honours: bool = True, unknown: bool = False, **kwargs):
        self._honours = honours
        self._unknown = unknown
        super().__init__(*args, **kwargs)

    def log_message(self, *args):  # keep the test output readable
        pass

    def do_GET(self):  # noqa: N802 — http.server's interface
        if self.path.startswith("/tracker.js"):
            body, content_type = b"/* tracker */", "application/javascript"
        elif self.path.startswith("/robots.txt"):
            body, content_type = b"User-agent: *\nAllow: /\n", "text/plain"
        else:
            page = UNKNOWN_CMP_PAGE if self._unknown else PAGE.format(
                honours="true" if self._honours else "false"
            )
            body, content_type = page.encode("utf-8"), "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(honours: bool = True, unknown: bool = False):
    server = HTTPServer(("127.0.0.1", 0), partial(_Handler, honours=honours, unknown=unknown))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}/"


async def _run(url: str):
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            return await run_refusal_pass(browser, url)
        finally:
            await browser.close()


# ---------------------------------------------------------------- catalogue


def test_every_catalogued_platform_documents_its_own_refusal_path():
    """The rule the catalogue exists to enforce: no entry may tell the engine to
    do something the vendor has not published."""
    platforms = load_catalogue()
    assert platforms
    for platform in platforms:
        assert platform.documentation.startswith("https://"), platform.id
        assert platform.detect, platform.id
        assert platform.method in ("api", "dom"), platform.id
        if platform.method == "api":
            assert platform.expression and not platform.selector
        else:
            assert platform.selector and not platform.expression
        # the readiness check must actually test the thing that gets called,
        # or the engine could report a refusal that silently did nothing
        needle = platform.expression or platform.selector
        root = needle.split("(")[0].split(".")[0].replace("window", "").strip(". ")
        assert root == "" or root in platform.detect or needle[:12] in platform.detect


def test_catalogue_ids_are_unique():
    ids = [p.id for p in load_catalogue()]
    assert len(ids) == len(set(ids))


# -------------------------------------------------------------------- pass


def test_a_platform_that_honours_the_refusal_leaves_nothing_behind():
    server, url = _serve(honours=True)
    try:
        result = asyncio.run(_run(url))
    finally:
        server.shutdown()

    assert result.attempt.outcome == REFUSED
    assert result.attempt.platform_id == "cookiebot"
    assert result.attempt.action == "window.Cookiebot.decline()"
    assert result.after is not None
    after_hosts = {req.path for req in result.after.requests}
    assert "/tracker.js" not in after_hosts
    assert not [c for c in result.after.cookies if c.name == "_ga"]


def test_a_platform_that_ignores_the_refusal_is_caught():
    """The finding this mode exists for: the refusal is recorded and the
    tracking continues."""
    server, url = _serve(honours=False)
    try:
        result = asyncio.run(_run(url))
    finally:
        server.shutdown()

    assert result.attempt.outcome == REFUSED
    assert result.after is not None
    assert "/tracker.js" in {req.path for req in result.after.requests}
    assert [c for c in result.after.cookies if c.name == "_ga"]


def test_an_identifier_set_before_the_refusal_and_left_behind_is_still_reported():
    """After "no", a tracking identifier on the device is a problem whether it
    was written before the refusal or after it. A platform that stops writing
    but never clears has done half the job."""
    from scanprivacy.analyze.context import build_context
    from scanprivacy.analyze.engine import evaluate, load_rules
    from scanprivacy.observe.browser import CookieSet, Observation

    after = Observation(url="https://x.it", final_url="https://x.it/", load_ok=True, status=200)
    after.cookies = [CookieSet("_ga", ".x.it", "/", True, False, "Lax", 1.0, False)]

    ctx = build_context([after])
    ctx.refusal = type(
        "Attempt",
        (),
        # field-verified: this test is about whether the finding fires at all,
        # and a documented-only path would additionally soften its confidence,
        # which belongs in tests/test_cmp_verification.py.
        {"performed": True, "outcome": "refused", "path_proven": True},
    )()
    findings = evaluate(ctx, load_rules(pass_="refusal"))
    assert "PM-REJ-02" in {f.rule_id for f in findings}


def test_an_unrecognised_platform_is_reported_and_left_untouched():
    """Guessing which control to click on somebody else's site is not an option
    the method allows — and the report has to say the check was not performed."""
    server, url = _serve(unknown=True)
    try:
        result = asyncio.run(_run(url))
    finally:
        server.shutdown()

    assert result.attempt.outcome == NOT_ATTEMPTED_UNKNOWN
    assert result.attempt.detected_markers  # a mechanism *was* seen
    assert result.after is None  # nothing was clicked, so nothing was re-observed


def test_no_consent_mechanism_means_nothing_to_refuse():
    class _Bare(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802
            body = b"<!doctype html><html lang='en'><head><title>t</title></head><body>hi</body></html>"
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), _Bare)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = asyncio.run(_run(f"http://127.0.0.1:{server.server_port}/"))
    finally:
        server.shutdown()

    assert result.attempt.outcome == NOT_ATTEMPTED_NO_CMP
    assert result.after is None


# ------------------------------------------------------------------ rules


def test_refusal_rules_never_fire_in_a_passive_scan():
    """A passive report must not gain a word because this mode exists."""
    from scanprivacy.analyze.engine import load_rules

    passive = {rule.id for rule in load_rules()}
    refusal = {rule.id for rule in load_rules(pass_="refusal")}
    assert refusal
    assert not (passive & refusal)
    assert all(rule_id.startswith("PM-REJ-") for rule_id in refusal)


def test_a_refusal_finding_cannot_exist_without_a_refusal():
    """Fail-closed: claiming "still tracking after refusal" when no refusal took
    place would be a fabrication."""
    from scanprivacy.analyze.context import build_context
    from scanprivacy.analyze.engine import evaluate, load_rules
    from scanprivacy.observe.browser import CookieSet, Observation, Request

    page = Observation(url="https://x.it", final_url="https://x.it/", load_ok=True, status=200)
    page.requests = [
        Request("https://www.google-analytics.com/g", "www.google-analytics.com", "GET", "/g", 200, None, "script")
    ]
    page.cookies = [CookieSet("_ga", ".x.it", "/", True, False, "Lax", 1.0, False)]

    ctx = build_context([page])
    ctx.refusal = None  # no refusal was performed
    assert evaluate(ctx, load_rules(pass_="refusal")) == []


# ------------------------------------------------- the path that clicks

# Everything above exercises the `api` method, where refusal is a documented
# function call. The `dom` method is the one that clicks a control on somebody
# else's page, and it was untested. That is the highest-stakes code in the
# package: a wrong click on a live site can empty a cart, log a user out, or
# submit something. The properties below are the ones that keep it from
# happening at all.

DOM_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>fixture</title>
</head><body>
<div id="cmp-root">
  {controls}
</div>
<button id="unrelated" onclick="window.__unrelated = true">Delete everything</button>
<script>window.__clicked = []; window.__unrelated = false;</script>
</body></html>"""

_CONTROL = '<button class="cmp-reject" onclick="window.__clicked.push(\'{name}\')">{name}</button>'
_HIDDEN = '<button class="cmp-reject" style="display:none" onclick="window.__clicked.push(\'{name}\')">{name}</button>'


def _dom_platform(selector: str = ".cmp-reject"):
    from scanprivacy.observe.consent import ConsentPlatform

    return ConsentPlatform(
        id="fixture-dom", name="Fixture", detect="true", method="dom",
        documentation="https://example.org/docs", selector=selector,
    )


async def _refuse_on(html: str, platform=None):
    from playwright.async_api import async_playwright

    from scanprivacy.observe.consent import refuse

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.set_content(html)
            attempt = await refuse(page, platform or _dom_platform())
            state = await page.evaluate("() => ({clicked: window.__clicked, unrelated: window.__unrelated})")
            return attempt, state
        finally:
            await browser.close()


def test_one_visible_control_is_clicked_and_reported_as_refused():
    attempt, state = asyncio.run(_refuse_on(DOM_PAGE.format(controls=_CONTROL.format(name="reject"))))
    assert attempt.outcome == REFUSED
    assert state["clicked"] == ["reject"]
    assert attempt.action == ".cmp-reject", "the report must name the selector used"


def test_two_matching_controls_stop_the_attempt_without_clicking_either():
    """Ambiguity is a stop condition, not something to resolve by picking the
    first match. Which of two controls a vendor's selector matches is not
    knowable from outside, and the wrong one on a live site can do anything."""
    from scanprivacy.observe.consent import NOT_ATTEMPTED_AMBIGUOUS

    html = DOM_PAGE.format(
        controls=_CONTROL.format(name="reject") + _CONTROL.format(name="reject-all")
    )
    attempt, state = asyncio.run(_refuse_on(html))
    assert attempt.outcome == NOT_ATTEMPTED_AMBIGUOUS
    assert state["clicked"] == [], "nothing may be clicked once the match is ambiguous"
    assert "2 visible elements" in attempt.detail


def test_a_selector_matching_nothing_is_also_a_stop_not_a_search():
    """Zero matches means the catalogue entry no longer fits the site. The
    engine says so; it does not go looking for a button that resembles one."""
    from scanprivacy.observe.consent import NOT_ATTEMPTED_AMBIGUOUS

    attempt, state = asyncio.run(
        _refuse_on(DOM_PAGE.format(controls=""), _dom_platform(".does-not-exist"))
    )
    assert attempt.outcome == NOT_ATTEMPTED_AMBIGUOUS
    assert state["clicked"] == []


def test_hidden_matches_do_not_create_ambiguity():
    """Consent banners routinely keep several copies in the DOM — mobile,
    desktop, a template — with one shown. Counting them all would make every
    such site unrefusable, which is a false stop rather than a safe one."""
    html = DOM_PAGE.format(
        controls=_HIDDEN.format(name="mobile")
        + _CONTROL.format(name="desktop")
        + _HIDDEN.format(name="template")
    )
    attempt, state = asyncio.run(_refuse_on(html))
    assert attempt.outcome == REFUSED
    assert state["clicked"] == ["desktop"], "the visible one, and only it"


def test_nothing_outside_the_documented_selector_is_ever_touched():
    """The guarantee a site owner is owed: one action, on one element the
    vendor publishes."""
    html = DOM_PAGE.format(controls=_CONTROL.format(name="reject"))
    attempt, state = asyncio.run(_refuse_on(html))
    assert attempt.outcome == REFUSED
    assert state["unrelated"] is False, "the engine clicked something it was not told to"


def test_an_unsupported_method_is_reported_rather_than_improvised():
    from scanprivacy.observe.consent import ConsentPlatform, FAILED

    platform = ConsentPlatform(
        id="x", name="X", detect="true", method="telepathy",
        documentation="https://example.org/docs",
    )
    attempt, state = asyncio.run(_refuse_on(DOM_PAGE.format(controls=""), platform))
    assert attempt.outcome == FAILED
    assert "unsupported method" in attempt.detail
    assert state["clicked"] == []


def test_the_attempt_always_reproduces_what_was_done():
    """A reader has to be able to confirm the supported path was used, which
    means the platform, the method and the vendor's documentation reach the
    record whatever the outcome."""
    for html, platform in (
        (DOM_PAGE.format(controls=_CONTROL.format(name="r")), _dom_platform()),
        (DOM_PAGE.format(controls=""), _dom_platform(".missing")),
    ):
        attempt, _ = asyncio.run(_refuse_on(html, platform))
        assert attempt.platform_id == "fixture-dom"
        assert attempt.method == "dom"
        assert attempt.documentation == "https://example.org/docs"


# --------------------------------------------- fail-closed, for this question


def test_a_pass_that_refused_nothing_is_not_a_clean_verdict():
    """The engine's own rule, applied to its strictest mode.

    A refusal pass asks one thing: what survives when the visitor says no. When
    no refusal happened — no mechanism found, the platform unrecognised, the
    control ambiguous, the documented call failed — there are no refusal
    findings, and zero findings graded A. That is a green verdict handed out for
    something nobody observed, which is the one thing this project exists not to
    do.
    """
    import asyncio
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    import pytest as _pytest

    _pytest.importorskip("playwright.async_api", reason="playwright is not installed")
    from scanprivacy.config import DEFAULTS
    from scanprivacy.core.enums import Grade
    from scanprivacy.scanner import refusal_scan

    PLAIN = (
        b'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        b"<title>t</title></head><body><h1>no banner here</h1></body></html>"
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802 — http.server's interface
            body = b"User-agent: *\nAllow: /\n" if self.path.startswith("/robots") else PLAIN
            ctype = "text/plain" if self.path.startswith("/robots") else "text/html"
            self.send_response(200)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = asyncio.run(refusal_scan(f"http://127.0.0.1:{server.server_port}/", DEFAULTS))
    finally:
        server.shutdown()

    assert result.findings == [], "the fixture site has nothing to refuse"
    assert result.verdict.grade is Grade.INCONCLUSIVE, (
        "a pass that refused nothing reported a clean site"
    )
    assert result.verdict.conformant is False
    assert result.verdict.note_key == "consent_pass.outcome.no_consent_mechanism", (
        "the verdict must say which of the reasons it was"
    )


def test_every_reason_a_refusal_did_not_happen_can_be_read():
    """The verdict note is built from the outcome constant, so a new outcome
    without a catalogue entry would print a missing-key marker on the verdict
    line of a report."""
    from scanprivacy.i18n import Translator
    from scanprivacy.observe import consent as consent_module

    outcomes = [
        getattr(consent_module, name)
        for name in dir(consent_module)
        if name.isupper() and isinstance(getattr(consent_module, name), str)
        and name.startswith(("NOT_ATTEMPTED", "FAILED", "REFUSED"))
    ]
    assert len(outcomes) >= 5, "the enumeration found almost nothing"
    for lang in ("en", "it"):
        t = Translator.for_locale(lang)
        for outcome in outcomes:
            text = t.t(f"consent_pass.outcome.{outcome}")
            assert "\u27e6" not in text, f"[{lang}] no wording for outcome {outcome!r}"
