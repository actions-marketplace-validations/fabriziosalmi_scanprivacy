"""Policies declared in the document, not in the response.

On hosting that serves fixed response headers — GitHub Pages, most static
hosts — a `<meta>` element is the only instrument available. Reading only the
header there reports a site as unprotected while its protection sits in the
`<head>`, and sends the reader to set a header the platform will never send.

The property under test is that absence means absence. An extraction that
fails — a bad selector, a renamed API — must not arrive at the rules dressed
as "the page has no policy": that is a finding the engine never observed.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
from pathlib import Path

import pytest

from pmate.analyze.context import build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.observe.browser import Observation, observe

PAGE = """<!doctype html><html><head>
<meta HTTP-EQUIV="Content-Security-Policy" content="default-src 'self'">
<meta name="Referrer" content="strict-origin-when-cross-origin">
<meta name="GENERATOR" content="Astro v4.5.0">
<title>t</title></head><body>x</body></html>"""

BARE = "<!doctype html><html><head><title>t</title></head><body>x</body></html>"


@pytest.fixture(scope="module")
def served(tmp_path_factory):
    root = tmp_path_factory.mktemp("meta")
    (root / "declared.html").write_text(PAGE, encoding="utf-8")
    (root / "bare.html").write_text(BARE, encoding="utf-8")

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=str(root), **kw)

        def log_message(self, *a):  # keep the test output readable
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _observe(url: str) -> Observation:
    return asyncio.run(observe(url))


# ------------------------------------------------------------ extraction


def test_a_declared_policy_is_read_whatever_its_case(served):
    """`HTTP-EQUIV` and `Referrer` are as valid as the lowercase spellings.
    HTML attribute names are case-insensitive; a matcher that is not would
    report a policy as absent on a page that declares it."""
    obs = _observe(f"{served}/declared.html")
    assert obs.meta_csp == "default-src 'self'"
    assert obs.meta_referrer == "strict-origin-when-cross-origin"


def test_a_page_without_meta_reports_none_not_empty_string(served):
    obs = _observe(f"{served}/bare.html")
    assert obs.meta_csp is None
    assert obs.meta_referrer is None


# ------------------------------------------------- what the rules then see


def test_the_effective_policy_names_where_it_comes_from(served):
    """A meta element is weaker than a header — it cannot carry
    `frame-ancestors` — so the report must be able to say which one is in
    force rather than flattening the two."""
    ctx = build_context([_observe(f"{served}/declared.html")])
    assert ctx.effective_csp() == ("default-src 'self'", "meta")
    assert ctx.effective_referrer_policy() == ("strict-origin-when-cross-origin", "meta")

    bare = build_context([_observe(f"{served}/bare.html")])
    assert bare.effective_csp() == (None, "none")
    assert bare.effective_referrer_policy() == (None, "none")


def test_a_header_wins_over_a_meta_element():
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'none'",
        "referrer-policy": "no-referrer",
    }
    obs.meta_csp = "default-src 'self'"
    obs.meta_referrer = "unsafe-url"
    ctx = build_context([obs])
    assert ctx.effective_csp() == ("default-src 'none'", "header")
    assert ctx.effective_referrer_policy() == ("no-referrer", "header")


def test_the_security_rules_do_not_fire_on_a_declared_policy(served):
    """The regression that produced 39 false findings across 44 sites: the
    policy was in the page and the engine reported it missing."""
    fired = {f.rule_id for f in evaluate(build_context([_observe(f"{served}/declared.html")]), load_rules())}
    assert "PM-SEC-03" not in fired  # content security policy
    assert "PM-SEC-02" not in fired  # referrer policy

    bare = {f.rule_id for f in evaluate(build_context([_observe(f"{served}/bare.html")]), load_rules())}
    assert "PM-SEC-03" in bare
    assert "PM-SEC-02" in bare


def test_a_permissive_declared_policy_still_fires(served):
    """Declaring `unsafe-url` is not protection. Presence is not conformance."""
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {"content-type": "text/html"}
    obs.meta_referrer = "unsafe-url"
    fired = {f.rule_id for f in evaluate(build_context([obs]), load_rules())}
    assert "PM-SEC-02" in fired


# ------------------------------------------------------- the generator meta


def test_the_generator_is_read_from_the_same_pass(served):
    """It drives the platform hint — "disable the Jetpack Stats module" rather
    than "remove the tracker" — so failing to read it costs the reader the only
    part of the remediation that is specific to them."""
    obs = _observe(f"{served}/declared.html")
    assert obs.generator_meta == "Astro v4.5.0"


def test_a_page_without_one_is_not_a_failed_observation(served):
    """The defect this file exists for, in its third variant. `generator` was
    read with `eval_on_selector`, which raises when nothing matches — and almost
    no page carries a generator meta. So almost every scan recorded a failed
    probe and declared itself partial.

    Over-reporting is not the safe direction. A report that warns "part of the
    observation did not complete" on every single run teaches its reader to skip
    the warning, and the warning exists for the run where it is true.
    """
    obs = _observe(f"{served}/bare.html")
    assert obs.generator_meta is None, "absence must be observed, not inferred"
    assert not [p for p in obs.probe_failures if "generator" in p], (
        f"a page with no generator meta reported a failed probe: {obs.probe_failures}"
    )


def test_a_clean_page_reports_no_partial_observation_at_all(served):
    """The end-to-end consequence: an ordinary static page must produce a report
    that does not claim something went unread."""
    obs = _observe(f"{served}/bare.html")
    assert obs.probe_failures == [], obs.probe_failures


# ------------------------------------------------- report-only is not a policy


def test_a_report_only_header_does_not_satisfy_the_rule():
    """It enforces nothing. A site serving only this has no policy in force."""
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {
        "content-type": "text/html",
        "content-security-policy-report-only": "default-src 'self'",
    }
    ctx = build_context([obs])
    assert ctx.effective_csp() == (None, "none")
    assert "PM-SEC-03" in {f.rule_id for f in evaluate(ctx, load_rules())}


def test_but_the_finding_says_the_header_is_there():
    """Found on audiolibri.org, which moved from an enforcing CSP to a
    report-only one. "No Content-Security-Policy" told against a response that
    carries a header by nearly that name is how a true finding gets dismissed:
    the owner checks, sees a CSP, and stops reading."""
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {
        "content-type": "text/html",
        "content-security-policy-report-only": "default-src 'self'; script-src 'self'",
    }
    finding = next(f for f in evaluate(build_context([obs]), load_rules()) if f.rule_id == "PM-SEC-03")
    assert "default-src 'self'" in finding.evidence.get("csp_report_only", "")


def test_a_site_with_no_policy_at_all_says_nothing_extra():
    """The distinction is only worth drawing where it exists."""
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {"content-type": "text/html"}
    finding = next(f for f in evaluate(build_context([obs]), load_rules()) if f.rule_id == "PM-SEC-03")
    assert "csp_report_only" not in finding.evidence


def test_an_enforcing_header_still_wins_over_report_only():
    obs = Observation(url="https://x.it/", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {
        "content-type": "text/html",
        "content-security-policy": "default-src 'none'",
        "content-security-policy-report-only": "default-src 'self'",
    }
    ctx = build_context([obs])
    assert ctx.effective_csp() == ("default-src 'none'", "header")
    assert "PM-SEC-03" not in {f.rule_id for f in evaluate(ctx, load_rules())}
