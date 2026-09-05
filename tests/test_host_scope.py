"""What a scan of one host is allowed to say about another.

Scanning `www.cyberapi.io` followed a link to `threats.cyberapi.io/docs` and
reported what it found there under `www.cyberapi.io: D`. The jsDelivr findings
were real, and they were on a different deployment: a different repository, a
different framework, in that case FastAPI's stock Swagger UI. The report named
the wrong host, and the reader went to a codebase with no jsDelivr in it.

`is_first_party` — same registrable domain — is the right question for "did the
visitor's data leave the site" and the wrong one for "which pages does this
scan cover". Two hosts under one domain share an owner and, very often, nothing
else: not a deployment, not a repository, not the person who reads the ticket.

The apex and its `www.` are the exception, because they usually are one server
with one redirecting to the other.

The other half is that not visiting must not be the same as not saying so. The
sibling host is listed in the page plan with the reason, exactly as a page
skipped by robots.txt is: this engine records the pages it chose not to visit,
because an omission nobody can see reads as coverage.
"""

from __future__ import annotations

import pytest

from scanprivacy.observe.browser import Observation
from scanprivacy.observe.pages import same_deployment, select_pages, sibling_hosts

SITE = "https://www.cyberapi.io"


def _entry(links: list[str], url: str = SITE) -> Observation:
    obs = Observation(url=url, final_url=f"{url}/", load_ok=True, status=200)
    obs.links = links
    return obs


# ------------------------------------------------------------- the boundary


@pytest.mark.parametrize(
    "a,b,same",
    [
        ("www.cyberapi.io", "threats.cyberapi.io", False),
        ("a.example.org", "b.example.org", False),
        ("shop.example.org", "example.org", False),
        ("www.example.org", "example.org", True),
        ("example.org", "www.example.org", True),
        ("WWW.Example.org", "example.org", True),
        ("www.example.org", "www.example.org", True),
        ("www.example.org", "example.com", False),
    ],
)
def test_the_deployment_boundary(a: str, b: str, same: bool):
    assert same_deployment(a, b) is same


# ------------------------------------------------------------- the selection


def test_a_link_to_a_sibling_host_is_not_followed():
    chosen = select_pages(
        _entry([f"{SITE}/contatti", "https://threats.cyberapi.io/docs"]), 5
    )
    hosts = {url.split("/")[2] for url in (c.url for c in chosen)}
    assert "threats.cyberapi.io" not in hosts, "the scan wandered onto another deployment"


def test_the_apex_and_its_www_are_one_site():
    chosen = select_pages(_entry(["https://cyberapi.io/chi-siamo"]), 5)
    assert [c.url for c in chosen] == ["https://cyberapi.io/chi-siamo"]


def test_ordinary_pages_are_still_selected():
    """The guard must not refuse everything: without this the test above would
    pass on a function that returns nothing at all."""
    chosen = select_pages(_entry([f"{SITE}/contatti", f"{SITE}/servizi"]), 5)
    assert len(chosen) == 2


def test_a_genuinely_external_link_is_not_a_sibling():
    """`sibling_hosts` reports the organisation's own other sites. A link to
    somebody else's site is not an omission from this scan's scope."""
    entry = _entry([f"{SITE}/x", "https://www.google.com/", "https://threats.cyberapi.io/docs"])
    assert sibling_hosts(entry) == ["threats.cyberapi.io"]


def test_siblings_are_reported_once_and_in_a_stable_order():
    entry = _entry(
        [
            "https://threats.cyberapi.io/docs",
            "https://threats.cyberapi.io/docs/other",
            "https://api.cyberapi.io/v1",
        ]
    )
    assert sibling_hosts(entry) == ["api.cyberapi.io", "threats.cyberapi.io"]


def test_the_scanned_host_is_never_its_own_sibling():
    assert sibling_hosts(_entry([f"{SITE}/contatti", "https://cyberapi.io/"])) == []


# ------------------------------------------------------------- the disclosure


def test_the_reason_is_stated_in_both_languages():
    from scanprivacy.i18n import Translator
    from scanprivacy.report.pdf import _why

    for lang in ("en", "it"):
        text = _why({"why": "page_choice.other_host", "kind": "other"}, Translator.for_locale(lang))
        assert "⟦" not in text, f"[{lang}] no translation for the sibling-host reason"
        assert len(text) > 40, f"[{lang}] the reason does not explain itself"


def test_a_skipped_sibling_reaches_the_page_plan(monkeypatch):
    """The wiring, not the boundary.

    `sibling_hosts` is covered above against real hostnames. What this checks is
    that `scan` actually calls it and puts the result in the plan — the half
    that could silently not exist while every unit test above stayed green.

    It has to be stubbed: loopback offers no pair of names that share a
    registrable domain, so the situation cannot be staged against a local
    server. Saying so beats a fixture that quietly tests something else.
    """
    import asyncio
    import threading
    from dataclasses import replace
    from http.server import BaseHTTPRequestHandler, HTTPServer

    pytest.importorskip("playwright.async_api", reason="playwright is not installed")
    from scanprivacy import scanner
    from scanprivacy.config import DEFAULTS

    monkeypatch.setattr(scanner, "sibling_hosts", lambda *_a, **_k: ["threats.cyberapi.io"])

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):  # noqa: N802 — http.server's interface
            if self.path.startswith("/robots.txt"):
                body, ctype = b"User-agent: *\nAllow: /\n", "text/plain"
            else:
                body = (
                    '<!doctype html><html lang="en"><head><meta charset="utf-8">'
                    "<title>t</title></head><body>"
                    '<a href="/contatti">contatti</a>'
                    "</body></html>"
                ).encode()
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        result = asyncio.run(
            scanner.scan(
                f"http://127.0.0.1:{server.server_port}/",
                replace(DEFAULTS, max_pages=3),
                read_documents=False,
            )
        )
    finally:
        server.shutdown()

    plan = (result.observation or {}).get("page_plan") or []
    declined = [row for row in plan if row.get("why") == "page_choice.other_host"]
    assert declined, "the sibling deployment was dropped without saying so"
    assert declined[0]["url"] == "threats.cyberapi.io"

    visited = {page.get("url") for page in (result.observation or {}).get("pages") or []}
    assert not any("cyberapi" in str(url) for url in visited), (
        "a host listed as declined was visited anyway"
    )
