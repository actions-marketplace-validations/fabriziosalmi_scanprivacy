"""Who the engine says it is, and whether the report says the same thing.

The User-Agent is the only channel through which the owner of an observed site
learns that we exist and how to object. Three things therefore have to hold,
and none of them was covered.

- The contact address belongs to whoever *runs* the instance. A mailbox
  hard-coded in a public repository conscripts one person into answering for
  every deployment they have never seen.
- Retrying as a plain browser when the identified string is refused is a
  decision, not a reflex. It drops the contact address, which is the whole
  accountability mechanism.
- Whichever string actually reached the site is the one the report names.
  Stating the identity we *intended* to use is the project's own worst failure
  mode wearing a different hat: an assertion about a request nobody made.
"""

from __future__ import annotations

import asyncio
import importlib
import threading
from pathlib import Path
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pmate import config
from pmate.config import DEFAULTS, UA, UA_FALLBACK
from pmate.core.enums import ScanStatus
from pmate.scanner import scan

pytest.importorskip("playwright.async_api", reason="playwright is not installed")


PAGE = b"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>fixture</title></head><body><h1>fixture</h1></body></html>"""


class _PickyHandler(BaseHTTPRequestHandler):
    """A host that drops the connection on an unfamiliar User-Agent.

    Not a 403: a refused *response* still loads, so it would never reach the
    retry. This reproduces what the fallback was written for — a WAF that hangs
    up before saying anything.
    """

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 — http.server's interface
        ua = self.headers.get("User-Agent", "")
        if "privacymate" in ua:
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("content-length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)


@pytest.fixture
def picky_site():
    server = HTTPServer(("127.0.0.1", 0), _PickyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/"
    server.shutdown()


# ------------------------------------------------------------------ contact


def test_the_contact_address_is_the_operators_to_set(monkeypatch):
    monkeypatch.setenv("PMATE_CONTACT", "privacy@example.org")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.UA_CONTACT == "privacy@example.org"
        assert "privacy@example.org" in reloaded.UA
    finally:
        monkeypatch.delenv("PMATE_CONTACT")
        importlib.reload(config)


def test_an_empty_contact_falls_back_rather_than_shipping_a_blank_one(monkeypatch):
    """A User-Agent reading `contact: )` is worse than the default: it claims
    accountability and offers nowhere to send it."""
    monkeypatch.setenv("PMATE_CONTACT", "   ")
    reloaded = importlib.reload(config)
    try:
        assert reloaded.UA_CONTACT == reloaded.UA_CONTACT_DEFAULT
    finally:
        monkeypatch.delenv("PMATE_CONTACT")
        importlib.reload(config)


def test_the_default_contact_is_an_address_and_not_a_placeholder():
    """A role address is what this should eventually be — `abuse@` on the
    project's own domain, so that a public file does not conscript one person
    into answering for deployments they never saw, and does not hand harvesters
    a working mailbox.

    That mailbox does not exist yet, and an address that bounces is worse than a
    personal one that works: it claims accountability without offering it. So
    while the repository is private the default is a real inbox, and what is
    enforced here is only that it *is* one.

    The stronger rule cannot be tested, because nothing in the source can see
    the day the repository is made public. It is stated in `config.py`, next to
    the line that has to change.
    """
    local, at, domain = config.UA_CONTACT_DEFAULT.partition("@")
    assert at and local and "." in domain, (
        f"{config.UA_CONTACT_DEFAULT!r} is not an email address"
    )
    assert "example" not in domain, "the default must be a mailbox somebody reads"


def test_the_engine_and_the_documents_promise_the_same_address():
    """The User-Agent tells a site owner where to write. The README shows that
    string, and SECURITY.md tells them the same thing in prose. Three copies of
    one fact, and the two documents are exactly what nobody updates — so a site
    owner would be told to write to an address the engine never sent."""
    root = Path(__file__).resolve().parents[1]
    address = config.UA_CONTACT_DEFAULT
    for name in ("README.md", "SECURITY.md"):
        text = (root / name).read_text(encoding="utf-8")
        assert address in text, (
            f"{name} does not name {address}, which is the address the engine sends"
        )
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert f"contact: {address}" in readme, (
        "the README's sample User-Agent has drifted from the one the engine builds"
    )


def test_the_identified_user_agent_carries_the_contact_and_the_purpose():
    assert config.UA_CONTACT in UA
    assert "privacymate" in UA
    assert "passive" in UA


# ----------------------------------------------------------------- fallback


def test_a_refused_identity_is_not_silently_retried_as_a_browser(picky_site):
    """Default posture. The site hung up on us; that is an answer, and working
    around it is not this function's decision to make."""
    result = asyncio.run(scan(picky_site, DEFAULTS, read_documents=False))

    assert result.status is not ScanStatus.OK, "the fallback fired without being asked"
    assert result.record["posture"]["user_agent"] == UA


def test_the_fallback_is_available_when_the_operator_asks_for_it(picky_site):
    settings = replace(DEFAULTS, ua_fallback_on_block=True, max_pages=1)
    result = asyncio.run(scan(picky_site, settings, read_documents=False))

    assert result.status is ScanStatus.OK, "opting in did not get the page loaded"


def test_the_report_names_the_identity_that_actually_reached_the_site(picky_site):
    """The one that matters. The evidence record is read as a compliance
    document; a posture section describing a request that was never made is a
    statement about something nobody observed."""
    settings = replace(DEFAULTS, ua_fallback_on_block=True, max_pages=1)
    result = asyncio.run(scan(picky_site, settings, read_documents=False))

    assert result.record["posture"]["user_agent"] == UA_FALLBACK
    assert result.record["posture"]["user_agent"] != UA
