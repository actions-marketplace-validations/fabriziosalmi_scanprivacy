"""The API must not make the browser, or the service, touch a private address.

The first defence looked at where the browser had been after it had been there:
the result was withheld, but the request to an internal service had already
been made. These tests use a real browser and servers that record whether they
were ever contacted, because "the check ran" proves nothing here. Only "the
server never saw the request" does.
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

pytest.importorskip("playwright")

from playwright.async_api import async_playwright  # noqa: E402

from scanprivacy.config import DEFAULTS  # noqa: E402
from scanprivacy.core.target import TargetCheck, check_public_target  # noqa: E402
from scanprivacy.observe.browser import launch_browser, new_context, observe_url  # noqa: E402
from scanprivacy.observe.egress import EgressProxy  # noqa: E402
from scanprivacy.observe.guard import RequestGuard, blocked_requests  # noqa: E402

GUARDED = replace(DEFAULTS, guard_requests=True, wait_after_load_ms=300)


class _Recorder:
    """A local HTTP server that remembers every path it was asked for."""

    def __init__(self, body: bytes = b"<html><body>internal</body></html>", redirect_to=None) -> None:
        hits: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                hits.append(self.path)
                if redirect_to:
                    self.send_response(302)
                    self.send_header("location", redirect_to)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("content-type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.hits = hits
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def servers():
    made: list[_Recorder] = []

    def make(**kwargs) -> _Recorder:
        server = _Recorder(**kwargs)
        made.append(server)
        return server

    yield make
    for server in made:
        server.close()


def _admitting(*ports: int):
    """The real policy, except that these loopback ports play the part of public sites."""

    def check(url: str, *, resolver=None):
        from urllib.parse import urlsplit

        parts = urlsplit(url)
        if parts.port in ports:
            return TargetCheck(host=parts.hostname or "", addresses=("127.0.0.1",))
        return check_public_target(url, **({"resolver": resolver} if resolver else {}))

    return check


async def _guarded_browser(pw, check):
    proxy = await EgressProxy(check=check).start()
    browser = await launch_browser(pw, proxy=proxy.playwright_proxy())
    browser._scanprivacy_egress = proxy
    return browser, proxy


def _run(coro):
    return asyncio.run(coro)


def test_without_the_guard_a_page_makes_the_browser_reach_the_internal_server(servers):
    """The control. This is the defect; if it stops reproducing, nothing below proves anything."""
    internal = servers()
    page = servers(body=f"<img src='http://127.0.0.1:{internal.port}/secret'>".encode())

    async def go():
        async with async_playwright() as pw:
            browser = await launch_browser(pw)
            await observe_url(browser, f"http://127.0.0.1:{page.port}/", replace(DEFAULTS, wait_after_load_ms=300))
            await browser.close()

    _run(go())
    assert internal.hits == ["/secret"]


def test_a_sub_resource_pointing_at_a_private_address_is_never_requested(servers):
    internal = servers()
    page = servers(body=f"<img src='http://127.0.0.1:{internal.port}/secret'>".encode())

    async def go():
        async with async_playwright() as pw:
            browser, proxy = await _guarded_browser(pw, _admitting(page.port))
            context = await new_context(browser, settings=GUARDED)
            p = await context.new_page()
            await p.goto(f"http://127.0.0.1:{page.port}/")
            await p.wait_for_timeout(400)
            blocked = list(proxy.blocked) + blocked_requests(context)
            await browser.close()
            await proxy.stop()
            return blocked

    blocked = _run(go())
    assert page.hits == ["/"], "the admitted page was not loaded, so the test proves nothing"
    assert internal.hits == [], "the sub-resource reached the internal server"
    assert any(b["reason"] == "not_a_public_address" for b in blocked)


def test_a_redirect_to_a_private_address_is_not_followed(servers):
    """The case a request-routing guard cannot see: the hop is not routed, only the proxy sees it."""
    internal = servers()
    entry = servers(redirect_to=f"http://127.0.0.1:{internal.port}/secret")

    async def go():
        async with async_playwright() as pw:
            browser, proxy = await _guarded_browser(pw, _admitting(entry.port))
            context = await new_context(browser, settings=GUARDED)
            p = await context.new_page()
            try:
                await p.goto(f"http://127.0.0.1:{entry.port}/start", timeout=5000)
            except Exception:
                pass  # the navigation is expected to fail: its redirect was refused
            blocked = list(proxy.blocked)
            await browser.close()
            await proxy.stop()
            return blocked

    blocked = _run(go())
    assert entry.hits == ["/start"], "the entry page was not loaded, so the test proves nothing"
    assert internal.hits == [], "the redirect to the private address was followed"
    assert [b["reason"] for b in blocked] == ["not_a_public_address"]


def test_a_websocket_to_a_private_address_is_not_opened():
    connections: list[bytes] = []

    async def go():
        async def on_connect(reader, writer):
            connections.append(await reader.read(64))
            writer.close()

        server = await asyncio.start_server(on_connect, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with async_playwright() as pw:
            browser, proxy = await _guarded_browser(pw, check_public_target)
            context = await new_context(browser, settings=GUARDED)
            page = await context.new_page()
            await page.goto("about:blank")
            await page.evaluate("p => { try { new WebSocket('ws://127.0.0.1:' + p) } catch (e) {} }", port)
            await page.wait_for_timeout(500)
            await browser.close()
            await proxy.stop()
        server.close()

    _run(go())
    assert connections == [], "a TCP connection to the private address was made"


def test_the_proxy_connects_to_the_address_it_checked_and_does_not_resolve_again(servers):
    """DNS rebinding needs a second resolution to win. `allowed.test` resolves
    nowhere on this machine: a tunnel to it can only succeed by using the
    checked address, so success shows the name is not looked up again."""
    target = servers()

    async def go():
        proxy = await EgressProxy(check=_admitting(target.port)).start()
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(f"CONNECT allowed.test:{target.port} HTTP/1.1\r\nhost: allowed.test\r\n\r\n".encode())
        await writer.drain()
        status = await reader.readline()
        writer.write(b"GET /pinned HTTP/1.1\r\nhost: allowed.test\r\nconnection: close\r\n\r\n")
        await writer.drain()
        await reader.read(200)
        writer.close()
        ips = dict(proxy.ips)
        await proxy.stop()
        return status, ips

    status, ips = _run(go())
    assert status.startswith(b"HTTP/1.1 200")
    assert target.hits == ["/pinned"]
    assert ips == {"allowed.test": "127.0.0.1"}


def test_the_proxy_refuses_a_name_that_resolves_to_a_private_address(servers):
    internal = servers()

    def rebinding_resolver(host, port, *args, **kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", 0))]  # a public-looking name, a loopback answer

    async def go():
        proxy = await EgressProxy(resolver=rebinding_resolver).start()
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
        writer.write(f"CONNECT looks-public.example:{internal.port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        status = await reader.readline()
        writer.close()
        blocked = list(proxy.blocked)
        await proxy.stop()
        return status, blocked

    status, blocked = _run(go())
    assert status.startswith(b"HTTP/1.1 403")
    assert internal.hits == []
    assert blocked[0]["reason"] == "not_a_public_address"


def test_a_whole_api_mode_scan_of_a_private_url_sends_nothing(servers):
    from scanprivacy.scanner import scan

    internal = servers()
    result = _run(scan(f"http://127.0.0.1:{internal.port}/secret", GUARDED, read_documents=False))
    assert internal.hits == []
    assert result.verdict is not None and result.verdict.conformant is False


def test_robots_txt_is_not_fetched_from_a_private_host_in_api_mode(servers):
    from scanprivacy.observe.robots import RobotsCache

    internal = servers()

    async def go():
        proxy = await EgressProxy().start()
        try:
            return await RobotsCache(proxy=proxy.url).allowed(f"http://127.0.0.1:{internal.port}/page")
        finally:
            await proxy.stop()

    _run(go())
    assert internal.hits == []


def test_the_tls_probe_does_not_connect_to_a_private_host_in_api_mode():
    from scanprivacy.observe.tls import probe

    info = _run(probe("127.0.0.1", guarded=True))
    assert info.ok is False
    assert "target refused" in (info.error or "")


def test_the_command_line_default_still_observes_a_local_target(servers):
    """`http://localhost:8000` is a legitimate thing to check before deploying;
    the guard is for the API, where a stranger chooses the target."""
    assert DEFAULTS.guard_requests is False
    local = servers()

    async def go():
        async with async_playwright() as pw:
            browser = await launch_browser(pw)
            obs = await observe_url(browser, f"http://127.0.0.1:{local.port}/", replace(DEFAULTS, wait_after_load_ms=100))
            await browser.close()
            return obs

    obs = _run(go())
    assert obs.load_ok is True
    assert local.hits == ["/"]


def test_the_api_runs_every_scan_with_the_guard_on():
    from scanprivacy import api

    assert api.API_SETTINGS.guard_requests is True


def test_a_scheme_that_is_not_web_is_refused_by_the_request_guard():
    guard = RequestGuard()
    assert _run(guard.allow("file:///etc/passwd")) is False
    assert _run(guard.allow("data:text/html,hi")) is True
    assert _run(guard.allow("about:blank")) is True
    assert guard.blocked[0]["reason"] == "scheme_not_permitted"
