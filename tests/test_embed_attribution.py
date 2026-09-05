"""What the site chose, and what its embed chose.

A site that embeds YouTube has chosen YouTube and answers for it. It has not
chosen the fonts YouTube then loads inside its own player: it cannot see them,
cannot configure them, and cannot prevent them without removing the embed it
already answers for. The engine attributed those inner requests to the site,
and on audiolibri.org that produced "the operator chose Google Fonts" about a
site that self-hosts its fonts and whose CSP says `font-src 'self'`.

A finding whose owner has no way to act on it is worse than no finding: it costs
an afternoon, closes nothing, and teaches the reader to skim the next one.

Suppressing it silently would be the same mistake mirrored — the visitor's data
really did reach that host. So the vendor stays in the inventory, attributed to
the embed under `reached_through`, and only the findings that assert a *choice
by the site* stand down.

Two layers, tested separately because they fail separately. Whether Chromium
tells us which frame issued a request is a browser fact, checked against a real
iframe. What that means for attribution is a domain rule, checked against the
hostnames it was actually wrong about.
"""

from __future__ import annotations

import asyncio
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from pmate.analyze.context import _embed_origin, build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.observe.browser import Observation, Request

SITE = "audiolibri.org"


def _req(url: str, host: str, *, rtype: str = "script", depth: int = 0, frame: str | None = None) -> Request:
    return Request(
        url=url,
        host=host,
        method="GET",
        path="/x",
        status=200,
        content_type=None,
        resource_type=rtype,
        frame_depth=depth,
        frame_url=frame,
    )


def _site(*requests: Request) -> Observation:
    obs = Observation(
        url=f"https://{SITE}/", final_url=f"https://{SITE}/", load_ok=True, status=200
    )
    obs.response_headers = {"content-type": "text/html"}
    obs.requests = list(requests)
    return obs


EMBED = _req(
    "https://www.youtube.com/embed/abc",
    "www.youtube.com",
    rtype="document",
    depth=1,
    frame="https://www.youtube.com/embed/abc",
)
INSIDE_EMBED = _req(
    "https://fonts.gstatic.com/s/roboto.woff2",
    "fonts.gstatic.com",
    rtype="font",
    depth=1,
    frame="https://www.youtube.com/embed/abc",
)
CHOSEN_BY_SITE = _req("https://fonts.gstatic.com/s/inter.woff2", "fonts.gstatic.com", rtype="font")


# --------------------------------------------------------- the attribution rule


def test_a_request_the_page_made_itself_belongs_to_the_site():
    assert _embed_origin(CHOSEN_BY_SITE, SITE) is None


def test_a_request_inside_a_third_party_embed_belongs_to_the_embed():
    assert _embed_origin(INSIDE_EMBED, SITE) == "www.youtube.com"


def test_the_embeds_own_document_is_still_the_sites_choice():
    """Putting the iframe there is the decision. If this were attributed to the
    embed, YouTube would disappear from the report entirely — which is the
    finding that actually matters."""
    assert _embed_origin(EMBED, SITE) is None


def test_an_embed_loading_its_own_resources_is_still_the_sites_choice():
    own = _req(
        "https://www.youtube.com/player.js",
        "www.youtube.com",
        depth=1,
        frame="https://www.youtube.com/embed/abc",
    )
    assert _embed_origin(own, SITE) is None


def test_the_sites_own_frame_is_not_an_embed():
    """A site framing its own pages has chosen everything inside them."""
    own_frame = _req(
        "https://fonts.gstatic.com/s/roboto.woff2",
        "fonts.gstatic.com",
        depth=1,
        frame=f"https://www.{SITE}/widget",
    )
    assert _embed_origin(own_frame, SITE) is None


def test_a_frame_we_could_not_identify_falls_back_to_the_site():
    """`_frame_origin` degrades to (0, None) when the walk fails. That must land
    on the attribution the engine already had, never on a silent drop."""
    unknown = _req("https://fonts.gstatic.com/x.woff2", "fonts.gstatic.com", depth=1, frame=None)
    assert _embed_origin(unknown, SITE) is None


# ------------------------------------------------------------------ the context


def test_a_vendor_only_seen_inside_an_embed_is_marked_as_such():
    ctx = build_context([_site(EMBED, INSIDE_EMBED)])
    fonts = next(f for f in ctx.vendors.values() if "gstatic.com" in " ".join(f.hosts))
    assert fonts.via_embed == "www.youtube.com"


def test_the_embed_itself_is_not_marked():
    ctx = build_context([_site(EMBED, INSIDE_EMBED)])
    youtube = next(f for f in ctx.vendors.values() if "youtube.com" in " ".join(f.hosts))
    assert youtube.via_embed is None


def test_one_direct_contact_settles_it():
    """If the page reaches the vendor itself even once, it chose it. That an
    embed also reaches it changes nothing."""
    ctx = build_context([_site(EMBED, INSIDE_EMBED, CHOSEN_BY_SITE)])
    fonts = next(f for f in ctx.vendors.values() if "gstatic.com" in " ".join(f.hosts))
    assert fonts.via_embed is None


def test_the_vendor_is_still_a_recipient():
    """Suppressing the finding must not suppress the transfer. The data did
    reach that host, and an Art. 30 record has to say so."""
    ctx = build_context([_site(EMBED, INSIDE_EMBED)])
    hosts = {h for f in ctx.third_party_vendors for h in f.hosts}
    assert "fonts.gstatic.com" in hosts


# ------------------------------------------------------------------ the findings


def _fired_for(ctx, host: str) -> set[str]:
    return {
        f.rule_id
        for f in evaluate(ctx, load_rules())
        if host in str(f.evidence.get("hosts", ""))
    }


def test_nothing_is_charged_to_the_site_for_what_its_embed_loaded():
    ctx = build_context([_site(EMBED, INSIDE_EMBED)])
    charged = _fired_for(ctx, "fonts.gstatic.com")
    assert charged == set(), f"findings the site cannot act on: {sorted(charged)}"


def test_the_embed_itself_is_still_charged():
    """The half that must not regress. Removing or gating the YouTube embed is
    a fix the operator can actually perform, and it is the real finding."""
    ctx = build_context([_site(EMBED, INSIDE_EMBED)])
    assert _fired_for(ctx, "youtube.com"), "the embed stopped being reported"


def test_the_same_vendor_chosen_directly_is_still_charged():
    ctx = build_context([_site(EMBED, INSIDE_EMBED, CHOSEN_BY_SITE)])
    assert _fired_for(ctx, "fonts.gstatic.com"), (
        "a vendor the page contacts itself must still produce findings"
    )


# ------------------------------------------------- the browser actually tells us

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>t</title>
</head><body><h1>t</h1><iframe src="{embed}"></iframe></body></html>"""

EMBED_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>e</title>
</head><body><img src="{inner}" alt=""></body></html>"""

PIXEL = bytes.fromhex(
    "47494638396101000100800000ffffff00000021f90401000000002c000000000100010000020144003b"
)


class _Handler(BaseHTTPRequestHandler):
    def __init__(self, *args, pages: dict[str, tuple[bytes, str]], **kwargs):
        self._pages = pages
        super().__init__(*args, **kwargs)

    def log_message(self, *args):
        pass

    def do_GET(self):  # noqa: N802 — http.server's interface
        body, ctype = self._pages.get(self.path.split("?")[0], (b"", "text/plain"))
        self.send_response(200 if body else 404)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _serve(pages: dict[str, tuple[bytes, str]]) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", 0), partial(_Handler, pages=pages))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_port


def test_chromium_reports_which_frame_issued_each_request():
    """The capture layer on its own. Everything above is reasoning about
    `frame_depth` and `frame_url`; if Playwright stopped populating them, all of
    it would keep passing while the engine went back to being wrong.

    Two servers on loopback. `localhost` and `127.0.0.1` are distinct hosts to
    the browser, which is all this test needs — it asserts what Chromium
    reported, not what the attribution rule concludes from it.
    """
    pytest.importorskip("playwright.async_api", reason="playwright is not installed")
    from pmate.config import DEFAULTS
    from pmate.observe.browser import observe

    inner_server, inner_port = _serve({"/pixel.gif": (PIXEL, "image/gif")})
    inner = f"http://127.0.0.1:{inner_port}/pixel.gif"
    outer_server, outer_port = _serve(
        {
            "/embed.html": (EMBED_PAGE.format(inner=inner).encode(), "text/html"),
            "/": (b"", "text/html"),
        }
    )
    embed = f"http://127.0.0.1:{outer_port}/embed.html"
    site_server, site_port = _serve(
        {"/": (PAGE.format(embed=embed).encode(), "text/html; charset=utf-8")}
    )

    try:
        obs = asyncio.run(observe(f"http://localhost:{site_port}/", DEFAULTS))
    finally:
        for server in (site_server, outer_server, inner_server):
            server.shutdown()

    assert obs.load_ok, f"the fixture page did not load: {obs.error}"

    by_url = {r.url: r for r in obs.requests}
    top = next(r for u, r in by_url.items() if u.endswith(f":{site_port}/"))
    assert top.frame_depth == 0 and top.frame_url is None, "the page itself is not in a frame"

    pixel = by_url.get(inner)
    assert pixel is not None, "the request inside the iframe was never observed"
    assert pixel.frame_depth == 1, "a request made inside an iframe was recorded as the page's own"
    assert pixel.frame_url == embed, "the frame the page embedded was not identified"
