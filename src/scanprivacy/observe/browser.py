"""Passive first-visit observation with headless Chromium.

What an ordinary visitor's browser does when the page opens, and nothing else:
no clicks, no submits, no authentication, no consent given or refused. Every
piece of evidence below is what the site itself chose to do to a visitor who
has not yet expressed anything.
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from playwright.async_api import Browser, Page, Response, async_playwright

from ..config import DEFAULTS, UA, Settings
from .guard import RequestGuard, blocked_requests, egress_of

# Link text / href patterns for the documents that carry legal obligations.
# Italian first (primary market), then EN/DE/FR/ES so the engine generalises.
LEGAL_LINK_PATTERNS: dict[str, re.Pattern[str]] = {
    "privacy": re.compile(
        r"\b(privacy|informativa|datenschutz|confidentialit|privacidad|"
        r"protezione\s+dei\s+dati|data\s+protection)\b",
        re.I,
    ),
    "cookie": re.compile(r"\bcookies?\b", re.I),
    "terms": re.compile(
        r"note\s*legali|termini|condizioni\s+d.?uso|terms|impressum|legal\s+notice|"
        r"mentions\s+l[ée]gales|aviso\s+legal",
        re.I,
    ),
    "accessibility": re.compile(r"accessibilit[àa]|accessibility|barrierefreiheit", re.I),
    "dpo": re.compile(r"\bdpo\b|responsabile\s+.*protezione\s+.*dati|data\s+protection\s+officer", re.I),
}

# Consent management platforms and generic banner markers. Presence of a CMP
# changes the legal reading of a pre-consent tracker: the site knows it needs
# consent and loaded the tracker anyway.
CMP_MARKERS: dict[str, re.Pattern[str]] = {
    "iubenda": re.compile(r"iubenda", re.I),
    "cookiebot": re.compile(r"cookiebot|usercentrics", re.I),
    "onetrust": re.compile(r"onetrust|cookielaw\.org|optanon", re.I),
    "cookieyes": re.compile(r"cookieyes", re.I),
    "complianz": re.compile(r"complianz|cmplz", re.I),
    "borlabs": re.compile(r"borlabs", re.I),
    "klaro": re.compile(r"klaro", re.I),
    "tarteaucitron": re.compile(r"tarteaucitron", re.I),
    "cookie-notice": re.compile(r"cookie-notice|cookie-law-info|cookieconsent", re.I),
    "quantcast": re.compile(r"quantcast|choice\.consensu\.org", re.I),
    "termly": re.compile(r"termly", re.I),
    "axeptio": re.compile(r"axeptio", re.I),
    # Widely deployed self-hosted banners. Missing one of these does not
    # understate a site — it overstates it: the engine would report "no
    # mechanism to collect consent" about a site that has a banner, which is
    # both wrong and the kind of error a supplier rightly throws back.
    "cookiealert": re.compile(r"mod_cookiealert|cookiecuttr", re.I),
    "cookie-consent-js": re.compile(r"cookieconsent\.min\.js|cookieconsent\.js|osano", re.I),
    "eu-cookie-law": re.compile(r"eu[-_]cookie[-_]law|cookie[-_]law[-_]info", re.I),
    "moove-gdpr": re.compile(r"moove[_-]gdpr", re.I),
    "gdpr-cookie-compliance": re.compile(r"gdpr[-_]cookie[-_]compliance", re.I),
    "civic-cookie-control": re.compile(r"cookiecontrol|civiccomputing", re.I),
    "didomi": re.compile(r"didomi", re.I),
    "sourcepoint": re.compile(r"sourcepoint|sp-prod\.net", re.I),
}

# AI transparency markers (EU AI Act Art. 50: content generated or manipulated
# by AI must be disclosed to the user). Deterministic surface signals only.
AI_MARKERS: dict[str, re.Pattern[str]] = {
    "ai-meta-disclosure": re.compile(
        r'<meta[^>]+name=["\'](?:ai-generated|ai-disclosure|generator-ai)["\']', re.I
    ),
    "ai-chat-widget": re.compile(r"chatbot|ai-assistant|openai|anthropic|dialogflow", re.I),
    "ai-generated-badge": re.compile(r"generato\s+con\s+(?:l.?)?(?:ia|ai)|ai[- ]generated|generated\s+by\s+ai", re.I),
}


class BrowserUnavailable(RuntimeError):
    """Chromium is not installed, or could not start.

    Installing the package installs the Playwright library, not the browser it
    drives. Those are separate steps, and nothing in `pip install` says so — so
    the first command a new user runs fails, and without this it fails as a
    twenty-line traceback ending in someone else's error class. The remedy is
    one line; the message has to be one line too.
    """


async def launch_browser(playwright, **kwargs):
    """Start Chromium, or explain what to do about it.

    Every launch in this package goes through here. Three call sites each
    catching their own version of this is three chances to phrase it badly.
    """
    from playwright.async_api import Error as PlaywrightError

    try:
        return await playwright.chromium.launch(headless=True, **kwargs)
    except PlaywrightError as exc:
        message = str(exc)
        if "playwright install" in message or "Executable doesn't exist" in message:
            raise BrowserUnavailable(
                "the Chromium build this engine drives is not installed.\n"
                "  python -m playwright install chromium\n"
                "Installing the package installs the driver, not the browser."
            ) from exc
        raise BrowserUnavailable(f"Chromium could not start: {message.splitlines()[0]}") from exc


@dataclass(slots=True)
class Request:
    url: str
    host: str
    method: str
    path: str
    status: int | None
    content_type: str | None
    resource_type: str
    failed: bool = False
    peer_ip: str | None = None
    """The address the browser actually connected to.

    Resolving a name before the fetch cannot settle where the fetch went: the
    record may change between the two, and a redirect moves the target after
    the check entirely. This is the observed answer rather than the predicted
    one, and it is what the API validates against."""
    t_ms: int | None = None
    """Milliseconds since navigation start. Makes the evidence checkable: a
    request at t=180ms cannot have followed a consent the user never gave."""
    frame_depth: int = 0
    """0 when the page itself issued the request, 1 inside a frame the page
    embeds, 2 inside a frame that frame embeds, and so on.

    A site is answerable for choosing to embed YouTube. It is not answerable for
    the fonts YouTube then loads inside its own player, which it cannot see,
    configure or prevent. Attributing those to the site produces findings whose
    owner has no way to act on them — and, on the site that exposed this, said
    the operator had chosen Google Fonts when its own CSP said `font-src
    'self'`."""
    frame_url: str | None = None
    """URL of the outermost embedded document in the chain — the frame the page
    itself put there. `None` when the page issued the request directly."""


@dataclass(slots=True)
class CookieSet:
    name: str
    domain: str
    path: str
    secure: bool
    http_only: bool
    same_site: str | None
    expires: float | None
    session: bool


@dataclass(slots=True)
class StorageEntry:
    kind: str  # localStorage | sessionStorage | indexedDB
    key: str
    size: int


@dataclass(slots=True)
class LegalLink:
    kind: str
    text: str
    href: str


@dataclass(slots=True)
class FormInfo:
    action: str
    action_host: str
    method: str
    fields: list[str]
    has_privacy_checkbox: bool
    has_password: bool = False
    """A password field is the strongest signal a form carries credentials. It
    is read from the DOM and never filled: the engine submits nothing, ever."""
    page_url: str = ""
    page_scheme: str = "https"


@dataclass(slots=True)
class Observation:
    url: str
    final_url: str
    load_ok: bool
    status: int | None
    error: str | None = None
    title: str | None = None
    lang: str | None = None
    generator_meta: str | None = None
    meta_csp: str | None = None
    """`<meta http-equiv="Content-Security-Policy">`. On hosting that does not
    let anyone set response headers — GitHub Pages, most static hosts — this is
    the only lever there is. Reading only the header would report a site as
    unprotected while its actual protection sits two lines above."""
    meta_referrer: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    requests: list[Request] = field(default_factory=list)
    cookies: list[CookieSet] = field(default_factory=list)
    storage: list[StorageEntry] = field(default_factory=list)
    legal_links: list[LegalLink] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    """Every same-document anchor target, resolved. Feeds page selection; the
    engine follows links from the entry page only, never from page to page."""
    forms: list[FormInfo] = field(default_factory=list)
    iframes: list[str] = field(default_factory=list)
    cmp_detected: list[str] = field(default_factory=list)
    tcf_api_present: bool | None = None
    """True, False, or *not established*. Three states rather than two, because
    a probe that threw used to be recorded as `False` — an error turned into
    evidence that the site has no consent framework."""
    ai_markers: list[str] = field(default_factory=list)
    html_len: int = 0
    html: str = field(default="", repr=False)
    blocked_requests: list[dict[str, str]] = field(default_factory=list)
    """Requests the context refused to send because their host did not resolve to
    public addresses only. Empty unless `Settings.guard_requests` is on."""
    probe_failures: list[str] = field(default_factory=list)
    """Which reads of the page did not complete, and why.

    An observation engine that silently substitutes an empty list for a failed
    read reports an absence it never witnessed. The failures are kept so the
    verdict and the report can say the observation was partial instead of
    presenting it as complete."""

    def probe_failed(self, probe: str, exc: BaseException) -> None:
        self.probe_failures.append(f"{probe}: {type(exc).__name__}")

    @property
    def host(self) -> str:
        return urlsplit(self.final_url or self.url).netloc


_MS_PER_SECOND = 1000

_STORAGE_JS = """() => {
  const out = [];
  const grab = (store, kind) => {
    try {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        let v = '';
        try { v = store.getItem(k) || ''; } catch (e) { v = ''; }
        out.push({ kind, key: k, size: v.length });
      }
    } catch (e) { /* storage blocked by the page's own policy */ }
  };
  grab(window.localStorage, 'localStorage');
  grab(window.sessionStorage, 'sessionStorage');
  return out;
}"""

_IDB_JS = """async () => {
  try {
    if (!indexedDB.databases) return [];
    const dbs = await indexedDB.databases();
    return dbs.map(d => d.name).filter(Boolean);
  } catch (e) { return []; }
}"""

_FORMS_JS = """() => {
  return Array.from(document.querySelectorAll('form')).slice(0, 20).map(f => ({
    action: f.getAttribute('action') || '',
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0, 40)
      .map(i => (i.getAttribute('type') || i.tagName.toLowerCase()) + ':' + (i.getAttribute('name') || '')),
    hasPrivacyCheckbox: !!f.querySelector('input[type=checkbox]') &&
      /privacy|informativa|consenso|consent|gdpr/i.test(f.innerHTML),
    hasPassword: !!f.querySelector('input[type=password]')
  }));
}"""


async def new_context(
    browser: Browser, user_agent: str | None = None, settings: Settings | None = None
):
    """A browsing context with no stored state: every scan is a first visit.

    When `settings.guard_requests` is set, every request the context makes is
    vetted before it is sent; see `observe/guard.py`.
    """
    context = await browser.new_context(
        user_agent=user_agent or UA,
        locale="it-IT",
        ignore_https_errors=False,
    )
    if settings is not None and settings.guard_requests:
        egress = getattr(browser, "_scanprivacy_egress", None)
        # One policy: the request guard judges with the same rule the proxy does.
        await (RequestGuard(check=egress.policy) if egress is not None else RequestGuard()).install(context)
        context._scanprivacy_egress = egress
    return context


async def observe_url(
    browser: Browser,
    url: str,
    settings: Settings = DEFAULTS,
    user_agent: str | None = None,
) -> Observation:
    """Load `url` in a clean context and return everything observed."""
    context = await new_context(browser, user_agent, settings)
    try:
        return await observe_in_context(context, url, settings)
    finally:
        await context.close()


async def observe_in_context(context, url: str, settings: Settings = DEFAULTS) -> Observation:
    """Observe `url` inside a context the caller owns.

    Separated from `observe_url` because the consent pass has to keep the same
    context across the refusal and the reload: a choice that does not persist is
    not a choice, and re-observing in a fresh context would measure nothing.
    """
    page: Page = await context.new_page()

    requests: list[Request] = []
    t0 = time.monotonic()

    # Declared before the recorders that append to it: losing one entry beats
    # losing the visit, but a lost entry is a third party that will not appear
    # in the inventory, and that has to be visible somewhere.
    listener_failures: list[str] = []

    def _frame_origin(request: Any) -> tuple[int, str | None]:
        """How deep inside embedded documents this request was made, and which
        document the page itself embedded to get there.

        Walking to the outermost *embedded* frame rather than to the immediate
        parent is deliberate: a chain of nested frames is still one decision the
        site made, and the one the site made is the outermost.

        Failure here degrades to "the page issued it", which is the attribution
        the engine already had — never to a silent drop of the request.
        """
        try:
            frame = request.frame
            chain = []
            while frame is not None and frame.parent_frame is not None:
                chain.append(frame)
                frame = frame.parent_frame
            if not chain:
                return 0, None
            return len(chain), chain[-1].url or None
        except Exception as exc:
            listener_failures.append(f"frame_attribution: {type(exc).__name__}")
            return 0, None

    def _record(
        url_: str,
        method: str,
        rtype: str,
        status: int | None,
        ctype: str | None,
        failed: bool,
        peer: str | None = None,
        frame_depth: int = 0,
        frame_url: str | None = None,
    ) -> None:
        parts = urlsplit(url_)
        if parts.scheme not in ("http", "https"):
            return
        requests.append(
            Request(
                url=url_,
                host=parts.netloc.lower(),
                method=method,
                path=parts.path,
                status=status,
                content_type=ctype,
                resource_type=rtype,
                failed=failed,
                peer_ip=peer,
                t_ms=int((time.monotonic() - t0) * _MS_PER_SECOND),
                frame_depth=frame_depth,
                frame_url=frame_url,
            )
        )

    async def on_response(resp: Response) -> None:
        try:
            try:
                egress = egress_of(page.context)
                if egress is not None:
                    # Behind the egress proxy the browser's peer is the proxy
                    # itself; the address that matters is the one it connected to.
                    peer = egress.public_peer(resp.url)
                else:
                    addr = await resp.server_addr()
                    peer = (addr or {}).get("ipAddress")
            except Exception as exc:
                # An address that could not be read is not an address that was
                # public. Say so in the observation instead of dropping it.
                peer = None
                if "server_addr" not in " ".join(listener_failures):
                    listener_failures.append(f"server_addr: {type(exc).__name__}")
            depth, frame_url = _frame_origin(resp.request)
            _record(
                resp.url,
                resp.request.method,
                resp.request.resource_type,
                resp.status,
                resp.headers.get("content-type"),
                False,
                peer,
                depth,
                frame_url,
            )
        except Exception as exc:  # pragma: no cover — losing one entry beats losing the visit
            listener_failures.append(f"response_listener: {type(exc).__name__}")

    def on_request_failed(req: Any) -> None:
        # A blocked or failed request still proves the page *tried* to contact
        # the host — legally that is an attempted transfer, and it belongs in
        # the evidence.
        try:
            depth, frame_url = _frame_origin(req)
            _record(req.url, req.method, req.resource_type, None, None, True, None, depth, frame_url)
        except Exception as exc:
            listener_failures.append(f"requestfailed_listener: {type(exc).__name__}")

    page.on("response", on_response)
    page.on("requestfailed", on_request_failed)

    obs = Observation(url=url, final_url=url, load_ok=False, status=None)
    try:
        main = await page.goto(url, wait_until="domcontentloaded", timeout=settings.nav_timeout_ms)
        await page.wait_for_timeout(settings.wait_after_load_ms)
        obs.load_ok = True
        obs.final_url = page.url
        obs.status = main.status if main else None
        if main is not None:
            obs.response_headers = {k.lower(): v for k, v in main.headers.items()}

        for c in await context.cookies():
            obs.cookies.append(
                CookieSet(
                    name=c.get("name", ""),
                    domain=c.get("domain", ""),
                    path=c.get("path", "/"),
                    secure=bool(c.get("secure")),
                    http_only=bool(c.get("httpOnly")),
                    same_site=c.get("sameSite"),
                    expires=c.get("expires"),
                    session=(c.get("expires") in (-1, None)),
                )
            )

        obs.title = await page.title()
        try:
            obs.lang = await page.eval_on_selector("html", "el => el.lang || null")
        except Exception as exc:
            obs.probe_failed("lang", exc)
            obs.lang = None
        # Every `<meta>` we care about, read in one DOM pass rather than through
        # CSS selectors. An attribute selector with the wrong case-insensitivity
        # syntax throws, and a caught throw is indistinguishable from "the page
        # has no policy" — the engine would report an absence it never observed.
        #
        # `generator` used to be read separately with `eval_on_selector`, which
        # raises when nothing matches. Most pages carry no generator meta, so
        # most scans recorded a failed probe and declared the observation
        # partial: the report cried wolf every time, which is how a reader
        # learns to skip the warning that matters. Absence is now observed as
        # absence, which is also why the platform hint works at all.
        obs.meta_csp, obs.meta_referrer, obs.generator_meta = await page.evaluate(
            """() => {
                const pick = (test) => {
                    for (const el of document.querySelectorAll('meta')) {
                        if (test(el) && el.content) return el.content;
                    }
                    return null;
                };
                const named = (n) => pick(el => (el.getAttribute('name') || '').toLowerCase() === n);
                return [
                    pick(el => (el.httpEquiv || '').toLowerCase() === 'content-security-policy'),
                    named('referrer'),
                    named('generator'),
                ];
            }"""
        )

        try:
            for e in await page.evaluate(_STORAGE_JS):
                obs.storage.append(StorageEntry(kind=e["kind"], key=e["key"], size=int(e["size"])))
        except Exception as exc:
            # An empty storage list and an unreadable one look identical to
            # every rule downstream. Say which happened.
            obs.probe_failed("web_storage", exc)
        try:
            for name in await page.evaluate(_IDB_JS):
                obs.storage.append(StorageEntry(kind="indexedDB", key=str(name), size=0))
        except Exception as exc:
            obs.probe_failed("indexed_db", exc)

        try:
            obs.tcf_api_present = bool(
                await page.evaluate("() => typeof window.__tcfapi === 'function' || typeof window.__cmp === 'function'")
            )
        except Exception as exc:
            # Not False. A probe that threw establishes nothing about whether
            # the site runs a consent framework.
            obs.probe_failed("tcf_api", exc)
            obs.tcf_api_present = None

        html = await page.content()
        obs.html = html
        obs.html_len = len(html)
        obs.cmp_detected = sorted(n for n, pat in CMP_MARKERS.items() if pat.search(html))
        obs.ai_markers = sorted(n for n, pat in AI_MARKERS.items() if pat.search(html))

        # legally relevant links, deduplicated by (kind, resolved href), and
        # the full link set used to choose which other pages to observe
        base = obs.final_url
        seen: set[tuple[str, str]] = set()
        all_links: list[str] = []
        for a in await page.query_selector_all("a[href]"):
            try:
                href = await a.get_attribute("href") or ""
                text = (await a.inner_text() or "").strip()
            except Exception as exc:
                # One unreadable anchor is not the page; keep going, but the
                # link set is then incomplete and page selection depends on it.
                obs.probe_failed("anchor", exc)
                continue
            if not href or href.startswith(("javascript:", "#")):
                continue
            resolved = urljoin(base, href)
            if len(all_links) < settings.max_links_recorded and resolved not in all_links:
                all_links.append(resolved)
            for kind, pat in LEGAL_LINK_PATTERNS.items():
                if pat.search(text) or pat.search(href):
                    key = (kind, resolved)
                    if key in seen:
                        continue
                    seen.add(key)
                    obs.legal_links.append(LegalLink(kind=kind, text=text[:120], href=resolved))

        try:
            for f in await page.evaluate(_FORMS_JS):
                action = urljoin(base, f["action"]) if f["action"] else obs.final_url
                obs.forms.append(
                    FormInfo(
                        action=action,
                        action_host=urlsplit(action).netloc.lower(),
                        method=f["method"],
                        fields=list(f["fields"]),
                        has_privacy_checkbox=bool(f["hasPrivacyCheckbox"]),
                        has_password=bool(f.get("hasPassword")),
                        page_url=obs.final_url,
                        page_scheme=urlsplit(obs.final_url).scheme or "https",
                    )
                )
        except Exception as exc:
            obs.probe_failed("forms", exc)

        try:
            obs.iframes = [
                urljoin(base, (await fr.get_attribute("src")) or "")
                for fr in await page.query_selector_all("iframe[src]")
            ][:40]
        except Exception as exc:
            obs.probe_failed("iframes", exc)

        obs.links = all_links
        obs.requests = requests[: settings.max_subresources]

    except Exception as e:
        obs.error = f"{type(e).__name__}: {e}"
    finally:
        obs.probe_failures.extend(listener_failures)
        await page.close()
    obs.blocked_requests = blocked_requests(page.context)
    return obs


async def observe(url: str, settings: Settings = DEFAULTS, user_agent: str | None = None) -> Observation:
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        try:
            return await observe_url(browser, url, settings, user_agent)
        finally:
            await browser.close()


def obs_to_dict(obs: Observation, include_html: bool = False) -> dict[str, Any]:
    d = asdict(obs)
    if not include_html:
        d.pop("html", None)
    if not d.get("blocked_requests"):
        d.pop("blocked_requests", None)  # keeps the evidence shape of every unguarded scan
    return d
