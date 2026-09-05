"""Derived facts: everything the rules are allowed to ask about.

The observation layer records what happened. This layer turns it into legal
facts — who the third parties are, which of them the notice declares, which
cookies are tracking cookies, which Art. 13 elements are missing — and nothing
else. Rules see only this, and only through predicates.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..core.enums import DataClass, Detection, TransferScope
from ..knowledge.registry import (
    Vendor,
    VendorRemediation,
    identify_platform,
    is_first_party,
    lookup_by_id,
    registered_domain,
    transfer_scope,
    vendor_for,
)
from ..observe.browser import CookieSet, Observation, Request, StorageEntry
from ..observe.docs import ART13_CONDITIONAL, DocumentEvidence

# Cookie and storage keys that are tracking by construction. Name-based, so it
# still works when the setting host is first-party: server-side GA4, proxied tag
# managers, plugins that write the identifier themselves.
TRACKING_KEY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^_ga($|_)|^_gid$|^_gat|^_gcl_", re.I), "google-analytics"),
    (re.compile(r"^__utm", re.I), "google-analytics"),
    (re.compile(r"^_fbp$|^_fbc$|^fr$", re.I), "meta-pixel"),
    (re.compile(r"^_hj", re.I), "hotjar"),
    (re.compile(r"^_clck$|^_clsk$|^MUID$|^CLID$", re.I), "microsoft-clarity"),
    (re.compile(r"^_pk_(id|ses)", re.I), "matomo-cloud"),
    (re.compile(r"^IDE$|^test_cookie$|^NID$|^DSID$", re.I), "google-ads"),
    (re.compile(r"^bcookie$|^li_(sugr|gc)$|^UserMatchHistory$|^lidc$", re.I), "linkedin-insight"),
    (re.compile(r"^_uet(sid|vid)", re.I), "microsoft-clarity"),
    (re.compile(r"^__hs|^hubspotutk$", re.I), "hubspot"),
    (re.compile(r"^intercom-", re.I), "intercom"),
    (re.compile(r"^tk_(ai|qs|r3d)|^wordpress_test", re.I), "wordpress-stats"),
    (re.compile(r"^AMP_|^ajs_", re.I), None),
]

# Consent-proof, security and preference keys: their presence is not a finding.
FUNCTIONAL_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"cookie[-_]?(consent|notice|law|yes|bot)|iub|CookieConsent|cmplz|borlabs|klaro|euconsent", re.I),
    re.compile(r"^(cf_clearance|__cf_bm|_cfuvid|__cflb|AWSALB|AWSALBCORS|incap_ses|visid_incap)", re.I),
    re.compile(r"^(theme|lang|locale|i18n|color[-_]?scheme|font[-_]?size|sidebar|darkmode)", re.I),
    re.compile(r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|csrftoken|XSRF-TOKEN|__Host-|__Secure-|wordpress_sec)", re.I),
]

# Processors that never appear as a subresource host because they *are* the
# first-party origin: CDN, edge, static hosting. They receive the visitor's IP
# all the same, and the notice has to name them.
HEADER_SIGNATURES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"^cloudflare$", re.I), "server", "cloudflare-cdn"),
    (re.compile(r".+"), "cf-ray", "cloudflare-cdn"),
    (re.compile(r"github\.com", re.I), "server", "github-pages"),
    (re.compile(r".+"), "x-github-request-id", "github-pages"),
    (re.compile(r".+"), "x-vercel-id", "vercel"),
    (re.compile(r"^Vercel$", re.I), "server", "vercel"),
    (re.compile(r"Netlify", re.I), "server", "netlify"),
    (re.compile(r".+"), "x-nf-request-id", "netlify"),
    (re.compile(r".+"), "x-amz-cf-id", "aws-cloudfront"),
    (re.compile(r"AmazonS3|CloudFront", re.I), "server", "aws-cloudfront"),
    (re.compile(r".+"), "fly-request-id", "fly-io"),
    (re.compile(r"Fastly|Varnish", re.I), "x-served-by", "fastly"),
]


def infra_from_headers(headers: dict[str, str]) -> list[str]:
    """Vendor ids inferred from the main response headers."""
    out: list[str] = []
    for pattern, header, vendor_id in HEADER_SIGNATURES:
        value = headers.get(header)
        if value and pattern.search(value) and vendor_id not in out:
            out.append(vendor_id)
    return out


def classify_key(name: str) -> tuple[DataClass, str | None]:
    """Return (class, vendor id hint) for a cookie name or storage key."""
    for pattern, vendor_id in TRACKING_KEY_PATTERNS:
        if pattern.search(name):
            return DataClass.TRACKING, vendor_id
    for pattern in FUNCTIONAL_KEY_PATTERNS:
        if pattern.search(name):
            return DataClass.FUNCTIONAL, None
    return DataClass.UNKNOWN, None


@dataclass(slots=True)
class VendorFact:
    vendor: Vendor
    detection: Detection = Detection.REQUEST
    hosts: list[str] = field(default_factory=list)
    sample_urls: list[str] = field(default_factory=list)
    resource_types: list[str] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)
    """Which observed pages contacted this vendor. "on every page" and "only on
    the contact form" call for different fixes, and the difference is only
    visible once more than one page has been observed."""
    first_party: bool = False
    declared: bool = False
    declared_in: list[str] = field(default_factory=list)
    transfer: TransferScope = TransferScope.EEA
    via_embed: str | None = None
    """Host of the embedded document this vendor was only ever reached through.

    A site that embeds YouTube has chosen YouTube, and answers for that. It has
    not chosen the fonts YouTube then loads inside its own player: it cannot see
    them, configure them or prevent them, and the only fix available to it is
    the one it already has for the embed. Reporting them as processors the site
    selected produces findings whose owner has no way to act on them — on the
    site that exposed this, "the operator chose Google Fonts" about a site whose
    own CSP says `font-src 'self'`.

    `None` the moment the page itself contacts the vendor directly, even once:
    then it *is* a choice, and the fact that an embed also reaches it changes
    nothing."""

    @property
    def id(self) -> str:
        return self.vendor.id


@dataclass(slots=True)
class CookieFact:
    cookie: CookieSet
    data_class: DataClass
    vendor_id: str | None
    third_party: bool
    declared: bool
    first_seen_page: str = ""


@dataclass(slots=True)
class FormFact:
    """One form, however many pages carry it.

    A login form in a shared header is one form, not one per page — counting it
    per page inflates the report the same way counting a vendor per page would.
    The identity is what the form *is* (its destination and its fields), which
    also makes the finding id stable across scans: an index would shift as soon
    as page order changed, and every SARIF alert would be recreated.
    """

    form: Any
    pages: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        """Identity from what the form *is*, never from field names.

        Field names are not stable: a CSRF token is a fresh hex string on every
        load, and anti-spam honeypots rotate their name from a word list. On the
        pilot site that produced five findings for one login form, each with a
        different id — which would also have meant five new SARIF alerts on
        every scan. The type profile is stable and still distinguishes a login
        form from a search box.
        """
        profile: dict[str, int] = {}
        for field_ in self.form.fields:
            kind = field_.split(":", 1)[0]
            profile[kind] = profile.get(kind, 0) + 1
        signature = "|".join(
            [self.form.action, self.form.method, "pw" if self.form.has_password else "nopw"]
            + [f"{kind}={count}" for kind, count in sorted(profile.items())]
        )
        return hashlib.sha256(signature.encode("utf-8")).hexdigest()[:12]


@dataclass(slots=True)
class StorageFact:
    entry: StorageEntry
    data_class: DataClass
    vendor_id: str | None
    first_seen_page: str = ""


@dataclass(slots=True)
class Context:
    obs: Observation
    """The entry page. Header, TLS and document rules are measured here: they
    describe the origin, and mixing per-page differences into them would turn
    one finding into one finding per page."""
    pages: list[Observation] = field(default_factory=list)
    documents: list[DocumentEvidence] = field(default_factory=list)
    tls: Any | None = None
    site_host: str = ""
    site_domain: str = ""
    platform_id: str | None = None
    platform_name: str | None = None
    vendors: dict[str, VendorFact] = field(default_factory=dict)
    cookies: list[CookieFact] = field(default_factory=list)
    storage: list[StorageFact] = field(default_factory=list)
    declared_vendor_ids: set[str] = field(default_factory=set)
    docs_by_kind: dict[str, DocumentEvidence] = field(default_factory=dict)
    refusal: Any | None = None
    """What the engine did to the consent mechanism, when the refusal pass ran.
    `None` in every passive scan, which is every scan by default."""
    before: "Context | None" = None
    """Facts observed before the refusal, so a finding can say a vendor was
    present before *and* survived the refusal."""

    @property
    def observed_pages(self) -> list[Observation]:
        return [page for page in self.pages if page.load_ok]

    @property
    def forms(self) -> list[FormFact]:
        """Every distinct form, with the pages that carry it."""
        by_signature: dict[str, FormFact] = {}
        for page in self.observed_pages:
            for form in page.forms:
                fact = FormFact(form=form)
                existing = by_signature.get(fact.slug)
                if existing is None:
                    fact.pages = [page.final_url]
                    by_signature[fact.slug] = fact
                elif page.final_url not in existing.pages:
                    existing.pages.append(page.final_url)
        return sorted(by_signature.values(), key=lambda f: f.slug)

    @property
    def third_party_vendors(self) -> list[VendorFact]:
        return [v for v in self.vendors.values() if not v.first_party]

    @property
    def consent_required_vendors(self) -> list[VendorFact]:
        from ..core.enums import ConsentClass

        return [
            v for v in self.third_party_vendors if v.vendor.consent_class is ConsentClass.REQUIRED
        ]

    @property
    def cmp_detected(self) -> list[str]:
        names: list[str] = []
        for page in self.observed_pages:
            for name in page.cmp_detected:
                if name not in names:
                    names.append(name)
        if any(page.tcf_api_present for page in self.observed_pages) and "TCF API" not in names:
            names.append("TCF API")
        return names

    @property
    def ai_markers(self) -> list[str]:
        markers: list[str] = []
        for page in self.observed_pages:
            for marker in page.ai_markers:
                if marker not in markers:
                    markers.append(marker)
        return markers

    @property
    def has_cmp(self) -> bool:
        return bool(self.cmp_detected)

    def art13_missing(self, kind: str = "privacy") -> list[str]:
        """Only elements due in every case; see ART13_CONDITIONAL."""
        doc = self.docs_by_kind.get(kind)
        if doc is None or not doc.ok:
            return []
        return [k for k, present in doc.elements.items() if not present and k not in ART13_CONDITIONAL]

    def art13_missing_conditional(self, kind: str = "privacy") -> list[str]:
        doc = self.docs_by_kind.get(kind)
        if doc is None or not doc.ok:
            return []
        return [k for k, present in doc.elements.items() if not present and k in ART13_CONDITIONAL]

    def has_document(self, kind: str) -> bool:
        doc = self.docs_by_kind.get(kind)
        return bool(doc and doc.ok)

    def header(self, name: str) -> str | None:
        return self.obs.response_headers.get(name.lower())

    @property
    def csp_report_only(self) -> str | None:
        """A `Content-Security-Policy-Report-Only` header, if one is served.

        It enforces nothing, so a site that has only this one has no policy in
        force and `PM-SEC-03` is right to fire. But telling an operator "no
        Content-Security-Policy" when their response carries a header by very
        nearly that name is how a true finding gets dismissed as a false one —
        they check, they see a CSP, they stop reading. The finding stands; the
        evidence says which of the two situations it is."""
        return self.header("content-security-policy-report-only")

    def effective_csp(self) -> tuple[str | None, str]:
        """The policy actually in force, and where it comes from.

        A meta element is a weaker instrument than a header — it cannot carry
        `frame-ancestors` or `report-uri`, and it applies only from the point
        the parser reaches it — but it is a real policy, and on hosting that
        forbids custom headers it is the only one available.
        """
        header = self.header("content-security-policy")
        if header:
            return header, "header"
        if self.obs.meta_csp:
            return self.obs.meta_csp, "meta"
        return None, "none"

    def effective_referrer_policy(self) -> tuple[str | None, str]:
        header = self.header("referrer-policy")
        if header:
            return header, "header"
        if self.obs.meta_referrer:
            return self.obs.meta_referrer, "meta"
        return None, "none"

    @property
    def fixed_header_platform(self) -> str | None:
        """The vendor id of hosting that serves response headers nobody can
        change, or None.

        The fact lives in `vendors.yml` rather than in a literal here: which
        platforms permit a header is knowledge about a vendor, and it changes
        when the vendor changes rather than when this file does."""
        for vendor_id, fact in self.vendors.items():
            if fact.vendor.response_headers_fixed:
                return vendor_id
        return None

    @property
    def headers_configurable(self) -> bool:
        """False on hosting that serves fixed response headers. Sending someone
        to "set a header" where the platform does not allow it wastes their
        afternoon and leaves the finding open forever."""
        return self.fixed_header_platform is None


def _embed_origin(req: Request, site_host: str) -> str | None:
    """The third-party document this request was made inside, or None.

    None covers three cases that are all "the site did this": the page issued
    the request itself, the frame belongs to the site, and the frame is the
    vendor loading its own resources — a YouTube player fetching from YouTube is
    still the embed the site chose, and the request that fetches the frame's own
    document is issued by that frame before it has a URL to be judged by.
    """
    if not req.frame_depth or not req.frame_url:
        return None
    embed_host = urlsplit(req.frame_url).netloc.lower()
    if not embed_host or is_first_party(embed_host, site_host):
        return None
    if is_first_party(req.host, embed_host):
        return None
    return embed_host


def _first_party_vendor(domain: str) -> Vendor:
    from ..core.enums import ConsentClass, VendorCategory

    return Vendor(
        id=f"self-{domain}",
        vendor=domain,
        product=domain,
        category=VendorCategory.INFRA,
        jurisdiction="self",
        transfer=TransferScope.EEA,
        storage_access=True,
        consent_class=ConsentClass.TECHNICAL,
        data_types=(),
        remediation=VendorRemediation(pattern="declare_processor"),
    )


def build_context(
    observations: Observation | list[Observation],
    documents: list[DocumentEvidence] | None = None,
    tls: Any | None = None,
) -> Context:
    """Facts from one or more pages of the same site.

    Accumulation is by identity, not by count: a vendor contacted on four pages
    is one vendor with four pages attributed to it, and a cookie present
    everywhere is one cookie that was first seen somewhere. Counting the same
    fact once per page would inflate every number in the report.
    """
    pages = [observations] if isinstance(observations, Observation) else list(observations)
    if not pages:
        raise ValueError("build_context needs at least one observation")
    entry = pages[0]
    documents = documents or []

    site_host = entry.host or urlsplit(entry.url).netloc
    ctx = Context(
        obs=entry,
        pages=pages,
        documents=documents,
        tls=tls,
        site_host=site_host,
        site_domain=registered_domain(site_host),
    )

    platform = identify_platform(entry.generator_meta, entry.html or "")
    if platform:
        ctx.platform_id, ctx.platform_name = platform.id, platform.name

    for doc in documents:
        if doc.ok and doc.kind not in ctx.docs_by_kind:
            ctx.docs_by_kind[doc.kind] = doc
        ctx.declared_vendor_ids.update(doc.declared_vendors)

    # --- hosts contacted, across every page observed
    #
    # Two attributions are collected per vendor and reconciled afterwards: was
    # it ever contacted by the page itself, and which embedded document reached
    # it otherwise. A vendor seen both ways is a vendor the site chose.
    contacted_directly: set[str] = set()
    embed_by_vendor: dict[str, str] = {}

    for page in ctx.observed_pages:
        page_url = page.final_url or page.url
        for req in page.requests:
            host = req.host
            if not host:
                continue
            first_party = is_first_party(host, site_host)
            key = f"self-{ctx.site_domain}" if first_party else vendor_for(host).id

            embed = _embed_origin(req, site_host)
            if embed is None:
                contacted_directly.add(key)
            else:
                embed_by_vendor.setdefault(key, embed)

            fact = ctx.vendors.get(key)
            if fact is None:
                vendor = _first_party_vendor(ctx.site_domain) if first_party else vendor_for(host)
                fact = VendorFact(vendor=vendor, first_party=first_party)
                ctx.vendors[key] = fact
            if host not in fact.hosts:
                fact.hosts.append(host)
            if page_url not in fact.pages:
                fact.pages.append(page_url)
            if len(fact.sample_urls) < 5 and req.url not in fact.sample_urls:
                fact.sample_urls.append(req.url)
            if req.resource_type not in fact.resource_types:
                fact.resource_types.append(req.resource_type)

    for vendor_key, embed in embed_by_vendor.items():
        if vendor_key not in contacted_directly and vendor_key in ctx.vendors:
            ctx.vendors[vendor_key].via_embed = embed

    # --- processors visible only in the response headers of the entry page
    for vendor_id in infra_from_headers(entry.response_headers):
        if vendor_id in ctx.vendors:
            continue
        vendor = lookup_by_id(vendor_id)
        if vendor is None:
            continue
        ctx.vendors[vendor_id] = VendorFact(
            vendor=vendor,
            detection=Detection.HEADER,
            first_party=False,
            pages=[entry.final_url or entry.url],
        )

    for fact in ctx.vendors.values():
        if fact.first_party:
            fact.transfer = TransferScope.EEA
            fact.declared = True
            continue
        fact.transfer = transfer_scope(fact.hosts[0]) if fact.hosts else fact.vendor.transfer
        fact.declared = fact.vendor.id in ctx.declared_vendor_ids
        fact.declared_in = [d.kind for d in documents if fact.vendor.id in d.declared_vendors]

    # --- cookies and terminal storage, deduplicated across pages
    seen_cookies: set[tuple[str, str]] = set()
    seen_storage: set[tuple[str, str]] = set()
    for page in ctx.observed_pages:
        page_url = page.final_url or page.url
        for cookie in page.cookies:
            identity = (cookie.domain, cookie.name)
            if identity in seen_cookies:
                continue
            seen_cookies.add(identity)
            data_class, hint = classify_key(cookie.name)
            third_party = not is_first_party(cookie.domain.lstrip("."), site_host)
            vendor_id = hint or (vendor_for(cookie.domain.lstrip(".")).id if third_party else None)
            ctx.cookies.append(
                CookieFact(
                    cookie=cookie,
                    data_class=data_class,
                    vendor_id=vendor_id,
                    third_party=third_party,
                    declared=bool(vendor_id and vendor_id in ctx.declared_vendor_ids),
                    first_seen_page=page_url,
                )
            )
        for entry_key in page.storage:
            identity = (entry_key.kind, entry_key.key)
            if identity in seen_storage:
                continue
            seen_storage.add(identity)
            data_class, hint = classify_key(entry_key.key)
            ctx.storage.append(
                StorageFact(
                    entry=entry_key,
                    data_class=data_class,
                    vendor_id=hint,
                    first_seen_page=page_url,
                )
            )

    return ctx
