"""Subjects: what a rule iterates over.

`per: vendor` is what lets one generic rule replace privacy-pa's one-rule-per-
tracker table. A subject carries three things: the graph node it belongs to,
the parameters its rule's text will be formatted with, and the evidence that
proves it. All three are language-neutral — parameters that are canonical
values stay canonical values and are translated at render time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from ..core.enums import SubjectKind
from .context import Context, CookieFact, StorageFact, VendorFact


def key(catalogue_key: str) -> dict[str, str]:
    """Mark a parameter as a catalogue key rather than a literal.

    Used where the value itself is a phrase — "Unidentified third party" — that
    has to be translated before it is substituted into a sentence.
    """
    return {"__key__": catalogue_key}


@dataclass(slots=True)
class Subject:
    kind: SubjectKind
    slug: str
    node_id: str
    params: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    payload: Any = None


def _site(ctx: Context) -> list[Subject]:
    return [
        Subject(
            kind=SubjectKind.SITE,
            slug="site",
            node_id=f"site:{ctx.site_domain}",
            params={"site": ctx.site_domain, "host": ctx.site_host},
            payload=ctx,
        )
    ]


def _vendors(ctx: Context) -> list[Subject]:
    out: list[Subject] = []
    for fact in sorted(ctx.vendors.values(), key=lambda f: f.vendor.id):
        vendor = fact.vendor
        out.append(
            Subject(
                kind=SubjectKind.VENDOR,
                slug=vendor.id,
                node_id=f"vendor:{vendor.id}",
                params={
                    "vendor": vendor.vendor or key(f"remediation.{vendor.vendor_key}"),
                    "product": vendor.product,
                    "category": vendor.category,
                    "jurisdiction": vendor.jurisdiction,
                    "hosts": ", ".join(fact.hosts[:6]) or vendor.product,
                    "transfer": fact.transfer,
                    "consent_class": vendor.consent_class,
                    "data_types": list(vendor.data_types),
                },
                evidence={
                    "detected_via": fact.detection,
                    # Stated rather than implied. A vendor missing from the
                    # findings because it sits inside somebody else's embed must
                    # still be visible as a recipient, or suppressing the wrong
                    # finding becomes hiding a real transfer.
                    "reached_through": fact.via_embed,
                    "pages": fact.pages,
                    "hosts": fact.hosts,
                    "observed_requests": fact.sample_urls,
                    "resource_types": fact.resource_types,
                    "transfer": fact.transfer,
                    "transfer_basis": (
                        key(f"remediation.transfer_basis.{vendor.transfer_basis}")
                        if vendor.transfer_basis
                        else None
                    ),
                    "declared_in": fact.declared_in,
                },
                payload=fact,
            )
        )
    return out


def _cookies(ctx: Context) -> list[Subject]:
    out: list[Subject] = []
    for fact in ctx.cookies:
        cookie = fact.cookie
        out.append(
            Subject(
                kind=SubjectKind.COOKIE,
                slug=f"{cookie.domain}|{cookie.name}",
                node_id=f"cookie:{cookie.domain}|{cookie.name}",
                params={
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "class": fact.data_class,
                    "lifetime": key(
                        "report.labels.session" if cookie.session else "report.labels.persistent"
                    ),
                },
                evidence={
                    "name": cookie.name,
                    "domain": cookie.domain,
                    "first_seen_page": fact.first_seen_page,
                    "secure": cookie.secure,
                    "http_only": cookie.http_only,
                    "same_site": cookie.same_site,
                    "session": cookie.session,
                    "classification": fact.data_class,
                    "attributed_to": fact.vendor_id,
                },
                payload=fact,
            )
        )
    return out


def _storage(ctx: Context) -> list[Subject]:
    out: list[Subject] = []
    for fact in ctx.storage:
        entry = fact.entry
        out.append(
            Subject(
                kind=SubjectKind.STORAGE,
                slug=f"{entry.kind}|{entry.key}",
                node_id=f"storage:{entry.kind}|{entry.key}",
                params={"key": entry.key, "kind": entry.kind, "class": fact.data_class},
                evidence={
                    "kind": entry.kind,
                    "key": entry.key,
                    "size": entry.size,
                    "classification": fact.data_class,
                    "first_seen_page": fact.first_seen_page,
                },
                payload=fact,
            )
        )
    return out


def _forms(ctx: Context) -> list[Subject]:
    out: list[Subject] = []
    for fact in ctx.forms:
        form = fact.form
        out.append(
            Subject(
                kind=SubjectKind.FORM,
                slug=fact.slug,
                node_id=f"page:{fact.pages[0]}" if fact.pages else f"site:{ctx.site_domain}",
                params={"action": form.action, "action_host": form.action_host},
                evidence={
                    "action": form.action,
                    "method": form.method,
                    "fields": form.fields,
                    "privacy_checkbox": form.has_privacy_checkbox,
                    "has_password": form.has_password,
                    "pages": fact.pages,
                },
                payload=form,
            )
        )
    return out


BUILDERS: dict[SubjectKind, Callable[[Context], list[Subject]]] = {
    SubjectKind.SITE: _site,
    SubjectKind.VENDOR: _vendors,
    SubjectKind.COOKIE: _cookies,
    SubjectKind.STORAGE: _storage,
    SubjectKind.FORM: _forms,
}


def build(kind: SubjectKind, ctx: Context) -> list[Subject]:
    builder = BUILDERS.get(kind)
    return builder(ctx) if builder else []
