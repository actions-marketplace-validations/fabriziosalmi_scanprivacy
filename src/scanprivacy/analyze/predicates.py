"""The predicate vocabulary — the closed DSL rules are written in.

Two constraints, both deliberate and both inherited from privacy-pa:

1. **The DSL is closed.** Every predicate is an explicit function registered
   here. Adding one means writing a function and documenting it in
   `rules/README.md`. An expressive DSL would allow rules nobody can review.
2. **An unknown predicate makes the rule not fire.** A rule the engine cannot
   fully evaluate must never produce a half-evaluated finding.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

from ..core.enums import ConsentClass, DataClass, TransferScope
from ..knowledge.registry import is_first_party
from .context import Context, CookieFact, StorageFact, VendorFact
from .subjects import Subject

logger = logging.getLogger("scanprivacy.rules")

Predicate = Callable[[Context, Subject, Any], bool]

REGISTRY: dict[str, Predicate] = {}

# Session identifiers, by the names the common stacks use. Name-based like the
# tracking classifier, and for the same reason: the flag that matters is on the
# cookie, whatever set it.
SESSION_COOKIE = re.compile(
    r"^(PHPSESSID|JSESSIONID|ASP\.NET_SessionId|ASPSESSIONID|CFID|CFTOKEN|"
    r"laravel_session|connect\.sid|express:sess|_session_id|sessionid|session_id|"
    r"sid|SSESS[0-9a-f]+|wordpress_logged_in_|symfony|rack\.session|JSESSION|"
    r"SESS[0-9a-f]{16,})",
    re.I,
)


def predicate(name: str) -> Callable[[Predicate], Predicate]:
    def register(fn: Predicate) -> Predicate:
        REGISTRY[name] = fn
        return fn

    return register


# ------------------------------------------------------------------ vendors


@predicate("vendor_third_party")
def _third_party(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return (not fact.first_party) is bool(arg)


@predicate("vendor_via_embed")
def _via_embed(ctx: Context, s: Subject, arg: Any) -> bool:
    """Was this vendor only ever reached from inside a third-party embed?

    Every rule below that says the *site* did something takes
    `vendor_via_embed: false`, because a site answers for the embed it chose and
    not for what that embed loads internally. The vendor stays in the inventory
    — the visitor's data did reach it, and the Art. 30 record should say so —
    attributed to the embed rather than to a decision the operator never made.
    """
    fact: VendorFact = s.payload
    return (fact.via_embed is not None) is bool(arg)


@predicate("vendor_extra_eea")
def _extra_eea(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return (fact.transfer is not TransferScope.EEA) is bool(arg)


@predicate("vendor_category_any")
def _category_any(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return fact.vendor.category.value in set(arg)


@predicate("vendor_consent_class_any")
def _consent_class_any(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return fact.vendor.consent_class.value in set(arg)


@predicate("vendor_storage_access")
def _storage_access(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return fact.vendor.storage_access is bool(arg)


@predicate("vendor_resource_type_any")
def _resource_type_any(ctx: Context, s: Subject, arg: Any) -> bool:
    """What the vendor was actually observed serving.

    A tracker known to write identifiers, but seen here delivering a single
    image, cannot have executed: the transfer is real, the storage access is
    not. Severity follows the observation, never the vendor's reputation.
    """
    fact: VendorFact = s.payload
    return bool(set(fact.resource_types) & set(arg))


@predicate("vendor_declared")
def _declared(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return fact.declared is bool(arg)


@predicate("vendor_known")
def _known(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    return fact.vendor.known is bool(arg)


# ------------------------------------------------------------------ cookies


@predicate("cookie_class_any")
def _cookie_class_any(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: CookieFact = s.payload
    return fact.data_class.value in set(arg)


@predicate("cookie_third_party")
def _cookie_third_party(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: CookieFact = s.payload
    return fact.third_party is bool(arg)


@predicate("cookie_attribute_missing")
def _cookie_attribute_missing(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: CookieFact = s.payload
    attribute = str(arg).lower()
    if attribute == "secure":
        return not fact.cookie.secure
    if attribute == "httponly":
        return not fact.cookie.http_only
    if attribute == "samesite":
        # Chromium reports "Lax" both when the attribute is set and when it is
        # merely defaulted, so absence is not observable. Only an explicit
        # SameSite=None is a fact we can state — see cookie_samesite_none.
        return fact.cookie.same_site in (None, "")
    return False


@predicate("cookie_samesite_none")
def _cookie_samesite_none(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: CookieFact = s.payload
    return (str(fact.cookie.same_site) == "None") is bool(arg)


# ------------------------------------------------------------------ storage


@predicate("storage_class_any")
def _storage_class_any(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: StorageFact = s.payload
    return fact.data_class.value in set(arg)


# -------------------------------------------------------------------- forms


@predicate("form_action_third_party")
def _form_third_party(ctx: Context, s: Subject, arg: Any) -> bool:
    form = s.payload
    if not form.action_host:
        return False
    return (not is_first_party(form.action_host, ctx.site_host)) is bool(arg)


@predicate("form_privacy_checkbox")
def _form_checkbox(ctx: Context, s: Subject, arg: Any) -> bool:
    return s.payload.has_privacy_checkbox is bool(arg)


@predicate("form_has_password")
def _form_has_password(ctx: Context, s: Subject, arg: Any) -> bool:
    return bool(getattr(s.payload, "has_password", False)) is bool(arg)


@predicate("form_page_not_https")
def _form_page_not_https(ctx: Context, s: Subject, arg: Any) -> bool:
    """A credential field on a page delivered over plain HTTP. Observed from
    the scheme the page was actually served with, not from what it links to."""
    return (getattr(s.payload, "page_scheme", "https") != "https") is bool(arg)


@predicate("framing_protection_absent")
def _framing_protection_absent(ctx: Context, s: Subject, arg: Any) -> bool:
    """No X-Frame-Options and no CSP frame-ancestors: the page can be framed,
    which is how a credential form gets clickjacked."""
    xfo = ctx.header("x-frame-options")
    csp = ctx.header("content-security-policy") or ""
    protected = bool(xfo) or "frame-ancestors" in csp.lower()
    return (not protected) is bool(arg)


@predicate("cookie_looks_like_session")
def _cookie_looks_like_session(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: CookieFact = s.payload
    return bool(SESSION_COOKIE.search(fact.cookie.name)) is bool(arg)


# --------------------------------------------------------------------- site


@predicate("privacy_document_present")
def _privacy_present(ctx: Context, s: Subject, arg: Any) -> bool:
    return ctx.has_document("privacy") is bool(arg)


@predicate("missing_document")
def _missing_document(ctx: Context, s: Subject, arg: Any) -> bool:
    return not ctx.has_document(str(arg))


@predicate("document_link_absent")
def _document_link_absent(ctx: Context, s: Subject, arg: Any) -> bool:
    return not any(
        link.kind == str(arg) for page in ctx.observed_pages for link in page.legal_links
    )


@predicate("art13_missing_any")
def _art13_missing_any(ctx: Context, s: Subject, arg: Any) -> bool:
    return bool(ctx.art13_missing("privacy")) is bool(arg)


@predicate("cookie_section_incomplete")
def _cookie_section_incomplete(ctx: Context, s: Subject, arg: Any) -> bool:
    doc = ctx.docs_by_kind.get("cookie") or ctx.docs_by_kind.get("privacy")
    if doc is None or not doc.ok:
        return bool(arg)  # no document at all is the incomplete case
    return (not all(doc.cookie_elements.values())) is bool(arg)


@predicate("header_missing")
def _header_missing(ctx: Context, s: Subject, arg: Any) -> bool:
    return ctx.header(str(arg)) is None


@predicate("header_regex_not_matching")
def _header_regex_not_matching(ctx: Context, s: Subject, arg: Any) -> bool:
    value = ctx.header(str(arg["name"]))
    if value is None:
        return True
    return not re.search(arg["regex"], value, re.I)


@predicate("csp_absent")
def _csp_absent(ctx: Context, s: Subject, arg: Any) -> bool:
    """No policy at all, from either instrument."""
    policy, _ = ctx.effective_csp()
    return (policy is None) is bool(arg)


@predicate("referrer_policy_permissive")
def _referrer_policy_permissive(ctx: Context, s: Subject, arg: Any) -> bool:
    policy, _ = ctx.effective_referrer_policy()
    if policy is None:
        return bool(arg)
    restrictive = re.search(r"no-referrer|same-origin|strict-origin", policy, re.I)
    return (not restrictive) is bool(arg)


@predicate("tls_classification")
def _tls_classification(ctx: Context, s: Subject, arg: Any) -> bool:
    return bool(ctx.tls and ctx.tls.ok and ctx.tls.classification == str(arg))


@predicate("cmp_present")
def _cmp_present(ctx: Context, s: Subject, arg: Any) -> bool:
    return ctx.has_cmp is bool(arg)


@predicate("consent_required_vendors_present")
def _consent_required_present(ctx: Context, s: Subject, arg: Any) -> bool:
    return bool(ctx.consent_required_vendors) is bool(arg)


@predicate("tracking_state_before_consent")
def _tracking_state(ctx: Context, s: Subject, arg: Any) -> bool:
    tracking = [c for c in ctx.cookies if c.data_class is DataClass.TRACKING]
    tracking += [st for st in ctx.storage if st.data_class is DataClass.TRACKING]
    return bool(tracking) is bool(arg)


@predicate("dpia_criteria_min")
def _dpia_criteria_min(ctx: Context, s: Subject, arg: Any) -> bool:
    """How many WP248 criteria the *observable* surface meets.

    Counts only what was seen. Scale, vulnerable subjects, special categories
    and legal effects are invisible from outside and are never counted — the
    screening reports them as unanswered instead of assuming they are absent.
    """
    from .dpia import screen

    return len(screen(ctx).met) >= int(arg)


@predicate("ai_marker_any")
def _ai_marker_any(ctx: Context, s: Subject, arg: Any) -> bool:
    return any(marker in ctx.ai_markers for marker in arg)


@predicate("ai_disclosure_absent")
def _ai_disclosure_absent(ctx: Context, s: Subject, arg: Any) -> bool:
    disclosed = bool({"ai-meta-disclosure", "ai-generated-badge"} & set(ctx.ai_markers))
    doc = ctx.docs_by_kind.get("privacy")
    if doc and doc.ok and re.search(
        r"\bintelligenza\s+artificiale\b|\bartificial\s+intelligence\b|\bai\b|\bllm\b|chatbot",
        doc.text,
        re.I,
    ):
        disclosed = True
    return (not disclosed) is bool(arg)


# ------------------------------------------------------------------ refusal


@predicate("refusal_performed")
def _refusal_performed(ctx: Context, s: Subject, arg: Any) -> bool:
    """True only when the engine actually refused, through a documented path.

    Fail-closed: if the refusal did not happen, no rule that depends on it may
    fire. A finding that says "still tracking after refusal" when no refusal
    took place would be a fabrication.
    """
    performed = bool(ctx.refusal is not None and getattr(ctx.refusal, "performed", False))
    return performed is bool(arg)


@predicate("refusal_not_possible")
def _refusal_not_possible(ctx: Context, s: Subject, arg: Any) -> bool:
    """A consent mechanism is there, and this engine has no documented way to
    refuse through it. Reported rather than hidden: the reader has to know the
    check was not performed."""
    if ctx.refusal is None:
        return not bool(arg)
    blocked = getattr(ctx.refusal, "outcome", "") in (
        "platform_not_recognised",
        "platform_not_ready",
        "control_ambiguous",
        "refusal_failed",
    )
    return blocked is bool(arg)


@predicate("vendor_present_before_refusal")
def _present_before(ctx: Context, s: Subject, arg: Any) -> bool:
    fact: VendorFact = s.payload
    before = ctx.before.vendors if ctx.before else {}
    return (fact.vendor.id in before) is bool(arg)


def evaluate_condition(ctx: Context, subject: Subject, condition: dict[str, Any]) -> bool:
    """AND across every key. Unknown predicate or raised exception: no fire.

    Not firing is the right answer in both cases — a rule the engine cannot
    evaluate must not assert anything — but it is not the *whole* answer. A
    predicate that throws is a defect in this engine, and if it goes unrecorded
    the only visible consequence is a finding that quietly stops appearing.
    That is the failure mode this project keeps meeting: something breaks and
    the report reads as clean.

    So: still no fire, and now a warning naming the rule and the predicate.
    """
    for name, arg in condition.items():
        fn = REGISTRY.get(name)
        if fn is None:
            logger.warning(
                "unknown predicate %r on subject %s — rule does not fire", name, subject.slug or subject.kind
            )
            return False
        try:
            if not fn(ctx, subject, arg):
                return False
        except Exception:
            logger.exception(
                "predicate %r raised on subject %s — rule does not fire", name, subject.slug or subject.kind
            )
            return False
    return True
