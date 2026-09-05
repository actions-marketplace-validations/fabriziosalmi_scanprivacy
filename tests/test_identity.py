"""The identity surface.

What this mission is allowed to look at, and what it deliberately does not:

- **Observed**: identity providers actually contacted, the hygiene of cookies
  that carry a session identifier, and the posture of a form containing a
  password field — its scheme, its destination, whether the page can be framed.
- **Never**: submitting a form, authenticating, probing for `/admin` or
  `/wp-login.php`. Multi-factor policy, password rules and role models are not
  observable from outside, and inventing them would be worse than omitting them.
"""

from __future__ import annotations

from pmate.analyze.context import build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.core.enums import ConsentClass, TransferScope, VendorCategory
from pmate.knowledge.registry import vendor_for
from pmate.observe.browser import CookieSet, FormInfo, Observation, Request


def _page(url: str = "https://x.it/") -> Observation:
    page = Observation(url=url, final_url=url, load_ok=True, status=200)
    page.response_headers = {"content-type": "text/html"}
    return page


def _login_form(action: str = "https://x.it/login", scheme: str = "https", page: str = "https://x.it/login"):
    from urllib.parse import urlsplit

    return FormInfo(
        action=action,
        action_host=urlsplit(action).netloc.lower(),
        method="post",
        fields=["text:user", "password:pass"],
        has_privacy_checkbox=False,
        has_password=True,
        page_url=page,
        page_scheme=scheme,
    )


# ------------------------------------------------------- identity providers


def test_identity_providers_are_attributed_as_such():
    """An identity provider receives who the user is, not merely that a visitor
    arrived. Filing it under "generic infrastructure" loses that."""
    for host, expected in (
        ("accounts.google.com", "google-identity"),
        ("login.microsoftonline.com", "microsoft-entra"),
        ("acme.okta.com", "okta"),
        ("tenant.eu.auth0.com", "auth0"),
        ("login.spid.gov.it", "spid"),
    ):
        vendor = vendor_for(host)
        assert vendor.id == expected, host
        assert vendor.category is VendorCategory.IDENTITY


def test_an_identity_provider_is_a_recipient_like_any_other():
    """No new rule was needed: putting the facts in the knowledge base makes the
    transfer and disclosure rules reach identity providers too."""
    page = _page()
    page.requests = [
        Request("https://acme.okta.com/oauth2/v1/authorize", "acme.okta.com", "GET", "/oauth2", 200, None, "document")
    ]
    ctx = build_context([page])
    ids = {f.rule_id for f in evaluate(ctx, load_rules())}
    assert "PM-TRF-01" in ids  # Okta processes outside the EEA


def test_a_european_identity_provider_is_not_reported_as_a_transfer():
    page = _page()
    page.requests = [
        Request("https://login.spid.gov.it/", "login.spid.gov.it", "GET", "/", 200, None, "document")
    ]
    ctx = build_context([page])
    assert vendor_for("login.spid.gov.it").transfer is TransferScope.EEA
    assert "PM-TRF-01" not in {f.rule_id for f in evaluate(ctx, load_rules())}
    assert vendor_for("login.spid.gov.it").consent_class is ConsentClass.TECHNICAL


# ------------------------------------------------------------ session hygiene


def test_a_session_cookie_readable_by_javascript_is_reported():
    """Every third-party script on the page can read what JavaScript can read;
    a stolen session identifier is a logged-in user."""
    page = _page()
    page.cookies = [CookieSet("PHPSESSID", "x.it", "/", True, False, "Lax", None, True)]
    findings = evaluate(build_context([page]), load_rules())
    assert "PM-IAM-01" in {f.rule_id for f in findings}


def test_a_session_cookie_without_secure_is_reported():
    page = _page()
    page.cookies = [CookieSet("JSESSIONID", "x.it", "/", False, True, "Lax", None, True)]
    findings = evaluate(build_context([page]), load_rules())
    assert "PM-IAM-02" in {f.rule_id for f in findings}


def test_a_well_set_session_cookie_produces_nothing():
    page = _page()
    page.cookies = [CookieSet("PHPSESSID", "x.it", "/", True, True, "Lax", None, True)]
    findings = {f.rule_id for f in evaluate(build_context([page]), load_rules())}
    assert "PM-IAM-01" not in findings and "PM-IAM-02" not in findings


def test_an_ordinary_cookie_is_not_treated_as_a_session():
    """The session rules must not fire on every cookie that happens to lack a
    flag, or the identity findings drown in noise."""
    page = _page()
    page.cookies = [CookieSet("theme", "x.it", "/", False, False, "Lax", None, True)]
    findings = {f.rule_id for f in evaluate(build_context([page]), load_rules())}
    assert "PM-IAM-01" not in findings and "PM-IAM-02" not in findings


# ------------------------------------------------------------ login posture


def test_a_password_field_over_plain_http_is_critical():
    from pmate.core.enums import Severity

    page = _page("http://x.it/login")
    page.forms = [_login_form(action="http://x.it/login", scheme="http", page="http://x.it/login")]
    findings = evaluate(build_context([page]), load_rules())
    critical = [f for f in findings if f.rule_id == "PM-IAM-03"]
    assert critical and critical[0].severity is Severity.CRITICAL


def test_credentials_posted_to_a_third_party_are_reported():
    page = _page()
    page.forms = [_login_form(action="https://auth.example-saas.com/session")]
    findings = evaluate(build_context([page]), load_rules())
    assert "PM-IAM-04" in {f.rule_id for f in findings}


def test_a_credential_page_that_can_be_framed_is_reported():
    page = _page()
    page.forms = [_login_form()]
    findings = evaluate(build_context([page]), load_rules())
    assert "PM-IAM-05" in {f.rule_id for f in findings}


def test_framing_protection_from_either_header_satisfies_the_rule():
    for headers in (
        {"x-frame-options": "SAMEORIGIN"},
        {"content-security-policy": "default-src 'self'; frame-ancestors 'self'"},
    ):
        page = _page()
        page.response_headers = {"content-type": "text/html", **headers}
        page.forms = [_login_form()]
        findings = {f.rule_id for f in evaluate(build_context([page]), load_rules())}
        assert "PM-IAM-05" not in findings, headers


def test_a_form_without_a_password_field_is_not_an_identity_finding():
    """A newsletter box is not a login form."""
    page = _page()
    page.forms = [
        FormInfo(
            action="https://x.it/newsletter",
            action_host="x.it",
            method="post",
            fields=["email:email"],
            has_privacy_checkbox=True,
            has_password=False,
            page_url="https://x.it/",
            page_scheme="https",
        )
    ]
    findings = {f.rule_id for f in evaluate(build_context([page]), load_rules())}
    assert not {"PM-IAM-03", "PM-IAM-04", "PM-IAM-05"} & findings


def test_nothing_is_ever_submitted():
    """The guarantee the whole method rests on, asserted against the source:
    the engine reads forms and never fills or submits them."""
    from pathlib import Path

    browser = Path("src/pmate/observe/browser.py").read_text(encoding="utf-8")
    for forbidden in (".fill(", ".type(", "form.submit", ".press(", "requestSubmit"):
        assert forbidden not in browser, forbidden


# ------------------------------------------------- one form, however many pages


def test_the_same_form_on_five_pages_is_one_finding():
    """A login form in a shared header is one form. Counting it per page
    inflates the report the same way counting a vendor per page would."""
    pages = []
    for path in ("/", "/contatti", "/chi-siamo"):
        page = _page(f"https://x.it{path}")
        page.forms = [_login_form()]
        pages.append(page)

    ctx = build_context(pages)
    assert len(ctx.forms) == 1
    assert ctx.forms[0].pages == ["https://x.it/", "https://x.it/contatti", "https://x.it/chi-siamo"]
    findings = [f for f in evaluate(ctx, load_rules()) if f.rule_id == "PM-IAM-05"]
    assert len(findings) == 1
    assert findings[0].evidence["pages"] == ctx.forms[0].pages


def test_a_form_identity_is_stable_across_page_order():
    """An index-based id would shift as soon as page order changed, and every
    SARIF alert would be recreated and every diff would report churn."""
    first = _page("https://x.it/")
    first.forms = [_login_form()]
    second = _page("https://x.it/contatti")
    second.forms = [_login_form(), _login_form(action="https://x.it/search")]

    forward = {f.slug for f in build_context([first, second]).forms}
    backward = {f.slug for f in build_context([second, first]).forms}
    assert forward == backward
    assert len(forward) == 2


def test_two_different_forms_stay_two_findings():
    page = _page()
    page.forms = [_login_form(), _login_form(action="https://auth.example-saas.com/session")]
    ctx = build_context([page])
    assert len(ctx.forms) == 2
    assert "PM-IAM-04" in {f.rule_id for f in evaluate(ctx, load_rules())}


def test_a_rotating_csrf_token_does_not_split_one_form_into_many():
    """Observed on the pilot site: the same Joomla login form produced five
    findings, because the CSRF token and an anti-spam honeypot change name on
    every load. Five ids also means five new SARIF alerts on every scan."""
    pages = []
    for token, honeypot in (("304025d6c721c819", "your_name_here"), ("64439e8e3bee75f4", "my_name")):
        page = _page(f"https://x.it/{token}")
        form = _login_form(action="https://x.it/cb-login")
        form.fields = [
            "hidden:option",
            f"hidden:{token}",
            "text:username",
            "password:passwd",
            f"text:{honeypot}",
        ]
        page.forms = [form]
        pages.append(page)

    ctx = build_context(pages)
    assert len(ctx.forms) == 1
    assert len([f for f in evaluate(ctx, load_rules()) if f.rule_id == "PM-IAM-05"]) == 1


def test_a_search_box_and_a_login_form_stay_distinct():
    page = _page()
    login = _login_form(action="https://x.it/go")
    login.fields = ["text:username", "password:passwd"]
    search = _login_form(action="https://x.it/go")
    search.has_password = False
    search.fields = ["text:q"]
    page.forms = [login, search]
    assert len(build_context([page]).forms) == 2
