"""Offline tests: no network, no browser.

They cover the places where a bug is expensive — attribution, document
discovery, fail-closed grading, and the language-neutrality of the model — with
fixtures shaped like what the two pilot sites actually returned.
"""

from __future__ import annotations

import yaml

from pmate.analyze.context import build_context, classify_key, infra_from_headers
from pmate.analyze.diff import diff
from pmate.analyze.engine import evaluate, load_rules
from pmate.analyze.graph import build_graph
from pmate.analyze.predicates import REGISTRY
from pmate.analyze.verdict import grade
from pmate.config import KNOWLEDGE_DIR, RULES_DIR
from pmate.core.enums import (
    ConsentClass,
    DataClass,
    Effort,
    Grade,
    Severity,
    SubjectKind,
    TransferScope,
)
from pmate.core.models import Finding, priority_for
from pmate.i18n.translator import Translator
from pmate.knowledge.registry import all_vendors, is_extra_eea, mapping_for, vendor_for
from pmate.observe.browser import CookieSet, LegalLink, Observation, Request
from pmate.observe.discover import looks_like, pick_documents, score_link
from pmate.observe.docs import DocumentEvidence, _declared_vendors, _to_text


# ------------------------------------------------------------ rule catalogue


def test_knowledge_files_parse():
    for name in ("vendors.yml", "platforms.yml", "frameworks.yml"):
        assert yaml.safe_load((KNOWLEDGE_DIR / name).read_text(encoding="utf-8"))


def test_rules_ship_inside_the_package():
    """A `pip install` that cannot find its own rules is not an installation."""
    assert RULES_DIR.is_dir() and RULES_DIR.name == "rules"
    assert RULES_DIR.parent.name == "pmate"
    assert len(list(RULES_DIR.glob("PM-*.yml"))) >= 20


def test_every_rule_is_loadable_and_uses_known_predicates():
    rules = load_rules(RULES_DIR)
    assert rules
    for rule in rules:
        assert isinstance(rule.severity, Severity)
        assert isinstance(rule.subject, SubjectKind)
        assert rule.references, f"{rule.id} has no legal reference"
        for key in rule.condition:
            assert key in REGISTRY, f"{rule.id}: unknown predicate {key}"


def test_rule_ids_are_unique():
    ids = [r.id for r in load_rules(RULES_DIR)]
    assert len(ids) == len(set(ids))


def test_every_rule_has_text_and_a_mapping_in_every_locale():
    """A rule with no text renders as ⟦rules.PM-XX-01.title⟧ in a client's PDF."""
    for locale in ("en", "it"):
        t = Translator.for_locale(locale, strict=True)
        for rule in load_rules(RULES_DIR):
            assert t.rule(rule.id, "title")
            assert t.rule(rule.id, "description")
            if rule.remediation_source == "rule":
                assert t.rule(rule.id, "remediation.summary")
                assert t.rule_list(rule.id, "remediation.steps")
            for reference in rule.references:
                assert t.reference(reference) != reference, f"{locale}: {reference} not in catalogue"
            assert mapping_for(rule.id).owner


def test_every_vendor_remediation_pattern_exists_in_every_locale():
    for locale in ("en", "it"):
        t = Translator.for_locale(locale, strict=True)
        for vendor in all_vendors():
            base = f"remediation.pattern.{vendor.remediation.pattern}"
            assert t.t(f"{base}.summary")
            assert t.items(f"{base}.steps")
            for alternative in vendor.remediation.alternatives:
                assert t.t(f"remediation.alternative.{alternative}")
            for extra in vendor.remediation.extra_steps:
                assert t.t(f"remediation.extra.{extra}")


# -------------------------------------------------------------- attribution


def test_host_attribution_and_transfers():
    assert vendor_for("fonts.googleapis.com").id == "google-fonts"
    assert vendor_for("eu-cdn.clarity.ms").id == "microsoft-clarity"  # suffix match
    assert vendor_for("media.licdn.com").id == "linkedin-cdn"
    assert vendor_for("yt3.ggpht.com").id == "youtube"
    assert is_extra_eea("fonts.gstatic.com") is True
    assert is_extra_eea("www.comune.genova.it") is False
    unknown = vendor_for("data.accentapi.com")
    assert unknown.known is False and unknown.transfer is TransferScope.NON_EEA
    assert unknown.vendor is None and unknown.vendor_key == "unknown_third_party"


def test_infra_detected_from_response_headers():
    assert "cloudflare-cdn" in infra_from_headers({"server": "cloudflare", "cf-ray": "abc"})
    assert "github-pages" in infra_from_headers({"x-github-request-id": "1:2:3"})
    assert infra_from_headers({"server": "nginx"}) == []


def test_cookie_classification():
    assert classify_key("_ga")[0] is DataClass.TRACKING
    assert classify_key("_fbp")[0] is DataClass.TRACKING
    assert classify_key("cf_clearance")[0] is DataClass.FUNCTIONAL  # anti-abuse, necessary
    assert classify_key("2956a59626d4ce57fa044c61836f6815")[0] is DataClass.UNKNOWN


def test_declared_vendors_uses_word_boundaries():
    """'vercel' must not match the Italian city 'Vercelli', and 'meta' must not
    match 'metà'. This wrongly marked vendors as declared on the first run."""
    vendors = list(all_vendors())
    declared, _ = _declared_vendors("sede di Vercelli, Piemonte", vendors)
    assert "vercel" not in declared
    declared, _ = _declared_vendors("hosting fornito da Vercel Inc.", vendors)
    assert "vercel" in declared


def test_a_vendor_named_only_to_deny_it_is_not_declared():
    vendors = list(all_vendors())
    declared, negated = _declared_vendors(
        "This site uses no analytics and no advertising: no Google Ads, no Meta Pixel.", vendors
    )
    assert "google-ads" in negated and "google-ads" not in declared
    declared, negated = _declared_vendors("We use Google Ads to measure our campaigns.", vendors)
    assert "google-ads" in declared and "google-ads" not in negated


def test_aliases_are_pooled_across_locales():
    """The language of a site's notice is unknown when the scan starts."""
    from pmate.knowledge.registry import aliases_for

    pool = aliases_for("youtube")
    assert "embedded video" in pool and "video incorporati" in pool


def test_html_entities_are_resolved_before_matching():
    assert "Processors & international transfers" in _to_text(
        "<p>Processors &amp; international transfers</p>"
    )
    assert "è" in _to_text("<p>Titolare &egrave; Tizio</p>")


# ------------------------------------------------------- document discovery


def test_article_about_privacy_scores_below_the_notice():
    article = score_link(
        "privacy",
        "Webinar: il contenzioso con il Garante per la protezione dei dati personali",
        "https://www.federprivacy.org/attivita/agenda/webinar-il-contenzioso-con-il-garante",
    )[0]
    notice = score_link(
        "privacy",
        "Informativa privacy",
        "https://www.federprivacy.org/associazione/informativa-privacy",
    )[0]
    assert notice > article
    assert article < 3  # below the acceptance threshold


def test_pick_documents_prefers_the_real_notice():
    obs = Observation(url="https://x.it", final_url="https://x.it", load_ok=True, status=200)
    obs.legal_links = [
        LegalLink(
            "privacy",
            "Privacy nella sanità: il nuovo provvedimento",
            "https://x.it/news/privacy-sanita-2026",
        ),
        LegalLink("privacy", "Informativa privacy", "https://x.it/privacy"),
    ]
    assert [c.url for c in pick_documents(obs)] == ["https://x.it/privacy"]


def test_looks_like_rejects_an_article():
    assert looks_like(
        "privacy", "Titolare del trattamento è … ai sensi del GDPR … diritti dell'interessato … finalità"
    )
    assert not looks_like(
        "privacy", "Il webinar si terrà il 12 marzo, iscrizioni aperte fino a esaurimento posti."
    )


# -------------------------------------------------------------- evaluation


def _observation_with_google_fonts() -> Observation:
    obs = Observation(url="https://x.it", final_url="https://x.it", load_ok=True, status=200)
    obs.response_headers = {"content-type": "text/html"}
    obs.requests = [
        Request("https://x.it/", "x.it", "GET", "/", 200, "text/html", "document"),
        Request(
            "https://fonts.googleapis.com/css2?family=Inter",
            "fonts.googleapis.com",
            "GET",
            "/css2",
            200,
            "text/css",
            "stylesheet",
        ),
    ]
    obs.cookies = [CookieSet("_ga", ".x.it", "/", True, False, "Lax", 1.0, False)]
    return obs


def _complete_notice() -> DocumentEvidence:
    doc = DocumentEvidence(
        kind="privacy", url="https://x.it/privacy", status=200, ok=True, text_len=900
    )
    doc.elements = {
        key: True
        for key in (
            "controller", "contact", "dpo", "purposes", "legal_basis", "recipients",
            "transfers", "retention", "rights", "complaint", "profiling", "last_updated",
        )
    }
    doc.cookie_elements = {"cookie_list": True, "how_to_withdraw": True}
    return doc


def test_undeclared_transfer_and_tracking_cookie_fire():
    ctx = build_context(_observation_with_google_fonts(), [_complete_notice()], None)
    ids = {f.rule_id for f in evaluate(ctx, load_rules(RULES_DIR))}
    assert "PM-TRF-01" in ids  # transfer to Google
    assert "PM-DIS-01" in ids  # not named in the notice
    assert "PM-COK-01" in ids  # _ga before any consent
    assert "PM-DOC-02" not in ids  # the notice is complete


def test_findings_are_language_neutral():
    """No sentence may reach the stored result: that is what makes one scan
    renderable in any language."""
    ctx = build_context(_observation_with_google_fonts(), [], None)
    finding = next(f for f in evaluate(ctx, load_rules(RULES_DIR)) if f.rule_id == "PM-TRF-01")
    assert isinstance(finding.severity, Severity)
    assert finding.references and all(":" in r for r in finding.references)
    assert finding.remediation and finding.remediation.source == "vendor"
    assert all(step.key.startswith("verification.") for step in finding.verification)
    assert finding.params["transfer"] is TransferScope.NON_EEA


def test_the_same_finding_renders_in_both_languages():
    from pmate.report.render import render_finding

    ctx = build_context(_observation_with_google_fonts(), [], None)
    finding = next(f for f in evaluate(ctx, load_rules(RULES_DIR)) if f.rule_id == "PM-TRF-01")
    english = render_finding(finding, Translator.for_locale("en", strict=True))
    italian = render_finding(finding, Translator.for_locale("it", strict=True))
    assert "Google" in english.title and "Google" in italian.title
    assert english.title != italian.title
    assert "⟦" not in english.description and "⟦" not in italian.description
    assert english.remediation and italian.remediation
    assert english.remediation.steps and italian.remediation.steps


def test_graph_links_finding_to_evidence_and_remediation():
    ctx = build_context(_observation_with_google_fonts(), [], None)
    findings = evaluate(ctx, load_rules(RULES_DIR))
    graph = build_graph(ctx, findings)
    types = {n.type for n in graph.nodes}
    assert {
        "site", "page", "host", "vendor", "cookie", "finding", "obligation", "remediation",
    } <= types
    assert any(e.type == "fixed_by" for e in graph.edges)
    assert any(e.type == "violates" for e in graph.edges)
    assert any(e.type == "transfers_to" for e in graph.edges)


def test_severity_follows_observation_not_reputation():
    """LinkedIn's image CDN serves a logo: a transfer, not terminal access."""
    assert vendor_for("media.licdn.com").storage_access is False
    assert vendor_for("snap.licdn.com").storage_access is True
    assert vendor_for("cdn.iubenda.com").consent_class is ConsentClass.TECHNICAL


# ------------------------------------------------------------- fail-closed


def test_unreachable_target_is_never_conformant():
    verdict = grade([], observed_ok=False)
    assert verdict.grade is Grade.INCONCLUSIVE and verdict.conformant is False


def test_grade_ladder():
    def finding(severity: Severity) -> Finding:
        return Finding(
            id=severity.value,
            rule_id="X",
            severity=severity,
            confidence="certain",
            subject_kind=SubjectKind.SITE,
            subject_node="site:x",
        )

    assert grade([], True).grade is Grade.A
    assert grade([finding(Severity.LOW)], True).grade is Grade.B
    assert grade([finding(Severity.MEDIUM)], True).grade is Grade.C
    assert grade([finding(Severity.HIGH)], True).grade is Grade.D
    assert grade([finding(Severity.CRITICAL)], True).grade is Grade.F
    assert grade([finding(Severity.HIGH)], True).conformant is False


def test_priority_prefers_the_cheap_fix():
    cheap, quick = priority_for(Severity.HIGH, Effort.LOW, "certain")
    costly, not_quick = priority_for(Severity.HIGH, Effort.HIGH, "certain")
    assert cheap.value < costly.value  # P1 sorts before P2
    assert quick is True and not_quick is False


# ---------------------------------------------------------- reproducibility


def test_record_digests_detect_tampering():
    from pmate.report.record import build_record, canonical_digest, verify_record

    observation = {"browser": {"requests": [{"host": "fonts.googleapis.com"}]}, "documents": []}
    record = build_record(url="https://x.it", observation=observation, user_agent="test")
    checked = verify_record({"record": record, "observation": observation})
    assert checked["evidence_intact"]
    assert checked["ruleset_unchanged"] and checked["knowledge_unchanged"]

    tampered = {"record": record, "observation": {"browser": {"requests": []}, "documents": []}}
    assert verify_record(tampered)["evidence_intact"] is False
    assert canonical_digest({"a": 1, "b": 2}) == canonical_digest({"b": 2, "a": 1})


# -------------------------------------------------------------------- diff


def test_diff_classifies_resolved_new_and_persistent():
    before = {
        "started_at": "2026-07-01T10:00:00+00:00",
        "verdict": {"grade": "F"},
        "findings": [
            {"id": "PM-TRF-01:google-fonts", "severity": "high"},
            {"id": "PM-COK-01:_ga", "severity": "high"},
        ],
    }
    after = {
        "started_at": "2026-07-29T10:00:00+00:00",
        "final_url": "https://x.it/",
        "verdict": {"grade": "C"},
        "findings": [
            {"id": "PM-TRF-01:google-fonts", "severity": "high"},
            {"id": "PM-SEC-01", "severity": "medium"},
        ],
    }
    result = diff(before, after)
    assert [f["id"] for f in result["resolved"]] == ["PM-COK-01:_ga"]
    assert [f["id"] for f in result["new"]] == ["PM-SEC-01"]
    assert result["persisting"][0]["age_days"] == 28
    assert result["verdict"]["improved"] is True
