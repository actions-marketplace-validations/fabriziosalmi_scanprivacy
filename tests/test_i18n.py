"""The catalogues are data, so they get the same scrutiny as code.

Three failure modes are cheap to prevent here and expensive to discover in a
delivered PDF: a YAML file that does not parse, a locale missing keys that
English has, and an enum member with no display string anywhere.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scanprivacy.core.enums import LOCALISED_ENUMS
from scanprivacy.i18n.translator import (
    CATALOGUES,
    DEFAULT_LOCALE,
    LOCALES_DIR,
    MissingTranslation,
    Translator,
    available_locales,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _flatten(tree, prefix: str = "") -> set[str]:
    """Leaf paths of a nested mapping, so two locales can be compared."""
    out: set[str] = set()
    if isinstance(tree, dict):
        for k, v in tree.items():
            out |= _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    else:
        out.add(prefix)
    return out


def _catalogue(locale: str, name: str):
    path = LOCALES_DIR / locale / f"{name}.yml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def test_every_yaml_in_the_repo_parses():
    """Three separate YAML syntax errors have already reached a running scan;
    unquoted colons in prose are the recurring cause."""
    for path in sorted(REPO_ROOT.glob("src/scanprivacy/**/*.yml")):
        yaml.safe_load(path.read_text(encoding="utf-8"))


def test_english_is_the_source_language():
    assert DEFAULT_LOCALE == "en"
    assert "en" in available_locales()


@pytest.mark.parametrize("locale", [l for l in available_locales() if l != DEFAULT_LOCALE])
@pytest.mark.parametrize("catalogue", CATALOGUES)
def test_locale_has_every_key_english_has(locale: str, catalogue: str):
    english = _flatten(_catalogue(DEFAULT_LOCALE, catalogue))
    translated = _flatten(_catalogue(locale, catalogue))
    missing = sorted(english - translated)
    assert not missing, f"{locale}/{catalogue}.yml is missing: {missing[:12]}"


@pytest.mark.parametrize("locale", available_locales())
def test_every_enum_member_has_a_label(locale: str):
    t = Translator.for_locale(locale, strict=True)
    for enum_cls in LOCALISED_ENUMS:
        for member in enum_cls:
            assert t.label(member), f"{locale}: {enum_cls.__name__}.{member.value} has no label"


def test_strict_mode_raises_on_a_missing_key():
    t = Translator.for_locale(DEFAULT_LOCALE, strict=True)
    with pytest.raises(MissingTranslation):
        t.t("this.key.does.not.exist")


def test_lenient_mode_makes_a_missing_key_visible():
    t = Translator.for_locale(DEFAULT_LOCALE)
    assert t.t("this.key.does.not.exist") == "⟦ui.this.key.does.not.exist⟧"


def test_unknown_locale_falls_back_to_english_instead_of_failing():
    t = Translator.for_locale("xx-YY")
    assert t.locale == DEFAULT_LOCALE
    assert t.t("report.labels.severity") == "Severity"


def test_regional_locale_resolves_to_its_base():
    assert Translator.for_locale("it-IT").locale == "it"


def test_placeholders_are_substituted_and_unknown_ones_stay_visible():
    t = Translator.for_locale(DEFAULT_LOCALE)
    assert "42" in t.t("report.labels.days", n=42)
    assert "{n}" in t.t("report.labels.days")


# ---------------------------------------------------- rendered output is whole


def _synthetic_result():
    """A scan result exercising every subject kind, built offline.

    Its purpose is to make a missing catalogue key fail a test rather than
    appear as ⟦ui.something⟧ in a client's PDF — which is exactly how the
    YAML-boolean trap (`yes:` parsed as True) reached a rendered report.
    """
    import asyncio
    from datetime import datetime, timezone

    from scanprivacy.analyze.context import build_context
    from scanprivacy.analyze.engine import evaluate, load_rules
    from scanprivacy.analyze.graph import build_graph
    from scanprivacy.analyze.verdict import grade
    from scanprivacy.core.enums import ScanStatus
    from scanprivacy.core.models import ScanResult
    from scanprivacy.observe.browser import CookieSet, Observation, Request, StorageEntry
    from scanprivacy.report.record import build_record

    obs = Observation(url="https://x.it", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {"server": "cloudflare", "cf-ray": "abc", "content-type": "text/html"}
    obs.requests = [
        Request("https://x.it/", "x.it", "GET", "/", 200, "text/html", "document", t_ms=10),
        Request(
            "https://fonts.googleapis.com/css2", "fonts.googleapis.com", "GET", "/css2",
            200, "text/css", "stylesheet", t_ms=120,
        ),
        Request(
            "https://widgets.sociablekit.com/a.js", "widgets.sociablekit.com", "GET", "/a.js",
            200, "application/javascript", "script", t_ms=200,
        ),
        Request(
            "https://data.unknown-vendor.example/x", "data.unknown-vendor.example", "GET", "/x",
            200, None, "xhr", t_ms=240,
        ),
    ]
    obs.cookies = [
        CookieSet("_ga", ".x.it", "/", True, False, "Lax", 1.0, False),
        CookieSet("opaque123", "x.it", "/", False, False, "None", None, True),
    ]
    obs.storage = [StorageEntry("localStorage", "_ga_XYZ", 24), StorageEntry("sessionStorage", "unique_id", 12)]

    ctx = build_context(obs, [], None)
    findings = evaluate(ctx, load_rules())
    now = datetime.now(timezone.utc).isoformat()
    result = ScanResult(
        scan_id="test", url=obs.url, final_url=obs.final_url, started_at=now, finished_at=now,
        status=ScanStatus.OK,
    )
    result.site = {
        "host": "x.it", "domain": "x.it", "title": "X", "lang": "it", "platform": None,
        "cmp": [], "third_parties": len(ctx.third_party_vendors), "cookies": len(ctx.cookies),
        "storage": len(ctx.storage), "documents_read": [],
    }
    result.findings = findings
    result.graph = build_graph(ctx, findings)
    result.verdict = grade(findings, observed_ok=True)
    result.observation = {
        "browser": {"requests": [], "cookies": [], "storage": [], "response_headers": {}},
        "documents": [],
        "tls": None,
    }
    result.inventory = [
        {
            "vendor": f.vendor.vendor, "vendor_key": f.vendor.vendor_key, "product": f.vendor.product,
            "category": f.vendor.category, "jurisdiction": f.vendor.jurisdiction, "hosts": f.hosts,
            "detected_via": f.detection, "transfer": f.transfer, "transfer_basis": f.vendor.transfer_basis,
            "consent_class": f.vendor.consent_class, "storage_access": f.vendor.storage_access,
            "data_types": list(f.vendor.data_types), "declared": f.declared, "declared_in": f.declared_in,
        }
        for f in ctx.third_party_vendors
    ]
    result.record = build_record(url=obs.url, observation=result.observation, user_agent="test")
    result.record["posture"] = {
        "keys": [
            "report.posture.method",
            "report.posture.interaction",
            "report.posture.consent",
        ],
        "user_agent": "test",
    }
    return result


@pytest.mark.parametrize("locale", available_locales())
def test_no_missing_translation_marker_in_a_rendered_report(locale: str):
    from scanprivacy.report.markdown import render

    output = render(_synthetic_result(), locale)
    missing = sorted({m for m in output.split() if m.startswith("⟦")})
    assert not missing, f"{locale}: unresolved keys {missing}"
    assert "⟦" not in output


@pytest.mark.parametrize("locale", available_locales())
def test_no_missing_translation_marker_in_the_pdf_html(locale: str):
    from scanprivacy.report.pdf import render_html

    html = render_html(_synthetic_result(), locale)
    assert "⟦" not in html
