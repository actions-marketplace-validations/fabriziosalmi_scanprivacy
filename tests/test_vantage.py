"""Where the measurement was made from.

A site does not answer every observer the same way. Consent banners are
geo-gated, CDNs reply from different edges, some hosts serve nothing outside
their market. Two honest scans of one site can therefore disagree for a reason
that has nothing to do with the site — and until this existed the record had no
field in which to say so, which left the disagreement looking like a change on
the site, or like an error in one of the two reports.

Taken from `preconsent-tracker`, whose own docstring puts it best: *registra da
dove parte la misura; senza questo il dato non è interpretabile*. What is not
taken is its default. That script asks ipinfo.io on every run. An engine that
sends the operator's address to a company nobody chose, in order to write a
privacy report, is doing the thing the report exists to detect — so here the
lookup is opt-in, the endpoint is the operator's to name, and the default says
plainly that the vantage point is undetermined rather than omitting it.
"""

from __future__ import annotations

import importlib

import pytest

from scanprivacy.analyze.diff import diff
from scanprivacy.i18n import Translator


@pytest.fixture(autouse=True)
def _restore_modules(monkeypatch):
    """These tests reload `config` and `vantage` under a patched environment.
    Put the environment back first, then reload once more, so no later test
    sees the last test's configuration."""
    yield
    monkeypatch.undo()
    from scanprivacy import config
    from scanprivacy.observe import vantage

    importlib.reload(config)
    importlib.reload(vantage)


def _reload(monkeypatch, **env):
    for key in ("SCANPRIVACY_VANTAGE", "SCANPRIVACY_VANTAGE_LOOKUP"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    from scanprivacy import config
    from scanprivacy.observe import vantage

    importlib.reload(config)
    importlib.reload(vantage)
    return vantage


# --------------------------------------------------------------- the states


def test_nothing_configured_says_so_rather_than_omitting_the_field(monkeypatch):
    """The engine's standing rule, applied to itself: an absence is stated."""
    point = _reload(monkeypatch).observation_point()
    assert point["source"] == "undetermined"
    assert point["reason_key"] == "record.vantage.not_configured"


def test_no_network_call_happens_by_default(monkeypatch):
    """The part deliberately not taken from preconsent-tracker. A scan must not
    reach a third party to find out where it is."""
    vantage = _reload(monkeypatch)

    def explode(*_a, **_k):
        raise AssertionError("the default path opened a network connection")

    monkeypatch.setattr(vantage.urllib.request, "urlopen", explode)
    assert vantage.observation_point()["source"] == "undetermined"


def test_a_declared_vantage_is_recorded_verbatim(monkeypatch):
    vantage = _reload(monkeypatch, SCANPRIVACY_VANTAGE="IT / Milano / AS29447 Iliad")

    def explode(*_a, **_k):
        raise AssertionError("a declared vantage point still called out")

    monkeypatch.setattr(vantage.urllib.request, "urlopen", explode)
    point = vantage.observation_point()
    assert point == {"source": "declared", "declared": "IT / Milano / AS29447 Iliad"}


def test_a_declaration_wins_over_a_lookup(monkeypatch):
    """The operator knows where they are better than an endpoint does, and
    saying so costs nothing and reaches nobody."""
    vantage = _reload(
        monkeypatch,
        SCANPRIVACY_VANTAGE="IT / Genova",
        SCANPRIVACY_VANTAGE_LOOKUP="https://example.invalid/json",
    )
    assert vantage.observation_point()["source"] == "declared"


def test_a_failed_lookup_is_not_an_absent_vantage_point(monkeypatch):
    """The scan happened somewhere. "We could not find out" and "there is
    nothing to find out" are different, and the record says which."""
    vantage = _reload(monkeypatch, SCANPRIVACY_VANTAGE_LOOKUP="https://example.invalid/json")
    point = vantage.observation_point()
    assert point["source"] == "undetermined"
    assert point["reason_key"] == "record.vantage.lookup_failed"
    assert point["endpoint"] == "https://example.invalid/json"
    assert point["detail"], "the reason the lookup failed was not recorded"


def test_a_lookup_keeps_only_the_fields_we_record(monkeypatch):
    """A geolocation endpoint answers with whatever it likes. A report is not
    the place to paste an unbounded third-party payload."""
    import io
    import json as jsonlib

    vantage = _reload(monkeypatch, SCANPRIVACY_VANTAGE_LOOKUP="https://example.test/json")
    payload = {
        "ip": "37.162.163.247",
        "city": "Milan",
        "country": "IT",
        "org": "AS29447 Iliad Italia S.p.A.",
        "loc": "45.4643,9.1895",
        "postal": "20121",
        "readme": "https://ipinfo.io/missingauth",
    }

    class _Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        vantage.urllib.request, "urlopen", lambda *_a, **_k: _Response(jsonlib.dumps(payload).encode())
    )
    point = vantage.observation_point()
    assert point["source"] == "looked_up"
    assert point["city"] == "Milan"
    assert "loc" not in point and "postal" not in point and "readme" not in point


# ------------------------------------------------------------- the comparison


def _scan(vantage: dict | None) -> dict:
    record = {"digests": {"ruleset": "a" * 64, "knowledge": "b" * 64, "catalogues": "c" * 64}}
    if vantage is not None:
        record["vantage"] = vantage
    return {"started_at": "2026-09-07T10:00:00+00:00", "findings": [], "record": record}


def test_the_same_place_says_nothing():
    here = {"source": "declared", "declared": "IT / Milano"}
    assert diff(_scan(here), _scan(dict(here)))["vantage"]["status"] == "same"


def test_a_different_place_is_reported():
    result = diff(
        _scan({"source": "declared", "declared": "IT / Milano"}),
        _scan({"source": "declared", "declared": "US / Ashburn"}),
    )
    assert result["vantage"]["status"] == "changed"
    assert result["vantage"]["note_key"] == "diff.vantage_changed"


def test_a_different_address_in_the_same_place_is_not_a_different_place():
    """Two scans from one city over a dynamic connection have different IPs.
    Warning about that would train the reader to skip the warning that matters."""
    monday = {"source": "looked_up", "ip": "37.162.0.1", "country": "IT", "org": "AS29447 Iliad"}
    friday = {"source": "looked_up", "ip": "37.162.99.9", "country": "IT", "org": "AS29447 Iliad"}
    assert diff(_scan(monday), _scan(friday))["vantage"]["status"] == "same"


def test_an_unrecorded_vantage_is_unknown_not_identical():
    """Silence about the observation point is not a claim that it was the same
    one — the same rule the engine digests already follow."""
    known = {"source": "declared", "declared": "IT / Milano"}
    for before, after in ((_scan(None), _scan(known)), (_scan(known), _scan(None))):
        assert diff(before, after)["vantage"]["status"] == "unknown"


def test_undetermined_counts_as_unknown_too():
    known = {"source": "declared", "declared": "IT / Milano"}
    unknown = {"source": "undetermined", "reason_key": "record.vantage.not_configured"}
    assert diff(_scan(known), _scan(unknown))["vantage"]["status"] == "unknown"


# ---------------------------------------------------------------- the reading


@pytest.mark.parametrize("lang", ["en", "it"])
def test_the_method_section_states_it_even_when_undetermined(lang: str):
    """Omitting it lets a reader assume it does not matter."""
    from scanprivacy.report.render import scan_posture_rows

    t = Translator.for_locale(lang)
    record = {
        "posture": {"keys": ["report.posture.method"], "max_pages": 3, "user_agent": "ua"},
        "vantage": {"source": "undetermined", "reason_key": "record.vantage.not_configured"},
    }
    label, value = scan_posture_rows(record, t)[-1]
    assert "⟦" not in label and "⟦" not in value, f"[{lang}] missing translation"
    assert "SCANPRIVACY_VANTAGE" in value, f"[{lang}] does not say how to record it"


@pytest.mark.parametrize("lang", ["en", "it"])
def test_the_warnings_read_in_both_languages(lang: str):
    t = Translator.for_locale(lang)
    for key in ("diff.vantage_changed", "diff.vantage_unknown"):
        text = t.t(key, before="IT", after="US")
        assert "⟦" not in text, f"[{lang}] {key} has no translation"
        assert "{" not in text, f"[{lang}] {key} left a placeholder"
        assert len(text) > 100, f"[{lang}] {key} states the problem without explaining it"
