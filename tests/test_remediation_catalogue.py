"""The fix catalogue, asked without observing anything.

All of this knowledge existed and none of it could be requested: the only way
to see a fix was to scan a site that happened to trigger the rule carrying it.
A lookup table with no lookup.

The audience is three-way and the tests reflect it. A person reads the steps. A
model wants the whole register at once, so that "how do I stop sending IP
addresses to Google Fonts" is answered from what this engine actually holds
rather than from a recollection of the GDPR. A tool wants one entry, by key,
with stable fields.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import scanprivacy.api as api
from scanprivacy.analyze.engine import load_rules
from scanprivacy.knowledge.registry import all_vendors
from scanprivacy.knowledge.remediation import catalogue, entry_for, patterns


# ------------------------------------------------------------- completeness


def test_every_rule_the_engine_can_fire_has_a_fix_in_the_catalogue():
    """A finding with no fix is a complaint. If a rule can appear in a report,
    what to do about it has to be answerable."""
    keys = {e.key for e in catalogue("en") if e.kind == "rule"}
    missing = [r.id for r in load_rules() if r.condition and r.id not in keys]
    assert missing == [], f"rules that can fire with no remediation: {missing}"


def test_every_pattern_the_knowledge_base_names_is_in_the_catalogue():
    named = {v.remediation.pattern for v in all_vendors() if v.remediation.pattern}
    present = {e.key for e in patterns("en")}
    assert named <= present, f"patterns referenced but not catalogued: {named - present}"


@pytest.mark.parametrize("locale", ["en", "it"])
def test_no_entry_is_empty_or_unresolved(locale):
    for entry in catalogue(locale):
        assert entry.summary.strip(), f"{entry.key}: no summary"
        assert entry.steps, f"{entry.key}: a fix with no steps is advice"
        assert "⟦" not in entry.summary and not any("⟦" in s for s in entry.steps), entry.key


def test_each_entry_says_when_it_applies():
    """Without it a catalogue is a list of good ideas. A reader has to be able
    to tell whether this fix is the one for their situation."""
    for entry in catalogue("en"):
        assert entry.applies_when.strip(), f"{entry.key}: nothing says when this applies"


# ----------------------------------------------------------------- lookup


def test_a_vendor_id_resolves_to_its_pattern():
    """The question people have is "how do I fix google-fonts", not "what does
    self_host_asset say"."""
    entry = entry_for("google-fonts")
    assert entry is not None
    assert entry.key == "self_host_asset"


def test_a_vendor_question_gets_the_vendor_filled_in():
    """Asked in the abstract the placeholder is the honest answer — the pattern
    really does cover ten vendors. Asked about one, it is half an answer, and
    the missing half is the half somebody needed."""
    entry = entry_for("google-fonts")
    assert "{product}" not in entry.summary and "{hosts}" not in " ".join(entry.steps)
    assert "Google Fonts" in entry.summary
    assert any("fonts.googleapis.com" in s for s in entry.steps), "the real hosts belong in the steps"
    assert entry.alternatives, "the vendor's own alternatives were dropped"


def test_the_generic_pattern_keeps_its_placeholders():
    """Substituting a made-up product into the abstract entry would state a fix
    for a vendor nobody asked about."""
    entry = entry_for("self_host_asset")
    assert "{product}" in entry.summary
    assert len(entry.vendors) > 1


def test_a_rule_id_resolves_to_its_own_procedure():
    entry = entry_for("PM-TRF-01")
    assert entry is not None and entry.kind == "rule"
    assert entry.severity == "high"
    assert entry.references, "a fix without its legal basis is an opinion"


def test_an_unknown_key_is_absent_rather_than_guessed():
    assert entry_for("PM-NOT-A-RULE") is None
    assert entry_for("some-vendor-we-never-heard-of") is None


# --------------------------------------------------------------- languages


def test_the_catalogue_answers_in_either_language_with_the_same_shape():
    en, it = catalogue("en"), catalogue("it")
    assert [e.key for e in en] == [e.key for e in it], "the two languages list different fixes"
    assert [e.severity for e in en] == [e.severity for e in it]
    assert any(e.summary != f.summary for e, f in zip(en, it)), "nothing was actually translated"


def test_the_order_is_stable_so_two_calls_can_be_compared():
    assert [e.key for e in catalogue("en")] == [e.key for e in catalogue("en")]


# ------------------------------------------------------------------- surface


@pytest.fixture
def client(monkeypatch):
    from scanprivacy.auth import ENV_VAR

    monkeypatch.delenv(ENV_VAR, raising=False)
    return TestClient(api.app)


def test_the_whole_catalogue_is_one_request(client):
    """What a model needs: the register in one call, not one call per rule."""
    body = client.get("/v1/remediation").json()
    assert len(body) >= 30
    assert {"key", "kind", "summary", "steps", "applies_when"} <= set(body[0])


def test_one_entry_by_key_over_http(client):
    body = client.get("/v1/remediation/google-fonts").json()
    assert body["key"] == "self_host_asset"
    assert "Google Fonts" in body["summary"]


def test_an_unknown_key_is_a_404_not_an_empty_answer(client):
    assert client.get("/v1/remediation/nonsense").status_code == 404


def test_the_language_is_honoured_and_validated(client):
    assert "⟦" not in json.dumps(client.get("/v1/remediation", params={"lang": "it"}).json())
    assert client.get("/v1/remediation", params={"lang": "../x"}).status_code == 400


def test_the_cli_answers_the_same_question(capsys):
    from scanprivacy.cli import main

    assert main(["remediation", "google-fonts"]) == 0
    assert "Google Fonts" in capsys.readouterr().out

    assert main(["remediation", "google-fonts", "--json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed[0]["key"] == "self_host_asset"


def test_the_cli_reports_an_unknown_key_on_stderr_and_exits_1(capsys):
    from scanprivacy.cli import main

    assert main(["remediation", "nope"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no remediation known" in captured.err
