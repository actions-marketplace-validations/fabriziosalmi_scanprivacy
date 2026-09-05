"""SARIF, source anchoring and badge.

These are the surfaces other systems consume, so their contract matters more
than their prose: GitHub matches alerts by fingerprint, bands them by
`security-severity`, and resolves locations against the checkout. A silent
change in any of those turns a working integration into a pile of duplicate
alerts.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from pmate.analyze.context import build_context
from pmate.analyze.engine import evaluate, load_rules
from pmate.analyze.graph import build_graph
from pmate.analyze.verdict import grade
from pmate.core.enums import Grade, ScanStatus, Severity
from pmate.core.models import ScanResult, scan_from_dict
from pmate.observe.browser import CookieSet, Observation, Request
from pmate.report.anchor import SourceIndex
from pmate.report.badge import render_badge
from pmate.report.record import build_record
from pmate.report.sarif import build_sarif, fingerprint

REPO_ROOT = Path(__file__).resolve().parents[1]


def _result() -> ScanResult:
    obs = Observation(url="https://x.it", final_url="https://x.it/", load_ok=True, status=200)
    obs.response_headers = {"server": "cloudflare", "cf-ray": "abc", "content-type": "text/html"}
    obs.requests = [
        Request("https://x.it/", "x.it", "GET", "/", 200, "text/html", "document", t_ms=10),
        Request(
            "https://fonts.googleapis.com/css2",
            "fonts.googleapis.com",
            "GET",
            "/css2",
            200,
            "text/css",
            "stylesheet",
            t_ms=120,
        ),
    ]
    obs.cookies = [CookieSet("_ga", ".x.it", "/", True, False, "Lax", 1.0, False)]

    ctx = build_context(obs, [], None)
    findings = evaluate(ctx, load_rules())
    result = ScanResult(
        scan_id="test1234",
        url=obs.url,
        final_url=obs.final_url,
        started_at="2026-07-29T10:00:00+00:00",
        finished_at="2026-07-29T10:00:20+00:00",
        status=ScanStatus.OK,
    )
    result.site = {"domain": "x.it", "cookies": 1, "storage": 0, "third_parties": 2, "cmp": []}
    result.findings = findings
    result.graph = build_graph(ctx, findings)
    result.verdict = grade(findings, observed_ok=True)
    result.observation = {"browser": {"requests": []}, "documents": [], "tls": None}
    # findings after they are attached, exactly as scanner.py does it: a record
    # built before them declares the digest of an empty list, and every result
    # derived from this fixture would then fail its own verification
    result.record = build_record(
        url=obs.url,
        observation=result.observation,
        user_agent="test",
        findings=result.to_dict()["findings"],
    )
    return result


# ------------------------------------------------------------------- SARIF


def test_sarif_shape_is_valid_for_code_scanning():
    sarif = build_sarif(_result())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "privacymate"
    assert run["tool"]["driver"]["rules"]
    assert run["results"]

    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        # ruleIndex must actually point at its rule, or GitHub attributes the
        # alert to the wrong rule
        assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in ("error", "warning", "note", "none")
        assert result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1
        assert result["partialFingerprints"]["privacymateFindingId/v1"]


def test_security_severity_and_level_agree():
    """The icon and GitHub's own banding must tell the same story."""
    run = build_sarif(_result())["runs"][0]
    for rule in run["tool"]["driver"]["rules"]:
        level = rule["defaultConfiguration"]["level"]
        severity = float(rule["properties"]["security-severity"])
        if level == "error":
            assert severity >= 7.0
        elif level == "warning":
            assert 4.0 <= severity < 7.0
        else:
            assert severity < 4.0


def test_fingerprints_are_stable_and_unique():
    """GitHub matches alerts across runs by fingerprint: an unstable one
    produces a duplicate alert on every scan, a colliding one merges two
    unrelated findings."""
    first, second = build_sarif(_result()), build_sarif(_result())
    prints = lambda sarif: [  # noqa: E731
        r["partialFingerprints"]["privacymateFindingId/v1"] for r in sarif["runs"][0]["results"]
    ]
    assert prints(first) == prints(second)
    assert len(set(prints(first))) == len(prints(first))
    assert fingerprint("PM-TRF-01:google-fonts") != fingerprint("PM-TRF-01:google-analytics")


def test_fingerprint_does_not_depend_on_language():
    """An alert must not be recreated because a report was rendered in Italian."""
    english = build_sarif(_result(), "en")
    italian = build_sarif(_result(), "it")
    assert [r["partialFingerprints"] for r in english["runs"][0]["results"]] == [
        r["partialFingerprints"] for r in italian["runs"][0]["results"]
    ]
    # the human text does change, though — that is the point of the locale
    assert english["runs"][0]["results"][0]["message"]["text"] != (
        italian["runs"][0]["results"][0]["message"]["text"]
    )


def test_message_carries_the_fix():
    """An alert nobody can act on gets muted."""
    run = build_sarif(_result())["runs"][0]
    transfer = next(r for r in run["results"] if r["ruleId"] == "PM-TRF-01")
    assert "Remediation" in transfer["message"]["text"]
    assert "1." in transfer["message"]["text"]


def test_sarif_can_be_rebuilt_from_the_published_json():
    """Every downstream artefact must derive from the stored evidence alone; if
    a consumer had to re-scan, the digests would stop meaning anything."""
    original = _result()
    rebuilt = scan_from_dict(json.loads(json.dumps(original.to_dict(), default=str)))
    assert [r["ruleId"] for r in build_sarif(rebuilt)["runs"][0]["results"]] == [
        r["ruleId"] for r in build_sarif(original)["runs"][0]["results"]
    ]
    assert rebuilt.verdict.grade is original.verdict.grade
    assert [f.severity for f in rebuilt.sorted_findings] == [
        f.severity for f in original.sorted_findings
    ]
    assert [f.id for f in rebuilt.sorted_findings] == [f.id for f in original.sorted_findings]


# --------------------------------------------------------- source anchoring


def test_anchor_finds_the_inclusion_line(tmp_path: Path):
    site = tmp_path / "src" / "layouts"
    site.mkdir(parents=True)
    (site / "base.html").write_text(
        "<html>\n<head>\n"
        '  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">\n'
        "</head>\n</html>\n",
        encoding="utf-8",
    )
    sarif = build_sarif(_result(), source_root=tmp_path)
    transfer = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "PM-TRF-01")
    location = transfer["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "src/layouts/base.html"
    assert location["region"]["startLine"] == 3
    assert transfer["properties"]["anchorKind"] == "inclusion"


def test_a_mention_is_not_reported_as_an_inclusion(tmp_path: Path):
    """An allowlist, a CSP note or a comment names the host without loading it.
    Saying otherwise sends a developer to the wrong line."""
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "notes.md").write_text(
        "We used to rely on fonts.googleapis.com before self-hosting.\n", encoding="utf-8"
    )
    sarif = build_sarif(_result(), source_root=tmp_path)
    transfer = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "PM-TRF-01")
    assert transfer["properties"]["anchorKind"] == "mention"
    assert "may be elsewhere" in transfer["message"]["text"]


def test_inclusion_wins_over_a_mention_elsewhere(tmp_path: Path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "notes.md").write_text("fonts.googleapis.com is mentioned here\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "head.html").write_text(
        '<link href="https://fonts.googleapis.com/css2">\n', encoding="utf-8"
    )
    index = SourceIndex(tmp_path)
    anchor = index.find("fonts.googleapis.com")
    assert anchor is not None and anchor.kind == "inclusion"
    assert anchor.path == "src/head.html"


def test_the_engine_does_not_anchor_to_its_own_reports(tmp_path: Path):
    """A report naturally contains every host it reported on. Anchoring a
    finding to our own output would be useless and quietly wrong."""
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "scan.md").write_text(
        "# privacymate\n\nEvidence digest: abc\n\n- `fonts.googleapis.com`\n", encoding="utf-8"
    )
    index = SourceIndex(tmp_path)
    assert index.find("fonts.googleapis.com") is None


def test_no_source_root_means_no_anchoring_cost():
    run = build_sarif(_result())["runs"][0]
    assert run["properties"]["sourceFilesSearched"] == 0
    assert run["properties"]["sourceAnchored"] == 0


# ------------------------------------------------------------------- badge


def test_badge_is_self_contained_svg():
    """A shields.io URL would disclose every README visitor's IP address to a
    third party — exactly the finding this tool raises against others."""
    svg = render_badge(_result())
    assert svg.startswith("<svg")
    assert "http://" not in svg.replace("http://www.w3.org/2000/svg", "")
    assert "https://" not in svg
    assert "<image" not in svg and "<script" not in svg


def test_badge_states_grade_and_is_accessible():
    result = _result()
    svg = render_badge(result)
    assert result.verdict.grade.value in svg
    assert 'role="img"' in svg and "<title>" in svg
    assert "aria-label" in svg


def test_badge_colour_follows_the_grade():
    result = _result()
    result.verdict.grade = Grade.A
    green = render_badge(result)
    result.verdict.grade = Grade.F
    red = render_badge(result)
    assert green != red


# ------------------------------------------------------------------ action


def test_action_metadata_is_wellformed_and_matches_the_cli():
    action = yaml.safe_load((REPO_ROOT / "action.yml").read_text(encoding="utf-8"))
    assert action["runs"]["using"] == "composite"
    inputs = action["inputs"]
    assert {"url", "fail-on", "source-root", "sarif-file"} <= set(inputs)
    assert {"grade", "conformant", "findings", "sarif"} <= set(action["outputs"])

    # every gate the CLI accepts must be documented by the action, or a
    # workflow author picks a value that fails at runtime with an argparse error
    import pmate.cli as cli

    described = inputs["fail-on"]["description"]
    for gate in (*cli._GATE_ORDER, "any-finding", "not-conformant", "never"):
        assert gate in described, f"action.yml does not document fail-on={gate}"


@pytest.mark.parametrize("path", ["examples/workflows/privacy-gate.yml"])
def test_example_workflow_parses_and_requests_the_right_permission(path: str):
    workflow = yaml.safe_load((REPO_ROOT / path).read_text(encoding="utf-8"))
    assert workflow["permissions"]["security-events"] == "write"
    steps = workflow["jobs"]["privacy"]["steps"]

    # Derived from the source URL the engine hands to network users, rather than
    # spelled out again here. The repository was renamed once already, and the
    # two drifting apart would mean the example points people at one repository
    # while `/healthz` names another.
    from pmate.config import SOURCE_URL_DEFAULT

    slug = SOURCE_URL_DEFAULT.removeprefix("https://github.com/")
    assert any(slug in str(step.get("uses", "")) for step in steps), (
        f"the example does not reference this project's own action ({slug})"
    )


# ------------------------------------------------------------- attestation


def _artifacts(tmp_path: Path) -> list[Path]:
    scan = tmp_path / "privacymate.json"
    scan.write_text(json.dumps(_result().to_dict(), default=str), encoding="utf-8")
    sarif = tmp_path / "privacymate.sarif"
    sarif.write_text(json.dumps(build_sarif(_result())), encoding="utf-8")
    badge = tmp_path / "privacy.svg"
    badge.write_text(render_badge(_result()), encoding="utf-8")
    return [scan, sarif, badge]


def test_statement_binds_every_artefact_and_the_configuration_digests(tmp_path: Path):
    from pmate.report.attestation import PREDICATE_TYPE, STATEMENT_TYPE, build_statement, file_digest

    artifacts = _artifacts(tmp_path)
    statement = build_statement(_result(), artifacts)
    assert statement["_type"] == STATEMENT_TYPE
    assert statement["predicateType"] == PREDICATE_TYPE
    assert {s["name"] for s in statement["subject"]} == {p.name for p in artifacts}
    for subject, path in zip(statement["subject"], artifacts):
        assert subject["digest"]["sha256"] == file_digest(path)
    # a verifier must not need to open the PDF to know what was claimed
    predicate = statement["predicate"]
    assert predicate["verdict"]["grade"]
    assert predicate["digests"]["evidence"]
    assert predicate["digests"]["ruleset"]


def test_canonical_form_is_what_gets_signed():
    """Re-serialisation must not change a byte, or every signature breaks."""
    from pmate.report.attestation import canonical_json

    payload = {"b": 1, "a": {"d": 2, "c": [3, 4]}}
    once = canonical_json(payload)
    assert canonical_json(json.loads(once)) == once
    assert " " not in once


def test_a_changed_artefact_is_detected(tmp_path: Path):
    from pmate.report.attestation import verify_attestation, write_attestation

    artifacts = _artifacts(tmp_path)
    statement_path = tmp_path / "attestation.json"
    write_attestation(_result(), artifacts, statement_path)

    assert verify_attestation(statement_path).subjects_matching == 3
    artifacts[1].write_text(artifacts[1].read_text().replace("note", "none", 1), encoding="utf-8")
    checked = verify_attestation(statement_path)
    assert checked.mismatched == ["privacymate.sarif"]
    assert checked.ok is False


def test_a_missing_artefact_is_detected(tmp_path: Path):
    from pmate.report.attestation import verify_attestation, write_attestation

    artifacts = _artifacts(tmp_path)
    statement_path = tmp_path / "attestation.json"
    write_attestation(_result(), artifacts, statement_path)
    artifacts[2].unlink()
    checked = verify_attestation(statement_path)
    assert checked.missing == ["privacy.svg"]
    assert checked.ok is False


def test_an_unsigned_statement_never_passes(tmp_path: Path):
    """Fail-closed: a statement nobody signed proves only that someone wrote a
    file. Treating it as a pass would be worse than not attesting at all."""
    from pmate.report.attestation import verify_attestation, write_attestation

    statement_path = tmp_path / "attestation.json"
    _, signature = write_attestation(_result(), _artifacts(tmp_path), statement_path)
    assert signature.signed is False
    checked = verify_attestation(statement_path)
    assert checked.subjects_matching == 3  # artefacts are fine …
    assert checked.signature_verified is None
    assert checked.ok is False  # … and it still does not pass


def test_signing_without_cosign_raises_instead_of_writing_an_unsigned_file(tmp_path: Path, monkeypatch):
    """A caller who asked for a signature must find out now, not when a
    recipient checks it."""
    import pmate.report.attestation as attestation

    monkeypatch.setattr(attestation.shutil, "which", lambda _: None)
    with pytest.raises(attestation.AttestationError):
        attestation.write_attestation(
            _result(), _artifacts(tmp_path), tmp_path / "attestation.json", sign="cosign-key"
        )


@pytest.mark.skipif(
    not __import__("shutil").which("cosign"), reason="cosign is not installed on this machine"
)
def test_sign_and_verify_roundtrip_with_a_real_key(tmp_path: Path, monkeypatch):
    import subprocess

    from pmate.report.attestation import verify_attestation, write_attestation

    monkeypatch.setenv("COSIGN_PASSWORD", "")
    generated = subprocess.run(
        ["cosign", "generate-key-pair"], cwd=tmp_path, capture_output=True, text=True, timeout=120
    )
    if generated.returncode != 0:  # pragma: no cover — environment dependent
        pytest.skip(f"cosign could not generate a key pair: {generated.stderr[:200]}")

    artifacts = _artifacts(tmp_path)
    statement_path = tmp_path / "attestation.json"
    _, signature = write_attestation(
        _result(), artifacts, statement_path, sign="cosign-key", key=tmp_path / "cosign.key"
    )
    assert signature.signed and Path(signature.bundle_path).is_file()
    # a local key proves the holder signed it; only keyless anchors in a log
    assert signature.transparency_log is False

    checked = verify_attestation(statement_path, public_key=tmp_path / "cosign.pub")
    assert checked.signature_verified is True
    assert checked.ok is True

    # rewriting the claim invalidates the signature
    statement = json.loads(statement_path.read_text(encoding="utf-8"))
    verdict = statement["predicate"]["verdict"]
    verdict["grade"] = "A" if verdict["grade"] != "A" else "F"
    statement_path.write_text(
        json.dumps(statement, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    tampered = verify_attestation(statement_path, public_key=tmp_path / "cosign.pub")
    assert tampered.signature_verified is False
    assert tampered.ok is False
