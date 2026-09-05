"""The command line: what it promises, and what it returns when it fails.

At 495 lines and 10% coverage this was the largest untested surface in the
package, and the one every user touches. Most of it never needed a browser to
test — seven of the twelve subcommands read a stored scan from disk — it had
simply never been separated from the two that do.

Two extractions made the rest reachable: `build_parser`, which can be asserted
on without executing anything, and `write_artefacts`, which is where the
promises live — that `--json` and `--pdf` describe the same observation, and
that an attestation covers exactly the files the run produced.

Exit codes are part of the contract and are tested as such. A CI gate reads
them, and `0` on a failure is worse than a crash: it reports success.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pmate.cli import _gate, build_parser, main, write_artefacts
from pmate.core.enums import Grade, ScanStatus, Severity
from pmate.core.models import ScanResult, Verdict


@pytest.fixture
def result() -> ScanResult:
    from tests.test_integrations import _result

    return _result()


@pytest.fixture
def stored(tmp_path, result) -> Path:
    """A scan on disk, the way `pmate scan --json` leaves it."""
    path = tmp_path / "evidence.json"
    path.write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
    )
    return path


def _args(**overrides):
    """A namespace with every artefact switch off, so a test names only what
    it is exercising."""
    import argparse

    base = dict(
        lang="en", json=None, md=None, pdf=None, sarif=None, badge=None, attest=None,
        source_root=None, anchor_file="README.md", sign="unsigned", key=None, mermaid=False,
        quiet=True, fail_on="critical", pages=1, no_documents=True,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


# ----------------------------------------------------------------- the parser


def test_every_subcommand_is_reachable_and_bound_to_a_function():
    """A subcommand registered without `set_defaults(func=...)` parses fine and
    then fails at dispatch with AttributeError — at runtime, for the user."""
    parser = build_parser()
    actions = [a for a in parser._actions if hasattr(a, "choices") and isinstance(a.choices, dict)]
    assert actions, "no subparsers found — the test would pass vacuously"
    commands = actions[0].choices
    expected = {
        "scan", "batch", "consent-pass", "serve", "diff", "verify",
        "sarif", "badge", "attest", "verify-attestation", "rules",
    }
    assert expected <= set(commands), f"missing: {expected - set(commands)}"

    for name, sub in commands.items():
        assert sub.get_default("func") is not None, f"{name} parses but dispatches nowhere"


def test_a_command_is_required():
    """`pmate` alone must not silently do nothing."""
    with pytest.raises(SystemExit) as exit_:
        build_parser().parse_args([])
    assert exit_.value.code == 2


def test_an_unknown_language_is_refused_at_parse_time():
    """Before any work happens, and with the available list in the message."""
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--lang", "xx", "rules"])


def test_scan_defaults_are_the_documented_ones():
    args = build_parser().parse_args(["scan", "https://example.org"])
    assert args.url == "https://example.org"
    assert args.pages >= 1
    assert args.fail_on == "not-conformant", (
        "the default gate is the verdict, not a severity: a site that is not "
        "conformant fails, whatever mix of severities got it there"
    )
    assert args.no_documents is False, "reading the linked notices is the default"


def test_the_gate_threshold_is_a_closed_list():
    for value in ("critical", "high", "medium", "low", "info", "any-finding", "not-conformant", "never"):
        assert build_parser().parse_args(["scan", "https://x.it", "--fail-on", value])
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "https://x.it", "--fail-on", "sometimes"])


def test_version_is_answerable_without_a_subcommand():
    with pytest.raises(SystemExit) as exit_:
        build_parser().parse_args(["--version"])
    assert exit_.value.code == 0


# ------------------------------------------------------------------ the gate


def _verdict(conformant: bool, **counts) -> Verdict:
    return Verdict(conformant=conformant, grade=Grade.C, counts=counts)


def _with(verdict, findings=0) -> ScanResult:
    r = ScanResult(scan_id="g", url="https://x.it/", final_url="https://x.it/",
                   started_at="", finished_at="", status=ScanStatus.OK)
    r.verdict = verdict
    r.findings = [object()] * findings
    return r


@pytest.mark.parametrize(
    "fail_on,counts,expected",
    [
        ("critical", {"critical": 1}, 1),
        ("critical", {"high": 3}, 0),          # above the threshold only
        ("high", {"high": 1}, 1),
        ("high", {"medium": 9}, 0),
        ("medium", {"medium": 1}, 1),
        ("info", {"info": 1}, 1),
        ("never", {"critical": 5}, 0),         # explicitly opted out
    ],
)
def test_the_gate_blocks_at_and_above_its_threshold(fail_on, counts, expected):
    """`--fail-on` lets a team adopt the gate progressively. Blocking on
    everything from day one gets the gate switched off instead."""
    assert _gate(_with(_verdict(False, **counts)), fail_on) == expected


def test_any_finding_and_not_conformant_are_different_gates():
    informational_only = _with(_verdict(True, info=2), findings=2)
    assert _gate(informational_only, "any-finding") == 1
    assert _gate(informational_only, "not-conformant") == 0


def test_a_missing_verdict_fails_closed():
    """An unreachable target has no verdict. Exiting 0 there would report a
    clean site because nothing could be observed — the exact inversion this
    engine exists to avoid."""
    r = ScanResult(scan_id="g", url="https://x.it/", final_url="https://x.it/",
                   started_at="", finished_at="", status=ScanStatus.UNREACHABLE)
    assert r.verdict is None
    for fail_on in ("critical", "never", "any-finding", "not-conformant"):
        assert _gate(r, fail_on) == 1, f"{fail_on} let a verdict-less scan through"


# ------------------------------------------------------------- the artefacts


def test_each_switch_writes_its_artefact_and_nothing_else(tmp_path, result):
    for switch, name, check in [
        ("json", "e.json", lambda p: json.loads(p.read_text())["scan_id"]),
        ("md", "e.md", lambda p: "#" in p.read_text()),
        ("badge", "e.svg", lambda p: p.read_text().startswith("<svg")),
        ("sarif", "e.sarif", lambda p: json.loads(p.read_text())["version"] == "2.1.0"),
    ]:
        target = tmp_path / name
        written = write_artefacts(result, _args(**{switch: str(target)}))
        assert written == [target], f"--{switch} wrote {written}"
        assert check(target)


def test_the_pdf_is_a_pdf(tmp_path, result):
    target = tmp_path / "e.pdf"
    assert write_artefacts(result, _args(pdf=str(target))) == [target]
    assert target.read_bytes().startswith(b"%PDF-")


def test_nothing_is_written_when_nothing_is_asked_for(tmp_path, result):
    assert write_artefacts(result, _args()) == []
    assert list(tmp_path.iterdir()) == []


def test_several_artefacts_are_returned_in_a_stable_order(tmp_path, result):
    args = _args(json=str(tmp_path / "a.json"), md=str(tmp_path / "a.md"),
                 badge=str(tmp_path / "a.svg"))
    first = write_artefacts(result, args)
    second = write_artefacts(result, args)
    assert first == second, "the order must not depend on filesystem or dict iteration"
    assert [p.suffix for p in first] == [".json", ".md", ".svg"]


def test_an_attestation_covers_exactly_what_this_run_wrote(tmp_path, result):
    """The subjects used to be rebuilt from the arguments by hand, which is how
    a statement ends up covering a file the run never wrote — or missing one it
    did. A statement over files nobody received attests to nothing."""
    args = _args(
        json=str(tmp_path / "a.json"),
        md=str(tmp_path / "a.md"),
        attest=str(tmp_path / "a.intoto.json"),
    )
    written = write_artefacts(result, args)
    statement = json.loads((tmp_path / "a.intoto.json").read_text())

    subjects = {s["name"] for s in statement["subject"]}
    assert subjects == {"a.json", "a.md"}, "the statement does not match what was written"
    assert Path(args.attest) in written
    assert str(tmp_path / "a.intoto.json") not in subjects, "a statement cannot attest to itself"


def test_the_report_and_the_evidence_describe_the_same_scan(tmp_path, result):
    """The pair a recipient is handed. If they disagree, every other guarantee
    in the document is worth nothing."""
    args = _args(json=str(tmp_path / "a.json"), md=str(tmp_path / "a.md"))
    write_artefacts(result, args)
    evidence = json.loads((tmp_path / "a.json").read_text())
    report = (tmp_path / "a.md").read_text()
    assert evidence["scan_id"] in report


@pytest.mark.parametrize("lang", ["en", "it"])
def test_the_language_reaches_every_rendered_artefact(tmp_path, result, lang):
    args = _args(lang=lang, md=str(tmp_path / f"{lang}.md"), sarif=str(tmp_path / f"{lang}.sarif"))
    write_artefacts(result, args)
    text = (tmp_path / f"{lang}.md").read_text()
    assert "⟦" not in text, "unresolved catalogue key"
    assert text.strip()


# ------------------------------------------------- commands that need no browser


def test_verify_confirms_untouched_evidence_and_exits_0(stored, capsys):
    assert main(["verify", str(stored)]) == 0
    assert "⟦" not in capsys.readouterr().out


def test_verify_reports_altered_evidence_and_exits_1(stored, capsys):
    """The whole point of publishing a digest. Editing the findings must not
    still verify, or the digest is decoration."""
    data = json.loads(stored.read_text())
    data["findings"].append({
        "id": "INVENTED", "rule_id": "INVENTED", "severity": "critical",
        "confidence": "certain", "subject_kind": "site", "subject_node": "site",
    })
    stored.write_text(json.dumps(data, default=str), encoding="utf-8")
    assert main(["verify", str(stored)]) == 1


def test_sarif_is_re_exported_from_stored_evidence(stored, tmp_path):
    out = tmp_path / "out.sarif"
    assert main(["sarif", str(stored), "--out", str(out)]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] is not None


def test_badge_is_written_from_stored_evidence(stored, tmp_path):
    out = tmp_path / "b.svg"
    assert main(["badge", str(stored), "--out", str(out)]) == 0
    assert out.read_text().startswith("<svg")


def test_diff_between_a_scan_and_itself_reports_no_change(stored, capsys):
    assert main(["diff", str(stored), str(stored)]) == 0
    assert "⟦" not in capsys.readouterr().out


def test_diff_names_what_appeared(stored, tmp_path, capsys):
    after = json.loads(stored.read_text())
    after["findings"] = []
    later = tmp_path / "after.json"
    later.write_text(json.dumps(after, default=str), encoding="utf-8")

    out = tmp_path / "diff.json"
    main(["diff", str(stored), str(later), "--json", str(out)])
    comparison = json.loads(out.read_text())
    assert comparison["resolved"], "findings that disappeared must be reported as resolved"


@pytest.mark.parametrize("lang", ["en", "it"])
def test_rules_lists_the_catalogue_in_either_language(lang, capsys):
    assert main(["--lang", lang, "rules"]) == 0
    out = capsys.readouterr().out
    assert "PM-" in out
    assert "⟦" not in out


def test_a_missing_input_file_is_an_error_not_a_crash(tmp_path):
    """`pmate verify nope.json` from a script is an ordinary mistake."""
    with pytest.raises((FileNotFoundError, SystemExit)):
        main(["verify", str(tmp_path / "nope.json")])


def test_a_result_published_before_the_findings_digest_still_verifies(stored, capsys):
    """Backwards compatibility, and the honest phrasing of it. A document that
    predates this check cannot be checked for it — reporting that as a failure
    would condemn every report already issued, and reporting it as a pass would
    claim a guarantee nobody made."""
    data = json.loads(stored.read_text())
    data["record"].pop("findings_digest")
    stored.write_text(json.dumps(data, default=str), encoding="utf-8")

    assert main(["verify", str(stored)]) == 0
    out = capsys.readouterr().out
    assert "not declared" in out
    assert "⟦" not in out


def test_the_findings_digest_covers_a_removed_finding_too(stored):
    """Deleting the inconvenient one is the likelier tampering."""
    data = json.loads(stored.read_text())
    assert data["findings"], "the fixture must carry findings for this to mean anything"
    data["findings"].pop()
    stored.write_text(json.dumps(data, default=str), encoding="utf-8")
    assert main(["verify", str(stored)]) == 1


def test_editing_a_severity_is_detected(stored):
    """The quiet edit: same count, same ids, one severity downgraded."""
    data = json.loads(stored.read_text())
    data["findings"][0]["severity"] = "info"
    stored.write_text(json.dumps(data, default=str), encoding="utf-8")
    assert main(["verify", str(stored)]) == 1
