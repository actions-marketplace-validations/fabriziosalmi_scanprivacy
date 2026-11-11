"""Command line: the same engine the API serves.

    scanprivacy scan https://example.org --pdf report.pdf --lang it
    scanprivacy serve --port 8099
    scanprivacy diff before.json after.json
    scanprivacy verify evidence.json
    scanprivacy rules
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from . import __version__
from .analyze.engine import load_rules
from .config import DEFAULTS
from .i18n.translator import DEFAULT_LOCALE, Translator, available_locales
from .report.markdown import render
from .scanner import refusal_scan, scan


def write_artefacts(result, args: argparse.Namespace) -> list[Path]:
    """Write every artefact the invocation asked for, and say which.

    Separated from the scan because it is the half that can be checked without
    a browser, and it is the half that carries the promises: that `--json` and
    `--pdf` describe the same observation, that an attestation covers exactly
    the files this run produced and not a list someone maintained by hand.

    Returns the paths written, in a stable order, so an attestation and a test
    see the same set.
    """
    written: list[Path] = []

    if args.json:
        Path(args.json).write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        written.append(Path(args.json))
    if args.md:
        Path(args.md).write_text(render(result, args.lang), encoding="utf-8")
        written.append(Path(args.md))
    if args.pdf:
        from .report.pdf import render_pdf

        render_pdf(result, Path(args.pdf), args.lang)
        written.append(Path(args.pdf))
    if args.sarif:
        from .report.sarif import build_sarif

        root = Path(args.source_root).resolve() if args.source_root else None
        sarif = build_sarif(result, args.lang, root, args.anchor_file)
        Path(args.sarif).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
        written.append(Path(args.sarif))
    if args.badge:
        from .report.badge import render_badge

        Path(args.badge).write_text(render_badge(result), encoding="utf-8")
        written.append(Path(args.badge))
    if args.attest:
        from .report.attestation import write_attestation

        # The subjects are exactly the artefacts this run produced. Rebuilding
        # that list by hand is how a statement ends up covering a file the run
        # never wrote, or missing one it did — so it comes from `written`.
        statement, signature = write_attestation(
            result,
            list(written),
            Path(args.attest),
            sign=args.sign,
            key=Path(args.key) if args.key else None,
        )
        state = signature.mode if signature.signed else "UNSIGNED"
        print(
            f"attestation: {len(statement['subject'])} artefacts, {state}"
            + (f", bundle {signature.bundle_path}" if signature.bundle_path else "")
        )
        written.append(Path(args.attest))
    return written


def _within_budget(coroutine, settings):
    """Run one scan under the same ceiling the API and `batch` apply.

    `per_scan_budget_s` is documented as a hard ceiling; it was enforced only on
    those two paths, so a hung page could keep a command-line scan (and a CI job
    running the Action) alive indefinitely.
    """
    return asyncio.run(
        asyncio.wait_for(coroutine, timeout=settings.per_scan_budget_s * max(1, settings.max_pages))
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    from dataclasses import replace

    settings = replace(
        DEFAULTS,
        max_pages=max(1, args.pages),
        ua_fallback_on_block=args.ua_fallback,
    )
    result = _within_budget(scan(args.url, settings, read_documents=not args.no_documents), settings)
    t = Translator.for_locale(args.lang)

    write_artefacts(result, args)

    if args.mermaid:
        from .core.graph import to_mermaid

        print(to_mermaid(result.graph) if result.graph else "")
        return 0

    if args.quiet:
        print(
            t.t(
                "cli.scan_summary",
                url=result.url,
                grade=result.verdict.grade.value if result.verdict else "?",
                n=len(result.findings),
            )
        )
    else:
        print(render(result, args.lang, include_graph=False))
    return _gate(result, args.fail_on)


_GATE_ORDER = ("critical", "high", "medium", "low", "info")


def _gate(result, fail_on: str) -> int:
    """Exit code in the AGSSH register: a failing gate is the default.

    `--fail-on` lets a team adopt the gate progressively — block on critical
    today, tighten later — without pretending the other findings are absent.
    """
    if result.verdict is None:
        return 1
    if fail_on == "never":
        return 0
    if fail_on == "any-finding":
        return 1 if result.findings else 0
    if fail_on == "not-conformant":
        return 0 if result.verdict.conformant else 1
    threshold = _GATE_ORDER.index(fail_on)
    counts = result.verdict.counts or {}
    return 1 if any(counts.get(s, 0) for s in _GATE_ORDER[: threshold + 1]) else 0


def _cmd_batch(args: argparse.Namespace) -> int:
    from dataclasses import replace

    from .batch import read_targets, run_batch
    from .report.fleet_markdown import render_fleet

    settings = replace(
        DEFAULTS,
        max_pages=max(1, args.pages),
        ua_fallback_on_block=args.ua_fallback,
    )
    source = Path(args.targets)
    targets = read_targets(source if source.is_file() else [args.targets])
    out_dir = Path(args.out)

    done = {"n": 0}

    def progress(url: str, result, error: str | None) -> None:
        done["n"] += 1
        if error == "cached":
            state = "cached"
        elif error:
            state = f"FAILED — {error[:60]}"
        else:
            grade = result.verdict.grade.value if result and result.verdict else "?"
            state = f"{grade} · {len(result.findings) if result else 0} findings"
        print(f"[{done['n']}/{len(targets)}] {url} — {state}", flush=True)

    results, summary = asyncio.run(
        run_batch(targets, out_dir, settings, concurrency=args.concurrency, on_result=progress)
    )

    (out_dir / "fleet.json").write_text(
        json.dumps(summary.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    report = render_fleet(summary, args.lang)
    (out_dir / "fleet.md").write_text(report, encoding="utf-8")
    if args.pdf:
        from .report.fleet_pdf import render_fleet_pdf

        render_fleet_pdf(summary, Path(args.pdf), args.lang)
    print()
    print(report)
    failed = [r for r in results if r.get("status") != "ok"]
    if failed:
        print(f"{len(failed)} of {len(results)} targets did not produce a result", file=sys.stderr)
        return 1
    return 0


def _cmd_consent_pass(args: argparse.Namespace) -> int:
    """The opt-in mode that interacts with the consent mechanism.

    A separate command on purpose: it produces a separate document with a
    separate declared method, and the passive report never changes because of it.
    """
    t = Translator.for_locale(args.lang)
    result = _within_budget(refusal_scan(args.url, DEFAULTS), DEFAULTS)
    attempt = (result.record.get("posture") or {}).get("refusal") or {}

    if args.json:
        Path(args.json).write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
    if args.md:
        Path(args.md).write_text(render(result, args.lang), encoding="utf-8")
    if args.pdf:
        from .report.pdf import render_pdf

        render_pdf(result, Path(args.pdf), args.lang)

    outcome = attempt.get("outcome", "")
    print(t.t(f"consent_pass.outcome.{outcome}") if outcome else "")
    if attempt.get("platform_name"):
        print(f"  {t.t('consent_pass.labels.platform')}: {attempt['platform_name']}")
        print(f"  {t.t('consent_pass.labels.action')}: {attempt.get('action')}")
        print(f"  {t.t('consent_pass.labels.documentation')}: {attempt.get('documentation')}")
    print(
        t.t(
            "cli.scan_summary",
            url=result.url,
            grade=result.verdict.grade.value if result.verdict else "?",
            n=len(result.findings),
        )
    )
    return _gate(result, args.fail_on)


def _cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .auth import UnsafeBind, api_key_configured, assert_bind_is_safe
    from .config import ConfigError

    # Importing the app reads its limits; a bad value is reported here, by name,
    # and not as a traceback from inside the server.
    try:
        import scanprivacy.api  # noqa: F401
    except ConfigError as bad:
        print(f"scanprivacy serve: {bad}", file=sys.stderr)
        return 2

    # Checked before the server starts, not on the first request: a service
    # that accepted one request it should not have accepted has already failed.
    try:
        assert_bind_is_safe(args.host)
    except UnsafeBind as unsafe:
        print(f"scanprivacy serve: {unsafe}", file=sys.stderr)
        return 2

    # Without this the service logs nothing the operator can tune: the module
    # loggers have no handler, so warnings (a refused target, a scan over its
    # budget) go nowhere. SCANPRIVACY_LOG_LEVEL picks the level.
    import logging
    import os

    level = os.environ.get("SCANPRIVACY_LOG_LEVEL", "INFO").upper()
    if level not in logging.getLevelNamesMapping():
        print(f"scanprivacy serve: SCANPRIVACY_LOG_LEVEL={level!r} is not a log level", file=sys.stderr)
        return 2
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    print(
        f"scanprivacy serve: {args.host}:{args.port} · authentication: "
        + ("api-key" if api_key_configured() else "none (loopback only)"),
        file=sys.stderr,
    )
    uvicorn.run("scanprivacy.api:app", host=args.host, port=args.port, reload=False)
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    from .analyze.diff import diff

    t = Translator.for_locale(args.lang)
    before = json.loads(Path(args.before).read_text(encoding="utf-8"))
    after = json.loads(Path(args.after).read_text(encoding="utf-8"))
    result = diff(before, after)
    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    print(
        t.t(
            "cli.diff_header",
            target=result["target"],
            before=result["verdict"]["before"],
            after=result["verdict"]["after"],
            days=result["days_elapsed"],
        )
    )
    # Before the counts, not after them. A reader who has already seen
    # "12 resolved" has drawn the conclusion the warning exists to prevent.
    configuration = result.get("configuration") or {}
    if configuration.get("note_key"):
        print()
        print(t.t(configuration["note_key"], changed=", ".join(configuration.get("changed") or [])))
        print()
    # The other half of what a measurement depends on: the engine, and the place
    # it was run from.
    vantage = result.get("vantage") or {}
    if vantage.get("status") == "changed":
        print(
            t.t(
                "diff.vantage_changed",
                before=" / ".join(str(x) for x in (vantage.get("before") or []) if x),
                after=" / ".join(str(x) for x in (vantage.get("after") or []) if x),
            )
        )
        print()
    print(t.t("cli.diff_resolved", n=sum(result["counts"]["resolved"].values())))
    print(t.t("cli.diff_new", n=sum(result["counts"]["new"].values())))
    print(t.t("cli.diff_persisting", n=sum(result["counts"]["persisting"].values())))
    for finding in result["new"][:10]:
        print(f"  + [{finding['severity']}] {finding['id']}")
    for finding in result["resolved"][:10]:
        print(f"  - [{finding['severity']}] {finding['id']}")
    for finding in [f for f in result["persisting"] if (f.get("age_days") or 0) >= 30][:10]:
        print(t.t("cli.diff_open_since", days=finding["age_days"], id=finding["id"]))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """Answers the two questions a recipient actually has: is this the evidence
    the report describes, and were the same rules applied?"""
    from .report.record import verify_record

    t = Translator.for_locale(args.lang)
    data = json.loads(Path(args.json_path).read_text(encoding="utf-8"))
    checked = verify_record(data)
    yes, no = t.t("report.labels.yes"), t.t("report.labels.no")
    print(t.t("cli.verify_evidence_intact", value=yes if checked["evidence_intact"] else no))
    intact = checked["findings_intact"]
    print(
        t.t(
            "cli.verify_findings_intact",
            value=t.t("report.labels.not_declared") if intact is None else (yes if intact else no),
        )
    )
    print(t.t("cli.verify_declared", value=checked["declared"]))
    print(t.t("cli.verify_recomputed", value=checked["recomputed"]))
    print(t.t("cli.verify_ruleset", value=yes if checked["ruleset_unchanged"] else no))
    print(t.t("cli.verify_knowledge", value=yes if checked["knowledge_unchanged"] else no))
    # False fails; None — a result published before the findings digest existed —
    # does not, because "could not be checked" is not "was checked and failed".
    return 0 if checked["evidence_intact"] and checked["findings_intact"] is not False else 1


def _cmd_sarif(args: argparse.Namespace) -> int:
    from .core.models import scan_from_dict
    from .report.sarif import build_sarif

    result = scan_from_dict(json.loads(Path(args.json_path).read_text(encoding="utf-8")))
    root = Path(args.source_root).resolve() if args.source_root else None
    sarif = build_sarif(result, args.lang, root, args.anchor_file)
    Path(args.out).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    run = sarif["runs"][0]
    print(
        f"{len(run['results'])} results, {run['properties']['sourceAnchored']} anchored to source "
        f"({run['properties']['sourceFilesSearched']} files searched) -> {args.out}"
    )
    return 0


def _cmd_badge(args: argparse.Namespace) -> int:
    from .core.models import scan_from_dict
    from .report.badge import render_badge

    result = scan_from_dict(json.loads(Path(args.json_path).read_text(encoding="utf-8")))
    Path(args.out).write_text(render_badge(result, args.label), encoding="utf-8")
    print(f"{result.verdict.grade.value if result.verdict else '?'} -> {args.out}")
    return 0


def _cmd_attest(args: argparse.Namespace) -> int:
    from .core.models import scan_from_dict
    from .report.attestation import write_attestation

    result = scan_from_dict(json.loads(Path(args.json_path).read_text(encoding="utf-8")))
    artifacts = [Path(a) for a in (args.artifact or [args.json_path])]
    statement, signature = write_attestation(
        result, artifacts, Path(args.out), sign=args.sign, key=Path(args.key) if args.key else None
    )
    for subject in statement["subject"]:
        print(f"  {subject['digest']['sha256'][:16]}…  {subject['name']}")
    print(f"{args.out}: {signature.mode if signature.signed else 'UNSIGNED'}")
    if signature.bundle_path:
        print(f"signature bundle: {signature.bundle_path}")
    return 0


def _cmd_verify_attestation(args: argparse.Namespace) -> int:
    from .report.attestation import verify_attestation

    checked = verify_attestation(
        Path(args.statement_path),
        Path(args.artifacts_dir) if args.artifacts_dir else None,
        certificate_identity=args.identity,
        certificate_oidc_issuer=args.oidc_issuer,
        public_key=Path(args.public_key) if args.public_key else None,
    )
    print(f"statement          : {'valid' if checked.statement_valid else 'NOT A SCANPRIVACY STATEMENT'}")
    print(f"artefacts matching : {checked.subjects_matching}/{checked.subjects_checked}")
    for name in checked.mismatched:
        print(f"  ALTERED  {name}")
    for name in checked.missing:
        print(f"  MISSING  {name}")
    if checked.signature_verified is None:
        print(f"signature          : NOT VERIFIED — {checked.signature_detail}")
    else:
        signature = "verified" if checked.signature_verified else "INVALID"
        print(f"signature          : {signature} ({checked.signature_mode})")
    # fail-closed: anything short of a verified signature over matching
    # artefacts is a failure, because that is what a recipient is relying on
    return 0 if checked.ok else 1


def _cmd_remediation(args: argparse.Namespace) -> int:
    """The fix catalogue, for a person or for a pipe.

    `--json` exists because the likeliest consumer is not a person: an agent
    answering a question about a real site should answer from this register,
    not from a recollection of the GDPR.
    """
    from .knowledge.remediation import catalogue, entry_for

    if args.key:
        entry = entry_for(args.key, args.lang)
        if entry is None:
            print(f"scanprivacy: no remediation known for {args.key!r}", file=sys.stderr)
            return 1
        entries = [entry]
    else:
        entries = catalogue(args.lang)

    if args.json:
        print(json.dumps([e.to_dict() for e in entries], ensure_ascii=False, indent=2))
        return 0

    for entry in entries:
        print(f"\n{entry.key}  [{entry.kind}]{'  ' + entry.severity if entry.severity else ''}")
        print(f"  {entry.summary}")
        for step in entry.steps:
            print(f"    - {step}")
        if entry.alternatives:
            print(f"  alternatives: {', '.join(entry.alternatives)}")
        if entry.vendors:
            print(f"  applies to: {', '.join(entry.vendors)}")
        if entry.applies_when:
            print(f"  fires when: {entry.applies_when}")
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    t = Translator.for_locale(args.lang)
    for rule in load_rules():
        print(
            f"{rule.id:<12} {rule.severity.value:<9} {rule.subject.value:<8} "
            f"{t.rule(rule.id, 'title')}"
        )
    return 0


def _cmd_install_browser(args: argparse.Namespace) -> int:
    """Install the Chromium build the engine drives, with the interpreter that runs this command.

    `python -m playwright` would resolve to whichever Python is first on PATH, which is not the one
    holding this package when it was installed with pipx or `uv tool`; `sys.executable` always is.
    """
    import subprocess

    command = [sys.executable, "-m", "playwright", "install"]
    if args.with_deps:
        command.append("--with-deps")
    command.append("chromium")
    return 0 if subprocess.run(command, check=False).returncode == 0 else 1


def _run(func, args: argparse.Namespace) -> int:
    """Run a subcommand, turning a missing browser into an instruction.

    Not a broad except: only the one failure that is both predictable and
    entirely the user's to fix. Everything else keeps its traceback, because a
    swallowed bug in this engine is worse than an ugly one.
    """
    from .observe.browser import BrowserUnavailable

    try:
        return func(args)
    except BrowserUnavailable as unavailable:
        print(f"scanprivacy: {unavailable}", file=sys.stderr)
        return 3
    except TimeoutError:
        print(
            f"scanprivacy: the scan did not finish within its budget of {DEFAULTS.per_scan_budget_s:.0f}s "
            "per page and was stopped",
            file=sys.stderr,
        )
        return 4


def build_parser() -> argparse.ArgumentParser:
    """The command surface, separated from running it.

    Two reasons, and neither is tidiness. A parser that can be built without
    executing anything can be *asserted on* — every default, every choice list,
    every exit code — which is most of what a command line promises. And the
    dispatch below stays four lines, so the thing that decides what runs is
    readable at a glance.
    """
    parser = argparse.ArgumentParser(
        prog="scanprivacy", description="Passive EU privacy conformance observation."
    )
    # Every report this tool writes names the engine version in its
    # reproducibility section, so the version has to be answerable from the
    # command line too — otherwise someone holding a report cannot check which
    # build produced it without reading the source.
    parser.add_argument(
        "--version",
        action="version",
        version=f"scanprivacy {__version__}",
    )
    parser.add_argument(
        "--lang",
        default=DEFAULT_LOCALE,
        choices=available_locales(),
        help="language of the human-readable output (default: %(default)s)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_cmd = sub.add_parser("scan", help="observe a URL and produce findings and fixes")
    scan_cmd.add_argument("url")
    scan_cmd.add_argument(
        "--pages",
        type=int,
        default=DEFAULTS.max_pages,
        help="pages to observe, entry page included (default: %(default)s). "
        "One page is not a site: a tracker on the contact form is invisible to a single-page scan",
    )
    scan_cmd.add_argument("--json", help="write the full result, graph included, to this file")
    scan_cmd.add_argument("--md", help="write the readable report to this file")
    scan_cmd.add_argument("--pdf", help="write the PDF report (full evidence and reproducibility)")
    scan_cmd.add_argument("--mermaid", action="store_true", help="print only the graph, as mermaid")
    scan_cmd.add_argument("--quiet", action="store_true", help="print a single outcome line")
    scan_cmd.add_argument("--sarif", help="write SARIF 2.1.0 for code scanning ingestion")
    scan_cmd.add_argument("--badge", help="write a self-contained SVG conformance badge")
    scan_cmd.add_argument(
        "--source-root",
        help="repository root: findings are anchored to the file and line that cause them",
    )
    scan_cmd.add_argument(
        "--anchor-file",
        default="README.md",
        help="file SARIF results point at when no source line matches (default: %(default)s)",
    )
    scan_cmd.add_argument(
        "--fail-on",
        default="not-conformant",
        choices=["critical", "high", "medium", "low", "info", "any-finding", "not-conformant", "never"],
        help="exit code 1 when a finding at or above this severity exists (default: %(default)s)",
    )
    scan_cmd.add_argument("--attest", help="write an in-toto statement over the artefacts produced")
    scan_cmd.add_argument(
        "--sign",
        default="unsigned",
        choices=["unsigned", "cosign-keyless", "cosign-key"],
        help="sign the attestation (default: %(default)s). Keyless needs an OIDC identity",
    )
    scan_cmd.add_argument("--key", help="cosign private key, for --sign cosign-key")
    scan_cmd.add_argument("--no-documents", action="store_true", help="do not read the linked legal documents")
    scan_cmd.add_argument(
        "--ua-fallback",
        action="store_true",
        help=(
            "if the identified User-Agent is refused, retry once as a plain browser. "
            "Off by default: the retry drops the contact address the site owner "
            "would need to object. The report always names the string that "
            "actually reached the site"
        ),
    )
    scan_cmd.set_defaults(func=_cmd_scan)

    batch_cmd = sub.add_parser(
        "batch",
        help="scan a list of targets and summarise what they have in common",
        description=(
            "One report says what to fix on one site. A fleet says what an owner keeps doing: "
            "the same font CDN on thirty sites is one decision repeated, not thirty problems. "
            "Targets share one courtesy budget per host, failures are isolated, and results are "
            "written as they complete so an interrupted run resumes."
        ),
    )
    batch_cmd.add_argument("targets", help="file with one URL per line, or a single URL")
    batch_cmd.add_argument("--out", required=True, help="directory for per-target results and the summary")
    batch_cmd.add_argument("--pages", type=int, default=3)
    batch_cmd.add_argument("--concurrency", type=int, default=3)
    batch_cmd.add_argument(
        "--ua-fallback",
        action="store_true",
        help="see `scanprivacy scan --ua-fallback`; off by default",
    )
    batch_cmd.add_argument("--pdf", help="write the estate summary as a PDF")
    batch_cmd.set_defaults(func=_cmd_batch)

    consent_cmd = sub.add_parser(
        "consent-pass",
        help="opt-in: refuse consent through the platform's documented path and measure what changes",
        description=(
            "Separate mode with a separate method and a separate document. Unlike every other "
            "command, this one interacts with the page: it performs exactly one documented "
            "refusal on a recognised consent platform, reloads, and compares. An unrecognised "
            "platform is reported and left untouched."
        ),
    )
    consent_cmd.add_argument("url")
    consent_cmd.add_argument("--json")
    consent_cmd.add_argument("--md")
    consent_cmd.add_argument("--pdf")
    consent_cmd.add_argument(
        "--fail-on",
        default="not-conformant",
        choices=["critical", "high", "medium", "low", "info", "any-finding", "not-conformant", "never"],
    )
    consent_cmd.set_defaults(func=_cmd_consent_pass)

    serve_cmd = sub.add_parser("serve", help="run the HTTP API")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8099)
    serve_cmd.set_defaults(func=_cmd_serve)

    diff_cmd = sub.add_parser("diff", help="compare two scans of the same target")
    diff_cmd.add_argument("before")
    diff_cmd.add_argument("after")
    diff_cmd.add_argument("--json", help="write the full comparison to this file")
    diff_cmd.set_defaults(func=_cmd_diff)

    verify_cmd = sub.add_parser("verify", help="recompute the digests of a published result")
    verify_cmd.add_argument("json_path", help="a JSON file produced by `scanprivacy scan --json`")
    verify_cmd.set_defaults(func=_cmd_verify)

    sarif_cmd = sub.add_parser("sarif", help="re-export a stored result as SARIF")
    sarif_cmd.add_argument("json_path")
    sarif_cmd.add_argument("--out", required=True)
    sarif_cmd.add_argument("--source-root")
    sarif_cmd.add_argument("--anchor-file", default="README.md")
    sarif_cmd.set_defaults(func=_cmd_sarif)

    badge_cmd = sub.add_parser("badge", help="write an SVG badge from a stored result")
    badge_cmd.add_argument("json_path")
    badge_cmd.add_argument("--out", required=True)
    badge_cmd.add_argument("--label", default="privacy")
    badge_cmd.set_defaults(func=_cmd_badge)

    attest_cmd = sub.add_parser("attest", help="attest a stored result and its artefacts")
    attest_cmd.add_argument("json_path")
    attest_cmd.add_argument("--artifact", action="append", default=[], help="repeatable")
    attest_cmd.add_argument("--out", required=True)
    attest_cmd.add_argument(
        "--sign", default="unsigned", choices=["unsigned", "cosign-keyless", "cosign-key"]
    )
    attest_cmd.add_argument("--key")
    attest_cmd.set_defaults(func=_cmd_attest)

    verify_att = sub.add_parser(
        "verify-attestation", help="check artefact digests and the signature of an attestation"
    )
    verify_att.add_argument("statement_path")
    verify_att.add_argument("--artifacts-dir")
    verify_att.add_argument("--identity", help="expected certificate identity (keyless)")
    verify_att.add_argument("--oidc-issuer", help="expected OIDC issuer (keyless)")
    verify_att.add_argument("--public-key", help="cosign public key, for key-signed statements")
    verify_att.set_defaults(func=_cmd_verify_attestation)

    rem_cmd = sub.add_parser(
        "remediation", help="the fix catalogue — by rule, pattern or vendor, without scanning"
    )
    rem_cmd.add_argument("key", nargs="?", help="a rule id, a pattern name, or a vendor id")
    rem_cmd.add_argument("--json", action="store_true", help="machine-readable, for tools and agents")
    rem_cmd.set_defaults(func=_cmd_remediation)

    browser_cmd = sub.add_parser("install-browser", help="install the Chromium build the engine drives")
    browser_cmd.add_argument(
        "--with-deps", action="store_true", help="also install the system libraries Chromium needs (Linux, needs root)"
    )
    browser_cmd.set_defaults(func=_cmd_install_browser)

    rules_cmd = sub.add_parser("rules", help="list the loaded rules")
    rules_cmd.set_defaults(func=_cmd_rules)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _run(args.func, args)


if __name__ == "__main__":
    sys.exit(main())
