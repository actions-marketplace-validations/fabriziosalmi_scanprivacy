# Quickstart

Requires Python 3.11 or newer.

```bash
pipx install scanprivacy         # or: uv tool install scanprivacy, or pip install scanprivacy
scanprivacy install-browser       # the package brings the driver, not the browser
scanprivacy scan https://example.org --pages 5 --pdf report.pdf --json evidence.json
```

PDF output needs the Pango/Cairo system libraries (Debian/Ubuntu: `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 libcairo2`; macOS: `brew install pango`).

## Repeating a scan

```bash
scanprivacy scan https://example.org --repeat 5 --json evidence.json
```

A single load is a photograph, and two loads of one page can differ (ad rotation, an A/B test, a CDN edge). `--repeat N` (2 to 10) loads the page N times, each in a fresh browser, and the report adds a section that lists the findings which did not appear in every load, with how many loads showed them.

Four rules decide what is reported:

- **The grade is the worst completed load**, and the grade of every load is listed beside it. It is not computed from the findings common to all loads: a tracker seen in two loads out of five did receive the visitor's data in those two, and an intersection would erase it and print a grade no load produced.
- **A load that did not finish is not an absence.** It leaves the denominator, so "seen in 3 of 4" means four loads completed. If none completed, the result is INCONCLUSIVE.
- **The one-page-load-per-second-per-host limit holds across the whole run**, not only inside each load. The time budget is multiplied by N.
- **The reported load is a whole scan**, so `scanprivacy verify` works on it. The other loads are kept in full inside the file, under `repeat`, and `verify` recomputes each load's digests, the digest of the block, the grade each load declares and the stability table. A scan without `--repeat` produces the same JSON as before.

`--fail-on` and `--sarif`, `--badge`, `--pdf` and `--attest` act on the reported load. The HTTP API does not take `repeat` yet.

## What you get

- `evidence.json`: the observation, the findings graph and the verdict, with digests
- `report.pdf`: the same, for a reader who is not an engineer. `--lang it` produces the Italian report
- `scanprivacy verify evidence.json` recomputes every digest
- `scanprivacy diff before.json after.json` shows resolved, new and persisting findings

## Other commands

`batch`, `consent-pass` (the opt-in refusal test, a separate document), `sarif`, `badge`, `attest`, `verify-attestation`, `remediation`, `rules`, `serve`. Run `scanprivacy <command> --help`.

## Exit codes

`0` success. `1` the command ran but its answer is a failure (a gate, a mismatch, a `batch` in which some targets did not produce a result). `2` bad usage or refused configuration (for example `serve` without a key on a non-loopback bind). `3` the Chromium build is not installed (`scanprivacy install-browser`). `4` the scan did not finish within its time budget and was stopped.

## In CI

See [examples/workflows/privacy-gate.yml](../examples/workflows/privacy-gate.yml) and the "In continuous integration" section of the README.
