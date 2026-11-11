# Quickstart

Requires Python 3.11 or newer.

```bash
git clone https://github.com/fabriziosalmi/scanprivacy && cd scanprivacy
pip install -e .
python -m playwright install chromium    # the package brings the driver, not the browser
scanprivacy scan https://example.org --pages 5 --pdf report.pdf --json evidence.json
```

PDF output needs the Pango/Cairo system libraries (Debian/Ubuntu: `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfribidi0 libcairo2`; macOS: `brew install pango`).

## What you get

- `evidence.json`: the observation, the findings graph and the verdict, with digests
- `report.pdf`: the same, for a reader who is not an engineer. `--lang it` produces the Italian report
- `scanprivacy verify evidence.json` recomputes every digest
- `scanprivacy diff before.json after.json` shows resolved, new and persisting findings

## Other commands

`batch`, `consent-pass` (the opt-in refusal test, a separate document), `sarif`, `badge`, `attest`, `verify-attestation`, `remediation`, `rules`, `serve`. Run `scanprivacy <command> --help`.

## Exit codes

`0` success. `1` the command ran but its answer is a failure (a gate, a mismatch, a `batch` in which some targets did not produce a result). `2` bad usage or refused configuration (for example `serve` without a key on a non-loopback bind). `3` the Chromium build is not installed (`python -m playwright install chromium`). `4` the scan did not finish within its time budget and was stopped.

## In CI

See [examples/workflows/privacy-gate.yml](../examples/workflows/privacy-gate.yml) and the "In continuous integration" section of the README.
