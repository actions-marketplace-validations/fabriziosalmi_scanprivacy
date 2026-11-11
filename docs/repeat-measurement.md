# Repeat mode, measured

`scanprivacy scan --repeat N` loads a page N times and reports how many loads showed each finding (see [Repeating a scan](quickstart.html)). This page records what it showed on real sites, with the predictions that were written before the measurement.

## Method

10 public sites, `--repeat 5 --pages 1`, 50 loads in all, from one machine in one run. Six static sites (documentation and reference sites) and four Italian news sites, which are advertising-heavy. The predictions were written to a file before the first load:

1. On the six static sites no finding is unstable and the grade is the same in all five loads.
2. On the four news sites at least three show at least one unstable finding.
3. Across all ten sites the grade differs between loads on at most two.
4. At least 49 of the 50 loads complete.

## Results

| | Static sites (6) | News sites (4) |
|---|---:|---:|
| Findings, all loads together | 36 | 322 |
| Findings not in every load | 0 | 87 (27%) |
| Range per site | 0% | 0% to 79% |
| Sites with at least one unstable finding | 0 | 3 |
| Sites whose grade differed between loads | 0 | 0 |

All 50 loads completed. `scanprivacy verify` reports the repeated loads intact on all ten results.

| Prediction | Held |
|---|---|
| 1. static sites stable | yes, 0 of 36 |
| 2. at least 3 of 4 news sites with an unstable finding | yes, exactly 3 |
| 3. grade differs on at most 2 sites | yes, on 0 |
| 4. at least 49 of 50 loads complete | yes, 50 |

## What it shows

On an advertising-heavy page, one load can list a very different set of findings from the next: on one site 79% of the findings appeared in some loads and not in others (analytics cookies and storage keys set by advertising partners, which vary with each load). On the static sites a single load told the whole story.

In this sample the grade did not move, but that is weak evidence: the four news sites are at the floor (F) in every load, so no unstable finding could change their grade. A site near a boundary, with an unstable finding that decides between two grades, was not in the sample, and this page does not claim how often that happens. That case is what the rule "the grade is the worst completed load" is for.

## Limits

- Ten sites, one run each, one machine, one place, a few minutes apart. Variance over days, from other countries or on other days was not measured.
- The news sites were chosen because they were expected to vary; this is not a sample of the web.
- The result file grows with N and with the page: the heaviest site measured produced 6.8 MB for five loads.

## Repeat it

```bash
scanprivacy scan https://example.org --pages 1 --repeat 5 --json evidence.json
scanprivacy verify evidence.json
```
Scan only sites you may observe, and keep the results out of the repository (`tests/test_repo_hygiene.py` enforces it).
