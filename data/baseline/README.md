# Baselines

A dated snapshot of a scan run, kept so that a later run can be compared with
it. Remediation is only demonstrable against the measurement it started from —
"we fixed it" means nothing without the number it used to be.

    scanprivacy batch data/fleet-targets.txt --out data/fleet
    cp -r data/fleet data/baseline/$(date +%F)
    scanprivacy diff data/baseline/2026-07-29/example.org.json data/fleet/example.org.json

## Nothing in here is tracked

`data/baseline/<date>/`, `data/fleet/` and `data/fleet-targets.txt` are all
ignored. They are the estate of whoever runs this engine, and this repository is
the engine. Committing one operator's snapshots put 46 files in the tree that
nothing references, plus a list of that person's sites with a grade against
each — which is a map, and a public repository is not where it belongs.

This file is tracked, because the convention is worth documenting even though
the data is not.

## A baseline is only comparable to the engine that produced it

Every scan records the digests of the ruleset, the knowledge base and the
catalogues that produced it. Change a rule and the findings it used to emit
stop appearing — in a comparison they surface under *resolved*, which reads as
though somebody fixed something.

`scanprivacy diff` checks those digests and says so before it shows any numbers. When
it does, the snapshot is not wrong; it is answering a question about a different
engine. Re-scan the earlier state with the current build before reading the
comparison as remediation.
