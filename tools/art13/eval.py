"""Measure the Art. 13 detectors against the labelled corpus.

    python tools/art13/eval.py              # all documents
    python tools/art13/eval.py --test       # only the held-out documents
    python tools/art13/eval.py --train      # everything else
    python tools/art13/eval.py -v           # also list every false positive and false negative
    python tools/art13/eval.py --pin        # rewrite tests/corpus/art13/pinned.json

The held-out documents were set aside before the detectors were tuned and were not read
while tuning: they are the check that an improvement is not an overfit.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "corpus" / "art13"
CACHE = ROOT / ".cache" / "art13"

HELD_OUT = {"en-atlassian", "en-gov-uk", "it-ansa", "it-polimi", "it-slack", "en-github"}


def load_labels() -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CORPUS / "labels").glob("*.json"))}


def main(argv: list[str]) -> int:
    from scanprivacy.observe.docs import ART13_ELEMENTS

    labels = load_labels()

    if "--pin" in argv:
        pinned = sorted(
            [doc, key]
            for doc, data in labels.items()
            for key, element in data["elements"].items()
            if element["present"] and ART13_ELEMENTS[key].search(element["quote"])
        )
        (CORPUS / "pinned.json").write_text(json.dumps(pinned, indent=1) + "\n", encoding="utf-8")
        print(f"pinned {len(pinned)} (document, element) pairs whose labelled quote the detector matches")
        return 0

    split = "test" if "--test" in argv else "train" if "--train" in argv else ""
    ids = [i for i in labels if not split or (i in HELD_OUT) == (split == "test")]
    missing = [i for i in ids if not (CACHE / f"{i}.txt").exists()]
    if missing:
        print(f"no cached text for {missing}: run tools/art13/fetch.py first", file=sys.stderr)
        return 2

    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    wrong: dict[str, list] = defaultdict(list)
    for doc in ids:
        text = (CACHE / f"{doc}.txt").read_text(encoding="utf-8")
        for key, pattern in ART13_ELEMENTS.items():
            gold = labels[doc]["elements"][key]["present"]
            found = pattern.search(text)
            counts[key]["tp" if gold and found else "fp" if found else "fn" if gold else "tn"] += 1
            if found and not gold:
                wrong[key].append(("FP", doc, found.group(0)))
            if gold and not found:
                wrong[key].append(("FN", doc, ""))

    print(f"{len(ids)} documents{' (' + split + ')' if split else ''}")
    print(f"{'element':13} {'TP':>3} {'FP':>3} {'FN':>3} {'TN':>3}  {'precision':>9} {'recall':>6}")
    total: dict[str, int] = defaultdict(int)
    for key in ART13_ELEMENTS:
        c = counts[key]
        for name in ("tp", "fp", "fn", "tn"):
            total[name] += c[name]
        precision = f"{c['tp'] / (c['tp'] + c['fp']):.2f}" if c["tp"] + c["fp"] else "-"
        recall = f"{c['tp'] / (c['tp'] + c['fn']):.2f}" if c["tp"] + c["fn"] else "-"
        print(f"{key:13} {c['tp']:3} {c['fp']:3} {c['fn']:3} {c['tn']:3}  {precision:>9} {recall:>6}")
    p = total["tp"] / (total["tp"] + total["fp"])
    r = total["tp"] / (total["tp"] + total["fn"])
    print(f"{'ALL':13} {total['tp']:3} {total['fp']:3} {total['fn']:3} {total['tn']:3}  {p:9.2f} {r:6.2f}")
    if "-v" in argv:
        for key, rows in wrong.items():
            for kind, doc, matched in rows:
                print(f"{kind} {key:13} {doc} {matched!r}" if matched else f"{kind} {key:13} {doc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
