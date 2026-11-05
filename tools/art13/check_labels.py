"""Check label files: all 12 elements, and every quote is a verbatim passage of the document.

    python tools/art13/check_labels.py [<id> ...]     # default: every document in the manifest

Needs the texts: run tools/art13/fetch.py first. A label whose quote is not found in the
text is rejected: that is how a hallucinated "present" is caught.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests" / "corpus" / "art13"
CACHE = ROOT / ".cache" / "art13"
KEYS = [
    "controller", "contact", "dpo", "purposes", "legal_basis", "recipients",
    "transfers", "retention", "rights", "complaint", "profiling", "last_updated",
]


def check(doc_id: str) -> list[str]:
    problems: list[str] = []
    data = json.loads((CORPUS / "labels" / f"{doc_id}.json").read_text(encoding="utf-8"))
    text = (CACHE / f"{doc_id}.txt").read_text(encoding="utf-8")
    elements = data.get("elements", {})
    if set(elements) != set(KEYS):
        return [f"{doc_id}: keys differ (missing {set(KEYS) - set(elements)}, extra {set(elements) - set(KEYS)})"]
    for key in KEYS:
        element = elements[key]
        if element.get("present") is True:
            quote = element.get("quote")
            if not quote or len(quote) > 300:
                problems.append(f"{doc_id}.{key}: quote missing or longer than 300 characters")
            elif quote not in text:
                problems.append(f"{doc_id}.{key}: quote not found verbatim: {quote[:70]!r}")
        elif element.get("present") is False:
            if element.get("quote") is not None:
                problems.append(f"{doc_id}.{key}: marked absent but has a quote")
        else:
            problems.append(f"{doc_id}.{key}: present must be true or false")
    return problems


def main(ids: list[str]) -> int:
    ids = ids or sorted(json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8")))
    bad = [problem for doc_id in ids for problem in check(doc_id)]
    print("\n".join(bad) if bad else f"OK: {len(ids)} label files")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
