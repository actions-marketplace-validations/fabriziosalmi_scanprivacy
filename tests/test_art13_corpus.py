"""The Art. 13 detectors, held to what was measured on real notices.

The corpus (tests/corpus/art13) is 21 public privacy notices with every element labelled by
reading them, each "present" backed by a quote. The texts are not stored (they are other
people's documents): the full measurement needs `tools/art13/fetch.py` and is documented in
docs/art13-measurement.md. What runs offline, here, is what protects it:

- the labels are well-formed and every one traces to a document in the manifest;
- every labelled quote that the detector matched when the corpus was pinned still matches,
  so no change can quietly lose a wording the engine already understood;
- the wordings the detectors were widened to catch are caught, and the look-alikes that would
  have made an element true everywhere are not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scanprivacy.observe.docs import ART13_ELEMENTS

CORPUS = Path(__file__).resolve().parents[1] / "tests" / "corpus" / "art13"
MANIFEST = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
LABELS = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CORPUS / "labels").glob("*.json"))}
PINNED = [tuple(pair) for pair in json.loads((CORPUS / "pinned.json").read_text(encoding="utf-8"))]


def test_every_document_has_labels_for_every_element_and_the_other_way_round():
    assert set(LABELS) == set(MANIFEST)
    for doc_id, data in LABELS.items():
        assert set(data["elements"]) == set(ART13_ELEMENTS), doc_id
        entry = MANIFEST[doc_id]
        assert entry["url"].startswith("https://") and len(entry["sha256"]) == 64, doc_id
        assert entry["lang"] in {"it", "en"}, doc_id


def test_a_present_label_carries_a_short_quote_and_an_absent_one_does_not():
    for doc_id, data in LABELS.items():
        for key, element in data["elements"].items():
            if element["present"]:
                assert element["quote"] and len(element["quote"]) <= 300, f"{doc_id}.{key}"
            else:
                assert element["quote"] is None, f"{doc_id}.{key}"


@pytest.mark.parametrize("doc_id,key", PINNED, ids=[f"{d}.{k}" for d, k in PINNED])
def test_a_wording_the_engine_understood_when_the_corpus_was_pinned_is_still_understood(doc_id, key):
    quote = LABELS[doc_id]["elements"][key]["quote"]
    assert ART13_ELEMENTS[key].search(quote), f"{key} no longer recognises: {quote[:120]!r}"


def test_the_pinned_set_is_not_quietly_emptied():
    assert len(PINNED) >= 120
    with_positives = {d for d, data in LABELS.items() if any(e["present"] for e in data["elements"].values())}
    assert {d for d, _ in PINNED} <= with_positives
    assert len(with_positives - {d for d, _ in PINNED}) <= 2, "documents whose every quote the detector now misses"



# Wordings found in the corpus that the detectors originally missed (and now catch).
CAUGHT = [
    ("controller", "are titolari del trattamento dei dati personali raccolti"),
    ("controller", "Different companies are the controller (or co-controller) of personal information"),
    ("controller", "the Controller of your personal information is the main subsidiary"),
    ("purposes", "We use this information to process and evaluate applications"),
    ("purposes", "We collect and use information to improve our business operations"),
    ("purposes", "We use the information you provide in the following ways"),
    ("recipients", "Our email management vendors are SalesForce and Mailchimp"),
    ("recipients", "The Commission's contractors are bound by a contractual clause"),
    ("recipients", "I Suoi dati potranno essere comunicati a soggetti terzi"),
    ("transfers", "information may be transferred from the U.S. to other countries"),
    ("transfers", "trasferire i dati in regioni esterne allo Spazio Economico Europeo"),
    ("retention", "records, which are retained for 10 years from the date of last payment"),
    ("retention", "The Commission only keeps this information for the time necessary"),
    ("retention", "I dati di navigazione non persistono per più di novanta giorni"),
    ("last_updated", "This Privacy Policy is effective as of November 4th, 2025."),
    ("last_updated", "Valida dal 12 giugno 2026"),
]

# Look-alikes the same widening must not accept: each would make an element true on a
# notice that never made the statement, and a finding that can never fire is worth nothing.
NOT_CAUGHT = [
    ("controller", "Plug a game controller into the console"),
    ("controller", "The domain controller replicates the directory"),
    ("recipients", "We do not use third-party cookies and we link to third party websites"),
    ("purposes", "We use cookies to remember your language"),
    ("purposes", "We use JavaScript to render the page"),
    ("transfers", "You can transfer money between your own accounts"),
    ("retention", "Please keep this page for your reference"),
    ("last_updated", "Our security measures are effective against attacks"),
    ("last_updated", "We updated our logo and the colour of the buttons"),
]


@pytest.mark.parametrize("key,text", CAUGHT)
def test_the_widened_detectors_catch_the_wordings_that_were_missed(key, text):
    assert ART13_ELEMENTS[key].search(text), text


@pytest.mark.parametrize("key,text", NOT_CAUGHT)
def test_the_widened_detectors_do_not_accept_look_alikes(key, text):
    assert not ART13_ELEMENTS[key].search(text), text
