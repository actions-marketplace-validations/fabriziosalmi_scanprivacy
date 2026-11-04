# Labelling rubric: GDPR Art. 13 elements in a privacy notice

You are labelling real public privacy notices, as a data protection lawyer would. For each document decide, for each of the 12 elements below, whether the notice contains an explicit statement that satisfies it.

Judge the MEANING, not keywords. A notice can satisfy an element without using the usual words, and can use the usual words without satisfying it. Do not try to guess how any software would score it. Read the whole document: a statement can be far from where you would expect it.

## The 12 elements

| key | what must be stated | Art. |
|-----|--------------------|------|
| controller | who the data controller is (a named entity or role that decides purposes and means) | 13(1)(a) |
| contact | how to contact the controller: an email address, postal address, phone number, contact form or PEC | 13(1)(a) |
| dpo | contact details of a Data Protection Officer (or an explicit statement of who handles this role) | 13(1)(b) |
| purposes | why personal data is processed (the purposes) | 13(1)(c) |
| legal_basis | the legal basis for processing (consent, contract, legitimate interests, legal obligation, public task, ...) | 13(1)(c) |
| recipients | who receives the data, by name or category (processors, partners, authorities, ...) | 13(1)(e) |
| transfers | transfers of personal data to third countries or international organisations, and the safeguards used; or a statement that there are none | 13(1)(f) |
| retention | how long the data is kept, or the criteria for it; or a statement that it is not kept | 13(2)(a) |
| rights | the data subject's rights (access, rectification, erasure, restriction, objection, portability, withdraw consent) | 13(2)(b) |
| complaint | the right to lodge a complaint with a supervisory authority | 13(2)(d) |
| profiling | whether automated decision-making including profiling takes place; counts as present if the notice says it does OR says it does not | 13(2)(f) |
| last_updated | a date or version showing when the notice was last updated | good practice |

## Rules

- `present: true` only when there is an explicit statement. A passing mention of the topic is not enough (for example, a link to "your rights" with no rights listed is NOT present for rights unless the rights are stated in this document).
- If the statement is in a different document the notice only links to, it is `present: false` for THIS text.
- If you are unsure after reading carefully, label `present: false` and write the doubt in `notes`.
- For every `present: true` give a `quote`: ONE contiguous passage copied EXACTLY, character for character, from the text file (the text has whitespace collapsed to single spaces; copy it as is). At most 300 characters. Choose the passage that most clearly satisfies the element. Do not paraphrase, do not join two passages, do not fix typos or punctuation.
- For `present: false`, `quote` must be null.

## Output

For each document write `tests/corpus/art13/labels/<id>.json`:

```json
{
  "id": "<id>",
  "elements": {
    "controller":   {"present": true,  "quote": "exact passage"},
    "contact":      {"present": false, "quote": null},
    "dpo":          {"present": false, "quote": null},
    "purposes":     {"present": false, "quote": null},
    "legal_basis":  {"present": false, "quote": null},
    "recipients":   {"present": false, "quote": null},
    "transfers":    {"present": false, "quote": null},
    "retention":    {"present": false, "quote": null},
    "rights":       {"present": false, "quote": null},
    "complaint":    {"present": false, "quote": null},
    "profiling":    {"present": false, "quote": null},
    "last_updated": {"present": false, "quote": null}
  },
  "notes": "anything uncertain, one or two sentences, or empty"
}
```

All 12 keys are required. Then run the checker and fix whatever it reports:

    python3 tools/art13/check_labels.py <id> [<id> ...]
