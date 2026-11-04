# Art. 13 detectors: measured on real notices

The engine decides which GDPR Art. 13 elements a privacy notice states by matching its text. A pattern like that can be too narrow (a missing element is reported that the notice does state) or too wide (an element is accepted that the notice never stated). Until now neither had a number. This page is the number, how it was obtained, and what it does not show.

## Method

1. **A corpus.** 21 public privacy notices (9 Italian, 12 in English; two files first sorted as English turned out to be Italian), chosen to differ in kind: public bodies, media, e-commerce, telecoms, SaaS and non-profits. Only the URL, the date and a hash of the extracted text are stored; the texts are other people's documents and are fetched again on demand (`tools/art13/fetch.py`), which also reports any document that changed since it was labelled.
2. **Labels.** For each notice and each of the 12 elements, a reader (a model working from a written rubric, `tools/art13/RUBRIC.md`) decided whether the notice contains an explicit statement satisfying it, judging the meaning and without seeing the detectors. Every "present" carries a passage quoted verbatim; `tools/art13/check_labels.py` rejects a quote that is not in the text, so an invented "present" cannot get in. An "absent" has no quote and cannot be checked this way.
3. **Measurement.** The detector is run on the whole text of each notice and compared with the labels: true and false positives and negatives, per element (`tools/art13/eval.py`).
4. **Held-out documents.** Six notices were set aside before any detector was changed and were not read while tuning. They are the check that an improvement is not an overfit to the documents that were looked at.

The prediction written before the first measurement was the wrong way round: it expected high recall and low precision. The detectors turned out precise and prone to miss.

## Result

| Element | Precision before | Recall before | Precision after | Recall after |
|---------|-----------------:|--------------:|----------------:|-------------:|
| controller | 1.00 | 0.55 | 1.00 | 0.75 |
| contact | 0.94 | 0.88 | 0.94 | 0.88 |
| dpo | 0.93 | 1.00 | 0.93 | 1.00 |
| purposes | 1.00 | 0.65 | 1.00 | 0.90 |
| legal_basis | 0.93 | 0.93 | 0.93 | 0.93 |
| recipients | 0.93 | 0.72 | 0.94 | 0.89 |
| transfers | 0.90 | 0.69 | 0.93 | 1.00 |
| retention | 1.00 | 0.78 | 1.00 | 1.00 |
| rights | 1.00 | 0.94 | 1.00 | 0.94 |
| complaint | 0.87 | 0.87 | 0.87 | 0.87 |
| profiling | 0.44 | 0.67 | 0.44 | 0.67 |
| last_updated | 1.00 | 0.36 | 1.00 | 0.86 |
| **All, 21 notices** | **0.92** | **0.75** | **0.93** | **0.90** |
| **Held out, 6 notices** | **0.98** | **0.78** | **0.98** | **0.89** |

Six elements were widened (controller, purposes, recipients, transfers, retention, last_updated), each only to the wordings the corpus showed were missed: "titolari del trattamento" in the plural, "are the controller", "We use this information to", "retained for 10 years", "effective as of", "Valida dal". Each widening is restricted to its context, because the cheap alternative (a bare "controller", "third party" or "we use") would make the element true on almost every notice and the finding worth nothing. Look-alike sentences that must not be accepted are pinned in `tests/test_art13_corpus.py`.

## What is still missed or wrong

- **A controller named but not called one.** Five notices identify who they are ("Mozilla (that's us)", "the Wikimedia Foundation operates the sites") without the word controller. No pattern can tell that from any sentence with a company name in it. These stay reported as missing, which is arguable under the article and is the safe direction.
- **`profiling` is not improved, on purpose.** The labelling was inconsistent on it: the same sentence ("no cookies are used for profiling") was labelled absent in one notice and present in another, because the element is about automated decision-making and the word "profiling" appears in cookie contexts. Until the definition is settled and relabelled, tuning it would tune noise. Its five false positives are all the word in a cookie sentence. It is a conditional element and never counted as a missing obligation.
- **Remaining false positives** are single cases: a bare mention of the Garante or a supervisory authority counted as the right to complain, an email-less "PEC" label, a link list that says "destinatari".

## What this does not show

- **21 documents, one labelling pass, not double-annotated.** The labels are as good as one careful reading. A sample should be checked by a second reader, ideally a lawyer, before the numbers are quoted as accurate to the second decimal.
- **Few negatives.** For several elements almost every notice states them, so the false-positive rate is estimated from one to seven documents. The look-alike tests cover the listed sentences only.
- **Whole-document detection.** An element counts if it matches anywhere in the text, including a footer or a different section; the measurement says nothing about whether the match is the statement a reader would point to.
- **Skew.** Large companies and English are over-represented; Italian public bodies are thin (many guessed URLs of Italian administrations returned 404 or blocked automated access, and are not in the corpus).
- **Documents change.** The hashes in `tests/corpus/art13/manifest.json` are those of 2026-11-04.

## Corpus

| Id | Language | Kind | URL | Characters |
|----|----------|------|-----|-----------:|
| it-agenziaentrate | it | public | https://www.agenziaentrate.gov.it/portale/privacy | 15,296 |
| it-ilpost | it | media | https://www.ilpost.it/privacy/ | 15,745 |
| it-polimi | it | public | https://www.polimi.it/privacy | 18,864 |
| it-istat | it | public | https://www.istat.it/privacy/ | 18,682 |
| it-amazon | it | ecommerce | https://www.amazon.it/gp/help/customer/display.html?nodeId=201909010 | 46,981 |
| it-wind | it | telco | https://www.windtre.it/privacy | 22,792 |
| it-ansa | it | media | https://www.ansa.it/sito/static/privacy.html | 39,700 |
| it-regione-lombardia | it | public | https://www.regione.lombardia.it/wps/portal/istituzionale/HP/privacy | 15,095 |
| it-unibo | it | public | https://www.unibo.it/it/privacy | 6,502 |
| en-github | en | saas | https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement | 43,717 |
| en-mozilla | en | nonprofit | https://www.mozilla.org/en-US/privacy/websites/ | 11,921 |
| en-wikimedia | en | nonprofit | https://foundation.wikimedia.org/wiki/Policy:Privacy_policy | 55,173 |
| en-cloudflare | en | saas | https://www.cloudflare.com/privacypolicy/ | 52,826 |
| en-atlassian | en | saas | https://www.atlassian.com/legal/privacy-policy | 68,799 |
| en-automattic | en | saas | https://automattic.com/privacy/ | 54,953 |
| en-gov-uk | en | public | https://www.gov.uk/help/privacy-notice | 13,238 |
| en-ec | en | public | https://commission.europa.eu/privacy-policy-websites-managed-european-commission_en | 12,588 |
| en-python | en | nonprofit | https://www.python.org/privacy/ | 4,158 |
| it-spotify | it | consumer | https://www.spotify.com/legal/privacy-policy/ | 68,037 |
| en-ibm | en | company | https://www.ibm.com/privacy | 41,523 |
| it-slack | it | saas | https://slack.com/trust/privacy/privacy-policy | 53,432 |

## Repeating it

```bash
python tools/art13/fetch.py              # download the texts into .cache/art13 and check their hashes
python tools/art13/check_labels.py       # every labelled quote must be in its text
python tools/art13/eval.py              # the table above; --test for the held-out six, -v for every miss
python tools/art13/eval.py --pin        # after an improvement: pin the quotes now recognised
```

To add a document, add it to the manifest, fetch it, have it labelled against the rubric, run the checker, and pin. Do not tune a detector on the held-out six.
