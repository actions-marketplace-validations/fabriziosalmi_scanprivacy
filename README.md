# scanprivacy

**URL in, findings graph and remediation out.** A deterministic engine for
passive privacy conformance observation (GDPR / ePrivacy / AI Act), usable from
the command line or as an HTTP API.

```bash
pip install -e .
python -m playwright install chromium   # the package brings the driver, not the browser
```

The second line is not optional and is the one people miss. Without it the
first scan fails; `scanprivacy` will tell you so in one line rather than a traceback,
but it is cheaper to read it here.

```bash
scanprivacy scan https://example.org --pages 5 --pdf report.pdf --json evidence.json
scanprivacy --lang it scan https://example.org --pdf rapporto.pdf   # same engine, Italian report
scanprivacy verify evidence.json      # recompute every digest: is this the evidence the report describes?
scanprivacy diff before.json after.json    # resolved / new / persisting, with the age of what is still open
scanprivacy serve --port 8099
```

```bash
curl -X POST localhost:8099/v1/scans -d '{"url":"https://example.org"}' -H 'content-type: application/json'
curl localhost:8099/v1/scans/<id>/graph              # nodes and edges
curl localhost:8099/v1/scans/<id>/report?lang=it     # markdown, any available language
curl localhost:8099/v1/scans/<id>/report.pdf?lang=en # PDF with the full evidence
curl localhost:8099/v1/scans/<id>/inventory          # recipients, shaped for an Art. 30 record
```

### Running the API anywhere but loopback

The engine fetches URLs on request and identifies itself with a User-Agent
naming the operator and their contact address. An open instance is therefore
not merely something a stranger can consume: requests it makes arrive at
third-party sites **in your name**, and the site owner receiving them has no
way to tell you did not send them.

So `scanprivacy serve` refuses to start on any bind other than loopback without a
key, and exits 3:

```bash
export SCANPRIVACY_API_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
scanprivacy serve --host 0.0.0.0 --port 8099

curl -H "X-API-Key: $SCANPRIVACY_API_KEY" localhost:8099/v1/rules     # or Authorization: Bearer
curl localhost:8099/healthz                                     # open: reports the posture, never the key
```

`/healthz` is deliberately unauthenticated and carries the AGPL section 13
source offer, because it is the one endpoint every network user can already
reach. If you run a **modified** build as a service, point `SCANPRIVACY_SOURCE_URL` at
your own source: your users are owed yours, not ours.

Three limits protect the host, all environment-tunable: `SCANPRIVACY_MAX_CONCURRENT_SCANS`
(default 3, each scan is a Chromium), `SCANPRIVACY_MAX_SCANS_IN_FLIGHT` (50, beyond
which submissions get `429` with `retry-after` rather than an id they can
poll), and `SCANPRIVACY_SCAN_RETENTION` (200 results kept in memory; older ones are
read from disk, and an entry that failed to persist is never evicted).

Targets are checked twice. Before the fetch, the hostname is resolved and every
address behind it must be public — a name whose A record points at
`169.254.169.254` is the technique, not an edge case. After the fetch, the
addresses Chromium reports having *actually reached* are checked again, which
catches a record that changed in between and a redirect that moved the
destination entirely. A result that touched a private address is discarded
rather than returned.

The command line has no such check, deliberately: there the operator chose the
target, and refusing `http://localhost:8000` would break the ordinary act of
checking a site before deploying it.

## Where it comes from

This is the deterministic core extracted from three strands of work:

- **privacy-pa** — passive observation, declarative rules, citable evidence, the
  register a public body can act on. The method survives here, generalised
  beyond Italian municipalities.
- **agssh / AGSSH-STD-001** — fail-closed posture, severities, verdicts:
  *nothing is green unless it was observed to be green*. An unreachable site is
  `INCONCLUSIVE`, never conformant.
- **a week of `privacy:` commits** across the author's repositories (Art. 13
  notice, footer link, meta-CSP, processor lists) — the catalogue of fixes,
  reported here next to each finding.

## What makes it different

**Rules are generic; facts live in data.** privacy-pa had one rule per tracker,
so every new tracker meant a new rule. Here a rule says *"a third party with
terminal access was contacted before consent"* and the facts about each vendor
live in [`knowledge/vendors.yml`](src/scanprivacy/knowledge/vendors.yml). Adding a
vendor is a data change — never code, never a rule.

**It reads the site's own documents.** The engine compares what a site
*declares* with what it *does*. That gap (`PM-DIS-01`) is the finding an
authority acts on, and it needs no judgement: either the notice names that
recipient, or it does not.

**Findings carry no sentences.** A scan result holds canonical values, catalogue
keys and parameters. Sentences are assembled at render time, so the same scan
produces an English and an Italian report — with the same evidence digest —
without observing the site twice.

## More than one page

```bash
scanprivacy scan https://example.org --pages 5
```

One page is not a site. A tracker that only runs on the contact form, an embed
that only appears on an article, a CDN pulled in by a single template: a
single-page scan does not know they exist. On the pilot site, moving from one
page to five surfaced `cdnjs.cloudflare.com` — loaded only on `/chi-siamo` —
and with it two findings that had been invisible.

Selection is **deterministic**: one page per kind (contact, form, services,
about, article…), then a leaf page, then the main navigation, ordered by kind,
depth and URL. The same site yields the same pages on every run, which is what
keeps `scanprivacy diff` honest — otherwise it would report churn that never happened.

The engine follows links **from the entry page only**. A conformance check is
not a crawl, and a crawl needs a conversation with the site owner that a scan
does not have. Downloads, feeds, pagination, legal documents (they have their
own reader) and anything that changes state — `/logout`, `/checkout`, `/wp-admin`
— are never requested. At most one page load per second per host.

Each finding says which pages produced it: "on every page" and "only on the
contact form" are different problems with different fixes.


## The refusal pass (opt-in, separate document)

```bash
scanprivacy consent-pass https://example.org --pdf refusal.pdf
```

Everything else in this engine observes a visitor who has not decided and never
touches the page. This one mode does: it refuses the consent the site itself
offers, reloads, and compares. It is a **separate command producing a separate
document with a separate declared method** — the standard report does not gain a
word because this exists, and never claims to cover it.

**Why refusal rather than acceptance.** What happens after "Accept" is roughly
what everyone expects. What happens after "Reject" is where a banner turns out
to be theatre, and it is the one thing passive observation can never see: before
any choice, "tracking is running" and "tracking is running because the refusal
was ignored" look identical.

**The engine never guesses.** It interacts only with consent platforms listed in
[`knowledge/consent.yml`](src/scanprivacy/knowledge/consent.yml), only through the
refusal path their own vendor documents, and only after the platform's own
readiness check passes. One action — one documented call, or one click on the
single control the vendor publishes. No searching for a button whose text
resembles "Reject", no second attempt with a different method, no navigation.
Clicking blindly on somebody else's site is how a scanner empties a cart or logs
a user out; "unlikely" is not a standard.

An unrecognised platform is a **result, not something to hide**: the report says
a consent mechanism was present, that no documented refusal path is known for
it, and that no conclusion about post-refusal behaviour can be drawn. The
document reproduces the platform, the method, the verbatim expression evaluated
and the vendor's documentation URL, so a reader can confirm the supported path
was used.

A refusal expressed by an automated agent measures the technical behaviour of
the mechanism. It is not the exercise of a data subject's will, and the document
says so.


## Identity surface

The same scan that a DPO asked for also answers questions an access team owns —
without a second tool and without a second visit. Passively observable, and
therefore covered:

- **Identity providers actually contacted** (Entra ID, Okta, Auth0, Sign in with
  Google or Apple, SPID, Keycloak). An IdP receives *who the user is*, not merely
  that a visitor arrived, so it is a recipient like any other: the transfer and
  disclosure rules already reach it. Adding them was a data change, not a rule.
- **Session cookie hygiene** — a session identifier without `HttpOnly` is
  readable by every third-party script on the page, and a stolen session
  identifier is a logged-in user with no password involved. Without `Secure`,
  one plain-HTTP request discloses it.
- **Login form posture** — a password field on a page served over plain HTTP, a
  form posting credentials to a third-party domain, a credential page that can
  be framed by another site.

Not covered, deliberately: multi-factor policy, password rules, role models —
none are observable from outside, and inventing them would be worse than
omitting them. No form is ever filled or submitted, nothing is authenticated,
and no administrative path is probed: only what the page itself exposes to a
visitor who opens it. A test asserts that guarantee against the source.


## Reproducibility

A report that cannot be re-derived is an opinion. Every scan carries:

- **configuration digests** (ruleset, knowledge base, catalogues): stable. Same
  digests and same target means the same analysis was applied. They make two
  scans comparable, and they are what a client can pin in a contract.
- **an evidence digest**: SHA-256 of the canonical JSON of the observation. It
  ties the report to the attached evidence. It is *not* stable across runs —
  sites change — which is exactly what makes it possible to prove that they did.
  `scanprivacy verify` recomputes all of them.
- **full evidence in the PDF**: every request with its time in milliseconds from
  the start of navigation, cookies with their attributes, storage, headers, the
  certificate with its fingerprint, and every document read with the SHA-256 of
  its extracted text and the passages that satisfied each Art. 13 element.
- **independent verification steps per finding**: what to do with a browser and
  `curl` to obtain the same result *without this tool*. A finding nobody can
  check alone is worth nothing — the first thing a supplier says is "your
  scanner is wrong".

## For whoever reads the report

Each finding carries, besides the legal reference: the **owner** who can close
it (dpo / cto / sysops / security / legal / procurement), a **priority** P1–P5
(severity corrected for effort, so a high finding fixable in ten minutes comes
first), a **quick win** marker, its technical **domain**, and a **control
mapping** to GDPR, ePrivacy, the AI Act, NIS2, ISO/IEC 27001:2022, ISO/IEC
27701, SOC 2 and AgID measures
([frameworks.yml](src/scanprivacy/knowledge/frameworks.yml)). The mappings orient the
work; they do not attest conformity to those schemes.

## Languages

English is the source language; Italian ships alongside it. German, French,
Spanish and Portuguese are additions of a directory, not of code:

```text
i18n/locales/<lang>/
  ui.yml           labels, legends, summary sentences, verification steps, remediation patterns
  rules.yml        one title, description and fix per rule
  vendors.yml      the aliases used to recognise a vendor in a notice written in that language
  references.yml   how each legal reference is written
```

Three properties hold by test: every key English has exists in every other
locale, every canonical value has a label in every locale, and no rendered
report contains an unresolved key.

Language and **jurisdiction** are kept apart on purpose: a report written in
Italian for a German controller should cite the TDDDG, not the Italian Privacy
Code. References are keys (`gdpr:13.1.f`, `it:privacy-code:122`), so a
jurisdiction pack is added next to `it:` without touching a single rule.

## In continuous integration

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: fabriziosalmi/scanprivacy@v1
    with:
      url: https://www.example.org
      fail-on: critical        # tighten to high, then not-conformant, as the backlog clears
      source-root: .
      badge-file: .github/badges/privacy.svg
```

A full example, with artefacts and a pull-request comment, is in
[examples/workflows/privacy-gate.yml](examples/workflows/privacy-gate.yml).

### SARIF, and why it is worth more than a report

`scanprivacy scan --sarif out.sarif` emits SARIF 2.1.0, so findings land in GitHub's
Security tab — the queue developers already work from — instead of a PDF someone
has to remember to open. Three properties do the actual work:

- **Findings are anchored to the line that causes them.** In CI the repository
  is right there, so the engine looks for the observed host in the source and
  points the alert at `src/layouts/base.html:3`, not at "your website". Where
  the line only *names* the host — an allowlist, a CSP directive, a comment —
  the alert says so instead of pretending: a confident wrong line is worse than
  an honest "not found".
- **Fingerprints are stable and language-independent.** An alert that persists
  stays the same alert, one whose cause is removed **closes by itself**, and
  rendering a report in Italian does not create duplicates. The remediation
  lifecycle ends up tracked by the platform at no cost.
- **The fix travels with the alert.** The message carries the remediation
  summary and its numbered steps, because an alert nobody can act on gets muted.

`--fail-on` makes adoption survivable: block on `critical` today, tighten to
`high`, then to `not-conformant`, without ever pretending the rest is absent.

### Signed attestation

The reproducibility record lets a reader recompute every digest. It does not
stop someone from editing the report *and* the digest together. An attestation
closes that gap:

```bash
scanprivacy scan https://example.org --json evidence.json --pdf report.pdf \
  --attest attestation.intoto.json --sign cosign-keyless

scanprivacy verify-attestation attestation.intoto.json \
  --identity 'https://github.com/acme/site/.github/workflows/privacy.yml@refs/heads/main' \
  --oidc-issuer 'https://token.actions.githubusercontent.com'
```

Each link is independently checkable, and none of them requires trusting
whoever sent you the file:

    the report states an evidence digest
      → an in-toto statement binds that digest and the digest of every artefact
        → cosign signs the statement
          → keyless signing records it in the public transparency log

Fail-closed here too. An unsigned statement is labelled unsigned and
`verify-attestation` exits `1`: a statement nobody signed proves only that
somebody wrote a file. If signing is requested and cosign is missing, the
command fails rather than quietly producing an unsigned file — the caller finds
out now, not when a recipient checks.

Two guarantees, deliberately distinguished: a **local key** proves the holder
signed it; **keyless** signing anchors the signature to a workflow identity in a
public log, which is what lets a stranger verify it. The tool never presents the
first as if it were the second.


### The badge

```bash
scanprivacy badge scan.json --out .github/badges/privacy.svg
```

Deliberately **not** a shields.io URL. A badge served by a third party makes
every visitor of the README disclose their IP address to that third party —
which is exactly the finding `PM-TRF-01` raises against everyone else. A tool
that breaks its own rule in its own README has no standing to raise it. So the
SVG is generated locally, committed, and loads nothing.


## Architecture

```text
core/        enums.py (canonical vocabularies) · models.py (language-neutral) · graph.py
i18n/        translator.py · locales/{en,it}/
knowledge/   registry.py · vendors.yml · platforms.yml · frameworks.yml
rules/       21 logic-only rules (see rules/README.md)
observe/     browser.py · discover.py (which link is really the notice) · docs.py · tls.py · robots.py
analyze/     context.py (facts) → subjects.py · predicates.py · engine.py → graph.py · verdict.py · diff.py
report/      render.py (facts → sentences, once) · markdown.py · pdf.py · record.py · templates/
api.py · cli.py · scanner.py
```

### The graph

| nodes | edges |
|---|---|
| `site` `page` `host` `vendor` `cookie` `storage` `document` `finding` `obligation` `remediation` | `loads` `operated_by` `transfers_to` `sets` `publishes` `declares` `evidences` `violates` `fixed_by` |

Every finding is attached to the evidence that produced it, to the provision it
hangs from, and to the fix that closes it: *why do you say so* and *what do I
do* are always one edge away.

## Scope: legitimate requests only

The engine does exactly what an ordinary visitor's browser does, and nothing
more:

- loads only the page given, headless, with no interaction;
- no clicks, no form submissions, no authentication, no restricted areas;
- expresses no consent: what gets observed is what the site does to a visitor
  who has not yet decided;
- extra requests: only the legal documents linked from the page, one per kind,
  plus at most three conventional paths (`/privacy`, …) when no link qualifies;
- no fuzzing, no enumeration, no intrusive testing;
- `robots.txt` honoured for every URL the engine requests, identified
  User-Agent with a contact address.

The TLS handshake on 443 is the one opening the page already performs.

### Who the engine says it is

Every request carries a User-Agent naming the software, the purpose, and a
contact address for **the instance that sent it**:

```
scanprivacy/0.1 (+passive EU privacy conformance observation; independent research, good faith; contact: fabrizio.salmi@gmail.com)
```

Set `SCANPRIVACY_CONTACT` to your own address before running this against anything
you do not own. The address is the only route by which the owner of an observed
site can object, so it has to reach whoever is operating the engine — not
whoever wrote it.

Some WAFs hang up on an unfamiliar User-Agent. `--ua-fallback` retries once as a
plain browser, and is **off by default**: the retry is not a disguise — we are a
browser either way — but it drops the contact address, which is the entire
accountability mechanism, so turning it on is a decision an operator makes for
an estate they own. Whichever string actually reached the site is the one the
report names under *posture*; the report never claims an identity that was not
used.

## Verdict (fail-closed)

`F` with any critical finding, `D` with any high, `C` medium, `B` low, `A`
clean; `INCONCLUSIVE` if the site could not be loaded — and, in the refusal
pass, if no refusal actually happened: a pass that found no consent mechanism,
or could not use the one it found, has not observed what survives a refusal,
and zero findings there means "never asked" rather than "clean". `scanprivacy scan` exits `1`
when the verdict is not conformant, so it works as a CI gate.

## Development

```bash
python3.12 -m venv .venv && ./.venv/bin/pip install -e '.[dev]'
./.venv/bin/python -m playwright install chromium
./.venv/bin/python -m pytest tests -q
```

`requirements.lock` pins the exact resolution — 49 packages with sha256 hashes,
generated with `uv pip compile --generate-hashes`. Use it when the versions
matter, which for this engine is more often than usual: the reports carry
configuration digests and signed attestations asserting that two scans are the
same analysis, and the Chromium build ships with Playwright.

```bash
./.venv/bin/pip install --require-hashes -r requirements.lock
```

The tests are offline: host attribution, document discovery, word boundaries in
aliases, negation handling, fail-closed grading, digest tampering, and the
completeness of every locale.

## Known limits (v0.1)

- Observes a site **once**. Several pages are visited (`--pages`), chosen
  deterministically, but a single visit is a photograph: two consecutive loads
  can differ. `scanprivacy diff` exposes that variance rather than hiding it;
  stabilising over N repeats is on the roadmap.
- The default pass expresses **no** consent, so what a site does after
  *acceptance* is never verified. `scanprivacy consent-pass` covers refusal only, is
  opt-in, produces its own document, and works solely through the nine
  platforms in `knowledge/consent.yml`. Eight of those nine are implemented
  from the vendor's documentation and have not been confirmed against a live
  installation — the catalogue now says which is which, the report states it,
  and findings built on an unconfirmed path are stated as indications rather
  than as facts.
- Requests made **inside a third-party iframe** are attributed to that embed,
  not to the site. Embedding YouTube is the site's choice and is reported as
  one; the fonts YouTube then loads inside its own player are not, since the
  operator can neither see nor prevent them. Those hosts stay in the inventory —
  the data did reach them — marked *reached through* the embed.
- A scan covers **one deployment**. Links to another host under the same domain
  are not followed — `api.example.org` is a different codebase and usually a
  different person, and reporting its findings under `www.example.org` sends
  the reader to the wrong repository. The apex and its `www.` count as one. Any
  sibling host the entry page links to is listed in the page plan, with the
  reason, so the omission is visible; scan it separately, or use `scanprivacy batch`.
- A finding may be **unfixable on the platform**, and the report now says so
  where it knows. GitHub Pages serves a fixed set of response headers and
  permits none, so `PM-SEC-01` (HSTS) is true there and cannot be closed in
  place; the finding stays, states the constraint, and names a fix that can
  actually be performed. The catalogue of such platforms is one vendor long.
- Art. 13 elements are recognised from text: an unusual wording can escape
  detection, which is why documentary findings carry `probable` confidence.
- Infrastructure providers are inferred from response headers: this covers the
  well-known CDNs and edges, not every hosting arrangement.
- When a read of the page does not complete, the report says so under *Stated
  limits* and names the probe. An observation that could not finish is not the
  same as one that found nothing, and neither is treated as the other.
- It is not legal advice.

## Licence

**GNU AGPL-3.0-only** — full text in [LICENSE](LICENSE).

Chosen for section 13, not out of habit. The natural way to deploy this engine
is as a network service: someone runs `scanprivacy serve` behind a domain and never
distributes a binary to anyone, which is precisely the case a permissive
licence leaves uncovered. Under the AGPL, offering the engine to others over a
network carries the same obligation as shipping it.

Nothing changes for the ordinary uses. Scanning your own estate, running it in
your CI, importing it in a private script, modifying it for yourself: no
obligation attaches, because none of that is conveying or offering it to
anybody. The obligation begins where your users do.
