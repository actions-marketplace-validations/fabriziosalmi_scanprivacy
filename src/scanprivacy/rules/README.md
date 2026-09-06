# Rules

A rule is a `PM-*.yml` file in this directory. It contains **logic only**:

```yaml
id: PM-TRF-01
severity: high            # critical | high | medium | low | info
confidence: certain       # certain — directly observed | probable — inferred from text
subject: vendor           # site | vendor | cookie | storage | form
tags: [transfers, third-parties]
references: [gdpr:13.1.f, gdpr:44, gdpr:5.1.a]
condition:                # AND across every key
  vendor_third_party: true
  vendor_extra_eea: true
  vendor_consent_class_any: [required, uncertain]
remediation:
  source: vendor          # vendor — a shared pattern | rule — written for this rule
  effort: low             # low | medium | high
```

Everything else lives elsewhere, on purpose:

| What | Where | Why |
|---|---|---|
| Title, description, rule-specific fix | `i18n/locales/<lang>/rules.yml` | a translator edits text, never logic |
| Legal reference wording | `i18n/locales/<lang>/references.yml` | keys are jurisdiction-aware; `gdpr:13.1.f` reads differently in German, and a German controller cites the TDDDG, not the Italian Privacy Code |
| Owner, domains, control mapping | `knowledge/frameworks.yml` | a CISO's view of the same finding |
| Vendor facts and fix patterns | `knowledge/vendors.yml` | adding a tracker is a data change |

A reviewer of a file in this directory is checking one thing: **does the
condition describe the fact the rule claims to have found?**

## Two constraints, both deliberate

1. **The DSL is closed.** Every predicate is an explicit function in
   `analyze/predicates.py`. Adding one means writing a function and documenting
   it below. An expressive DSL would allow rules nobody can review.
2. **An unknown predicate makes the rule not fire.** A rule the engine cannot
   fully evaluate must never produce a half-evaluated finding.

## `subject:` — what the rule iterates over

This is what lets one generic rule replace a one-rule-per-tracker table. With
`subject: vendor` the rule produces one finding per vendor that satisfies the
condition, and the facts about the vendor come from the knowledge base rather
than from the rule.

| `subject` | subjects |
|---|---|
| `site` | the observed site (exactly one) |
| `vendor` | every party contacted, first and third |
| `cookie` | every cookie present on first visit |
| `storage` | every localStorage / sessionStorage / IndexedDB key |
| `form` | every form on the page |

## Predicates

### Vendors (`subject: vendor`)

- `vendor_third_party: true|false` — registrable domain differs from the site's.
- `vendor_extra_eea: true|false` — serving it exports data outside the EEA.
- `vendor_category_any: [analytics, ads, fonts, cdn, …]` — `VendorCategory` values.
- `vendor_consent_class_any: [required, technical, uncertain]`
- `vendor_storage_access: true|false` — reads or writes terminal storage (the Art. 5(3) trigger).
- `vendor_resource_type_any: [script, xhr, fetch, …]` — what it was *observed* serving. A tracker seen delivering one image cannot have executed.
- `vendor_declared: true|false` — named in the legal documents that were read.
- `vendor_known: true|false` — present in the knowledge base, or attributed to its domain.

### Cookies (`subject: cookie`)

- `cookie_class_any: [tracking, functional, unknown]`
- `cookie_third_party: true|false`
- `cookie_attribute_missing: secure|httponly|samesite`
- `cookie_samesite_none: true|false` — explicit `SameSite=None`.

### Storage (`subject: storage`)

- `storage_class_any: [tracking, functional, unknown]`

### Forms (`subject: form`)

- `form_action_third_party: true|false`
- `form_privacy_checkbox: true|false`

### Site (`subject: site`)

- `missing_document: privacy|cookie|terms|accessibility`
- `document_link_absent: <kind>`
- `privacy_document_present: true|false`
- `art13_missing_any: true|false` — only elements due in every case.
- `cookie_section_incomplete: true|false`
- `header_missing: <header-name>`
- `header_regex_not_matching: {name: X, regex: Y}`
- `tls_classification: free|commercial|unknown`
- `cmp_present: true|false`
- `consent_required_vendors_present: true|false`
- `tracking_state_before_consent: true|false`
- `ai_marker_any: [ai-chat-widget, ai-meta-disclosure, ai-generated-badge]`
- `ai_disclosure_absent: true|false`

## Placeholders in the texts

Titles, descriptions and remediation steps accept `{...}` placeholders resolved
against the subject:

- vendor — `{vendor} {product} {category} {jurisdiction} {hosts} {transfer} {data_types}`
- cookie — `{name} {domain} {class} {lifetime}`
- storage — `{key} {kind} {class}`
- form — `{action} {action_host}`
- site — `{site} {host}`

An unknown placeholder stays visible in the output: a writing mistake in a rule
should be obvious, not silent.

## The `PM-` prefix, and when it becomes `SP-`

The project was renamed from privacymate to scanprivacy; the rule ids were not.
They are identifiers rather than branding. Each appears in every finding id
derived from it, in every SARIF `ruleId`, in kept baselines, and in any
code-scanning alert already raised — so renaming them makes every existing
finding a *different* finding, and a comparison across the change reports the
whole estate resolved and an identical estate discovered.

Agreed 2026-09-06: **`SP-` at the next minor bump.** A version boundary is where
a reader expects identifiers to move, and it is the one place the cost is worth
paying.

`tests/test_rule_ids.py` fails the moment `__version__` reaches 0.2.0 with `PM-`
ids still in this directory, and its message carries the checklist: the files
here, the keys in `i18n/locales/*/rules.yml`, the mappings in
`knowledge/frameworks.yml`, and every rule id written into a test. Take a fresh
baseline afterwards, and do not diff across the boundary.
