# Rule catalogue

Generated from `scanprivacy rules` (27 rules in the passive scan, version 0.1.0) plus the 4 `PM-REJ` rules of the opt-in refusal pass, taken from the rule files. The definition of each rule, with its legal basis and the evidence it requires, is in `src/scanprivacy/rules/<ID>.yml`. Placeholders in braces are filled from the observation.

| Rule | Severity | Subject | Title |
|------|----------|---------|-------|
| PM-AI-01 | medium | site | Conversational or AI component with no notice to the user |
| PM-CNS-01 | critical | vendor | {product} is loaded before any consent |
| PM-CNS-02 | high | site | Services requiring consent, with no mechanism to collect it |
| PM-CNS-03 | critical | site | A consent mechanism is present, but tracking starts before the choice |
| PM-COK-01 | high | cookie | Tracking cookie «{name}» set on first visit |
| PM-COK-02 | low | cookie | Cookie «{name}» set on first visit, nature not determinable from outside |
| PM-COK-03 | medium | cookie | Cookie «{name}» has no Secure attribute |
| PM-COK-04 | low | cookie | Cookie «{name}» has SameSite=None: it travels in cross-site contexts |
| PM-COST-01 | info | site | Commercial TLS certificate where equivalent free alternatives exist |
| PM-DIS-01 | high | vendor | {product} is active on the site but is not named in the privacy notice |
| PM-DOC-01 | critical | site | No privacy notice reachable from the public page |
| PM-DOC-02 | medium | site | Notice published but missing mandatory elements of Art. 13 |
| PM-DOC-03 | medium | site | Cookies or storage set on first visit without a complete cookie section |
| PM-DPIA-01 | medium | site | The observable surface meets criteria that usually call for an impact assessment |
| PM-FRM-01 | high | form | Public form submitting data to a third-party domain ({action_host}) |
| PM-IAM-01 | high | cookie | Session cookie «{name}» is readable by JavaScript |
| PM-IAM-02 | high | cookie | Session cookie «{name}» has no Secure attribute |
| PM-IAM-03 | critical | form | Password field on a page not served over HTTPS |
| PM-IAM-04 | high | form | Credentials submitted to a third-party domain ({action_host}) |
| PM-IAM-05 | medium | form | Page with a password field can be framed by another site |
| PM-SEC-01 | medium | site | Strict-Transport-Security not set |
| PM-SEC-02 | medium | site | Referrer-Policy absent or permissive |
| PM-SEC-03 | low | site | No Content-Security-Policy |
| PM-STO-01 | high | storage | Tracking identifier written to {kind} («{key}») on first visit |
| PM-STO-02 | info | storage | Write to {kind} («{key}») on first visit, nature not determinable |
| PM-TRF-01 | high | vendor | Personal data transferred to {vendor} ({transfer}) on first load |
| PM-TRF-02 | info | vendor | Technical provider outside the EEA: {product} ({vendor}) |
| PM-REJ-01 | critical | vendor | {product} is still loaded after the visitor refused (refusal pass) |
| PM-REJ-02 | critical | cookie | Tracking cookie «{name}» is still set after the visitor refused (refusal pass) |
| PM-REJ-03 | high | storage | Tracking identifier in {kind} («{key}») survives the refusal (refusal pass) |
| PM-REJ-04 | info | site | Consent mechanism present, with no documented way to refuse through it (refusal pass) |
