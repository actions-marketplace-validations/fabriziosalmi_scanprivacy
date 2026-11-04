# HTTP API

`scanprivacy serve --port 8099` starts it on loopback. Every `/v1` route requires `SCANPRIVACY_API_KEY` when one is configured; `/healthz` is always open and carries the AGPL section 13 source offer.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/scans` | submit `{"url": ...}`; returns 202 and a scan id |
| GET | `/v1/scans/{id}` | status and result |
| GET | `/v1/scans/{id}/graph` | nodes and edges |
| GET | `/v1/scans/{id}/report?lang=it` | Markdown report |
| GET | `/v1/scans/{id}/report.pdf?lang=en` | PDF with the full evidence |
| GET | `/v1/scans/{id}/inventory` | recipients, shaped for an Art. 30 record |
| GET | `/v1/rules`, `/v1/remediation`, `/v1/vendors`, `/v1/locales` | the loaded catalogues |
| GET | `/healthz` | liveness and source offer |

Targets are resolved and must be public addresses, both before the fetch and for the addresses the browser actually reached (403 `target refused` otherwise).

Limits, all environment variables: `SCANPRIVACY_MAX_CONCURRENT_SCANS` (3), `SCANPRIVACY_MAX_SCANS_IN_FLIGHT` (50, beyond it 429 with `retry-after`), `SCANPRIVACY_SCAN_RETENTION` (200 results in memory).
