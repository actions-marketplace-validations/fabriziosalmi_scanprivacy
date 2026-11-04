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

## Status and errors

`POST /v1/scans` answers 202 with an id. `GET /v1/scans/{id}` answers 200 for a scan in any state and carries `status` (`queued`, `running`, `done`, `error`); a failed scan is a 200 with `status: "error"`, an `error` text and an `error_ref` to quote to the operator, so a poller has one shape to read. The sub-resources (`graph`, `report`, `inventory`, ...) answer 409 until the scan is `done`. Other errors use FastAPI's `{"detail": ...}` shape:

| Code | Meaning |
|------|---------|
| 400 | invalid URL or unknown locale |
| 401 | missing or wrong API key |
| 403 | target refused: not a public address |
| 404 | unknown scan id |
| 409 | the scan is not finished |
| 429 | too many scans queued or running; honour `retry-after` |
| 500 | a stored result exists and cannot be read |
| 503 | results cannot be stored right now (also `/healthz`) |

A scan id stays valid across restarts and in-memory eviction: results are read back from disk. A scan still running when the service stops is reported as `error`.

Targets are resolved and must be public addresses, both before the fetch and for the addresses the browser actually reached (403 `target refused` otherwise).

Limits, all environment variables: `SCANPRIVACY_MAX_CONCURRENT_SCANS` (3), `SCANPRIVACY_MAX_SCANS_IN_FLIGHT` (50, beyond it 429 with `retry-after`), `SCANPRIVACY_SCAN_RETENTION` (200 results in memory).
