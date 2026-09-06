"""Where the measurement was made from.

A site does not behave the same towards every observer. Consent banners are
geo-gated, CDNs answer from different edges, some hosts serve nothing outside
their market. Two honest scans of one site can disagree for a reason that has
nothing to do with the site — and without this field the disagreement reads as
a change on the site, or as an error in one of the two reports.

Three states, and the record always carries one of them:

- `declared` — the operator said where they are. No network call, no third
  party, and the operator is the one who knows.
- `looked_up` — the operator opted into an endpoint and named it. What that
  endpoint returned is recorded verbatim, along with which endpoint it was, so
  a reader can weigh it.
- `undetermined` — neither was configured, or the lookup did not complete. Said
  plainly, with the reason, rather than omitted.

The default is `undetermined`, and that is a deliberate refusal rather than an
oversight. An engine that asks a third party where it is, on every scan, sends
the operator's address to a company nobody chose in order to produce a privacy
report. That is the shape of the thing this tool exists to report.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Any

from ..config import VANTAGE_DECLARED, VANTAGE_LOOKUP_URL

# Only these are kept from a lookup response. A geolocation endpoint answers
# with whatever it likes — postal codes, coordinates, a "readme" link — and a
# report is not the place to paste an unbounded third-party payload.
LOOKUP_FIELDS = ("ip", "city", "region", "country", "org", "asn", "timezone")


def _lookup(url: str, timeout: float = 8.0) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 — operator-named
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError(f"expected a JSON object, got {type(payload).__name__}")
    kept = {k: payload[k] for k in LOOKUP_FIELDS if payload.get(k)}
    if not kept:
        raise ValueError("the response carried none of the fields we record")
    return kept


def observation_point() -> dict[str, Any]:
    """The vantage point, as a record fragment. Never raises."""
    if VANTAGE_DECLARED:
        return {"source": "declared", "declared": VANTAGE_DECLARED}

    if not VANTAGE_LOOKUP_URL:
        return {"source": "undetermined", "reason_key": "record.vantage.not_configured"}

    try:
        return {"source": "looked_up", "endpoint": VANTAGE_LOOKUP_URL, **_lookup(VANTAGE_LOOKUP_URL)}
    except Exception as exc:
        # A failed lookup is not an absent vantage point: the scan happened
        # somewhere. Saying which of the two it is keeps the record honest.
        return {
            "source": "undetermined",
            "endpoint": VANTAGE_LOOKUP_URL,
            "reason_key": "record.vantage.lookup_failed",
            "detail": f"{type(exc).__name__}: {exc}"[:200],
        }
