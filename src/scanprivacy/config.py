"""Shared configuration: paths, identified User-Agent, observation budget.

The posture is inherited from privacy-pa and AGSSH-STD-001: everything the
engine does must be something an ordinary visitor's browser would do anyway.
No submits, no auth, no fuzzing, no active probing beyond the TLS handshake
that opening the page already performs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
ROOT = PACKAGE_DIR.parents[1]

# Rules and knowledge ship inside the package: a `pip install scanprivacy` that
# cannot find its own rules is not an installation, it is a source checkout.
RULES_DIR = PACKAGE_DIR / "rules"
KNOWLEDGE_DIR = PACKAGE_DIR / "knowledge"

# Written output stays outside the package, next to the working directory.
DATA_DIR = Path.cwd() / "data"
SCANS_DIR = DATA_DIR / "scans"

# AGPL section 13. Someone who reaches this engine over a network is entitled to
# its source, and the practical form of that offer is a URL an unauthenticated
# caller can reach — `/healthz` carries it. The default names upstream; an
# operator running a *modified* build owes their users their own source, not
# ours, and points this at it.
LICENCE = "AGPL-3.0-only"
SOURCE_URL_DEFAULT = "https://github.com/fabriziosalmi/scanprivacy"
SOURCE_URL = os.environ.get("SCANPRIVACY_SOURCE_URL", "").strip() or SOURCE_URL_DEFAULT

# Where the measurement was made from.
#
# A site does not behave the same towards every observer. Consent banners are
# geo-gated, CDNs answer from different edges, and some hosts serve nothing at
# all outside their market. Two honest scans of one site can therefore disagree
# for a reason that has nothing to do with the site, and the evidence record had
# no field in which to say so — which makes the disagreement look like a change
# on the site, or worse, like an error in one of the two reports.
#
# Determined the way this engine determines everything else: by declaration or
# by observation, never by assumption.
#
#   SCANPRIVACY_VANTAGE="IT / Milano / <network name>"   declared by the operator
#   SCANPRIVACY_VANTAGE_LOOKUP=https://ipinfo.io/json   looked up, opt-in
#
# Neither is set by default, and the record then says the vantage point is
# undetermined rather than omitting the field. An engine that asks a third party
# where it is, on every scan, would be sending the operator's address to a
# company nobody chose in order to write a privacy report — the exact shape of
# the thing it exists to report. So the lookup is opt-in, the endpoint is the
# operator's to name, and the record always states which of the three happened.
VANTAGE_DECLARED = os.environ.get("SCANPRIVACY_VANTAGE", "").strip()
VANTAGE_LOOKUP_URL = os.environ.get("SCANPRIVACY_VANTAGE_LOOKUP", "").strip()

# This address travels in the User-Agent of every request the engine makes, to
# every site it observes. Two requirements pull against each other.
#
# It must be an address the owner of a scanned site can actually reach. A
# contact that bounces is worse than no contact: it claims accountability
# without offering it. `abuse@scanprivacy.org` does not exist yet, so it cannot
# be the default of a build anybody runs today.
#
# And it should not stay one person's mailbox once this file is public: a
# personal address in a public repository conscripts its owner into answering
# for every deployment they never saw, and hands harvesters a working address.
#
# The first requirement wins while the repository is private and the mailbox is
# not there. `SCANPRIVACY_CONTACT` overrides it. **Before this repository is made
# public, create `abuse@scanprivacy.org` and change this line.**
# tests/test_user_agent.py holds the address here, the README and SECURITY.md to
# the same value, so the three cannot drift apart — but nothing can tell you the
# day the repository stops being private.
UA_CONTACT_DEFAULT = "fabrizio.salmi@gmail.com"
UA_CONTACT = os.environ.get("SCANPRIVACY_CONTACT", "").strip() or UA_CONTACT_DEFAULT
UA = (
    "scanprivacy/0.1 (+passive EU privacy conformance observation; "
    f"independent research, good faith; contact: {UA_CONTACT})"
)

# A realistic Firefox string, for hosts whose WAF rejects an unusual UA outright.
#
# Using it is a deliberate choice, never a silent retry, which is why it is
# opt-in through `Settings.ua_fallback_on_block` and off by default. The whole
# identity posture of this engine is that it says who it is and leaves a contact
# address; retrying as a generic browser the moment a site declines is the
# opposite of that, and on a hosted service it is simply evasion. Whichever
# string actually reached the site is the one the report states — see
# `scanner.py`.
UA_FALLBACK = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0"


@dataclass(frozen=True, slots=True)
class Settings:
    """Budget and courtesy parameters for a single scan."""

    nav_timeout_ms: int = 20_000
    """Per-navigation timeout."""

    wait_after_load_ms: int = 4_000
    """Settle time after DOMContentLoaded. Below ~3.5s tag managers often have
    not fired yet (GTM -> GA/Clarity/Pixel); above it the budget grows for
    little extra signal. Empirical value carried over from privacy-pa."""

    per_scan_budget_s: float = 120.0
    """Hard ceiling for one target: observe + documents + TLS + analysis."""

    respect_robots: bool = True
    """robots.txt is honoured for every URL we fetch, documents included."""

    ua_fallback_on_block: bool = False
    """Retry once as a plain browser when the identified User-Agent is refused.

    Off by default. The retry is not dishonest — we are a browser either way —
    but it drops the contact address the site owner would need to object, so it
    has to be something an operator turns on for their own estate rather than
    something that happens to a stranger's site without anyone deciding."""

    per_host_rps: float = 1.0
    """At most one request per second per host, beyond what the page itself
    triggers. Applies to our document fetches, not to the browser's own
    subresource loading (which is the page's behaviour, not ours)."""

    max_pages: int = 1
    """Pages observed per scan, entry page included. One page is not a site: a
    tracker on the contact form does not exist as far as a single-page scan is
    concerned. Raised from the command line with --pages."""

    max_links_recorded: int = 600
    max_subresources: int = 400
    max_documents: int = 4
    """How many legal documents (privacy / cookie / imprint / terms) to read."""

    document_max_bytes: int = 900_000


DEFAULTS = Settings()
