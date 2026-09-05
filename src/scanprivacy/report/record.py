"""The reproducibility record.

A report that cannot be re-derived is an opinion. This module pins everything a
third party needs to obtain the same result, or to show that the result has
changed: which engine ran, which rules and knowledge base were loaded (by
digest), with which parameters, against which evidence (by digest).

Two kinds of digest live here, and the distinction matters:

- **configuration digests** (`ruleset`, `knowledge`) are stable. Same digests
  plus same target means the same analysis was applied. They make two scans
  comparable, and they are what a client can pin in a contract.
- **the evidence digest** identifies *this observation*. Sites change between
  visits — that is the point of observing them — so it does not repeat across
  runs. It proves that report and attached JSON describe the same capture, and
  that nothing was edited afterwards.

Everything here is keys and values. The labels a reader sees come from the
locale catalogues under `record.*`.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .. import __version__
from ..config import DEFAULTS, KNOWLEDGE_DIR, RULES_DIR, Settings
from ..i18n.translator import LOCALES_DIR


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(obj: Any) -> str:
    """Digest over a canonical JSON encoding: stable across dict ordering and
    Python versions, so anyone can recompute it from the published JSON."""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    return _sha256(payload.encode("utf-8"))


def _package(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "absent"


def _fingerprint(paths: list[Path]) -> dict[str, Any]:
    per_file = {p.name: _sha256(p.read_bytes()) for p in sorted(paths)}
    return {"digest": canonical_digest(per_file), "files": per_file}


def ruleset_fingerprint(directory: Path = RULES_DIR) -> dict[str, Any]:
    return _fingerprint(list(directory.glob("PM-*.yml")))


def knowledge_fingerprint(directory: Path = KNOWLEDGE_DIR) -> dict[str, Any]:
    return _fingerprint(list(directory.glob("*.yml")))


def catalogue_fingerprint(directory: Path = LOCALES_DIR) -> dict[str, Any]:
    """Translations are part of what a reader receives: a changed catalogue can
    change what a finding says without changing what the engine found."""
    files = sorted(directory.rglob("*.yml"))
    per_file = {str(p.relative_to(directory)): _sha256(p.read_bytes()) for p in files}
    return {"digest": canonical_digest(per_file), "files": per_file}


def engine_identity(browser_version: str | None = None) -> dict[str, Any]:
    return {
        "engine": f"scanprivacy {__version__}",
        "python": sys.version.split()[0],
        "system": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "playwright": _package("playwright"),
        "browser": browser_version or "chromium (version not recorded)",
        "weasyprint": _package("weasyprint"),
    }


def parameters(settings: Settings = DEFAULTS, user_agent: str = "") -> dict[str, Any]:
    return {
        "user_agent": user_agent,
        "wait_after_domcontentloaded_ms": settings.wait_after_load_ms,
        "navigation_timeout_ms": settings.nav_timeout_ms,
        "scan_budget_s": settings.per_scan_budget_s,
        "robots_respected": settings.respect_robots,
        "max_documents": settings.max_documents,
        "max_requests_recorded": settings.max_subresources,
    }


def build_record(
    *,
    url: str,
    observation: dict[str, Any],
    settings: Settings = DEFAULTS,
    user_agent: str = "",
    browser_version: str | None = None,
    findings: list[Any] | None = None,
) -> dict[str, Any]:
    ruleset = ruleset_fingerprint()
    knowledge = knowledge_fingerprint()
    catalogues = catalogue_fingerprint()
    return {
        "engine": engine_identity(browser_version),
        "digests": {
            "ruleset": ruleset["digest"],
            "knowledge": knowledge["digest"],
            "catalogues": catalogues["digest"],
            "rules": ruleset["files"],
            "knowledge_files": knowledge["files"],
        },
        "evidence_digest": {
            "sha256": canonical_digest(observation),
            "computed_on_key": "record.evidence_digest_computed_on",
            "note_key": "record.evidence_digest_note",
        },
        # The evidence digest covers the observation, which is the right subject
        # for it: findings are derived, and the ruleset digest above says which
        # rules derived them. But a reader running `scanprivacy verify` and seeing
        # "evidence intact: yes" concludes the *document* is intact, and until
        # this existed that sentence was true of a file whose findings had been
        # edited. A guarantee that reads stronger than it is, is the failure
        # this engine exists to avoid.
        "findings_digest": {
            "sha256": canonical_digest(findings if findings is not None else []),
            "note_key": "record.findings_digest_note",
        },
        "parameters": parameters(settings, user_agent),
        "rerun_key": "record.rerun",
        "rerun_params": {"url": url},
    }


def verify_record(scan_json: dict[str, Any]) -> dict[str, Any]:
    """Recompute the digests of a published result — `scanprivacy verify`."""
    record = scan_json.get("record") or {}
    declared = (record.get("evidence_digest") or {}).get("sha256")
    recomputed = canonical_digest(scan_json.get("observation", {}))
    digests = record.get("digests") or {}

    # A result published before findings_digest existed cannot be checked for
    # this, and saying so beats both failing it and passing it silently.
    declared_findings = (record.get("findings_digest") or {}).get("sha256")
    recomputed_findings = canonical_digest(scan_json.get("findings", []))
    if declared_findings is None:
        findings_intact = None
    else:
        findings_intact = declared_findings == recomputed_findings

    return {
        "evidence_intact": bool(declared) and declared == recomputed,
        "declared": declared,
        "recomputed": recomputed,
        "findings_intact": findings_intact,
        "declared_findings": declared_findings,
        "recomputed_findings": recomputed_findings,
        "ruleset_unchanged": digests.get("ruleset") == ruleset_fingerprint()["digest"],
        "knowledge_unchanged": digests.get("knowledge") == knowledge_fingerprint()["digest"],
        "catalogues_unchanged": digests.get("catalogues") == catalogue_fingerprint()["digest"],
    }
