"""HTTP API: submit a URL, get back the findings graph and the remediation.

    POST /v1/scans                          {"url": "...", "read_documents": true}
    GET  /v1/scans/{id}                     full result (language-neutral)
    GET  /v1/scans/{id}/graph               nodes and edges (?format=mermaid)
    GET  /v1/scans/{id}/report?lang=it      markdown
    GET  /v1/scans/{id}/report.pdf?lang=de  PDF
    GET  /v1/scans/{id}/inventory           recipients, shaped for an Art. 30 record
    GET  /v1/rules?lang=it                  the rule catalogue
    GET  /v1/vendors                        the vendor knowledge base
    GET  /v1/locales                        languages this build can report in
    GET  /healthz

Scans run in the background; the POST returns immediately with an id. The
stored result carries no sentences, so the language is chosen when a report is
requested — the same scan renders in any locale without re-observing anything.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .analyze.engine import load_rules
from .auth import posture as auth_posture, require_api_key
from . import __version__
from .config import DEFAULTS, LICENCE, SCANS_DIR, SOURCE_URL, env_int
from .core.graph import to_mermaid
from .core.models import ScanResult, scan_from_dict
from .core.target import TargetRefused, check_observed_peers, check_public_target, peers_of
from .i18n.translator import DEFAULT_LOCALE, Translator, available_locales
from .knowledge.registry import all_vendors
from .knowledge.remediation import catalogue as remediation_catalogue, entry_for
from .report.markdown import render
from .observe.rate import PerHostLimiter
from .scanner import scan

@asynccontextmanager
async def _lifespan(_: FastAPI):
    yield
    # Scans run as background tasks of this process; stopping it ends them. Say
    # so, and mark them, rather than leaving callers polling an id that will never
    # finish. (Finished results are on disk and survive; see _from_disk.)
    lost = [sid for sid, e in _SCANS.items() if e.get("status") in ("queued", "running")]
    for sid in lost:
        _SCANS[sid].update(status="error", error="the service stopped before this scan finished", error_ref=sid)
    if lost:
        logger.warning("shutdown interrupted %d scans: %s", len(lost), ", ".join(lost))


app = FastAPI(
    lifespan=_lifespan,
    title="scanprivacy",
    version=__version__,
    description="Passive privacy conformance observation: URL in, findings graph and remediation out.",
)

# How much of this machine one caller may occupy.
#
# A scan launches a Chromium. Without a ceiling, a loop of POSTs launches as
# many as the caller cares to ask for, and the store below keeps every result —
# observation included — for the lifetime of the process. Neither needed an
# attacker: a well-meaning script with a list of domains would do it.
MAX_CONCURRENT_SCANS = env_int("SCANPRIVACY_MAX_CONCURRENT_SCANS", 3)
MAX_SCANS_IN_FLIGHT = env_int("SCANPRIVACY_MAX_SCANS_IN_FLIGHT", 50)
SCAN_RETENTION = env_int("SCANPRIVACY_SCAN_RETENTION", 200)

logger = logging.getLogger("scanprivacy.api")

# Across this boundary a stranger chooses the target, so every request the
# browser makes is vetted before it is sent. The command line does not do this.
API_SETTINGS = replace(DEFAULTS, guard_requests=True)

# One per-host budget for every scan this process runs. A limiter per scan kept
# "one page load per second per host" true inside a scan and false across the
# scans of a service that two callers can point at the same site.
_HOST_LIMITER = PerHostLimiter(API_SETTINGS.per_host_rps)

_SCAN_SLOTS = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

# Insertion-ordered, so the oldest entry is the first key. Results are written
# to disk by _persist before eviction, so dropping one from memory loses the
# fast path and not the evidence.
_SCANS: "OrderedDict[str, dict[str, Any]]" = OrderedDict()


def _evict_if_needed() -> None:
    for scan_id, entry in list(_SCANS.items()):
        if len(_SCANS) <= SCAN_RETENTION:
            break
        if entry.get("status") in ("queued", "running"):
            # Never evict work that has not finished: the caller is still
            # holding an id we told them to poll.
            continue
        if entry.get("status") == "done" and not entry.get("persisted", False):
            # Eviction is only safe because the result is on disk. If the write
            # failed, dropping the entry destroys the only copy, so it stays; the
            # entries behind it are still evictable, and new scans are refused
            # while results cannot be stored (see create_scan) so the store
            # cannot grow without bound.
            logger.warning("scan %s was never persisted; keeping it in memory", scan_id)
            continue
        _SCANS.pop(scan_id, None)


class ScanRequest(BaseModel):
    url: str = Field(..., description="public URL to observe (http/https)")
    read_documents: bool = Field(default=True, description="also read the linked legal documents")
    context: dict[str, Any] = Field(
        default_factory=dict, description="tenant, project, labels, sector, NIS2 status"
    )


def _persist(result: ScanResult) -> bool:
    """Write the result to disk. Returns whether it got there.

    This used to swallow OSError on the grounds that persistence is a
    convenience and never a scan failure. That was true until eviction was
    added: the store now drops old entries precisely because the result is
    already on disk, so a silent write failure turns a bounded cache into
    quiet data loss. The caller needs the answer, and the operator needs the
    reason.
    """
    try:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
        (SCANS_DIR / f"{result.scan_id}.json").write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        return True
    except OSError:
        logger.exception("could not persist scan %s", result.scan_id)
        return False


async def _run(scan_id: str, request: ScanRequest) -> None:
    # Queued until a slot frees. The caller already has an id and a poll URL,
    # so waiting here costs them nothing and keeps the machine standing.
    async with _SCAN_SLOTS:
        if _SCANS.get(scan_id) is None:  # evicted or cancelled while queued
            return
        _SCANS[scan_id]["status"] = "running"
        await _observe(scan_id, request)


async def _observe(scan_id: str, request: ScanRequest) -> None:
    try:
        result = await asyncio.wait_for(
            scan(
                request.url,
                API_SETTINGS,
                scan_id=scan_id,
                read_documents=request.read_documents,
                context=request.context,
                limiter=_HOST_LIMITER,
            ),
            timeout=API_SETTINGS.per_scan_budget_s,
        )
        # The pre-flight check resolved a name and decided; this checks where
        # the browser actually went. Between the two, a record can change and a
        # redirect can move the destination entirely — so the observation is
        # discarded rather than returned, which is what makes the attempt
        # worthless to whoever made it.
        try:
            check_observed_peers(peers_of((result.observation or {}).get("pages")))
        except TargetRefused as refused:
            logger.warning(
                "scan %s reached a non-public address (%s); result discarded",
                scan_id, refused.detail,
            )
            _SCANS[scan_id].update(
                status="error",
                error="the target resolved to an address this service will not observe",
                error_ref=scan_id,
                error_detail=f"reached {refused.detail}",
            )
            return

        persisted = _persist(result)  # on disk before the entry can ever be evicted
        _SCANS[scan_id].update(status="done", result=result, persisted=persisted)
    except asyncio.TimeoutError:
        logger.warning("scan %s exceeded its budget of %ss", scan_id, API_SETTINGS.per_scan_budget_s)
        _SCANS[scan_id].update(status="error", error="scan budget exceeded", error_ref=scan_id)
    except Exception as exc:
        # The client is told a scan failed and is given a reference; the cause
        # goes to the log. An exception's text carries filesystem paths, module
        # layout and sometimes the content that caused it — detail that helps
        # whoever operates the service and helps an attacker equally.
        logger.exception("scan %s failed", scan_id)
        _SCANS[scan_id].update(
            status="error",
            error="the scan did not complete",
            error_ref=scan_id,
            error_detail=f"{type(exc).__name__}: {exc}",  # kept server-side only
        )
    finally:
        _evict_if_needed()


_SCAN_ID = re.compile(r"[0-9a-f]{12}")


def _from_disk(scan_id: str) -> dict[str, Any] | None:
    """A result that left memory, or that predates this process.

    Eviction and restarts drop the in-memory entry on the grounds that the
    result is on disk; this is the half that reads it back. The id is matched
    against the shape the service itself issues before it reaches a path.
    """
    if not _SCAN_ID.fullmatch(scan_id):
        return None
    path = SCANS_DIR / f"{scan_id}.json"
    if not path.is_file():
        return None
    try:
        result = scan_from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, KeyError, TypeError):
        # Not "unknown": the result exists and cannot be read, and saying 404
        # would tell the caller the scan never happened.
        logger.exception("stored result for scan %s is unreadable", scan_id)
        raise HTTPException(status_code=500, detail="stored result is unreadable") from None
    return {
        "status": "done",
        "url": result.url,
        "result": result,
        "persisted": True,
        "error": None,
    }


def _get(scan_id: str) -> dict[str, Any]:
    entry = _SCANS.get(scan_id)
    if entry is None:
        entry = _from_disk(scan_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="unknown scan_id")
    return entry


def _done(scan_id: str) -> ScanResult:
    entry = _get(scan_id)
    if entry["status"] != "done":
        raise HTTPException(status_code=409, detail=f"scan is '{entry['status']}'")
    return entry["result"]


def _locale(lang: str) -> str:
    """Accept only a locale this build can actually report in.

    `Translator.for_locale` falls back to the default for anything it does not
    recognise and raises nothing, which is right for rendering and wrong for a
    value that reaches a filesystem path: an unvalidated `lang` renders happily
    and writes the PDF wherever the caller points it.
    """
    if lang not in available_locales():
        raise HTTPException(
            status_code=400,
            detail=f"unknown locale '{lang}': this build reports in {available_locales()}",
        )
    return lang


def _storage_writable() -> bool:
    try:
        SCANS_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(SCANS_DIR, os.W_OK)


@app.get("/healthz")
async def healthz() -> JSONResponse:
    """Deliberately unauthenticated. A liveness probe that needs a credential
    stops working the day the credential rotates, and it discloses nothing a
    caller could not learn by reading the package.

    `ok` is false, with a 503, when results cannot be stored: the service would
    accept scans whose evidence it then loses.
    """
    storage_ok = _storage_writable()
    return JSONResponse(status_code=200 if storage_ok else 503, content={
        "ok": storage_ok,
        "storage_writable": storage_ok,
        "version": __version__,
        # AGPL section 13: whoever reaches this instance over a network is owed
        # its source. An unauthenticated liveness probe is the one place every
        # such caller can already read, so the offer lives here rather than in a
        # page nobody fetches.
        "licence": LICENCE,
        "source": SOURCE_URL,
        "rules": len(load_rules()),
        "vendors": len(all_vendors()),
        "locales": available_locales(),
        **auth_posture(),
    })


@app.get("/v1/locales", dependencies=[Depends(require_api_key)])
async def locales() -> dict[str, Any]:
    return {"default": DEFAULT_LOCALE, "available": available_locales()}


@app.post("/v1/scans", status_code=202, dependencies=[Depends(require_api_key)])
async def create_scan(request: ScanRequest, background: BackgroundTasks) -> dict[str, Any]:
    parts = urlsplit(request.url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise HTTPException(status_code=400, detail="invalid url: only http/https are accepted")
    # Across an HTTP boundary the caller chooses the target, so the service
    # must not be usable as a probe into the network it happens to run on.
    # The command line deliberately has no such check — see core/target.py.
    try:
        await asyncio.to_thread(check_public_target, request.url)
    except TargetRefused as refused:
        raise HTTPException(
            status_code=403,
            detail=f"target refused: {refused.reason}"
            + (f" ({refused.detail})" if refused.detail else ""),
        ) from None
    if not _storage_writable():
        raise HTTPException(
            status_code=503,
            detail="results cannot be stored right now; retry later",
            headers={"retry-after": "60"},
        )
    in_flight = sum(1 for e in _SCANS.values() if e.get("status") in ("queued", "running"))
    if in_flight >= MAX_SCANS_IN_FLIGHT:
        raise HTTPException(
            status_code=429,
            detail=f"{in_flight} scans already queued or running; retry when some have finished",
            headers={"retry-after": "30"},
        )

    scan_id = uuid.uuid4().hex[:12]
    _SCANS[scan_id] = {
        "status": "queued",
        "url": request.url,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    background.add_task(_run, scan_id, request)
    return {"scan_id": scan_id, "status": "queued", "url": request.url, "poll": f"/v1/scans/{scan_id}"}


@app.get("/v1/scans/{scan_id}", dependencies=[Depends(require_api_key)])
async def get_scan(scan_id: str) -> JSONResponse:
    entry = _get(scan_id)
    if entry["status"] != "done":
        # error_detail is deliberately not in this payload — see _observe.
        return JSONResponse(
            {
                "scan_id": scan_id,
                "status": entry["status"],
                "error": entry["error"],
                "error_ref": entry.get("error_ref"),
            }
        )
    return JSONResponse(json.loads(json.dumps(entry["result"].to_dict(), default=str)))


@app.get("/v1/scans/{scan_id}/graph", dependencies=[Depends(require_api_key)])
async def get_graph(scan_id: str, format: str = "json") -> Response:
    result = _done(scan_id)
    if format == "mermaid":
        return PlainTextResponse(to_mermaid(result.graph) if result.graph else "")
    return JSONResponse(json.loads(json.dumps(result.graph.to_dict() if result.graph else {}, default=str)))


@app.get("/v1/scans/{scan_id}/report", dependencies=[Depends(require_api_key)])
async def get_report(scan_id: str, lang: str = Query(DEFAULT_LOCALE)) -> Response:
    return PlainTextResponse(
        render(_done(scan_id), _locale(lang)), media_type="text/markdown; charset=utf-8"
    )


@app.get("/v1/scans/{scan_id}/report.pdf", dependencies=[Depends(require_api_key)])
async def get_report_pdf(scan_id: str, lang: str = Query(DEFAULT_LOCALE)) -> Response:
    from .report.pdf import render_pdf

    lang = _locale(lang)
    result = _done(scan_id)
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    path = SCANS_DIR / f"{scan_id}.{lang}.pdf"
    # Belt as well as braces: the locale is already an allow-listed value, and
    # scan_id comes from uuid4 hex, but a path assembled from request input is
    # worth confirming rather than reasoning about.
    if path.resolve().parent != SCANS_DIR.resolve():
        raise HTTPException(status_code=400, detail="invalid report path")
    render_pdf(result, path, lang)
    domain = result.site.get("domain", scan_id)
    return Response(
        content=path.read_bytes(),
        media_type="application/pdf",
        headers={"content-disposition": f'inline; filename="scanprivacy-{domain}-{lang}.pdf"'},
    )


@app.get("/v1/scans/{scan_id}/inventory", dependencies=[Depends(require_api_key)])
async def get_inventory(scan_id: str) -> JSONResponse:
    """Recipients observed, shaped the way an Art. 30 record needs them."""
    return JSONResponse(json.loads(json.dumps(_done(scan_id).inventory, default=str)))


@app.get("/v1/rules", dependencies=[Depends(require_api_key)])
async def get_rules(lang: str = Query(DEFAULT_LOCALE)) -> list[dict[str, Any]]:
    t = Translator.for_locale(_locale(lang))
    return [
        {
            "id": rule.id,
            "title": t.rule(rule.id, "title"),
            "severity": rule.severity.value,
            "confidence": rule.confidence.value,
            "subject": rule.subject.value,
            "references": [t.reference(r) for r in rule.references],
            "reference_keys": list(rule.references),
            "tags": list(rule.tags),
            "condition": rule.condition,
        }
        for rule in load_rules()
    ]


@app.get("/v1/remediation", dependencies=[Depends(require_api_key)])
async def get_remediation(lang: str = Query(DEFAULT_LOCALE)) -> list[dict[str, Any]]:
    """Every fix this engine knows, without observing anything.

    The knowledge was only reachable by scanning a site that happened to
    trigger the rule carrying it, which made the catalogue a lookup table with
    no lookup. A model answering "how do I stop sending IP addresses to Google
    Fonts" should be able to answer from this register rather than from
    whatever it remembers about the GDPR.
    """
    return [entry.to_dict() for entry in remediation_catalogue(_locale(lang))]


@app.get("/v1/remediation/{key}", dependencies=[Depends(require_api_key)])
async def get_remediation_entry(key: str, lang: str = Query(DEFAULT_LOCALE)) -> dict[str, Any]:
    """One fix, by rule id, pattern name, or vendor id."""
    entry = entry_for(key, _locale(lang))
    if entry is None:
        raise HTTPException(status_code=404, detail=f"no remediation known for {key!r}")
    return entry.to_dict()


@app.get("/v1/vendors", dependencies=[Depends(require_api_key)])
async def get_vendors() -> list[dict[str, Any]]:
    return [
        {
            "id": v.id,
            "vendor": v.vendor,
            "product": v.product,
            "category": v.category.value,
            "jurisdiction": v.jurisdiction,
            "transfer": v.transfer.value,
            "transfer_basis": v.transfer_basis,
            "storage_access": v.storage_access,
            "consent_class": v.consent_class.value,
            "data_types": [d.value for d in v.data_types],
            "remediation_pattern": v.remediation.pattern,
            "hosts": list(v.hosts) + list(v.host_suffixes),
        }
        for v in all_vendors()
    ]
