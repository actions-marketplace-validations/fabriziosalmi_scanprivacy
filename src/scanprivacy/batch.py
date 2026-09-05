"""Scanning a fleet.

Three properties separate a fleet run from a loop over `scan()`:

- **Shared courtesy.** Forty targets on one host share one budget. A per-scan
  limiter would let the fleet hammer a server the method promised to treat like
  one visitor.
- **Failure isolation.** One target that hangs, redirects into a loop or dies
  must not take the run with it. Every target gets its own budget and its own
  error, recorded in place of a result.
- **Resumable.** Results land on disk as they complete, so an interrupted run
  costs the targets still pending and nothing else.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from .analyze.fleet import FleetSummary, summarise
from .config import DEFAULTS, Settings
from .core.enums import ScanStatus
from .core.models import ScanResult
from .observe.rate import PerHostLimiter
from .scanner import scan


def read_targets(source: Path | Iterable[str]) -> list[str]:
    """One URL per line; blank lines and `#` comments ignored."""
    if isinstance(source, Path):
        lines = source.read_text(encoding="utf-8").splitlines()
    else:
        lines = list(source)
    out: list[str] = []
    for line in lines:
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        if not candidate.startswith(("http://", "https://")):
            candidate = f"https://{candidate}"
        if candidate not in out:
            out.append(candidate)
    return out


def _slug(url: str) -> str:
    parts = urlsplit(url)
    path = (parts.path or "/").strip("/").replace("/", "-")
    return f"{parts.netloc}{'-' + path if path else ''}".replace(":", "_")


async def run_batch(
    targets: list[str],
    out_dir: Path,
    settings: Settings = DEFAULTS,
    concurrency: int = 3,
    resume: bool = True,
    on_result: Callable[[str, ScanResult | None, str | None], None] | None = None,
) -> tuple[list[dict[str, Any]], FleetSummary]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    limiter = PerHostLimiter(settings.per_host_rps)
    gate = asyncio.Semaphore(max(1, concurrency))
    results: dict[str, dict[str, Any]] = {}

    async def one(url: str) -> None:
        path = out_dir / f"{_slug(url)}.json"
        if resume and path.is_file():
            try:
                results[url] = json.loads(path.read_text(encoding="utf-8"))
                if on_result:
                    on_result(url, None, "cached")
                return
            except (OSError, json.JSONDecodeError):
                pass  # unreadable cache is not a reason to skip the target

        async with gate:
            try:
                result = await asyncio.wait_for(
                    scan(url, settings, limiter=limiter),
                    timeout=settings.per_scan_budget_s * max(1, settings.max_pages),
                )
                payload = result.to_dict()
            except Exception as exc:  # one bad target must not end the run
                payload = {
                    "scan_id": "",
                    "url": url,
                    "final_url": url,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "status": ScanStatus.ERROR.value,
                    "error": f"{type(exc).__name__}: {exc}"[:300],
                    "site": {},
                    "findings": [],
                    "verdict": None,
                    "inventory": [],
                }
                if on_result:
                    on_result(url, None, payload["error"])
                results[url] = payload
                path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                return

        results[url] = payload
        # written as it completes: an interrupted run costs only what is pending
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        if on_result:
            on_result(url, result, None)

    await asyncio.gather(*(one(url) for url in targets))

    ordered = [results[url] for url in targets if url in results]
    return ordered, summarise(ordered)

