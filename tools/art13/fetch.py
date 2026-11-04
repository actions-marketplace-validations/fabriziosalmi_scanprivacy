"""Fetch the corpus documents with the engine's own extractor, and check they are unchanged.

    python tools/art13/fetch.py            # fetch what is missing from .cache/art13
    python tools/art13/fetch.py --refresh  # fetch everything again

Texts are never committed (they are other people's documents): only URLs, hashes and short
quotes are. A document whose hash differs from the manifest has changed since it was
labelled, and its labels are stale until it is labelled again.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "corpus" / "art13" / "manifest.json"
CACHE = ROOT / ".cache" / "art13"


async def main(refresh: bool) -> int:
    from playwright.async_api import async_playwright

    from scanprivacy.config import DEFAULTS
    from scanprivacy.observe.browser import launch_browser
    from scanprivacy.observe.docs import fetch_document

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    CACHE.mkdir(parents=True, exist_ok=True)
    stale = 0
    async with async_playwright() as pw:
        browser = await launch_browser(pw)
        for doc_id, entry in manifest.items():
            target = CACHE / f"{doc_id}.txt"
            if target.exists() and not refresh:
                text = target.read_text(encoding="utf-8")
            else:
                evidence = await fetch_document(browser, entry["url"], "privacy", DEFAULTS)
                text = evidence.text or ""
                target.write_text(text, encoding="utf-8")
                await asyncio.sleep(1.2)  # one request per host per second, as the engine promises
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            same = digest == entry["sha256"]
            stale += 0 if same else 1
            print(f"{doc_id:24} {len(text):7} chars  {'unchanged' if same else 'CHANGED since it was labelled'}")
        await browser.close()
    if stale:
        print(f"\n{stale} document(s) changed: their labels may be out of date.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main("--refresh" in sys.argv)))
