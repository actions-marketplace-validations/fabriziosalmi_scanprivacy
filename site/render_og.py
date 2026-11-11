"""Render site/og.html to site/assets/og.png, the 1200x630 preview shown when a link is shared.

    python site/render_og.py

The PNG is committed: the Pages build does not need a browser for it, and
tests/test_site_build.py checks its size.
"""

from pathlib import Path

from playwright.sync_api import sync_playwright

SITE = Path(__file__).resolve().parent

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1200, "height": 630}, device_scale_factor=1)
    page.goto((SITE / "og.html").as_uri())
    page.evaluate("document.fonts.ready")
    page.wait_for_function("document.fonts.status === 'loaded'")
    page.screenshot(path=str(SITE / "assets" / "og.png"))
    browser.close()
