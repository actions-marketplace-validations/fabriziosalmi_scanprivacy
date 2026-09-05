"""robots.txt courtesy for an identified User-Agent.

A privacy scan that ignores the site's own stated wishes would be a poor
advertisement for the thing it is selling.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import httpx

from ..config import UA


class RobotsCache:
    def __init__(self, ua: str = UA) -> None:
        self._ua = ua
        self._by_origin: dict[str, RobotFileParser | None] = {}

    def _fetch(self, scheme: str, host: str) -> RobotFileParser | None:
        url = f"{scheme}://{host}/robots.txt"
        try:
            r = httpx.get(url, timeout=10.0, headers={"User-Agent": self._ua}, follow_redirects=True)
        except httpx.HTTPError:
            return None
        if r.status_code >= 400:
            return None  # no robots.txt reachable -> permitted, but recorded upstream
        rp = RobotFileParser()
        rp.parse(r.text.splitlines())
        return rp

    def allowed_sync(self, url: str) -> bool:
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        if origin not in self._by_origin:
            self._by_origin[origin] = self._fetch(parts.scheme, parts.netloc)
        rp = self._by_origin[origin]
        return True if rp is None else rp.can_fetch(self._ua, url)

    async def allowed(self, url: str) -> bool:
        return await asyncio.to_thread(self.allowed_sync, url)
