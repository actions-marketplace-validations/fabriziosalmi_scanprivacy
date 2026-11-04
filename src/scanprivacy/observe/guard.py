"""Refuse a request before the browser sends it.

`check_public_target` vets the URL a caller submits, and `check_observed_peers`
vets where the browser turned out to have gone. Neither stops a request: a
redirect, a sub-resource or a rebound name reaches the private address first and
is only withheld afterwards, which still lets a stranger make this service touch
an internal endpoint (a blind request, with a side effect and no answer).

This is the preventive half. Every request a guarded context makes, the first
navigation and every redirect hop and every sub-resource included, is routed
through here and aborted unless its host resolves to public addresses only.

One race remains and is not pretended away: the name is resolved here and again
by Chromium a moment later, so a record that changes between the two can still
steer the connection. `check_observed_peers` still runs afterwards and withholds
the result, and a deployment should not rely on either alone: deny egress from
the container to private ranges (docs/deploy.md).
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from ..core.target import TargetRefused, check_public_target

# Schemes that never leave the machine.
_LOCAL_SCHEMES = frozenset({"data", "blob", "about"})


class RequestGuard:
    """Per-context policy, with a record of what it refused."""

    def __init__(self, check: Callable[[str], Any] = check_public_target) -> None:
        self._check = check
        self._verdicts: dict[str, TargetRefused | None] = {}
        self.blocked: list[dict[str, str]] = []

    async def _decide(self, url: str) -> TargetRefused | None:
        parts = urlsplit(url)
        if parts.scheme in _LOCAL_SCHEMES:
            return None
        if parts.scheme not in ("http", "https", "ws", "wss"):
            return TargetRefused("scheme_not_permitted", parts.scheme or "(none)")
        # ws/wss resolve exactly like http/https; only the scheme name differs.
        probe = url.replace("ws", "http", 1) if parts.scheme.startswith("ws") else url
        key = parts.netloc
        if key not in self._verdicts:
            try:
                await asyncio.to_thread(self._check, probe)
                self._verdicts[key] = None
            except TargetRefused as refused:
                self._verdicts[key] = refused
        return self._verdicts[key]

    async def allow(self, url: str) -> bool:
        refused = await self._decide(url)
        if refused is None:
            return True
        self.blocked.append({"url": url, "reason": refused.reason, "detail": refused.detail})
        return False

    async def _route(self, route) -> None:
        if await self.allow(route.request.url):
            await route.continue_()
        else:
            await route.abort("blockedbyclient")

    async def _route_ws(self, ws) -> None:
        if await self.allow(ws.url):
            ws.connect_to_server()
        else:
            await ws.close()

    async def install(self, context) -> "RequestGuard":
        await context.route("**/*", self._route)
        await context.route_web_socket(re.compile(r".*"), self._route_ws)
        context._scanprivacy_guard = self  # read back by the observer
        return self


def egress_of(context):
    """The egress proxy this context's browser was launched behind, if any."""
    return getattr(context, "_scanprivacy_egress", None)


def blocked_requests(context) -> list[dict[str, str]]:
    guard = getattr(context, "_scanprivacy_guard", None)
    return list(guard.blocked) if guard else []
