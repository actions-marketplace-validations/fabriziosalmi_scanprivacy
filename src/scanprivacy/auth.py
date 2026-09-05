"""Who may ask this service to observe something.

The engine fetches URLs and reports what it saw, using a User-Agent that names
the operator and carries their contact address. An unauthenticated instance is
therefore not merely a resource someone can consume: it is a way to make
requests to third-party sites *in the operator's name*, and the site owner
receiving them has no way to tell that the operator did not send them.

That is why the rule here is mechanical rather than advisory. A key may be
absent, but only while the service is bound to loopback, where the only callers
are already on the machine. Binding anywhere else without a key is refused at
startup — a warning would be read once and then not read again.

    SCANPRIVACY_API_KEY=<secret>   required on every /v1 route
    unset                    permitted on 127.0.0.1 / ::1 only

`/healthz` stays open in both cases. A liveness probe that needs a credential
is a liveness probe that stops working the day the credential rotates.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
from typing import Any

from fastapi import Header, HTTPException

__all__ = ["api_key_configured", "require_api_key", "assert_bind_is_safe", "UnsafeBind"]

ENV_VAR = "SCANPRIVACY_API_KEY"
MIN_KEY_LENGTH = 16


class UnsafeBind(Exception):
    """Refusing to start: this combination of host and credential is not safe."""


def api_key_configured() -> str | None:
    key = os.environ.get(ENV_VAR, "").strip()
    return key or None


def _is_loopback(host: str) -> bool:
    """Whether binding here exposes the service beyond this machine.

    An empty host and 0.0.0.0 both mean "every interface", which is the case
    this exists to catch, so anything that is not demonstrably loopback counts
    as exposed.
    """
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() in ("localhost", "localhost.localdomain")


def assert_bind_is_safe(host: str) -> None:
    """Raise `UnsafeBind` for a configuration that would expose an open API.

    Called before the server starts rather than on the first request: a service
    that accepts one request it should not have accepted has already failed.
    """
    key = api_key_configured()
    if key is not None:
        if len(key) < MIN_KEY_LENGTH:
            raise UnsafeBind(
                f"{ENV_VAR} is set but is only {len(key)} characters; "
                f"use at least {MIN_KEY_LENGTH} from a random source, e.g. "
                f"`python -c 'import secrets; print(secrets.token_urlsafe(32))'`"
            )
        return
    if not _is_loopback(host):
        raise UnsafeBind(
            f"refusing to bind {host!r} without {ENV_VAR}.\n"
            "This service fetches URLs on request and identifies itself with the "
            "operator's contact address, so an open instance lets a stranger send "
            "requests to third parties in your name.\n"
            f"Either set {ENV_VAR}, or bind 127.0.0.1 and reach it through a tunnel."
        )


async def require_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
) -> None:
    """FastAPI dependency. No key configured means no check — which is only
    reachable on loopback, because `assert_bind_is_safe` refused otherwise."""
    expected = api_key_configured()
    if expected is None:
        return

    presented = x_api_key
    if presented is None and authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer":
            presented = value.strip()

    # compare_digest on both branches: returning early for a missing header
    # and comparing for a present one leak nothing here, but a wrong-length
    # key must not be distinguishable from a wrong-value one.
    if presented is None or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=401,
            detail="a valid X-API-Key header is required",
            headers={"www-authenticate": "Bearer"},
        )


def posture() -> dict[str, Any]:
    """What /healthz may say about authentication: whether it is on, never
    anything derived from the key itself."""
    return {"authentication": "api-key" if api_key_configured() else "none"}
