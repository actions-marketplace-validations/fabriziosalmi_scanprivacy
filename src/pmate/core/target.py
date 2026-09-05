"""Whether a target may be observed on someone else's say-so.

The engine fetches whatever URL it is given. On the command line that is
correct: the operator is asking about a target they chose, and refusing
`http://localhost:8000` would break the ordinary act of checking a site before
deploying it.

Across an HTTP boundary it is the opposite. An endpoint that fetches any URL a
stranger submits is a probe into whatever network the service happens to run
on — cloud metadata at 169.254.169.254, an internal dashboard on a private
range, a service listening only on loopback — and this engine hands the result
back in a report. So the API validates and the CLI does not, and the asymmetry
is the point rather than an oversight.

The name is resolved before the decision. A public hostname whose A record
points at 169.254.169.254 is not an edge case; it is the entire technique.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

__all__ = [
    "TargetRefused",
    "check_public_target",
    "check_observed_peers",
    "PORTS_NOT_OBSERVED",
]


class TargetRefused(Exception):
    """The target is not something this service will fetch on request."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# Ports that never serve a public web page. Observing them would be a port
# scan wearing a report as a disguise, and the engine has no business there.
PORTS_NOT_OBSERVED = frozenset(
    {22, 23, 25, 110, 143, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}
)


@dataclass(frozen=True, slots=True)
class TargetCheck:
    host: str
    addresses: tuple[str, ...]


def _is_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """`is_global` alone is not enough on every Python version and family, so
    the disqualifying properties are named explicitly."""
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def check_public_target(url: str, *, resolver=socket.getaddrinfo) -> TargetCheck:
    """Raise `TargetRefused` unless every address behind `url` is public.

    Every address, not the first: a name with one public and one private A
    record would otherwise be a way through, and which one the browser picks
    is not ours to predict.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise TargetRefused("scheme_not_permitted", parts.scheme or "(none)")
    host = parts.hostname
    if not host:
        raise TargetRefused("no_host")
    if parts.port is not None and parts.port in PORTS_NOT_OBSERVED:
        raise TargetRefused("port_not_observed", str(parts.port))

    # A literal address still has to be checked; it simply skips resolution.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        addresses = [literal]
    else:
        try:
            infos = resolver(host, None)
        except socket.gaierror as exc:
            raise TargetRefused("does_not_resolve", str(exc)) from exc
        addresses = []
        for info in infos:
            try:
                addresses.append(ipaddress.ip_address(info[4][0]))
            except ValueError:  # pragma: no cover — the resolver returned a non-address
                continue
        if not addresses:
            raise TargetRefused("does_not_resolve", "no usable address")

    for address in addresses:
        if not _is_public(address):
            raise TargetRefused("not_a_public_address", str(address))

    return TargetCheck(host=host, addresses=tuple(str(a) for a in addresses))


def check_observed_peers(peers) -> None:
    """Raise `TargetRefused` if the browser actually reached a non-public address.

    `check_public_target` resolves a name and decides; between that decision and
    the fetch, the record can change, and a redirect moves the destination after
    the check entirely. Neither is exotic — rebinding to 127.0.0.1 after a
    passing check is the standard way around a pre-flight guard.

    This is the answer instead of the prediction: the addresses the browser
    reports having connected to. It runs after the observation, so it cannot
    prevent the request — the API's job here is to refuse to hand back what
    came of it, which is what makes the request worthless to whoever sent it.

    `None` entries are ignored: an address the browser did not report is not an
    address we can call private.
    """
    for peer in peers:
        if not peer:
            continue
        try:
            address = ipaddress.ip_address(peer)
        except ValueError:
            continue
        if not _is_public(address):
            raise TargetRefused("reached_a_private_address", peer)


def peers_of(observation_pages) -> list[str]:
    """Every address reached across an observation, main document included."""
    out: list[str] = []
    for page in observation_pages or []:
        for request in (page.get("requests") if isinstance(page, dict) else page.requests) or []:
            peer = request.get("peer_ip") if isinstance(request, dict) else request.peer_ip
            if peer:
                out.append(peer)
    return out
