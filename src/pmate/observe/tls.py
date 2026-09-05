"""TLS certificate observation.

A TLS handshake on port 443 is exactly what opening the page already does, so
this stays inside the passive perimeter. Two facts are extracted: who issued
the certificate (free vs commercial CA — a cost finding, carried over from
privacy-pa's R-COST-01) and how long it has left.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

FREE_CA_MARKERS = ("let's encrypt", "lets encrypt", "zerossl", "buypass", "google trust services", "actalis free")
COMMERCIAL_CA_MARKERS = (
    "digicert", "sectigo", "globalsign", "comodo", "entrust", "thawte", "geotrust",
    "rapidssl", "verisign", "godaddy", "network solutions", "identrust", "actalis",
)


@dataclass(slots=True)
class TlsInfo:
    ok: bool
    host: str
    issuer_org: str | None = None
    issuer_cn: str | None = None
    subject_cn: str | None = None
    not_after: str | None = None
    not_before: str | None = None
    serial: str | None = None
    sha256: str | None = None
    """Fingerprint of the leaf certificate: lets anyone re-run
    `openssl s_client` and confirm they are looking at the same certificate."""
    days_to_expiry: int | None = None
    classification: str = "unknown"  # free | commercial | unknown
    protocol: str | None = None
    error: str | None = None


def _iso(value: str | None) -> str | None:
    """OpenSSL dates come as 'Jul 15 19:57:42 2026 GMT'."""
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
    except ValueError:
        return value


def _rdn(seq, key: str) -> str | None:
    for rdn in seq or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def _classify(org: str | None, cn: str | None) -> str:
    hay = f"{org or ''} {cn or ''}".lower()
    if not hay.strip():
        return "unknown"
    for m in FREE_CA_MARKERS:
        if m in hay:
            return "free"
    for m in COMMERCIAL_CA_MARKERS:
        if m in hay:
            return "commercial"
    return "unknown"


def _probe_sync(host: str, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    info = TlsInfo(ok=False, host=host)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
                info.protocol = tls.version()
        if der:
            info.sha256 = hashlib.sha256(der).hexdigest()
        info.issuer_org = _rdn(cert.get("issuer"), "organizationName")
        info.issuer_cn = _rdn(cert.get("issuer"), "commonName")
        info.subject_cn = _rdn(cert.get("subject"), "commonName")
        info.serial = cert.get("serialNumber")
        # Both dates in the same ISO form: the report must not show one raw
        # C-locale string next to one ISO timestamp.
        info.not_before = _iso(cert.get("notBefore"))
        info.not_after = _iso(cert.get("notAfter"))
        if info.not_after:
            dt = datetime.fromisoformat(info.not_after)
            info.days_to_expiry = (dt - datetime.now(timezone.utc)).days
        info.classification = _classify(info.issuer_org, info.issuer_cn)
        info.ok = True
    except Exception as e:
        info.error = f"{type(e).__name__}: {e}"
    return info


async def probe(host: str, port: int = 443) -> TlsInfo:
    host = host.split(":")[0]
    return await asyncio.to_thread(_probe_sync, host, port)


def tls_to_dict(info: TlsInfo) -> dict:
    return asdict(info)
