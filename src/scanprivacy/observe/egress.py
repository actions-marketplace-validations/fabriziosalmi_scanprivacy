"""A local forward proxy that only lets public addresses out.

The request guard in `guard.py` sees what the browser asks for, but Playwright
does not route the hops of a redirect, and the name it vetted is resolved again
by Chromium afterwards. Both are the same hole: the connection is made by
something that has not been told where it may not go.

This is the structural answer. In API mode the browser (and the robots.txt
reader) is pointed at this proxy and cannot connect anywhere else, so:

  - every connection, including each redirect hop and every sub-resource, is a
    fresh request to the proxy and is judged on its own;
  - the proxy resolves the name, requires every address to be public, and
    connects to the address it checked. There is no second resolution to race;
  - HTTPS passes through as an opaque CONNECT tunnel, so the browser still
    negotiates TLS with the real server and the observation is unchanged.

The proxy records the address it connected to for each host, because the
browser can only see the proxy's own address and the report needs the real one.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from urllib.parse import urlsplit

from ..core.target import TargetRefused, check_public_target

logger = logging.getLogger("scanprivacy.egress")

_HEAD_LIMIT = 64 * 1024
_HEAD_TIMEOUT = 15.0
_CONNECT_TIMEOUT = 15.0
_STRIPPED = {b"proxy-connection", b"proxy-authorization", b"connection", b"keep-alive"}


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


class EgressProxy:
    def __init__(self, resolver=socket.getaddrinfo, check=check_public_target) -> None:
        self._resolver = resolver
        self.policy = check  # one policy, shared with the request guard; injectable for tests
        self._server: asyncio.AbstractServer | None = None
        self.port: int = 0
        self.ips: dict[str, str] = {}
        """host -> the public address the proxy connected to."""
        self.blocked: list[dict[str, str]] = []

    async def start(self) -> "EgressProxy":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, limit=_HEAD_LIMIT)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def playwright_proxy(self) -> dict[str, str]:
        # Chromium never proxies loopback unless told to, which would make
        # `http://127.0.0.1` the one destination that skipped this check.
        return {"server": self.url, "bypass": "<-loopback>"}

    def public_peer(self, url: str) -> str | None:
        return self.ips.get(urlsplit(url).hostname or "")

    async def _pin(self, host: str, port: int) -> str:
        """Resolve once, require every address to be public, return the one used."""
        check = await asyncio.to_thread(
            self.policy, f"http://{_url_host(host)}:{port}/", resolver=self._resolver
        )
        ip = check.addresses[0]
        self.ips[host] = ip
        return ip

    def _refuse(self, host: str, port: int, refused: TargetRefused) -> None:
        self.blocked.append(
            {"url": f"{host}:{port}", "reason": refused.reason, "detail": refused.detail}
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _HEAD_TIMEOUT)
            request_line, _, header_block = head.partition(b"\r\n")
            method, target, version = request_line.split(b" ", 2)
            if method.upper() == b"CONNECT":
                await self._tunnel(reader, writer, target.decode("latin-1"))
            else:
                await self._forward(reader, writer, method, target.decode("latin-1"), version, header_block)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, ValueError, OSError):
            pass
        except Exception:  # never let one connection take the proxy down
            logger.exception("egress proxy connection failed")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _deny(self, writer: asyncio.StreamWriter, host: str, port: int, refused: TargetRefused) -> None:
        self._refuse(host, port, refused)
        writer.write(b"HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
        await writer.drain()

    async def _open(self, host: str, port: int):
        ip = await self._pin(host, port)
        return await asyncio.wait_for(asyncio.open_connection(ip, port), _CONNECT_TIMEOUT)

    async def _tunnel(self, reader, writer, authority: str) -> None:
        host, _, port_text = authority.rpartition(":")
        host = host.strip("[]")
        port = int(port_text)
        try:
            up_reader, up_writer = await self._open(host, port)
        except TargetRefused as refused:
            await self._deny(writer, host, port, refused)
            return
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            await writer.drain()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await _pipe(reader, writer, up_reader, up_writer)

    async def _forward(self, reader, writer, method: bytes, target: str, version: bytes, header_block: bytes) -> None:
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            writer.write(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            await writer.drain()
            return
        host = parts.hostname
        port = parts.port or 80
        try:
            up_reader, up_writer = await self._open(host, port)
        except TargetRefused as refused:
            await self._deny(writer, host, port, refused)
            return
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            await writer.drain()
            return

        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        lines = [l for l in header_block.split(b"\r\n") if l]
        upgrade = any(l.lower().startswith(b"upgrade:") for l in lines)
        kept = [l for l in lines if upgrade or l.split(b":", 1)[0].strip().lower() not in _STRIPPED]
        if not upgrade:
            kept.append(b"Connection: close")  # one request per connection: no second host rides this one
        up_writer.write(method + b" " + path.encode("latin-1") + b" " + version + b"\r\n" + b"\r\n".join(kept) + b"\r\n\r\n")
        await up_writer.drain()
        await _pipe(reader, writer, up_reader, up_writer)


async def _pipe(c_reader, c_writer, u_reader, u_writer) -> None:
    async def copy(src, dst) -> None:
        try:
            while chunk := await src.read(64 * 1024):
                dst.write(chunk)
                await dst.drain()
        except (ConnectionError, OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(copy(c_reader, u_writer), copy(u_reader, c_writer))
