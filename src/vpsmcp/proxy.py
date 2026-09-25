"""Authenticated forward proxy so fleet nodes can egress through the gateway.

A node opts in at enrollment (`--proxy`) and points http_proxy/https_proxy at the
gateway. The gateway gives it one stable egress IP; the node can flip back to its
own system proxy at any time (the toggle lives on the node).

Two properties make this safe to expose:

  - Every request needs Proxy-Authorization: Basic, checked against a scrypt hash.
    No credentials, no proxying (407).
  - The destination is resolved once and every resolved address is checked; if any
    is private, loopback, link-local, reserved or multicast the request is refused,
    and the connection is opened to the exact validated IP (not re-resolved), so a
    node cannot use the proxy to reach the gateway's own 127.0.0.1:8848, its SSH,
    a cloud metadata endpoint, or anything else on the gateway's internal network.
    An egress proxy without this is a pivot into the gateway; with it, it only
    reaches the public internet.

CONNECT (used for https and by most clients) is the primary path; absolute-form
HTTP is also proxied, with Connection: close to keep it simple.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import logging
import socket
import ssl
from urllib.parse import urlsplit

from .auth.keys import verify_password
from .settings import Settings

log = logging.getLogger("vpsmcp.proxy")

_HDR_CAP = 65536          # request line + headers we are willing to buffer
_HOP_BY_HOP = {"proxy-authorization", "proxy-connection", "connection",
               "keep-alive", "te", "trailer", "transfer-encoding", "upgrade"}


class ProxyDenied(Exception):
    """Refuse the request; carries the HTTP status and short reason to return."""
    def __init__(self, status: int, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _addr_is_public(ip: str) -> bool:
    ipo = ipaddress.ip_address(ip)
    if ipo.version == 6 and ipo.ipv4_mapped is not None:
        ipo = ipo.ipv4_mapped
    return not (ipo.is_private or ipo.is_loopback or ipo.is_link_local
                or ipo.is_reserved or ipo.is_multicast or ipo.is_unspecified)


def resolve_public(host: str, port: int) -> tuple[int, str]:
    """Resolve host:port and return (family, ip) for a public address, pinning the
    exact IP so the later connect cannot be rebound to an internal one. Raises
    ProxyDenied if the host does not resolve or any resolved address is not public."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        raise ProxyDenied(502, "cannot resolve host")
    if not infos:
        raise ProxyDenied(502, "cannot resolve host")
    for info in infos:
        ip = info[4][0]
        if not _addr_is_public(ip):
            # One private answer poisons the name (DNS rebinding defence).
            raise ProxyDenied(403, "destination is not a public address")
    fam, _, _, _, sa = infos[0]
    return fam, sa[0]


class ForwardProxy:
    def __init__(self, settings: Settings, audit=None):
        self.s = settings
        self.audit = audit
        self.user = settings.proxy_user
        self.pass_hash = settings.proxy_pass_hash

    # ---------- auth ----------
    def _authorized(self, headers: dict[str, str]) -> bool:
        raw = headers.get("proxy-authorization", "")
        if not raw.lower().startswith("basic "):
            return False
        try:
            user, _, pwd = base64.b64decode(raw[6:]).decode("utf-8", "replace").partition(":")
        except Exception:  # noqa: BLE001
            return False
        # constant-time on the username, scrypt on the password
        return (hmac.compare_digest(user, self.user)
                and verify_password(pwd, self.pass_hash))

    # ---------- connection entry ----------
    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            return await self._fail(writer, ProxyDenied(400, "malformed request"))
        if len(head) > _HDR_CAP:
            return await self._fail(writer, ProxyDenied(431, "header too large"))

        try:
            line, headers = _parse_head(head)
            method, target, _ = line.split(" ", 2)
        except ValueError:
            return await self._fail(writer, ProxyDenied(400, "malformed request line"))

        if not self._authorized(headers):
            self._log("deny", peer, target, "auth")
            return await self._fail(writer, ProxyDenied(407, "proxy authentication required"))

        try:
            if method.upper() == "CONNECT":
                await self._connect(reader, writer, target, peer)
            else:
                await self._forward(reader, writer, method, target, headers, peer)
        except ProxyDenied as d:
            await self._fail(writer, d)
        except (OSError, asyncio.TimeoutError) as exc:
            await self._fail(writer, ProxyDenied(502, "upstream error"))
            log.debug("upstream error to %s: %s", target, exc)

    # ---------- CONNECT tunnel (https and most clients) ----------
    async def _connect(self, reader, writer, target, peer) -> None:
        host, _, port_s = target.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_s)
        except ValueError:
            raise ProxyDenied(400, "bad CONNECT target")
        if not (0 < port < 65536):
            raise ProxyDenied(400, "bad port")
        fam, ip = resolve_public(host, port)
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=fam), timeout=self.s.proxy_connect_timeout)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        self._log("connect", peer, f"{host}:{port}", "ok")
        await _splice(reader, writer, up_r, up_w)

    # ---------- absolute-form HTTP (plain http egress) ----------
    async def _forward(self, reader, writer, method, target, headers, peer) -> None:
        u = urlsplit(target)
        if u.scheme != "http" or not u.hostname:
            raise ProxyDenied(400, "only http absolute-form or CONNECT is supported")
        port = u.port or 80
        fam, ip = resolve_public(u.hostname, port)
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        out = [f"{method} {path} HTTP/1.1", f"Host: {u.hostname}" + (f":{port}" if u.port else "")]
        for k, v in headers.items():
            if k not in _HOP_BY_HOP and k != "host":
                out.append(f"{_title(k)}: {v}")
        out.append("Connection: close")
        body_len = int(headers.get("content-length", "0") or "0")
        up_r, up_w = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=fam), timeout=self.s.proxy_connect_timeout)
        up_w.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1", "replace"))
        if body_len > 0:
            up_w.write(await reader.readexactly(body_len))
        await up_w.drain()
        self._log("http", peer, f"{u.hostname}:{port}", method)
        # stream the response back until upstream closes
        while True:
            chunk = await up_r.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
        up_w.close()

    # ---------- helpers ----------
    async def _fail(self, writer, denied: ProxyDenied) -> None:
        try:
            extra = ('Proxy-Authenticate: Basic realm="vpsmcp"\r\n'
                     if denied.status == 407 else "")
            writer.write(f"HTTP/1.1 {denied.status} {denied.reason}\r\n{extra}"
                         f"Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
        except OSError:
            pass
        finally:
            _close(writer)

    def _log(self, event, peer, target, detail) -> None:
        ip = peer[0] if peer else "?"
        log.info("%s %s -> %s (%s)", event, ip, target, detail)
        if self.audit:
            self.audit.write(event=f"proxy.{event}", ip=ip, target=target, detail=detail)


def _parse_head(head: bytes) -> tuple[str, dict[str, str]]:
    text = head.decode("latin-1")
    lines = text.split("\r\n")
    line = lines[0]
    headers: dict[str, str] = {}
    for h in lines[1:]:
        if not h:
            continue
        k, _, v = h.partition(":")
        headers[k.strip().lower()] = v.strip()
    return line, headers


def _title(k: str) -> str:
    return "-".join(p.capitalize() for p in k.split("-"))


def _close(writer) -> None:
    try:
        writer.close()
    except OSError:
        pass


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while True:
            chunk = await r.read(65536)
            if not chunk:
                break
            w.write(chunk)
            await w.drain()
    except OSError:
        pass
    finally:
        _close(w)


async def _splice(c_r, c_w, u_r, u_w) -> None:
    await asyncio.gather(_pipe(c_r, u_w), _pipe(u_r, c_w))


async def serve(settings: Settings, audit=None) -> None:
    proxy = ForwardProxy(settings, audit)
    ssl_ctx = None
    if settings.proxy_tls_cert and settings.proxy_tls_key:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(settings.proxy_tls_cert, settings.proxy_tls_key)
    server = await asyncio.start_server(
        proxy.handle, settings.proxy_bind_host, settings.proxy_bind_port, ssl=ssl_ctx)
    log.info("egress proxy on %s:%s  tls=%s  user=%s",
             settings.proxy_bind_host, settings.proxy_bind_port,
             bool(ssl_ctx), settings.proxy_user)
    async with server:
        await server.serve_forever()
