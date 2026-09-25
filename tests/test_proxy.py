"""Egress forward proxy: authentication, CONNECT tunnelling, and the SSRF guard
that stops a node from using the proxy to reach the gateway's own internals.

Runs the proxy against loopback origin servers; no gateway needed.
"""
import asyncio
import base64
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.auth.keys import hash_password  # noqa: E402
from vpsmcp.proxy import ForwardProxy, resolve_public, ProxyDenied, _addr_is_public  # noqa: E402


class S:
    proxy_user = "node"
    proxy_pass_hash = hash_password("proxy-secret-123")
    proxy_connect_timeout = 5
    proxy_bind_host = "127.0.0.1"
    proxy_bind_port = 0
    proxy_tls_cert = ""
    proxy_tls_key = ""


def basic(user, pw):
    return "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()


async def start_origin():
    """A tiny HTTP origin that answers 200 OK on any connection."""
    async def handle(r, w):
        try:
            await r.read(65536)
        except OSError:
            pass
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nhey")
        await w.drain()
        w.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def start_proxy():
    proxy = ForwardProxy(S())
    srv = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
    return srv, srv.sockets[0].getsockname()[1]


async def main():
    # --- unit: the address classifier blocks every internal form ---
    assert _addr_is_public("1.1.1.1")
    for bad in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254",
                "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "0.0.0.0"):
        assert not _addr_is_public(bad), f"{bad} should be blocked"
    print("1. address classifier blocks loopback/private/link-local/mapped/metadata")

    # localhost must not resolve to a public address (SSRF guard at resolve time)
    try:
        resolve_public("127.0.0.1", 80)
        raise AssertionError("resolve_public allowed loopback")
    except ProxyDenied as e:
        assert e.status == 403
    print("2. resolve_public refuses a loopback destination (403)")

    origin_srv, origin_port = await start_origin()
    proxy_srv, proxy_port = await start_proxy()

    async def proxy_conn():
        return await asyncio.open_connection("127.0.0.1", proxy_port)

    # --- 3. no auth -> 407 ---
    r, w = await proxy_conn()
    w.write(f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n\r\n".encode())
    await w.drain()
    resp = await r.read(200)
    assert b"407" in resp and b"Proxy-Authenticate" in resp, resp
    w.close()
    print("3. CONNECT without credentials is refused (407)")

    # --- 4. wrong password -> 407 ---
    r, w = await proxy_conn()
    w.write((f"CONNECT example.com:443 HTTP/1.1\r\n"
             f"Proxy-Authorization: {basic('node', 'wrong')}\r\n\r\n").encode())
    await w.drain()
    assert b"407" in await r.read(200)
    w.close()
    print("4. CONNECT with a wrong password is refused (407)")

    # --- 5. authed CONNECT to an internal address -> 403 (the pivot guard) ---
    r, w = await proxy_conn()
    w.write((f"CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\n"
             f"Proxy-Authorization: {basic('node', 'proxy-secret-123')}\r\n\r\n").encode())
    await w.drain()
    resp = await r.read(200)
    assert b"403" in resp, resp
    w.close()
    print("5. authed CONNECT to a loopback/internal target is refused (403) — no pivot")

    # --- 6. authed CONNECT to a *public-looking* host that we force-resolve to the
    #        local origin proves the happy tunnel path. We can't use a real public
    #        host offline, so monkeypatch resolve to the origin and check the tunnel. ---
    import vpsmcp.proxy as pmod
    real_resolve = pmod.resolve_public
    pmod.resolve_public = lambda host, port: (socket.AF_INET, "127.0.0.1")
    try:
        r, w = await proxy_conn()
        w.write((f"CONNECT example.com:{origin_port} HTTP/1.1\r\n"
                 f"Proxy-Authorization: {basic('node', 'proxy-secret-123')}\r\n\r\n").encode())
        await w.drain()
        established = await r.readuntil(b"\r\n\r\n")
        assert b"200 Connection Established" in established, established
        # now speak to the tunnelled origin
        w.write(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        await w.drain()
        body = await r.read(1000)
        assert b"200 OK" in body and b"hey" in body, body
        w.close()
        print("6. authed CONNECT establishes a tunnel and passes bytes end to end")
    finally:
        pmod.resolve_public = real_resolve

    origin_srv.close()
    proxy_srv.close()
    print("\nall proxy checks passed")


asyncio.run(main())
