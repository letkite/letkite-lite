"""tunnel_http must not buffer an unbounded response body.

tunnel_http reaches a service on the far end of a tunnel to a node, which may be
a compromised machine. Reading response.text/.read() buffers the whole body into
the gateway first, so a node serving an endless or huge body OOMs it. _http_capped
streams and stops at the cap.

Uses a tiny local server that streams forever; no gateway needed.
"""
import asyncio
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.tools.ops import _http_capped  # noqa: E402

CAP = 100_000


def _serve_forever(sock):
    """Accept one connection and stream chunked data until the client hangs up."""
    conn, _ = sock.accept()
    try:
        conn.recv(65536)  # request headers; ignore
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                     b"Transfer-Encoding: chunked\r\n\r\n")
        blob = b"A" * 65536
        chunk = (b"%X\r\n" % len(blob)) + blob + b"\r\n"
        while True:
            conn.sendall(chunk)  # raises once the client disconnects
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _serve_small(sock, body: bytes):
    conn, _ = sock.accept()
    try:
        conn.recv(65536)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                     b"Content-Length: %d\r\n\r\n" % len(body) + body)
    except OSError:
        pass
    finally:
        conn.close()


def _spawn(target, *args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    t = threading.Thread(target=target, args=(sock, *args), daemon=True)
    t.start()
    return port, sock


async def main():
    # 1. Endless body: capped and aborted, does not run away.
    port, sock = _spawn(_serve_forever)
    status, hdrs, text, truncated = await asyncio.wait_for(
        _http_capped("GET", f"http://127.0.0.1:{port}/", headers={}, content=None,
                     timeout=10, cap=CAP), timeout=8)
    assert status == 200, status
    assert truncated is True, "endless body not flagged truncated"
    assert len(text) == CAP, f"body not capped: {len(text)} != {CAP}"
    sock.close()
    print(f"1. endless chunked body capped at {CAP} and aborted")

    # 2. A small body under the cap is returned whole, not flagged truncated.
    port, sock = _spawn(_serve_small, b"hello world")
    status, hdrs, text, truncated = await _http_capped(
        "GET", f"http://127.0.0.1:{port}/", headers={}, content=None, timeout=10, cap=CAP)
    assert text == "hello world" and truncated is False, (text, truncated)
    sock.close()
    print("2. a small body is returned intact, not truncated")

    print("\nall tunnel_http cap checks passed")


asyncio.run(main())
