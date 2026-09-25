"""Deriving the real client address behind a reverse proxy.

`X-Forwarded-For` is a list the *client* can prefill: a request can arrive with
`X-Forwarded-For: 1.2.3.4` already set, and the proxy appends the real peer to
the right of it. So the leftmost entry is attacker-controlled and must never be
trusted - trusting it lets a caller forge its source address, which would defeat
the enrollment CIDR allowlist and the login/enroll rate limiter (spoof a victim's
IP to lock them out, or rotate the IP to brute-force without ever tripping it).

The only trustworthy entries are the ones your own infrastructure appended. With
`n` trusted proxies in front of the app, the client is the `n`-th entry from the
right; everything further left came from outside. `n` is deployment knowledge, so
it is configuration (`VPSMCP_TRUSTED_PROXY_HOPS`), not a guess:

    1  the documented setup - one Caddy/nginx on localhost (default)
    0  the app is bound to a public port with no proxy - ignore the header
    2  a proxy behind a CDN or load balancer that also appends
"""
from __future__ import annotations

from starlette.requests import Request


def client_ip(request: Request, trusted_hops: int) -> str:
    """The caller's address as seen by the outermost trusted proxy.

    Fails closed: if the header is shorter than the configured hop count (the
    deployment does not match the setting, or the header was stripped), it returns
    the direct peer instead of an attacker-supplied value, so a CIDR check denies
    and the rate limiter buckets the request rather than trusting a forgery.
    """
    peer = request.client.host if request.client else ""
    if trusted_hops <= 0:
        return peer
    xff = request.headers.get("x-forwarded-for", "")
    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if len(parts) >= trusted_hops:
        return parts[-trusted_hops]
    return peer
