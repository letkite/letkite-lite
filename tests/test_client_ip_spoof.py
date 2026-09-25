"""Source-address spoofing via X-Forwarded-For.

The enrollment CIDR allowlist and the login / enroll rate limiters key off the
caller's IP. If that IP is taken from the leftmost X-Forwarded-For entry, a
caller forges it: bypass the allowlist, lock a victim out by spoofing their
address, or rotate the address to brute-force the admin password without ever
tripping the limiter. netutil.client_ip must take the proxy-appended entry, not
the client-supplied prefix.

Two parts:
  - a pure unit check of client_ip (no server needed)
  - a live check that needs the lab from tests/README.md started with
    VPSMCP_TRUSTED_PROXY_HOPS=0 (no proxy in front), VPSMCP_ENROLL_MODE=approve
    and VPSMCP_ENROLL_ALLOW_CIDRS=203.0.113.0/24
"""
import os
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.netutil import client_ip  # noqa: E402

BASE = "http://127.0.0.1:8848"
USER, PASSWORD = os.environ.get("VPSMCP_ADMIN_USER", "admin"), "correct-horse-battery"


class Req:
    def __init__(self, xff=None, peer="127.0.0.1"):
        self.headers = {"x-forwarded-for": xff} if xff else {}
        self.client = type("C", (), {"host": peer})()


# ---------------------------------------------------------------- unit
# One proxy appends the real client as the LAST entry; the client may prefill
# anything to the left of it, and that prefix must never be trusted.
assert client_ip(Req("203.0.113.7, 198.51.100.20"), 1) == "198.51.100.20"
assert client_ip(Req("198.51.100.20"), 1) == "198.51.100.20"          # proxy, no prefill
assert client_ip(Req(None, "198.51.100.20"), 1) == "198.51.100.20"    # header absent
assert client_ip(Req("evil, cdn, real"), 2) == "cdn"                  # two hops
# hops=0: no proxy, header ignored entirely, direct peer used
assert client_ip(Req("203.0.113.7"), 0) == "127.0.0.1"
# fewer entries than configured hops -> fail closed to the direct peer, never a
# client-supplied value
assert client_ip(Req("203.0.113.7"), 2) == "127.0.0.1"
print("1. client_ip trusts only the proxy-appended entry (unit)")

if os.environ.get("SKIP_LIVE"):
    print("\nunit checks passed (live checks skipped)")
    raise SystemExit(0)

c = httpx.Client(timeout=10)
body = {"host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITEST spoof-test",
        "alias": "spoof", "user": "root", "port": 22}
lp = dict(response_type="code", client_id="x",
          redirect_uri="https://claude.ai/api/mcp/auth_callback", scope="fleet.read")

# ---------------------------------------------------------------- CIDR allowlist
# The lab runs with hops=0, so the real peer (127.0.0.1) is outside the
# 203.0.113.0/24 allowlist and a spoofed header must not change that.
r = c.post(f"{BASE}/enroll/register", json=body)
assert r.status_code == 403 and r.json()["code"] == "E_NOT_ALLOWED", r.text
r = c.post(f"{BASE}/enroll/register", json=body, headers={"X-Forwarded-For": "203.0.113.7"})
assert r.status_code == 403 and r.json()["code"] == "E_NOT_ALLOWED", \
    f"CIDR allowlist bypassed via X-Forwarded-For: {r.text}"
print("2. enroll CIDR allowlist is not bypassable with a spoofed source")

# ---------------------------------------------------------------- rate limiter
# Rotating a spoofed IP per attempt must still trip the shared limiter, because
# all requests key to the same real peer.
locked = False
for i in range(12):
    r = c.post(f"{BASE}/oauth/login", data={**lp, "username": USER, "password": f"g{i}"},
               headers={"X-Forwarded-For": f"10.0.0.{i}"})
    if r.status_code == 429:
        locked = True
        break
assert locked, "login lockout evaded by rotating X-Forwarded-For"
print(f"3. login lockout enforced despite rotating spoofed IPs (tripped at try {i + 1})")

print("\nall spoofing checks passed")
