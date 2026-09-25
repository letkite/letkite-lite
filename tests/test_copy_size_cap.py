"""copy_between_hosts must not trust a source node's self-reported size.

A compromised source node (肉鸡) runs the SFTP server the gateway reads from. If
the relay limit is enforced against the server-reported stat, the node understates
its size, slips past the check, and then streams unbounded data into the gateway's
memory. read_capped enforces the limit on the bytes actually read, so the lie does
not help.

Pure unit test, no server needed.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from fastmcp.exceptions import ToolError  # noqa: E402
from vpsmcp.tools.files import read_capped  # noqa: E402

CAP = 4_000_000


class FakeFile:
    def __init__(self, payload: bytes):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def read(self, n=-1):
        # Faithful SFTP semantics: return up to n bytes of what we actually hold.
        return self._payload if n is None or n < 0 else self._payload[:n]


class LyingSftp:
    """stat() understates the size; the file actually holds `real` bytes."""
    def __init__(self, real: int, claimed: int):
        self._payload = b"A" * real
        self.claimed = claimed

    async def stat(self, path):
        return type("St", (), {"size": self.claimed})()

    def open(self, path, mode):
        return FakeFile(self._payload)


async def main():
    # 1. Honest small file: returned intact.
    data = await read_capped(LyingSftp(real=1000, claimed=1000), "/f", CAP)
    assert data == b"A" * 1000
    print("1. small file copied intact")

    # 2. Node lies (stat says 10 bytes) but serves cap+5MB: rejected on real bytes.
    big = LyingSftp(real=CAP + 5_000_000, claimed=10)
    try:
        await read_capped(big, "/f", CAP)
    except ToolError as e:
        assert "relay limit" in str(e), e
        print("2. oversized stream rejected despite a stat that lies (size cap enforced)")
    else:
        raise AssertionError("read_capped accepted a stream larger than the cap")

    # 3. Exactly at the cap is allowed; one byte over is not.
    assert len(await read_capped(LyingSftp(CAP, CAP), "/f", CAP)) == CAP
    try:
        await read_capped(LyingSftp(CAP + 1, 0), "/f", CAP)
    except ToolError:
        print("3. boundary is exact: cap ok, cap+1 rejected")
    else:
        raise AssertionError("cap+1 was not rejected")

    print("\nall copy size-cap checks passed")


asyncio.run(main())
