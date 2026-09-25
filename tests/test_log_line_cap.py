"""A log line from a node is capped, so a 肉鸡 cannot OOM the gateway.

The log follower feeds a tail -F / journalctl -f stream into a ring buffer whose
maxlen bounds the line COUNT. A compromised node can still stream one endless
line with no newline; the old readline() buffered it whole. _capped_lines bounds
memory to ~max_line regardless of what the node sends.

Pure unit test, no server needed.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.ssh.logs import _capped_lines, _TRUNC  # noqa: E402

MAX = 1000


class FakeStream:
    """Serves a fixed script of chunks, then EOF, like asyncssh's reader.read(n)."""
    def __init__(self, chunks):
        self._chunks = list(chunks)

    async def read(self, n):
        if not self._chunks:
            return ""
        c = self._chunks.pop(0)
        return c[:n] if len(c) > n else c


async def collect(chunks):
    return [line async for line in _capped_lines(FakeStream(chunks), MAX)]


async def main():
    # 1. Ordinary lines pass through, split on newlines, across chunk boundaries.
    out = await collect(["a\nbb\ncc", "cc\n"])
    assert out == ["a", "bb", "cccc"], out
    print("1. normal lines split correctly across chunks")

    # 2. An endless line with no newline: bounded to one truncated line, and the
    #    line after it stays intact. Feed 5 MB with no newline, then a real line.
    huge = "X" * 5_000_000
    out = await collect([huge, "\nafter\n"])
    assert len(out) == 2, out
    assert out[0].startswith("X" * MAX) and out[0].endswith(_TRUNC), out[0][:40]
    assert len(out[0]) == MAX + len(_TRUNC), len(out[0])
    assert out[1] == "after", out[1]
    print("2. endless line truncated once; the line after it is intact")

    # 3. The truncated tail is not re-emitted as extra lines.
    out = await collect(["Y" * (MAX * 3) + "\n" + "Z" * (MAX * 3) + "\n"])
    assert len(out) == 2 and all(x.endswith(_TRUNC) for x in out), [len(x) for x in out]
    print("3. two over-long lines -> exactly two truncated lines, no tail spam")

    # 4. Exactly max_line with newline is not marked truncated.
    out = await collect(["W" * MAX + "\n"])
    assert out == ["W" * MAX], (len(out), len(out[0]))
    print("4. a line exactly at the cap is not truncated")

    print("\nall log line-cap checks passed")


asyncio.run(main())
