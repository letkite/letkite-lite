"""One-shot command execution with timeout, output cap and partial-output capture."""
from __future__ import annotations

import asyncio
import shlex
from dataclasses import dataclass

import asyncssh


@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    duration_ms: int
    timed_out: bool = False

    def as_dict(self) -> dict:
        d = {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
        }
        if self.stdout_truncated:
            d["stdout_truncated"] = True
        if self.stderr_truncated:
            d["stderr_truncated"] = True
        if self.timed_out:
            d["timed_out"] = True
        return d


def build_script(
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    sudo: bool = False,
    login_shell: bool = True,
) -> str:
    """Wrap a command for the remote login shell."""
    parts: list[str] = ["set -o pipefail 2>/dev/null || true"]
    for k, v in (env or {}).items():
        parts.append(f"export {shlex.quote(k)}={shlex.quote(str(v))}")
    if cwd:
        parts.append(f"cd {shlex.quote(cwd)} || {{ echo 'vpsmcp: no such cwd' >&2; exit 97; }}")
    parts.append(command)
    script = "\n".join(parts)
    flag = "-lc" if login_shell else "-c"
    inner = f"bash {flag} {shlex.quote(script)}"
    return f"sudo -n -H {inner}" if sudo else inner


async def _drain(stream, cap: int, sink: bytearray, flag: list[bool]) -> None:
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            return
        room = cap - len(sink)
        if room > 0:
            sink.extend(chunk[:room])
        if len(chunk) > max(room, 0):
            flag[0] = True


async def run_command(
    conn: asyncssh.SSHClientConnection,
    command: str,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    sudo: bool = False,
    timeout: int = 60,
    max_bytes: int = 256_000,
    pty: bool = False,
) -> ExecResult:
    script = build_script(command, cwd=cwd, env=env, sudo=sudo)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    out, err = bytearray(), bytearray()
    out_tr, err_tr = [False], [False]
    timed_out = False

    proc = await conn.create_process(
        script, term_type="xterm-256color" if pty else None, encoding=None
    )
    try:
        drain = asyncio.gather(
            _drain(proc.stdout, max_bytes, out, out_tr),
            _drain(proc.stderr, max_bytes, err, err_tr),
        )
        try:
            await asyncio.wait_for(drain, timeout=timeout)
            await asyncio.wait_for(proc.wait_closed(), timeout=10)
        except asyncio.TimeoutError:
            timed_out = True
            drain.cancel()
            try:
                proc.kill()
            except Exception:  # noqa: BLE001
                pass
            try:
                await asyncio.wait_for(proc.wait_closed(), timeout=5)
            except Exception:  # noqa: BLE001
                pass
    finally:
        proc.close()

    rc = proc.exit_status
    if rc is None:
        rc = 124 if timed_out else -1
    return ExecResult(
        exit_code=int(rc),
        stdout=bytes(out).decode("utf-8", "replace"),
        stderr=bytes(err).decode("utf-8", "replace"),
        stdout_truncated=out_tr[0],
        stderr_truncated=err_tr[0],
        duration_ms=int((loop.time() - t0) * 1000),
        timed_out=timed_out,
    )
