"""Persistent shell sessions: cwd, env and shell functions survive across calls.

A non-interactive bash on the remote end prints an unguessable sentinel plus the
exit code after each command. stdout and stderr are merged (no tty, no reliable
way to interleave them).
"""
from __future__ import annotations

import asyncio
import secrets
import shlex
import time
import uuid
from dataclasses import dataclass, field

import asyncssh


class SessionError(RuntimeError):
    pass


@dataclass
class ShellSession:
    id: str
    alias: str
    node_id: str
    process: asyncssh.SSHClientProcess
    sentinel: str
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    created: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    closed: bool = False

    async def run(self, command: str, timeout: int, max_bytes: int) -> dict:
        if self.closed:
            raise SessionError(f"session {self.id} is closed")
        async with self.lock:
            self.last_used = time.time()
            marker = f"{self.sentinel}:{secrets.token_hex(4)}"
            payload = (
                f"{command}\n"
                f"__vpsmcp_rc=$?\n"
                f"printf '\\n{marker}:%s:%s\\n' \"$__vpsmcp_rc\" \"$PWD\"\n"
            )
            self.process.stdin.write(payload)
            buf = bytearray()
            truncated = False
            needle = f"{marker}:".encode()
            loop = asyncio.get_running_loop()
            deadline = loop.time() + timeout
            while True:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    # a single command cannot be interrupted safely -> drop the session
                    await self.close()
                    raise SessionError(
                        f"session {self.id}: command exceeded {timeout}s, session destroyed; "
                        f"use job_start for long work")
                try:
                    chunk = await asyncio.wait_for(self.process.stdout.read(65536), remaining)
                except asyncio.TimeoutError:
                    continue
                if not chunk:
                    self.closed = True
                    raise SessionError(f"session {self.id}: remote shell exited")
                data = chunk.encode() if isinstance(chunk, str) else chunk
                buf.extend(data)
                if needle in buf:
                    break
                if len(buf) > max_bytes * 4:
                    truncated = True
                    del buf[: len(buf) - max_bytes * 2]
            text = bytes(buf).decode("utf-8", "replace")
            head, _, tail = text.rpartition(f"{marker}:")
            rc_str, _, cwd = tail.strip().partition(":")
            output = head.rstrip("\n")
            if len(output) > max_bytes:
                output = output[-max_bytes:]
                truncated = True
            try:
                rc = int(rc_str)
            except ValueError:
                rc = -1
            return {
                "session_id": self.id,
                "exit_code": rc,
                "output": output,
                "cwd": cwd.strip(),
                "truncated": truncated,
            }

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.process.stdin.write("exit\n")
        except Exception:  # noqa: BLE001
            pass
        try:
            self.process.close()
        except Exception:  # noqa: BLE001
            pass


class SessionManager:
    def __init__(self, pool, idle_ttl: int = 1800, max_per_host: int = 4):
        self.pool = pool
        self.idle_ttl = idle_ttl
        self.max_per_host = max_per_host
        self._sessions: dict[str, ShellSession] = {}

    async def open(self, host, inv, *, cwd: str | None = None, env: dict | None = None) -> ShellSession:
        live = [s for s in self._sessions.values() if s.node_id == host.node_id and not s.closed]
        if len(live) >= self.max_per_host:
            raise SessionError(f"{host.alias}: session limit {self.max_per_host} reached")
        conn = await self.pool.acquire(host, inv)
        proc = await conn.create_process("bash -l", term_type=None, encoding="utf-8", errors="replace")
        sess = ShellSession(
            id=f"sh_{uuid.uuid4().hex[:12]}",
            alias=host.alias, node_id=host.node_id,
            process=proc,
            sentinel=f"__VPSMCP_{secrets.token_hex(8)}__",
        )
        self.pool.pin(host.node_id)
        self._sessions[sess.id] = sess
        # merge stderr, seed the environment
        boot = ["exec 2>&1", "export PS1=", "set +o histexpand"]
        for k, v in (env or {}).items():
            boot.append(f"export {shlex.quote(k)}={shlex.quote(str(v))}")
        if cwd:
            boot.append(f"cd {shlex.quote(cwd)}")
        await sess.run("; ".join(boot), timeout=20, max_bytes=8192)
        return sess

    def get(self, session_id: str) -> ShellSession:
        s = self._sessions.get(session_id)
        if s is None or s.closed:
            raise SessionError(f"session {session_id} not found or closed")
        return s

    async def close(self, session_id: str) -> None:
        s = self._sessions.pop(session_id, None)
        if s:
            await s.close()
            self.pool.unpin(s.node_id)

    def list(self) -> list[dict]:
        now = time.time()
        return [
            {
                "session_id": s.id,
                "host": s.alias,
                "idle_s": round(now - s.last_used, 1),
                "age_s": round(now - s.created, 1),
                "closed": s.closed,
            }
            for s in self._sessions.values()
        ]

    async def reap(self) -> None:
        now = time.time()
        for sid, s in list(self._sessions.items()):
            if s.closed or now - s.last_used > self.idle_ttl:
                await self.close(sid)

    async def close_all(self) -> None:
        for sid in list(self._sessions):
            await self.close(sid)
