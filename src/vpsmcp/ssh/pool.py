"""asyncssh connection pool: one reused connection per node, idle-reaped."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from ..inventory import Host, Inventory
from ..settings import Settings

log = logging.getLogger("vpsmcp.ssh")


class SSHError(RuntimeError):
    pass


@dataclass
class _Entry:
    conn: asyncssh.SSHClientConnection
    alias: str
    created: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    pinned: int = 0  # held by a shell session / log sub / tunnel; never reaped while >0


class SSHPool:
    def __init__(self, settings: Settings):
        self.s = settings
        self._conns: dict[str, _Entry] = {}  # keyed by node_id; aliases may repeat
        self._locks: dict[str, asyncio.Lock] = {}
        self._reaper: asyncio.Task | None = None

    # ---------- lifecycle ----------
    async def start(self) -> None:
        if self._reaper is None:
            self._reaper = asyncio.create_task(self._reap_loop())

    async def close(self) -> None:
        if self._reaper:
            self._reaper.cancel()
            self._reaper = None
        for entry in list(self._conns.values()):
            entry.conn.close()
        for entry in list(self._conns.values()):
            try:
                await entry.conn.wait_closed()
            except Exception:  # noqa: BLE001
                pass
        self._conns.clear()

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            for nid, e in list(self._conns.items()):
                if e.pinned > 0:
                    continue
                if now - e.last_used > self.s.idle_conn_ttl:
                    log.info("reaping idle connection %s (%s)", e.alias, nid)
                    e.conn.close()
                    self._conns.pop(nid, None)

    # ---------- acquire ----------
    def _lock(self, node_id: str) -> asyncio.Lock:
        return self._locks.setdefault(node_id, asyncio.Lock())

    def _known_hosts(self, host: Host):
        if host.host_key:
            # Defence in depth: the key is validated at enrollment, but hosts.yaml
            # can also be hand-edited. Refuse to template a multi-line / malformed
            # key into the known_hosts document, where it would inject entries.
            from ..inventory import valid_host_key
            if not valid_host_key(host.host_key.strip()):
                raise SSHError(
                    f"{host.alias}: host_key is not a single valid SSH public key line")
            key = host.host_key.strip()
            line = f"[{host.address}]:{host.port} {key}\n{host.address} {key}\n"
            return asyncssh.import_known_hosts(line)
        if self.s.strict_host_keys:
            p = self.s.known_hosts_path
            if not p or not Path(p).exists():
                raise SSHError(
                    f"strict host key checking is on but {p} does not exist; "
                    f"enrolled nodes get host_key written automatically, "
                    f"manual entries need it in the inventory")
            return str(p)
        return None  # lab only; keep strict in production

    def _client_keys(self, host: Host) -> list:
        path = Path(host.key_file) if host.key_file else self.s.ssh_key_path
        if not path.exists():
            raise SSHError(f"ssh key not found: {path}")
        try:
            return [asyncssh.read_private_key(str(path), passphrase=self.s.ssh_key_passphrase)]
        except asyncssh.KeyEncryptionError as exc:
            raise SSHError(f"{path} needs a correct VPSMCP_SSH_KEY_PASSPHRASE") from exc

    async def acquire(self, host: Host, inv: Inventory) -> asyncssh.SSHClientConnection:
        nid = host.node_id
        entry = self._conns.get(nid)
        if entry is not None and not _dead(entry.conn):
            entry.last_used = time.monotonic()
            return entry.conn
        async with self._lock(nid):
            entry = self._conns.get(nid)
            if entry is not None and not _dead(entry.conn):
                entry.last_used = time.monotonic()
                return entry.conn
            self._conns.pop(nid, None)
            conn = await self._connect(host, inv)
            self._conns[nid] = _Entry(conn=conn, alias=host.alias)
            return conn

    async def _connect(self, host: Host, inv: Inventory) -> asyncssh.SSHClientConnection:
        tunnel = None
        if host.jump:
            jump_host = inv.get(host.jump)
            tunnel = await self.acquire(jump_host, inv)
        opts = dict(
            host=host.address,
            port=host.port,
            username=host.user,
            client_keys=self._client_keys(host),
            known_hosts=self._known_hosts(host),
            connect_timeout=self.s.connect_timeout,
            keepalive_interval=30,
            keepalive_count_max=3,
            tunnel=tunnel,
        )
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(**opts), timeout=self.s.connect_timeout + 5
            )
        except asyncssh.HostKeyNotVerifiable as exc:
            raise SSHError(
                f"{host.alias}: host key verification failed: {exc}") from exc
        except (OSError, asyncssh.Error, asyncio.TimeoutError) as exc:
            raise SSHError(f"cannot connect to {host.alias} "
                           f"({host.user}@{host.address}:{host.port}): {exc}") from exc
        log.info("connected %s", host.alias)
        return conn

    # ---------- refcount ----------
    def pin(self, node_id: str) -> None:
        e = self._conns.get(node_id)
        if e:
            e.pinned += 1

    def unpin(self, node_id: str) -> None:
        e = self._conns.get(node_id)
        if e and e.pinned > 0:
            e.pinned -= 1

    def stats(self) -> list[dict]:
        now = time.monotonic()
        return [
            {
                "alias": e.alias,
                "node_id": nid,
                "age_s": round(now - e.created, 1),
                "idle_s": round(now - e.last_used, 1),
                "pinned": e.pinned,
                "alive": not _dead(e.conn),
            }
            for nid, e in sorted(self._conns.items(), key=lambda kv: (kv[1].alias, kv[0]))
        ]


def _dead(conn: asyncssh.SSHClientConnection) -> bool:
    try:
        return bool(conn.is_closed())
    except AttributeError:  # older asyncssh
        return getattr(conn, "_transport", None) is None
