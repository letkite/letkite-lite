"""Local port forwarding plus an HTTP client through the tunnel.

A bare tunnel is useless to the model (it cannot open sockets), so tunnel_http
lets it reach services bound to 127.0.0.1 on the node.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field


class TunnelError(RuntimeError):
    pass


@dataclass
class Tunnel:
    id: str
    alias: str
    node_id: str
    remote_host: str
    remote_port: int
    local_port: int
    listener: object
    created: float = field(default_factory=time.time)


class TunnelManager:
    def __init__(self, pool, max_tunnels: int = 8, ttl: int = 3600):
        self.pool = pool
        self.max_tunnels = max_tunnels
        self.ttl = ttl
        self._tunnels: dict[str, Tunnel] = {}

    async def open(self, host, inv, *, remote_host: str = "127.0.0.1", remote_port: int = 80) -> Tunnel:
        if len(self._tunnels) >= self.max_tunnels:
            raise TunnelError(f"tunnel limit {self.max_tunnels} reached")
        conn = await self.pool.acquire(host, inv)
        listener = await conn.forward_local_port("127.0.0.1", 0, remote_host, int(remote_port))
        t = Tunnel(id=f"tun_{uuid.uuid4().hex[:10]}", alias=host.alias, node_id=host.node_id,
                   remote_host=remote_host, remote_port=int(remote_port),
                   local_port=listener.get_port(), listener=listener)
        self._tunnels[t.id] = t
        self.pool.pin(host.node_id)
        return t

    def get(self, tid: str) -> Tunnel:
        t = self._tunnels.get(tid)
        if not t:
            raise TunnelError(f"tunnel {tid} not found")
        return t

    async def close(self, tid: str) -> None:
        t = self._tunnels.pop(tid, None)
        if not t:
            return
        try:
            t.listener.close()
        except Exception:  # noqa: BLE001
            pass
        self.pool.unpin(t.node_id)

    def list(self) -> list[dict]:
        now = time.time()
        return [
            {"tunnel_id": t.id, "host": t.alias,
             "target": f"{t.remote_host}:{t.remote_port}",
             "local": f"127.0.0.1:{t.local_port}", "age_s": round(now - t.created, 1)}
            for t in self._tunnels.values()
        ]

    async def reap(self) -> None:
        now = time.time()
        for tid, t in list(self._tunnels.items()):
            if now - t.created > self.ttl:
                await self.close(tid)

    async def close_all(self) -> None:
        for tid in list(self._tunnels):
            await self.close(tid)
