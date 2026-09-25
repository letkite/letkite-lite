"""Runtime container: inventory, connection pool, managers, audit."""
from __future__ import annotations

import asyncio
import logging

from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token

from .audit import Audit
from .inventory import Host, InventoryError, InventoryWatcher
from .policy import PolicyError, guard, require_scope
from .settings import SCOPES, Settings
from .ssh.logs import LogManager
from .ssh.pool import SSHPool
from .ssh.session import SessionManager
from .ssh.tunnels import TunnelManager

log = logging.getLogger("vpsmcp")


class Runtime:
    def __init__(self, settings: Settings):
        self.s = settings
        self.audit = Audit(settings.audit_path)
        self.inv = InventoryWatcher(settings.inventory_path)
        self.pool = SSHPool(settings)
        self.sessions = SessionManager(self.pool)
        self.logs = LogManager(self.pool)
        self.tunnels = TunnelManager(self.pool)
        self._reaper: asyncio.Task | None = None

    async def start(self) -> None:
        await self.pool.start()
        self._reaper = asyncio.create_task(self._reap_loop())
        log.info("runtime started; %d hosts", len(self.inv.get().hosts))

    async def stop(self) -> None:
        if self._reaper:
            self._reaper.cancel()
        await self.logs.close_all()
        await self.tunnels.close_all()
        await self.sessions.close_all()
        await self.pool.close()

    async def _reap_loop(self) -> None:
        while True:
            await asyncio.sleep(60)
            try:
                await self.sessions.reap()
                await self.tunnels.reap()
            except Exception:  # noqa: BLE001
                log.exception("reaper failed")

    # ---------- auth ----------
    def scopes(self) -> set[str]:
        tok = get_access_token()
        if tok is None:          # local stdio / auth disabled
            return set(SCOPES)
        return set(tok.scopes or [])

    def subject(self) -> str:
        tok = get_access_token()
        return (tok.subject or tok.client_id) if tok else "local"

    def require(self, need: str) -> None:
        """Token-only check, for tools that name no host (audit) or act on a handle
        whose host may already be gone (closing a shell, a log, a tunnel). Anything
        that reaches a host goes through resolve() instead."""
        try:
            require_scope(self.scopes(), need)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc

    # ---------- host resolution ----------
    def resolve(self, key: str, need: str) -> Host:
        """key may be an alias or a node_id; aliases may repeat."""
        try:
            host = self.inv.get().get(key)
        except InventoryError as exc:
            raise ToolError(str(exc)) from exc
        if self.s.read_only and need != "fleet.read":
            raise ToolError("gateway is in read-only mode (VPSMCP_READ_ONLY=1)")
        try:
            guard(self.scopes(), host, need)
        except PolicyError as exc:
            raise ToolError(f"{exc} ({host.label})") from exc
        return host

    def resolve_many(self, hosts: list[str] | None, tags: list[str] | None,
                     need: str) -> list[Host]:
        try:
            selected = self.inv.get().select(aliases=hosts, tags=tags)
        except InventoryError as exc:
            raise ToolError(str(exc)) from exc
        return [self.resolve(h.node_id, need) for h in selected]

    async def conn(self, host: Host):
        from .ssh.pool import SSHError
        try:
            return await self.pool.acquire(host, self.inv.get())
        except SSHError as exc:
            raise ToolError(str(exc)) from exc

    def record(self, tool: str, **fields) -> None:
        self.audit.write(event="tool", tool=tool, subject=self.subject(), **fields)

    def clamp_timeout(self, timeout: int | None) -> int:
        t = timeout or self.s.default_timeout
        return max(1, min(int(t), self.s.max_timeout))
