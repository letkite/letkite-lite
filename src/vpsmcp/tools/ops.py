"""Tools: detached jobs, log subscriptions, port forwarding, audit."""
from __future__ import annotations

from typing import Annotated

import httpx
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from ..policy import PolicyError, check_command
from ..runtime import Runtime
from ..ssh import jobs as jobmod
from ..ssh.logs import LogError
from ..ssh.tunnels import TunnelError


async def _http_capped(method: str, url: str, *, headers: dict, content: bytes | None,
                       timeout: int, cap: int) -> tuple[int, dict, str, bool]:
    """One HTTP request whose response body is read streaming and stopped at cap.

    The target sits on the far end of a tunnel to a node, which can be a
    compromised machine. `response.text` / `.read()` would buffer the whole body
    into the gateway's memory first; a node serving an endless or huge body would
    OOM it. Streaming and breaking at cap+1 bounds memory to ~cap and aborts the
    rest of the download.
    """
    buf = bytearray()
    truncated = False
    async with httpx.AsyncClient(timeout=timeout) as c:
        async with c.stream(method, url, headers=headers,
                            content=content) as r:
            async for chunk in r.aiter_bytes():
                room = cap - len(buf)
                if room > 0:
                    buf.extend(chunk[:room])
                if len(chunk) > max(room, 0):
                    truncated = True
                    break
            resp_headers = dict(r.headers)
            encoding = r.encoding or "utf-8"
    return r.status_code, resp_headers, bytes(buf).decode(encoding, "replace"), truncated


def register(mcp: FastMCP, rt: Runtime) -> None:

    # ---------------- detached jobs ----------------
    @mcp.tool
    async def job_start(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        command: Annotated[str, Field(description="command to run in the background")],
        label: Annotated[str, Field(description="human-readable label")] = "",
        cwd: Annotated[str | None, Field(description="working directory")] = None,
        env: Annotated[dict[str, str] | None, Field(description="extra environment")] = None,
        confirm: Annotated[bool, Field(description="confirm a high-risk command")] = False,
    ) -> dict:
        """Start a detached job on the node and return a job_id immediately.

        The job outlives the SSH connection, the gateway restart and this
        conversation. stdout/stderr land in ~/.vpsmcp/jobs/<job_id>/ on the node.
        Use this for builds, backups, bulk transfers, benchmarks.
        """
        h = rt.resolve(host, "fleet.exec")
        try:
            check_command(command, confirm=confirm, enabled=rt.s.enable_guardrails)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc
        conn = await rt.conn(h)
        try:
            info = await jobmod.start(conn, command=command, cwd=cwd or h.workdir,
                                      env={**h.env, **(env or {})}, label=label or command[:40])
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"cannot start job: {exc}") from exc
        rt.record("job_start", host=h.node_id, job_id=info["job_id"], command=command)
        return {"host": h.alias, **info,
                "next": "poll job_status, read incrementally with job_output"}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def job_status(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        job_id: Annotated[str | None, Field(description="omit to list all jobs on the host")] = None,
    ) -> dict:
        """Job state: running / finished / aborted, plus exit code and output sizes."""
        h = rt.resolve(host, "fleet.read")
        conn = await rt.conn(h)
        rows = await jobmod.status(conn, job_id=job_id)
        return {"host": h.alias, "count": len(rows), "jobs": rows}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def job_output(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        job_id: Annotated[str, Field(description="id from job_start")],
        stream: Annotated[str, Field(description="stdout or stderr")] = "stdout",
        offset: Annotated[int, Field(description="byte offset; pass back next_offset for incremental reads", ge=0)] = 0,
        max_bytes: Annotated[int, Field(description="max bytes to return", ge=1)] = 64_000,
        tail: Annotated[bool, Field(description="ignore offset, return the tail")] = False,
    ) -> dict:
        """Read job output. Returns next_offset for a gap-free incremental follow-up."""
        h = rt.resolve(host, "fleet.read")
        conn = await rt.conn(h)
        return {"host": h.alias, **await jobmod.output(
            conn, job_id=job_id, stream=stream, offset=offset,
            max_bytes=min(max_bytes, rt.s.max_output_bytes), tail=tail)}

    @mcp.tool
    async def job_kill(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        job_id: Annotated[str, Field(description="job to terminate")],
        signal: Annotated[str, Field(description="TERM / KILL / INT / HUP")] = "TERM",
    ) -> dict:
        """Signal the job's whole process group."""
        h = rt.resolve(host, "fleet.exec")
        conn = await rt.conn(h)
        out = await jobmod.kill(conn, job_id=job_id, signal=signal)
        rt.record("job_kill", host=h.node_id, job_id=job_id, signal=signal)
        return {"host": h.alias, **out}

    @mcp.tool
    async def job_purge(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        job_id: Annotated[str, Field(description="finished job to purge")],
    ) -> dict:
        """Delete a finished job's directory and logs. Running jobs are left alone."""
        h = rt.resolve(host, "fleet.write")
        conn = await rt.conn(h)
        out = await jobmod.purge(conn, job_id=job_id)
        rt.record("job_purge", host=h.node_id, job_id=job_id)
        return {"host": h.alias, **out}

    # ---------------- log subscriptions ----------------
    @mcp.tool
    async def log_open(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        path: Annotated[str | None, Field(description="log file path (or use unit)")] = None,
        unit: Annotated[str | None, Field(description="systemd unit (or use path)")] = None,
        grep: Annotated[str | None, Field(description="line filter, ERE")] = None,
        initial_lines: Annotated[int, Field(description="initial history lines", ge=0, le=500)] = 50,
    ) -> dict:
        """Start collecting a log on the gateway; read it later with log_read.

        Subscribe first, trigger something with exec, then read what appeared.
        That ordering is not possible with exec alone.
        """
        h = rt.resolve(host, "fleet.read")
        try:
            sub = await rt.logs.open(h, rt.inv.get(), path=path, unit=unit,
                                     grep=grep, initial_lines=initial_lines)
        except (LogError, Exception) as exc:  # noqa: BLE001
            raise ToolError(f"cannot subscribe: {exc}") from exc
        rt.record("log_open", host=h.node_id, source=sub.source, sub_id=sub.id)
        return {"sub_id": sub.id, "host": h.alias, "source": sub.source,
                "next": "read with log_read(sub_id, since_seq), then log_close"}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def log_read(
        sub_id: Annotated[str, Field(description="id from log_open")],
        since_seq: Annotated[int, Field(description="next_seq from the previous call, 0 to start", ge=0)] = 0,
        limit: Annotated[int, Field(description="max lines", ge=1, le=2000)] = 300,
    ) -> dict:
        """Read new log lines. dropped_lines > 0 means the ring buffer overflowed."""
        try:
            sub = rt.logs.get(sub_id)
        except LogError as exc:
            raise ToolError(str(exc)) from exc
        rt.resolve(sub.node_id, "fleet.read")   # the id is a handle, not a capability
        return rt.logs.read(sub_id, since_seq=since_seq, limit=limit)

    @mcp.tool
    async def log_close(
        sub_id: Annotated[str, Field(description="subscription to close")],
    ) -> dict:
        """Close a subscription and kill the remote tail/journalctl."""
        rt.require("fleet.read")
        await rt.logs.close(sub_id)
        rt.record("log_close", sub_id=sub_id)
        return {"closed": sub_id}

    # ---------------- port forwarding ----------------
    @mcp.tool
    async def tunnel_open(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        remote_port: Annotated[int, Field(description="remote port", ge=1, le=65535)],
        remote_host: Annotated[str, Field(description="target address as seen from the node")] = "127.0.0.1",
    ) -> dict:
        """Forward a node-local port to the gateway.

        Pair with tunnel_http to reach admin interfaces bound to 127.0.0.1 on the
        node (Grafana, Prometheus, pprof, database HTTP gateways).
        """
        rt.require("fleet.admin")
        h = rt.resolve(host, "fleet.admin")
        try:
            t = await rt.tunnels.open(h, rt.inv.get(), remote_host=remote_host,
                                      remote_port=remote_port)
        except TunnelError as exc:
            raise ToolError(str(exc)) from exc
        rt.record("tunnel_open", host=h.node_id, target=f"{remote_host}:{remote_port}",
                  tunnel_id=t.id)
        return {"tunnel_id": t.id, "host": h.alias,
                "target": f"{remote_host}:{remote_port}",
                "local_port": t.local_port,
                "note": "use tunnel_http; reaped after 1 hour"}

    @mcp.tool
    async def tunnel_http(
        tunnel_id: Annotated[str, Field(description="id from tunnel_open")],
        path: Annotated[str, Field(description="request path")] = "/",
        method: Annotated[str, Field(description="HTTP method")] = "GET",
        headers: Annotated[dict[str, str] | None, Field(description="extra headers")] = None,
        body: Annotated[str | None, Field(description="request body")] = None,
        timeout: Annotated[int, Field(ge=1, le=120)] = 20,
    ) -> dict:
        """Send one HTTP request through an open tunnel."""
        rt.require("fleet.admin")
        try:
            t = rt.tunnels.get(tunnel_id)
        except TunnelError as exc:
            raise ToolError(str(exc)) from exc
        rt.resolve(t.node_id, "fleet.admin")    # the host may have lost it since tunnel_open
        url = f"http://127.0.0.1:{t.local_port}{path if path.startswith('/') else '/' + path}"
        cap = rt.s.max_output_bytes
        try:
            status, hdrs, text, truncated = await _http_capped(
                method.upper(), url, headers=headers or {},
                content=body.encode() if body else None, timeout=timeout, cap=cap)
        except Exception as exc:  # noqa: BLE001
            raise ToolError(f"tunnel request failed: {exc}") from exc
        rt.record("tunnel_http", tunnel_id=tunnel_id, host=t.alias,
                  method=method, path=path, status=status)
        return {"status": status, "headers": hdrs, "body": text, "truncated": truncated}

    @mcp.tool
    async def tunnel_close(
        tunnel_id: Annotated[str, Field(description="tunnel to close")],
    ) -> dict:
        """Close a tunnel."""
        rt.require("fleet.admin")
        await rt.tunnels.close(tunnel_id)
        rt.record("tunnel_close", tunnel_id=tunnel_id)
        return {"closed": tunnel_id}

    # ---------------- audit ----------------
    @mcp.tool(annotations={"readOnlyHint": True})
    async def audit_tail(
        limit: Annotated[int, Field(description="how many records", ge=1, le=500)] = 50,
    ) -> dict:
        """Tail the gateway audit log: who ran what, where, when."""
        rt.require("fleet.admin")
        return {"records": rt.audit.tail(limit)}
