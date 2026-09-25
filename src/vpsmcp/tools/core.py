"""Tools: inventory, execution, persistent shells."""
from __future__ import annotations

import asyncio
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from ..policy import PolicyError, check_command
from ..runtime import Runtime
from ..ssh.runner import run_command
from ..ssh.session import SessionError

FACTS = (
    "printf 'hostname\\t%s\\n' \"$(hostname -f 2>/dev/null || hostname)\"; "
    "printf 'os\\t%s\\n' \"$( (. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\") || uname -s)\"; "
    "printf 'kernel\\t%s\\n' \"$(uname -r)\"; "
    "printf 'arch\\t%s\\n' \"$(uname -m)\"; "
    "printf 'uptime\\t%s\\n' \"$(uptime -p 2>/dev/null || uptime)\"; "
    "printf 'load\\t%s\\n' \"$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)\"; "
    "printf 'cpus\\t%s\\n' \"$(nproc 2>/dev/null)\"; "
    "printf 'mem\\t%s\\n' \"$(free -m 2>/dev/null | awk '/Mem:/{print $3\"/\"$2\" MiB\"}')\"; "
    "printf 'disk\\t%s\\n' \"$(df -h / 2>/dev/null | awk 'NR==2{print $3\"/\"$2\" (\"$5\")\"}')\"; "
    "printf 'whoami\\t%s\\n' \"$(id -un)@$(id -gn)\"; "
    "printf 'docker\\t%s\\n' \"$(command -v docker >/dev/null && docker ps -q 2>/dev/null | wc -l || echo n/a)\""
)

HOST_ARG = "alias or node_id from list_hosts"


def register(mcp: FastMCP, rt: Runtime) -> None:

    @mcp.tool(annotations={"readOnlyHint": True})
    async def list_hosts(
        tags: Annotated[list[str] | None, Field(description="filter by tag")] = None,
    ) -> dict:
        """List every host in the fleet: node_id, alias, address, user, tags, scopes, notes.

        Entry point for every other tool. Their `host` argument takes an alias or a
        node_id, never a bare IP. Aliases may repeat; if one is ambiguous the call
        fails and lists the candidate node_ids.
        """
        inv = rt.inv.get()
        want = set(tags or [])
        out = []
        for h in sorted(inv.hosts.values(), key=lambda x: (x.alias, x.address)):
            if want and not want & set(h.tags):
                continue
            out.append({
                "node_id": h.node_id, "alias": h.alias, "address": h.address,
                "user": h.user, "port": h.port, "tags": list(h.tags),
                "scopes": list(h.scopes), "workdir": h.workdir, "sudo": h.sudo,
                "jump": h.jump, "notes": h.notes,
            })
        return {"count": len(out), "hosts": out,
                "all_tags": sorted({t for h in inv.hosts.values() for t in h.tags}),
                "your_scopes": sorted(rt.scopes())}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def host_facts(
        host: Annotated[str, Field(description=HOST_ARG)],
    ) -> dict:
        """Collect basic facts: distro, kernel, load, memory, disk, current user, containers.

        Run this before doing real work on a host so you do not send Debian commands
        to Alpine, or assume you are root.
        """
        h = rt.resolve(host, "fleet.read")
        conn = await rt.conn(h)
        res = await run_command(conn, FACTS, timeout=30, max_bytes=16384)
        facts: dict[str, Any] = {}
        for line in res.stdout.splitlines():
            k, _, v = line.partition("\t")
            if k:
                facts[k] = v.strip()
        rt.record("host_facts", host=h.node_id)
        return {"host": h.alias, "node_id": h.node_id, "facts": facts,
                "stderr": res.stderr[:2000] or None}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def fleet_status() -> dict:
        """Gateway internals: SSH pool, shell sessions, log subscriptions, tunnels."""
        rt.require("fleet.read")
        return {
            "connections": rt.pool.stats(),
            "shell_sessions": rt.sessions.list(),
            "log_subscriptions": rt.logs.list(),
            "tunnels": rt.tunnels.list(),
            "read_only": rt.s.read_only,
            "guardrails": rt.s.enable_guardrails,
        }

    @mcp.tool
    async def exec(
        host: Annotated[str, Field(description=HOST_ARG)],
        command: Annotated[str, Field(description="bash command, run in a login shell")],
        cwd: Annotated[str | None, Field(description="working directory")] = None,
        env: Annotated[dict[str, str] | None, Field(description="extra environment")] = None,
        timeout: Annotated[int | None, Field(description="seconds", ge=1)] = None,
        sudo: Annotated[bool, Field(description="run via sudo -n (host must allow it)")] = False,
        confirm: Annotated[bool, Field(description="confirm a high-risk command")] = False,
    ) -> dict:
        """Run one command on one host and wait for the result.

        For work measured in seconds to a couple of minutes. Anything longer
        (builds, backups, large transfers) belongs in job_start, which survives
        SSH disconnects. Each call is a fresh process: cd and export do not carry
        over. Use shell_open when you need that state.

        Batch several steps into one command rather than making many round trips.
        """
        h = rt.resolve(host, "fleet.exec")
        if sudo and not h.sudo:
            raise ToolError(f"host {h.alias} does not allow sudo")
        try:
            warn = check_command(command, confirm=confirm, enabled=rt.s.enable_guardrails)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc
        conn = await rt.conn(h)
        res = await run_command(
            conn, command, cwd=cwd or h.workdir, env={**h.env, **(env or {})},
            sudo=sudo, timeout=rt.clamp_timeout(timeout), max_bytes=rt.s.max_output_bytes,
        )
        rt.record("exec", host=h.node_id, command=command, exit_code=res.exit_code,
                  duration_ms=res.duration_ms, sudo=sudo, warnings=warn)
        out = {"host": h.alias, **res.as_dict()}
        if warn:
            out["guardrail_warnings"] = warn
        return out

    @mcp.tool
    async def exec_many(
        command: Annotated[str, Field(description="command to run on every target")],
        hosts: Annotated[list[str] | None, Field(description="aliases or node_ids")] = None,
        tags: Annotated[list[str] | None, Field(description="select by tag instead")] = None,
        timeout: Annotated[int | None, Field(ge=1)] = None,
        concurrency: Annotated[int, Field(ge=1, le=32)] = 5,
        confirm: Annotated[bool, Field(description="confirm a high-risk command")] = False,
    ) -> dict:
        """Run the same command on several hosts concurrently.

        Use this for sweeps instead of looping over exec. One host failing does not
        stop the others.
        """
        targets = rt.resolve_many(hosts, tags, "fleet.exec")
        if len(targets) > rt.s.max_fanout:
            raise ToolError(f"fan-out limit is {rt.s.max_fanout}, got {len(targets)}")
        try:
            check_command(command, confirm=confirm, enabled=rt.s.enable_guardrails)
        except PolicyError as exc:
            raise ToolError(str(exc)) from exc
        sem = asyncio.Semaphore(min(concurrency, rt.s.max_fanout))
        t = rt.clamp_timeout(timeout)

        async def one(h) -> dict:
            async with sem:
                try:
                    conn = await rt.conn(h)
                    res = await run_command(conn, command, cwd=h.workdir, env=h.env,
                                            timeout=t, max_bytes=rt.s.max_output_bytes // 2)
                    return {"host": h.alias, "node_id": h.node_id,
                            "ok": res.exit_code == 0, **res.as_dict()}
                except Exception as exc:  # noqa: BLE001
                    return {"host": h.alias, "node_id": h.node_id, "ok": False,
                            "error": str(exc)}

        results = await asyncio.gather(*(one(h) for h in targets))
        rt.record("exec_many", hosts=[h.node_id for h in targets], command=command,
                  failures=[r["host"] for r in results if not r.get("ok")])
        return {"command": command, "total": len(results),
                "failed": [r["host"] for r in results if not r.get("ok")],
                "results": list(results)}

    # ---------------- persistent shell ----------------
    @mcp.tool
    async def shell_open(
        host: Annotated[str, Field(description=HOST_ARG)],
        cwd: Annotated[str | None, Field(description="initial working directory")] = None,
        env: Annotated[dict[str, str] | None, Field(description="initial environment")] = None,
    ) -> dict:
        """Open a persistent bash session; cwd, variables and functions persist.

        For continuous debugging: cd somewhere, source an env, activate a venv, then
        keep working. Close it with shell_close; idle sessions are reaped after 30 min.
        """
        h = rt.resolve(host, "fleet.exec")
        try:
            sess = await rt.sessions.open(h, rt.inv.get(), cwd=cwd or h.workdir,
                                          env={**h.env, **(env or {})})
        except SessionError as exc:
            raise ToolError(str(exc)) from exc
        rt.record("shell_open", host=h.node_id, session_id=sess.id)
        return {"session_id": sess.id, "host": h.alias,
                "note": "stdout and stderr are merged in a session"}

    @mcp.tool
    async def shell_run(
        session_id: Annotated[str, Field(description="id from shell_open")],
        command: Annotated[str, Field(description="command to run in that session")],
        timeout: Annotated[int | None, Field(ge=1)] = None,
        confirm: Annotated[bool, Field(description="confirm a high-risk command")] = False,
    ) -> dict:
        """Run a command in an open session; returns exit code, merged output and cwd.

        A command inside a session cannot be interrupted on its own: a timeout
        destroys the session. Use job_start for long work.
        """
        try:
            sess = rt.sessions.get(session_id)
        except SessionError as exc:
            raise ToolError(str(exc)) from exc
        # The id is a handle, not a capability: check the caller against the host
        # the shell runs on, as exec does. Otherwise any token that learns the id
        # (fleet_status lists it) drives a shell someone else opened, and a host
        # whose fleet.exec was withdrawn keeps running commands.
        rt.resolve(sess.node_id, "fleet.exec")
        try:
            check_command(command, confirm=confirm, enabled=rt.s.enable_guardrails)
            out = await sess.run(command, timeout=rt.clamp_timeout(timeout),
                                 max_bytes=rt.s.max_output_bytes)
        except (PolicyError, SessionError) as exc:
            raise ToolError(str(exc)) from exc
        rt.record("shell_run", session_id=session_id, host=sess.alias,
                  command=command, exit_code=out["exit_code"])
        return {"host": sess.alias, **out}

    @mcp.tool
    async def shell_close(
        session_id: Annotated[str, Field(description="session to close")],
    ) -> dict:
        """Close a persistent shell session."""
        rt.require("fleet.exec")
        await rt.sessions.close(session_id)
        rt.record("shell_close", session_id=session_id)
        return {"closed": session_id}
