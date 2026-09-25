"""Application wiring: auth, tools, lifespan, health check."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse

from .auth.keys import KeyStore
from .auth.provider import FleetAuthProvider
from .auth.store import Store
from .enroll import EnrollService, EnrollStore
from .runtime import Runtime
from .settings import Settings
from .tools import core as tools_core
from .tools import files as tools_files
from .tools import ops as tools_ops

log = logging.getLogger("vpsmcp")

INSTRUCTIONS = """\
Remote execution gateway for a fleet of VPS hosts. You can run commands, read and
write files, run detached jobs, follow logs, and forward ports.

Conventions:
1. Call list_hosts first. Every tool takes an alias or node_id, never a bare IP.
   Aliases may repeat; use node_id when one is ambiguous.
2. Run host_facts before real work: do not assume root, or a particular distro.
3. exec for work measured in seconds; shell_open + shell_run when you need cwd and
   variables to persist; job_start for anything that may exceed a minute or two.
4. Batch several steps into one exec instead of many round trips, and keep outputs
   small (pipe through grep/tail) - every byte returned costs context.
5. Sweeps use exec_many with tags, not a loop over exec.
6. Config edits: read_file, write_file (auto-backup), validate (nginx -t, sshd -t),
   then reload.
7. High-risk commands are refused until you state the exact command to the user and
   pass confirm=true.
8. Every call is audited. Say what you are about to do before destructive work.
"""


def build(settings: Settings) -> tuple[FastMCP, Runtime]:
    keys = KeyStore(settings.data_dir)
    store = Store(settings.data_dir / "oauth.db")
    rt = Runtime(settings)
    auth = FleetAuthProvider(settings, store, keys, rt.audit)
    enroll_store = EnrollStore(settings.data_dir / "oauth.db")
    enroll = EnrollService(settings, enroll_store, rt.inv, rt.pool, rt.audit)

    @asynccontextmanager
    async def lifespan(_server: FastMCP):
        await rt.start()
        store.gc()
        enroll_store.gc()
        try:
            yield
        finally:
            await rt.stop()

    mcp = FastMCP(
        name="vps-fleet",
        version="1.0",
        instructions=INSTRUCTIONS,
        auth=auth,
        lifespan=lifespan,
    )

    tools_core.register(mcp, rt)
    tools_files.register(mcp, rt)
    tools_ops.register(mcp, rt)

    # Node enrollment: fixed path, no token. Admission is gated in EnrollService._gate.
    @mcp.custom_route("/enroll/install.sh", methods=["GET"])
    async def enroll_script(request: Request):
        return await enroll.get_script(request)

    @mcp.custom_route("/enroll/uninstall.sh", methods=["GET"])
    async def enroll_uninstall(request: Request):
        return await enroll.get_uninstall(request)

    @mcp.custom_route("/enroll/pubkey", methods=["GET"])
    async def enroll_pubkey(request: Request):
        return await enroll.get_pubkey(request)

    @mcp.custom_route("/enroll/register", methods=["POST"])
    async def enroll_register(request: Request):
        return await enroll.register(request)

    @mcp.custom_route("/enroll/deregister", methods=["POST"])
    async def enroll_deregister(request: Request):
        return await enroll.deregister(request)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(_request: Request) -> JSONResponse:
        inv = rt.inv.get()
        return JSONResponse({
            "ok": True,
            "hosts": len(inv.hosts),
            "resource": settings.resource_url,
            "issuer": settings.issuer,
            "clients": list(settings.clients),
            "connections": len(rt.pool.stats()),
        })

    rt.enroll_store = enroll_store
    return mcp, rt
