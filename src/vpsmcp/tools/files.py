"""File tools over SFTP."""
from __future__ import annotations

import base64
import posixpath
import shlex
import stat as statmod
import time
from typing import Annotated

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from ..runtime import Runtime
from ..ssh.runner import run_command


def _fmt_mode(m: int) -> str:
    return statmod.filemode(m)


async def read_capped(sftp, path: str, cap: int) -> bytes:
    """Read at most `cap` bytes; raise if the source has more.

    The size is enforced on the bytes actually returned, never on the SFTP
    server's self-reported stat: a compromised source node can understate its
    size to slip past a stat check and then stream unbounded data into the
    gateway's memory. Reading cap+1 and rejecting len > cap closes that.
    """
    async with sftp.open(path, "rb") as fh:
        data = await fh.read(cap + 1)
    if len(data) > cap:
        raise ToolError(f"source exceeds the {cap}-byte relay limit; "
                        f"use exec with rsync between the hosts")
    return data


def register(mcp: FastMCP, rt: Runtime) -> None:

    @mcp.tool(annotations={"readOnlyHint": True})
    async def list_dir(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        path: Annotated[str, Field(description="absolute path, or relative to workdir")] = ".",
        depth: Annotated[int, Field(description="recursion depth", ge=1, le=4)] = 1,
        show_hidden: Annotated[bool, Field(description="include dotfiles")] = False,
    ) -> dict:
        """List a remote directory: size, mode, mtime. Optionally recursive."""
        h = rt.resolve(host, "fleet.read")
        conn = await rt.conn(h)
        base = path if path.startswith("/") else posixpath.join(h.workdir or ".", path)
        async with conn.start_sftp_client() as sftp:
            try:
                entries = []

                async def walk(p: str, level: int) -> None:
                    for name in sorted(await sftp.listdir(p)):
                        if name in (".", ".."):
                            continue
                        if not show_hidden and name.startswith("."):
                            continue
                        full = posixpath.join(p, name)
                        try:
                            st = await sftp.lstat(full)
                        except Exception:  # noqa: BLE001
                            continue
                        is_dir = statmod.S_ISDIR(st.permissions or 0)
                        entries.append({
                            "path": full,
                            "type": "dir" if is_dir else
                                    ("link" if statmod.S_ISLNK(st.permissions or 0) else "file"),
                            "size": st.size,
                            "mode": _fmt_mode(st.permissions or 0),
                            "mtime": time.strftime("%Y-%m-%d %H:%M",
                                                   time.localtime(st.mtime or 0)),
                        })
                        if is_dir and level < depth and len(entries) < 2000:
                            await walk(full, level + 1)

                await walk(base, 1)
            except Exception as exc:  # noqa: BLE001
                raise ToolError(f"cannot list {base}: {exc}") from exc
        rt.record("list_dir", host=host, path=base, count=len(entries))
        return {"host": host, "path": base, "count": len(entries), "entries": entries[:2000]}

    @mcp.tool(annotations={"readOnlyHint": True})
    async def read_file(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        path: Annotated[str, Field(description="remote file path")],
        max_bytes: Annotated[int, Field(description="max bytes to read", ge=1)] = 200_000,
        offset: Annotated[int, Field(description="byte offset", ge=0)] = 0,
        binary: Annotated[bool, Field(description="return base64 for binary files")] = False,
    ) -> dict:
        """Read a remote file. Text is decoded as UTF-8; set binary=true for base64."""
        h = rt.resolve(host, "fleet.read")
        conn = await rt.conn(h)
        cap = min(max_bytes, rt.s.max_file_bytes)
        async with conn.start_sftp_client() as sftp:
            try:
                st = await sftp.stat(path)
                async with sftp.open(path, "rb") as fh:
                    await fh.seek(offset)
                    data = await fh.read(cap)
            except Exception as exc:  # noqa: BLE001
                raise ToolError(f"cannot read {path}: {exc}") from exc
        total = st.size or 0
        rt.record("read_file", host=host, path=path, bytes=len(data))
        body = (base64.b64encode(data).decode() if binary
                else data.decode("utf-8", "replace"))
        return {
            "host": host, "path": path, "total_bytes": total, "offset": offset,
            "returned_bytes": len(data), "encoding": "base64" if binary else "utf-8",
            "truncated": offset + len(data) < total,
            "next_offset": offset + len(data),
            "content": body,
        }

    @mcp.tool
    async def write_file(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        path: Annotated[str, Field(description="target path; parent dirs are created")],
        content: Annotated[str, Field(description="file content")],
        append: Annotated[bool, Field(description="append instead of overwrite")] = False,
        base64_content: Annotated[bool, Field(description="content is base64-encoded")] = False,
        mode: Annotated[str | None, Field(description="octal mode, e.g. '0644'")] = None,
        backup: Annotated[bool, Field(description="back up before overwriting")] = True,
    ) -> dict:
        """Write a remote file. Overwrites are backed up by default.

        Config edits: read_file, write_file with backup, validate with exec
        (nginx -t, sshd -t), then reload.
        """
        h = rt.resolve(host, "fleet.write")
        conn = await rt.conn(h)
        data = base64.b64decode(content) if base64_content else content.encode("utf-8")
        if len(data) > rt.s.max_file_bytes:
            raise ToolError(f"content exceeds {rt.s.max_file_bytes} bytes")
        backup_path = None
        parent = posixpath.dirname(path) or "."
        async with conn.start_sftp_client() as sftp:
            try:
                await sftp.makedirs(parent, exist_ok=True)
            except Exception:  # noqa: BLE001
                pass
            exists = await sftp.exists(path)
            if exists and backup and not append:
                backup_path = f"{path}.bak-{time.strftime('%Y%m%d%H%M%S')}"
                # The path is client input, so shlex.quote it. repr() is not shell
                # quoting: a name with ' makes it switch to "...", where $(...) runs,
                # and fleet.write would become fleet.exec.
                try:
                    res = await run_command(
                        conn, f"cp -p -- {shlex.quote(path)} {shlex.quote(backup_path)}",
                        timeout=30)
                    if res.exit_code != 0:
                        backup_path = None
                except Exception:  # noqa: BLE001
                    backup_path = None
            try:
                async with sftp.open(path, "ab" if append else "wb") as fh:
                    await fh.write(data)
                if mode:
                    await sftp.chmod(path, int(mode, 8))
            except Exception as exc:  # noqa: BLE001
                raise ToolError(f"cannot write {path}: {exc}") from exc
        rt.record("write_file", host=host, path=path, bytes=len(data),
                  append=append, backup=backup_path)
        return {"host": host, "path": path, "bytes_written": len(data),
                "append": append, "backup": backup_path, "mode": mode}

    @mcp.tool
    async def delete_path(
        host: Annotated[str, Field(description="alias or node_id from list_hosts")],
        path: Annotated[str, Field(description="absolute path to delete")],
        recursive: Annotated[bool, Field(description="recurse into directories")] = False,
        confirm: Annotated[bool, Field(description="must be true to proceed")] = False,
    ) -> dict:
        """Delete a remote path. Requires confirm=true; refuses system directories."""
        if not confirm:
            raise ToolError("delete requires confirm=true; confirm the exact path first")
        norm = posixpath.normpath(path)
        if not norm.startswith("/") or norm.count("/") < 2 or norm in (
            "/", "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot",
            "/home", "/root", "/opt", "/srv",
        ):
            raise ToolError(f"refusing to delete {norm}")
        h = rt.resolve(host, "fleet.write")
        conn = await rt.conn(h)
        flag = "-rf" if recursive else "-f"
        res = await run_command(conn, f"rm {flag} -- {shlex.quote(norm)} && echo removed",
                                timeout=60)
        rt.record("delete_path", host=host, path=norm, recursive=recursive,
                  exit_code=res.exit_code)
        if res.exit_code != 0:
            raise ToolError(f"delete failed: {res.stderr or res.stdout}")
        return {"host": host, "path": norm, "recursive": recursive, "result": "removed"}

    @mcp.tool
    async def copy_between_hosts(
        src_host: Annotated[str, Field(description="source host")],
        src_path: Annotated[str, Field(description="source path")],
        dst_host: Annotated[str, Field(description="destination host")],
        dst_path: Annotated[str, Field(description="destination path")],
    ) -> dict:
        """Copy a file between two hosts through the gateway.

        For large files use exec with rsync/scp directly between the hosts.
        """
        sh = rt.resolve(src_host, "fleet.read")
        dh = rt.resolve(dst_host, "fleet.write")
        sc, dc = await rt.conn(sh), await rt.conn(dh)
        cap = rt.s.max_file_bytes
        async with sc.start_sftp_client() as s_sftp:
            data = await read_capped(s_sftp, src_path, cap)
        async with dc.start_sftp_client() as d_sftp:
            try:
                await d_sftp.makedirs(posixpath.dirname(dst_path) or ".", exist_ok=True)
            except Exception:  # noqa: BLE001
                pass
            async with d_sftp.open(dst_path, "wb") as fh:
                await fh.write(data)
        rt.record("copy_between_hosts", src=f"{src_host}:{src_path}",
                  dst=f"{dst_host}:{dst_path}", bytes=len(data))
        return {"bytes": len(data), "src": f"{src_host}:{src_path}",
                "dst": f"{dst_host}:{dst_path}"}
