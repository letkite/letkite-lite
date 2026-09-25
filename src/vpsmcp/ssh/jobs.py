"""Detached jobs: setsid on the node, state stored under the node's home.

State lives on the node, not in gateway memory, so jobs survive gateway restarts,
dropped connections and even a gateway migration.
"""
from __future__ import annotations

import base64
import shlex
import time
import uuid

from .runner import run_command

JOB_ROOT = "${VPSMCP_JOB_ROOT:-$HOME/.vpsmcp/jobs}"


def _b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


async def start(conn, *, command: str, cwd: str | None, env: dict | None,
                label: str, timeout: int = 30) -> dict:
    job_id = f"job_{time.strftime('%Y%m%d-%H%M%S')}_{uuid.uuid4().hex[:6]}"
    meta = {
        "job_id": job_id,
        "label": label,
        "command": command,
        "cwd": cwd or "",
        "started_at": int(time.time()),
    }
    import json

    script = f"""
set -eu
root="{JOB_ROOT}"
d="$root/{job_id}"
mkdir -p "$d"
printf '%s' {shlex.quote(_b64(command))} > "$d/cmd.b64"
printf '%s' {shlex.quote(json.dumps(meta, ensure_ascii=False))} > "$d/meta.json"
cd {shlex.quote(cwd) if cwd else '"$HOME"'}
setsid bash -c 'base64 -d "$1/cmd.b64" | bash -l; echo $? > "$1/exit_code"' _ "$d" \
    </dev/null >"$d/stdout.log" 2>"$d/stderr.log" &
pid=$!
echo "$pid" > "$d/pid"
( ps -o pgid= -p "$pid" 2>/dev/null || echo "$pid" ) | tr -d ' ' > "$d/pgid"
echo "$d"
"""
    res = await run_command(conn, script, env=env, timeout=timeout, max_bytes=16384)
    if res.exit_code != 0:
        raise RuntimeError(f"job start failed (rc={res.exit_code}): {res.stderr or res.stdout}")
    return {"job_id": job_id, "dir": res.stdout.strip().splitlines()[-1] if res.stdout.strip() else "", **meta}


_STATUS_SCRIPT = """
set -u
root="%(root)s"
for d in "$root"/%(pat)s; do
  [ -d "$d" ] || continue
  id=$(basename "$d")
  pid=$(cat "$d/pid" 2>/dev/null || echo "")
  rc=$(cat "$d/exit_code" 2>/dev/null || echo "")
  state=unknown
  if [ -n "$rc" ]; then
    state=finished
  elif [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    # containers often do not reap children: a killed job lingers as a zombie and
    # kill -0 still succeeds, so check the process state as well
    pstate=$(ps -o state= -p "$pid" 2>/dev/null | tr -d ' ' || echo "")
    if [ "$pstate" = "Z" ]; then state=aborted; else state=running; fi
  elif [ -n "$pid" ]; then
    state=aborted
  fi
  so=$(wc -c < "$d/stdout.log" 2>/dev/null || echo 0)
  se=$(wc -c < "$d/stderr.log" 2>/dev/null || echo 0)
  meta=$(cat "$d/meta.json" 2>/dev/null || echo '{}')
  printf '%%s\\t%%s\\t%%s\\t%%s\\t%%s\\t%%s\\n' "$id" "$state" "${rc:--}" "$so" "$se" "$meta"
done
"""


async def status(conn, *, job_id: str | None = None, timeout: int = 20, max_bytes: int = 200_000) -> list[dict]:
    import json

    pat = shlex.quote(job_id) if job_id else "*"
    script = _STATUS_SCRIPT % {"root": JOB_ROOT, "pat": pat}
    res = await run_command(conn, script, timeout=timeout, max_bytes=max_bytes)
    out = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        jid, state, rc, so, se, meta = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        try:
            m = json.loads(meta)
        except ValueError:
            m = {}
        out.append({
            "job_id": jid,
            "state": state,
            "exit_code": None if rc == "-" else int(rc),
            "stdout_bytes": int(so or 0),
            "stderr_bytes": int(se or 0),
            "label": m.get("label", ""),
            "command": m.get("command", ""),
            "started_at": m.get("started_at"),
        })
    return sorted(out, key=lambda j: j["job_id"], reverse=True)


async def output(conn, *, job_id: str, stream: str = "stdout", offset: int = 0,
                 max_bytes: int = 64_000, tail: bool = False, timeout: int = 20) -> dict:
    name = "stderr.log" if stream == "stderr" else "stdout.log"
    f = f'"{JOB_ROOT}"/{shlex.quote(job_id)}/{name}'
    if tail:
        script = f"size=$(wc -c < {f} 2>/dev/null || echo 0); tail -c {int(max_bytes)} {f} 2>/dev/null; printf '\\n__SIZE__%s\\n' \"$size\""
    else:
        script = (
            f"size=$(wc -c < {f} 2>/dev/null || echo 0); "
            f"tail -c +{int(offset) + 1} {f} 2>/dev/null | head -c {int(max_bytes)}; "
            f"printf '\\n__SIZE__%s\\n' \"$size\""
        )
    res = await run_command(conn, script, timeout=timeout, max_bytes=max_bytes + 4096)
    body, _, sz = res.stdout.rpartition("__SIZE__")
    try:
        total = int(sz.strip())
    except ValueError:
        total = 0
    body = body.rstrip("\n")
    return {
        "job_id": job_id,
        "stream": stream,
        "offset": offset,
        "returned_bytes": len(body.encode()),
        "total_bytes": total,
        "next_offset": total if tail else min(offset + len(body.encode()), total),
        "content": body,
    }


async def kill(conn, *, job_id: str, signal: str = "TERM", timeout: int = 20) -> dict:
    sig = signal.upper().lstrip("-")
    if sig not in ("TERM", "KILL", "INT", "HUP", "USR1", "USR2"):
        raise ValueError(f"unsupported signal: {signal}")
    script = f"""
set -u
d="{JOB_ROOT}"/{shlex.quote(job_id)}
pgid=$(cat "$d/pgid" 2>/dev/null || echo "")
pid=$(cat "$d/pid" 2>/dev/null || echo "")
if [ -n "$pgid" ] && kill -{sig} -- -"$pgid" 2>/dev/null; then echo "killed pgid $pgid"
elif [ -n "$pid" ] && kill -{sig} "$pid" 2>/dev/null; then echo "killed pid $pid"
else echo "no live process"; fi
"""
    res = await run_command(conn, script, timeout=timeout, max_bytes=8192)
    return {"job_id": job_id, "signal": sig, "result": res.stdout.strip(), "exit_code": res.exit_code}


async def purge(conn, *, job_id: str, timeout: int = 20) -> dict:
    script = f"""
set -u
d="{JOB_ROOT}"/{shlex.quote(job_id)}
case "$d" in *"/.vpsmcp/jobs/"*) ;; *) echo "refuse"; exit 1;; esac
[ -f "$d/exit_code" ] || {{ echo "still running"; exit 2; }}
rm -rf -- "$d" && echo removed
"""
    res = await run_command(conn, script, timeout=timeout, max_bytes=4096)
    return {"job_id": job_id, "result": res.stdout.strip(), "exit_code": res.exit_code}
