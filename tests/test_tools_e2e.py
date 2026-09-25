import asyncio, json, sys, time
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

TOK = json.load(open(sys.argv[1]))["access_token"]
URL = "http://127.0.0.1:8848/mcp"

def body(r):
    d = getattr(r, "data", None)
    if d is not None: return d
    return json.loads(r.content[0].text)

async def main():
    t = StreamableHttpTransport(URL, headers={"Authorization": f"Bearer {TOK}"})
    async with Client(t) as c:
        tools = await c.list_tools()
        print(f"tools = {len(tools)}")
        print("  " + ", ".join(sorted(x.name for x in tools)))

        r = body(await c.call_tool("list_hosts", {}))
        lab = next((h for h in r["hosts"] if h["alias"] == "lab-1"), None)
        assert lab, r
        print("\n[list_hosts] ok ->", r["count"], "hosts,", lab["alias"], lab["tags"])

        r = body(await c.call_tool("host_facts", {"host": "lab-1"}))
        print("[host_facts] ok ->", r["facts"].get("os"), "|", r["facts"].get("whoami"))

        r = body(await c.call_tool("exec", {"host": "lab-1", "command": "echo hi; echo err >&2; pwd"}))
        assert r["exit_code"] == 0 and "hi" in r["stdout"] and "err" in r["stderr"], r
        assert r["stdout"].strip().endswith("/tmp"), r
        print("[exec] ok -> rc=0, cwd defaults to the inventory workdir (/tmp)")

        r = body(await c.call_tool("exec", {"host": "lab-1", "command": "exit 42"}))
        assert r["exit_code"] == 42
        print("[exec] exit code passed through")

        r = body(await c.call_tool("exec", {"host": "lab-1", "command": "sleep 30", "timeout": 2}))
        assert r.get("timed_out") and r["exit_code"] == 124, r
        print("[exec] timeout killed the process ->", r["duration_ms"], "ms")

        r = body(await c.call_tool("exec", {"host": "lab-1",
              "command": "for i in $(seq 1 200000); do echo 0123456789; done"}))
        assert r.get("stdout_truncated") and len(r["stdout"]) <= 256_000 + 16, len(r["stdout"])
        print("[exec] output truncated ->", len(r["stdout"]), "bytes")

        # guardrails
        try:
            await c.call_tool("exec", {"host": "lab-1", "command": "rm -rf /"})
            raise SystemExit("guardrail did not block rm -rf /")
        except Exception as e:
            assert "guardrail" in str(e), e
        print("[guardrail] rm -rf / refused")
        try:
            await c.call_tool("exec", {"host": "lab-1", "command": "systemctl stop nginx"})
            raise SystemExit("confirm was not required")
        except Exception as e:
            assert "confirm=true" in str(e), e
        print("[guardrail] systemctl stop requires confirm")
        r = body(await c.call_tool("exec", {"host": "lab-1",
              "command": "echo 'systemctl stop nginx (drill)'", "confirm": True}))
        print("[guardrail] confirm=true allows it")

        # fan-out
        r = body(await c.call_tool("exec_many", {"command": "hostname", "tags": ["lab"]}))
        assert r["total"] == 1 and not r["failed"], r
        print("[exec_many] ok ->", r["total"], "hosts")

        # persistent shell
        s = body(await c.call_tool("shell_open", {"host": "lab-1", "cwd": "/etc"}))
        sid = s["session_id"]
        r = body(await c.call_tool("shell_run", {"session_id": sid, "command": "MYVAR=42; cd /var; pwd"}))
        assert r["cwd"] == "/var", r
        r = body(await c.call_tool("shell_run", {"session_id": sid, "command": "echo $MYVAR; pwd"}))
        assert "42" in r["output"] and r["cwd"] == "/var", r
        print("[shell] state persists -> cwd=/var, MYVAR=42")
        await c.call_tool("shell_close", {"session_id": sid})
        print("[shell] closed")

        # files
        r = body(await c.call_tool("write_file", {"host": "lab-1", "path": "/tmp/vt/a.conf",
              "content": "key = old\n", "mode": "0640"}))
        print("[write_file] created ->", r["bytes_written"], "bytes")
        r = body(await c.call_tool("write_file", {"host": "lab-1", "path": "/tmp/vt/a.conf",
              "content": "key = new\n"}))
        assert r["backup"], r
        print("[write_file] overwrite made a backup ->", r["backup"].split("/")[-1])
        r = body(await c.call_tool("read_file", {"host": "lab-1", "path": "/tmp/vt/a.conf"}))
        assert r["content"] == "key = new\n", r
        print("[read_file] ok")
        r = body(await c.call_tool("read_file", {"host": "lab-1", "path": "/tmp/vt/a.conf",
              "max_bytes": 4}))
        assert r["truncated"] and r["next_offset"] == 4, r
        print("[read_file] chunked read -> next_offset=", r["next_offset"])
        r = body(await c.call_tool("list_dir", {"host": "lab-1", "path": "/tmp/vt"}))
        assert r["count"] >= 2, r
        print("[list_dir] ok ->", r["count"], "entries")
        try:
            await c.call_tool("delete_path", {"host": "lab-1", "path": "/etc", "confirm": True})
            raise SystemExit("dangerous delete was not blocked")
        except Exception as e:
            assert "refusing to delete" in str(e), e
        print("[delete_path] /etc refused")
        r = body(await c.call_tool("delete_path", {"host": "lab-1", "path": "/tmp/vt",
              "recursive": True, "confirm": True}))
        print("[delete_path] normal delete ok")

        # A path is data, never shell: a quote plus $(...) in a file name must reach
        # cp/rm as one literal argument. fleet.write must not become fleet.exec.
        probe = "test -e ~/vq-pwned && echo PWNED || echo clean"
        body(await c.call_tool("exec", {"host": "lab-1", "command": "rm -rf ~/vq-pwned /tmp/vq",
              "confirm": True}))
        odd = "/tmp/vq/it's $(touch vq-pwned).conf"
        body(await c.call_tool("write_file", {"host": "lab-1", "path": odd, "content": "v1\n"}))
        r = body(await c.call_tool("write_file", {"host": "lab-1", "path": odd, "content": "v2\n"}))
        assert r["backup"], r
        assert body(await c.call_tool("exec", {"host": "lab-1", "command": probe}))["stdout"].strip() == "clean"
        r = body(await c.call_tool("read_file", {"host": "lab-1", "path": r["backup"]}))
        assert r["content"] == "v1\n", r
        print("[write_file] quote + $(...) in the path: literal backup, nothing executed")
        body(await c.call_tool("delete_path", {"host": "lab-1", "path": odd, "confirm": True}))
        r = body(await c.call_tool("exec", {"host": "lab-1",
              "command": f"{probe}; ls -A /tmp/vq | wc -l"}))
        assert r["stdout"].split() == ["clean", "1"], r   # the file is gone, its backup stays
        print("[delete_path] quote + $(...) in the path: deleted literally, nothing executed")
        body(await c.call_tool("delete_path", {"host": "lab-1", "path": "/tmp/vq",
              "recursive": True, "confirm": True}))

        # jobs
        j = body(await c.call_tool("job_start", {"host": "lab-1", "label": "counter",
              "command": "for i in $(seq 1 5); do echo line-$i; sleep 0.4; done; echo done >&2; exit 7"}))
        jid = j["job_id"]
        print("[job_start] ok ->", jid)
        await asyncio.sleep(1.0)
        st = body(await c.call_tool("job_status", {"host": "lab-1", "job_id": jid}))
        assert st["jobs"][0]["state"] == "running", st
        o1 = body(await c.call_tool("job_output", {"host": "lab-1", "job_id": jid}))
        print("[job_output] incremental read while running ->", repr(o1["content"][:24]), "next_offset=", o1["next_offset"])
        for _ in range(30):
            st = body(await c.call_tool("job_status", {"host": "lab-1", "job_id": jid}))
            if st["jobs"][0]["state"] == "finished": break
            await asyncio.sleep(0.4)
        assert st["jobs"][0]["exit_code"] == 7, st
        print("[job_status] finished -> exit_code=7")
        o2 = body(await c.call_tool("job_output", {"host": "lab-1", "job_id": jid,
              "offset": o1["next_offset"]}))
        assert "line-5" in o2["content"], o2
        print("[job_output] resumed without duplicates")
        e = body(await c.call_tool("job_output", {"host": "lab-1", "job_id": jid, "stream": "stderr"}))
        assert "done" in e["content"]
        print("[job_output] stderr ok")
        # kill
        j2 = body(await c.call_tool("job_start", {"host": "lab-1", "command": "sleep 300"}))
        await asyncio.sleep(0.6)
        k = body(await c.call_tool("job_kill", {"host": "lab-1", "job_id": j2["job_id"]}))
        await asyncio.sleep(0.6)
        st = body(await c.call_tool("job_status", {"host": "lab-1", "job_id": j2["job_id"]}))
        assert st["jobs"][0]["state"] != "running", st
        print("[job_kill] ok ->", k["result"], "-> state =", st["jobs"][0]["state"])
        body(await c.call_tool("job_purge", {"host": "lab-1", "job_id": jid}))
        body(await c.call_tool("job_purge", {"host": "lab-1", "job_id": j2["job_id"]}))
        print("[job_purge] ok")

        # log subscription
        body(await c.call_tool("exec", {"host": "lab-1", "command": "mkdir -p /tmp/vl && : > /tmp/vl/app.log"}))
        sub = body(await c.call_tool("log_open", {"host": "lab-1", "path": "/tmp/vl/app.log",
              "initial_lines": 0}))
        await asyncio.sleep(0.8)
        body(await c.call_tool("exec", {"host": "lab-1",
              "command": "for i in 1 2 3; do echo \"ERROR boom $i\" >> /tmp/vl/app.log; done"}))
        await asyncio.sleep(1.2)
        lr = body(await c.call_tool("log_read", {"sub_id": sub["sub_id"], "since_seq": 0}))
        assert len(lr["lines"]) == 3, lr
        print("[log_open/read] ok ->", [l["text"] for l in lr["lines"]])
        body(await c.call_tool("exec", {"host": "lab-1", "command": "echo 'ERROR again' >> /tmp/vl/app.log"}))
        await asyncio.sleep(1.0)
        lr2 = body(await c.call_tool("log_read", {"sub_id": sub["sub_id"], "since_seq": lr["next_seq"]}))
        assert len(lr2["lines"]) == 1, lr2
        print("[log_read] cursor ok ->", lr2["lines"][0]["text"])
        await c.call_tool("log_close", {"sub_id": sub["sub_id"]})
        print("[log_close] ok")

        # tunnel + HTTP
        body(await c.call_tool("job_start", {"host": "lab-1", "label": "httpd",
              "command": "cd /tmp && python3 -m http.server 18099 --bind 127.0.0.1"}))
        await asyncio.sleep(1.5)
        tun = body(await c.call_tool("tunnel_open", {"host": "lab-1", "remote_port": 18099}))
        print("[tunnel_open] ok -> local port", tun["local_port"])
        h = body(await c.call_tool("tunnel_http", {"tunnel_id": tun["tunnel_id"], "path": "/"}))
        assert h["status"] == 200, h
        print("[tunnel_http] ok -> HTTP", h["status"], "body", len(h["body"]), "bytes")
        await c.call_tool("tunnel_close", {"tunnel_id": tun["tunnel_id"]})
        body(await c.call_tool("exec", {"host": "lab-1", "command": "pkill -f 'http.server 18099' || true"}))

        # status and audit
        fs = body(await c.call_tool("fleet_status", {}))
        print("[fleet_status] ok -> connections", len(fs["connections"]), "shells", len(fs["shell_sessions"]))
        au = body(await c.call_tool("audit_tail", {"limit": 5}))
        assert au["records"], au
        print("[audit_tail] ok -> last record:", au["records"][-1]["tool"])

    print("\nall tool tests passed")

asyncio.run(main())
