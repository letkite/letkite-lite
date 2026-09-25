"""The gateway works as a node but cannot read the gateway's own secrets."""
import asyncio, json, sys
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

TOK = json.load(open(sys.argv[1]))["access_token"]
def body(r):
    d = getattr(r, "data", None)
    return d if d is not None else json.loads(r.content[0].text)

async def main():
    t = StreamableHttpTransport("http://127.0.0.1:8848/mcp",
                                headers={"Authorization": f"Bearer {TOK}"})
    async with Client(t) as c:
        hs = body(await c.call_tool("list_hosts", {}))
        print("inventory:", [(h["alias"], h["user"], h["tags"]) for h in hs["hosts"]])

        f = body(await c.call_tool("host_facts", {"host": "gw"}))
        print("\n[gw host_facts]", f["facts"].get("whoami"), "|", f["facts"].get("os"),
              "| disk", f["facts"].get("disk"))

        r = body(await c.call_tool("exec", {"host": "gw",
              "command": "id -un; hostname; uptime -p"}))
        print("[gw exec] rc=%d" % r["exit_code"], "->", " / ".join(r["stdout"].split("\n")[:2]))

        print("\n--- privilege probes (all must fail) ---")
        probes = [
            ("fleet private key", "cat /etc/vpsmcp/id_ed25519"),
            ("inventory",         "cat /etc/vpsmcp/hosts.yaml"),
            ("password hash",     "cat /etc/vpsmcp/vpsmcp.env"),
            ("oauth.db",          "cat /var/lib/vpsmcp/oauth.db"),
            ("audit log",         "cat /var/lib/vpsmcp/audit.jsonl"),
            ("venv",              "ls /opt/vpsmcp/.venv/bin"),
        ]
        for name, cmd in probes:
            r = body(await c.call_tool("exec", {"host": "gw", "command": cmd}))
            ok = r["exit_code"] != 0 and "Permission denied" in (r["stderr"] + r["stdout"])
            print(f"  {'denied ' if ok else 'LEAKED!'}  {name:<20} rc={r['exit_code']}  {r['stderr'].strip()[:48]}")
            assert ok, (name, r)

        try:
            await c.call_tool("exec", {"host": "gw",
                  "command": "systemctl restart vpsmcp", "sudo": True})
            raise SystemExit("sudo was not blocked")
        except Exception as e:
            assert "does not allow sudo" in str(e), e
            print("  denied   sudo restart of its own service ->", str(e).strip().splitlines()[0][:44])
        r = body(await c.call_tool("exec", {"host": "gw",
              "command": "systemctl restart vpsmcp"}))
        print("  denied   plain systemctl rc=%d" % r["exit_code"])

        print("\n--- normal use of the gateway node ---")
        r = body(await c.call_tool("exec", {"host": "gw",
              "command": "df -h / | tail -1; free -m | awk '/Mem:/{print \"mem \"$3\"/\"$2}'; ss -ltn 2>/dev/null | wc -l"}))
        print("  resources:", " | ".join(r["stdout"].split("\n")[:3]))
        r = body(await c.call_tool("exec_many", {"command": "hostname; uptime -p", "tags": ["gateway", "lab"]}))
        print("  fan-out: %d hosts, failed %s" % (r["total"], r["failed"] or "none"))

    print("\ngateway-as-node checks passed")

asyncio.run(main())
