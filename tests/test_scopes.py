import asyncio, base64, hashlib, json, os, re, secrets, sys
import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

BASE="http://127.0.0.1:8848"; RES="http://localhost:8848/mcp"; RD="https://claude.ai/api/mcp/auth_callback"
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def body(r):
    d=getattr(r,"data",None)
    return d if d is not None else json.loads(r.content[0].text)

def get_token(scope):
    c=httpx.Client(follow_redirects=False,timeout=20)
    cid=c.post(f"{BASE}/oauth/register",json={"client_name":"scoped","redirect_uris":[RD]}).json()["client_id"]
    v=secrets.token_urlsafe(48); ch=b64u(hashlib.sha256(v.encode()).digest())
    p=dict(response_type="code",client_id=cid,redirect_uri=RD,state="s",
           code_challenge=ch,code_challenge_method="S256",scope=scope,resource=RES)
    r=c.post(f"{BASE}/oauth/login",data={**p,"username":"admin","password":"correct-horse-battery"})
    ck=r.headers["set-cookie"].split(";")[0]
    form={**p,"_action":"approve",**{f"scope_{s}":"on" for s in scope.split()}}
    r=c.post(f"{BASE}/oauth/authorize",data=form,headers={"cookie":ck})
    code=re.search(r"[?&]code=([^&]+)",r.headers["location"]).group(1)
    return c.post(f"{BASE}/oauth/token",data=dict(grant_type="authorization_code",code=code,
        client_id=cid,redirect_uri=RD,code_verifier=v,resource=RES)).json()["access_token"]

async def main():
    tok=get_token("fleet.read")
    async with Client(StreamableHttpTransport(f"{BASE}/mcp",headers={"Authorization":f"Bearer {tok}"})) as c:
        r=body(await c.call_tool("list_hosts",{}))
        assert r["your_scopes"]==["fleet.read"], r["your_scopes"]
        print("read-only token scopes =", r["your_scopes"])
        for tool,args in [("exec",{"host":"lab-1","command":"id"}),
                          ("write_file",{"host":"lab-1","path":"/tmp/x","content":"y"}),
                          ("tunnel_open",{"host":"lab-1","remote_port":22}),
                          ("audit_tail",{})]:
            try:
                await c.call_tool(tool,args); raise SystemExit(f"{tool} was not blocked")
            except Exception as e:
                assert "lacks" in str(e), (tool,e)
                print(f"  ok  {tool} denied: {str(e).strip().splitlines()[0][:60]}")
        r=body(await c.call_tool("read_file",{"host":"lab-1","path":"/etc/hostname"}))
        print("  ok  read_file still works ->", r["content"].strip())

    # A session id is a handle, not a capability: the tools that take one check the
    # caller's scope against the host it belongs to, exactly as the opening tool did.
    full=get_token("fleet.read fleet.exec")
    async with Client(StreamableHttpTransport(f"{BASE}/mcp",headers={"Authorization":f"Bearer {full}"})) as fc, \
               Client(StreamableHttpTransport(f"{BASE}/mcp",headers={"Authorization":f"Bearer {tok}"})) as rc:
        sid=body(await fc.call_tool("shell_open",{"host":"lab-1"}))["session_id"]
        listed=[s["session_id"] for s in body(await rc.call_tool("fleet_status",{}))["shell_sessions"]]
        assert sid in listed, listed
        for tool,args in [("shell_run",{"session_id":sid,"command":"id"}),
                          ("shell_close",{"session_id":sid})]:
            try:
                await rc.call_tool(tool,args); raise SystemExit(f"{tool} on another token's shell was not blocked")
            except Exception as e:
                assert "lacks fleet.exec" in str(e), (tool,e)
                print(f"  ok  read-only {tool} on another token's shell denied")
        r=body(await fc.call_tool("shell_run",{"session_id":sid,"command":"echo alive"}))
        assert r["output"].strip()=="alive", r
        print("  ok  the shell survived and still works for its owner")

        # Taking fleet.exec away from the host stops an open shell, too.
        inv=os.environ.get("VPSMCP_INVENTORY")
        if inv:
            orig=open(inv).read()
            try:
                open(inv,"w").write(orig.replace(
                    "scopes: [fleet.read, fleet.exec, fleet.write, fleet.admin]","scopes: [fleet.read]"))
                try:
                    await fc.call_tool("shell_run",{"session_id":sid,"command":"id"})
                    raise SystemExit("shell_run kept working after the host lost fleet.exec")
                except Exception as e:
                    assert "does not grant fleet.exec" in str(e), e
                print("  ok  host lost fleet.exec -> its open shell is refused")
            finally:
                open(inv,"w").write(orig)
        else:
            print("  --  VPSMCP_INVENTORY not set, host-scope check skipped")
        await fc.call_tool("shell_close",{"session_id":sid})

    ex=get_token("fleet.exec")
    async with Client(StreamableHttpTransport(f"{BASE}/mcp",headers={"Authorization":f"Bearer {ex}"})) as c:
        try:
            await c.call_tool("fleet_status",{}); raise SystemExit("fleet_status without fleet.read was not blocked")
        except Exception as e:
            assert "lacks fleet.read" in str(e), e
        print("  ok  fleet_status needs fleet.read")

    # no token / forged token
    async with httpx.AsyncClient() as h:
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"})
        assert r.status_code==401 and "resource_metadata" in r.headers.get("www-authenticate","")
        print("no token -> 401 + WWW-Authenticate")
        bad=tok[:-6]+"AAAAAA"
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"},
                       headers={"Authorization":f"Bearer {bad}"})
        assert r.status_code==401, r.status_code
        print("tampered signature -> 401")
        import jwt as pyjwt, time
        forged=pyjwt.encode({"iss":"http://localhost:8848","sub":"admin",
            "aud":"https://other.example/mcp","scope":"fleet.admin",
            "exp":int(time.time())+300},"x",algorithm="HS256")
        r=await h.post(f"{BASE}/mcp",json={"jsonrpc":"2.0","id":1,"method":"initialize"},
                       headers={"Authorization":f"Bearer {forged}"})
        assert r.status_code==401, r.status_code
        print("forged audience + HS256 -> 401")
    print("\nscope and token checks passed")

asyncio.run(main())
