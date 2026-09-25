"""Client compatibility: Kimi, GLM and anything else that is not Claude.

Covers what differs between clients - the callback host, where they look for
discovery, whether they authenticate, and how loosely they read RFC 8707 - not
the OAuth core, which test_oauth_flow.py already pins down.

Needs the lab from tests/README.md (same env vars; the store is opened directly
to prove that `vpsmcp redirect allow` needs no restart).
"""
import base64, hashlib, os, re, secrets, sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.auth.store import Store  # noqa: E402

BASE = "http://127.0.0.1:8848"
ORIGIN = "http://localhost:8848"          # what VPSMCP_PUBLIC_URL is set to
RES = f"{ORIGIN}/mcp"
USER, PASSWORD = os.environ.get("VPSMCP_ADMIN_USER", "admin"), "correct-horse-battery"
SCOPES = ["fleet.read", "fleet.exec", "fleet.write", "fleet.admin"]


def env_on(name, default):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


# The last two checks assert the opposite behaviour when the compatibility
# switches are on, so the same file covers both settings (see tests/README.md).
RELAXED_PKCE = not env_on("VPSMCP_REQUIRE_PKCE", "1")
LENIENT_BODY = env_on("VPSMCP_LENIENT_TOKEN_BODY", "0")

store = Store(Path(os.environ["VPSMCP_DATA_DIR"]) / "oauth.db")
c = httpx.Client(follow_redirects=False, timeout=20)


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def register(redirect_uri, name, **extra):
    return c.post(f"{BASE}/oauth/register",
                  json={"client_name": name, "redirect_uris": [redirect_uri], **extra})


def authorize_params(client_id, redirect_uri, verifier, *, resource=RES, method="S256"):
    challenge = (b64u(hashlib.sha256(verifier.encode()).digest())
                 if method == "S256" else verifier)
    return dict(response_type="code", client_id=client_id, redirect_uri=redirect_uri,
                state="st4te", code_challenge=challenge, code_challenge_method=method,
                scope=" ".join(SCOPES) + " offline_access", resource=resource)


def login(params):
    r = c.post(f"{BASE}/oauth/login", data={**params, "username": USER, "password": PASSWORD})
    assert r.status_code == 303, (r.status_code, r.text[:200])
    return r.headers["set-cookie"].split(";")[0]


def approve(params, cookie):
    form = {**params, "_action": "approve", **{f"scope_{s}": "on" for s in SCOPES}}
    r = c.post(f"{BASE}/oauth/authorize", data=form, headers={"cookie": cookie})
    assert r.status_code == 302, (r.status_code, r.text[:300])
    return re.search(r"[?&]code=([^&]+)", r.headers["location"]).group(1)


# ---------------------------------------------------------------- discovery
issuers = []
for path in ("/.well-known/oauth-authorization-server",
             "/.well-known/oauth-authorization-server/mcp",
             "/mcp/.well-known/oauth-authorization-server",
             "/.well-known/openid-configuration",
             "/.well-known/openid-configuration/mcp"):
    r = c.get(f"{BASE}{path}")
    assert r.status_code == 200, (path, r.status_code)
    issuers.append(r.json()["issuer"])
assert len(set(issuers)) == 1, issuers
doc = c.get(f"{BASE}/.well-known/oauth-authorization-server").json()
assert doc["registration_endpoint"].endswith("/oauth/register"), doc
print("1. discovery answers on the origin and both RFC 8414 path forms")

# ---------------------------------------------------------------- Kimi
kimi_cb = "https://kimi.com/api/mcp/auth_callback"
r = register(kimi_cb, "Kimi")
assert r.status_code == 201, (r.status_code, r.text)
kimi_id = r.json()["client_id"]
assert "client_secret" not in r.json()
print("2. Kimi callback accepted by the built-in profile")

# the consent page must say whose callback it is before anything is approved
verifier = secrets.token_urlsafe(48)
params = authorize_params(kimi_id, kimi_cb, verifier, resource=ORIGIN)
cookie = login(params)
r = c.get(f"{BASE}/oauth/authorize", params=params, headers={"cookie": cookie})
assert r.status_code == 200 and "Kimi (Moonshot AI)" in r.text, r.text[:400]
assert "kimi.com" in r.text
print("3. consent page names the client behind the callback host")

# resource=<origin> instead of the endpoint: accepted, audience stays the endpoint
code = approve(params, cookie)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=kimi_id, redirect_uri=kimi_cb, code_verifier=verifier, resource=ORIGIN))
assert r.status_code == 200, r.text
tok = r.json()
import jwt  # noqa: E402

claims = jwt.decode(tok["access_token"], options={"verify_signature": False})
assert claims["aud"] == RES, claims
assert tok["scope"] and tok["refresh_token"]
print("4. resource=origin accepted; token audience is still", claims["aud"])

code = approve(params, cookie)      # codes are single use
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=kimi_id, redirect_uri=kimi_cb, code_verifier=verifier,
           resource="https://someone-else.example/mcp"))
assert r.status_code == 400 and r.json()["error"] == "invalid_target", r.text
print("5. a foreign resource is still refused")

# ---------------------------------------------------------------- GLM
glm_cb = "https://chat.z.ai/api/mcp/callback"
r = register(glm_cb, "GLM")
assert r.status_code == 201, (r.status_code, r.text)
glm_id = r.json()["client_id"]
verifier = secrets.token_urlsafe(48)
params = authorize_params(glm_id, glm_cb, verifier)
cookie = login(params)
r = c.get(f"{BASE}/oauth/authorize", params=params, headers={"cookie": cookie})
assert "GLM (Zhipu AI / Z.ai)" in r.text, r.text[:400]
code = approve(params, cookie)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=glm_id, redirect_uri=glm_cb, code_verifier=verifier))
assert r.status_code == 200, r.text
print("6. GLM: register -> consent -> code -> token")

# the token opens an MCP session (the handshake, which is as far as a transport
# test belongs here; test_tools_e2e.py exercises the tools themselves)
access = r.json()["access_token"]
r = c.post(f"{BASE}/mcp", json={
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "glm-test", "version": "1"}}},
    headers={"authorization": f"Bearer {access}",
             "accept": "application/json, text/event-stream",
             "content-type": "application/json"})
assert r.status_code == 200, (r.status_code, r.text[:300])
assert "vps-fleet" in r.text, r.text[:300]
r = c.post(f"{BASE}/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                "params": {"protocolVersion": "2025-06-18",
                                           "capabilities": {}, "clientInfo": {}}},
           headers={"accept": "application/json, text/event-stream",
                    "content-type": "application/json"})
assert r.status_code == 401 and "resource_metadata=" in r.headers.get("www-authenticate", "")
print("7. the GLM token opens an MCP session; without it the endpoint still 401s")

# ---------------------------------------------------------------- unknown client
mystery = "https://some-new-client.example/oauth/mcp"
r = register(mystery, "Mystery")
assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri", r.text
assert "vpsmcp redirect allow" in r.json()["error_description"], r.json()
rows = store.rejected_redirects()
assert any(x["uri"] == mystery for x in rows), rows
print("8. an unknown callback is refused and recorded for the admin")

store.allow_redirect(mystery, note="test")
r = register(mystery, "Mystery")
assert r.status_code == 201, r.text
assert not any(x["uri"] == mystery for x in store.rejected_redirects())
mystery_id = r.json()["client_id"]
verifier = secrets.token_urlsafe(48)
params = authorize_params(mystery_id, mystery, verifier)
cookie = login(params)
r = c.get(f"{BASE}/oauth/authorize", params=params, headers={"cookie": cookie})
assert "belongs to no configured client" in r.text, r.text[:400]
code = approve(params, cookie)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=mystery_id, redirect_uri=mystery, code_verifier=verifier))
assert r.status_code == 200, r.text
print("9. `redirect allow` takes effect with no restart; consent page flags it as manual")

store.disallow_redirect(mystery)
r = register(mystery, "Mystery")
assert r.status_code == 400, r.text
print("10. `redirect deny` takes it away again")

# ---------------------------------------------------------------- confidential client
conf_cb = "https://kimi.moonshot.cn/api/mcp/callback"
r = register(conf_cb, "Confidential", token_endpoint_auth_method="client_secret_basic")
assert r.status_code == 201, r.text
body = r.json()
cid, sec = body["client_id"], body["client_secret"]
assert body["token_endpoint_auth_method"] == "client_secret_basic"
assert body["client_secret_expires_at"] == 0
verifier = secrets.token_urlsafe(48)
params = authorize_params(cid, conf_cb, verifier)
cookie = login(params)
code = approve(params, cookie)
basic = base64.b64encode(f"{cid}:{sec}".encode()).decode()

r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=cid, redirect_uri=conf_cb, code_verifier=verifier))
assert r.status_code == 401 and r.json()["error"] == "invalid_client", r.text
print("11. a registered secret is required once issued")

code = approve(params, cookie)
r = c.post(f"{BASE}/oauth/token", headers={"authorization": f"Basic {basic}"},
           data=dict(grant_type="authorization_code", code=code, redirect_uri=conf_cb,
                     code_verifier=verifier))
assert r.status_code == 200, r.text
refresh = r.json()["refresh_token"]
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token", client_id=cid,
           client_secret=sec, refresh_token=refresh))
assert r.status_code == 200, r.text
print("12. client_secret_basic and client_secret_post both work")

rt2 = r.json()["refresh_token"]
wrong = base64.b64encode(f"{cid}:not-the-secret".encode()).decode()
r = c.post(f"{BASE}/oauth/token", headers={"authorization": f"Basic {wrong}"},
           data=dict(grant_type="refresh_token", refresh_token=rt2))
assert r.status_code == 401 and r.json()["error"] == "invalid_client", r.text
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token", refresh_token=rt2))
assert r.status_code == 401 and r.json()["error"] == "invalid_client", r.text
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token", refresh_token=rt2,
                                            client_id=cid, client_secret=sec))
assert r.status_code == 200, r.text
print("13. a wrong secret is refused, and so is dropping the credentials entirely, "
      "without burning the token")

# ---------------------------------------------------------------- the two switches
assert doc["code_challenge_methods_supported"] == (
    ["S256", "plain"] if RELAXED_PKCE else ["S256"]), doc
verifier = secrets.token_urlsafe(48)
params = authorize_params(kimi_id, kimi_cb, verifier, method="plain")
r = c.get(f"{BASE}/oauth/authorize", params=params, headers={"cookie": cookie})
if RELAXED_PKCE:
    assert r.status_code == 200 and "Authorize" in r.text, r.text[:300]
    code = approve(params, cookie)
    bad = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
                 client_id=kimi_id, redirect_uri=kimi_cb, code_verifier="wrong"))
    assert bad.status_code == 400 and bad.json()["error"] == "invalid_grant", bad.text
    code = approve(params, cookie)
    r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
               client_id=kimi_id, redirect_uri=kimi_cb, code_verifier=verifier))
    assert r.status_code == 200, r.text
    print("14. VPSMCP_REQUIRE_PKCE=0: plain accepted and still verified")
else:
    assert r.status_code == 302 and "error=invalid_request" in r.headers["location"], r.headers
    print("14. PKCE plain refused while VPSMCP_REQUIRE_PKCE is on (the default)")

r = c.post(f"{BASE}/oauth/token", json={"grant_type": "refresh_token"})
assert r.status_code == 400, r.text
if LENIENT_BODY:
    assert r.json()["error"] == "invalid_grant", r.json()
    print("15. VPSMCP_LENIENT_TOKEN_BODY=1: a JSON token request is parsed")
else:
    assert "VPSMCP_LENIENT_TOKEN_BODY" in r.json()["error_description"], r.json()
    print("15. a JSON token request is refused, and says which switch accepts it")

print("\nall client-compat checks passed")
