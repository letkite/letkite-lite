"""End to end: DCR -> login -> consent -> code+PKCE -> token -> MCP call."""
import base64, hashlib, json, re, secrets, sys
import httpx

BASE = "http://127.0.0.1:8848"
RES = "http://localhost:8848/mcp"
RD = "https://claude.ai/api/mcp/auth_callback"

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

c = httpx.Client(follow_redirects=False, timeout=20)

# 1. DCR
r = c.post(f"{BASE}/oauth/register", json={"client_name": "Claude (test)", "redirect_uris": [RD]})
assert r.status_code == 201, (r.status_code, r.text)
client_id = r.json()["client_id"]
print("1. DCR ok ->", client_id[:20], "...")

# 2. authorize -> login page
verifier = secrets.token_urlsafe(48)
challenge = b64u(hashlib.sha256(verifier.encode()).digest())
params = dict(response_type="code", client_id=client_id, redirect_uri=RD,
              state="st4te", code_challenge=challenge, code_challenge_method="S256",
              scope="fleet.read fleet.exec fleet.write fleet.admin offline_access",
              resource=RES)
r = c.get(f"{BASE}/oauth/authorize", params=params)
assert r.status_code == 200 and "Sign in" in r.text, r.status_code
print("2. unauthenticated -> login page")

# 3. wrong password rejected and counted
r = c.post(f"{BASE}/oauth/login", data={**params, "username": "admin", "password": "wrong"})
assert r.status_code == 401, r.status_code
print("3. wrong password rejected")

# 4. correct password
r = c.post(f"{BASE}/oauth/login", data={**params, "username": "admin", "password": "correct-horse-battery"})
assert r.status_code == 303, (r.status_code, r.text[:300])
cookie = r.headers["set-cookie"].split(";")[0]
print("4. login ok, cookie issued")

# 5. consent page
r = c.get(f"{BASE}/oauth/authorize", params=params, headers={"cookie": cookie})
assert r.status_code == 200 and "Authorize" in r.text, r.status_code
assert "claude.ai" in r.text
print("5. consent page ok (shows the claude.ai callback domain)")

# 6. approve -> code
form = {**params, "_action": "approve",
        **{f"scope_{s}": "on" for s in ["fleet.read", "fleet.exec", "fleet.write", "fleet.admin"]}}
r = c.post(f"{BASE}/oauth/authorize", data=form, headers={"cookie": cookie})
assert r.status_code == 302, (r.status_code, r.text[:300])
loc = r.headers["location"]
code = re.search(r"[?&]code=([^&]+)", loc).group(1)
assert "state=st4te" in loc and "iss=" in loc
print("6. approve -> code")

# 7. wrong PKCE rejected
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=client_id, redirect_uri=RD, code_verifier="bogus", resource=RES))
assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text
print("7. wrong code_verifier rejected (code burned)")

# 8. repeat the flow for a real token
r = c.post(f"{BASE}/oauth/authorize", data=form, headers={"cookie": cookie})
code = re.search(r"[?&]code=([^&]+)", r.headers["location"]).group(1)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code,
           client_id=client_id, redirect_uri=RD, code_verifier=verifier, resource=RES))
assert r.status_code == 200, r.text
tok = r.json()
print("8. token ok, scope =", tok["scope"], "| refresh =", bool(tok.get("refresh_token")))

# 9. refresh rotation and reuse detection, on its own token family
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token",
           refresh_token=tok["refresh_token"], client_id=client_id))
assert r.status_code == 200, r.text
tok2 = r.json()
assert tok2["refresh_token"] != tok["refresh_token"]
print("9. refresh rotated (old and new differ)")

r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token",
           refresh_token=tok["refresh_token"], client_id=client_id))
assert r.status_code == 400 and r.json()["error"] == "invalid_grant", r.text
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="refresh_token",
           refresh_token=tok2["refresh_token"], client_id=client_id))
assert r.status_code == 400, r.text
print("10. reused refresh -> whole family revoked")

# 11. code replay rejected, on another family
r = c.post(f"{BASE}/oauth/authorize", data=form, headers={"cookie": cookie})
code3 = re.search(r"[?&]code=([^&]+)", r.headers["location"]).group(1)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code3,
           client_id=client_id, redirect_uri=RD, code_verifier=verifier, resource=RES))
assert r.status_code == 200, r.text
tok3 = r.json()
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code3,
           client_id=client_id, redirect_uri=RD, code_verifier=verifier, resource=RES))
assert r.status_code == 400 and "already used" in r.json()["error_description"], r.text
print("11. code replay rejected")

# 12. wrong resource -> invalid_target
r = c.post(f"{BASE}/oauth/authorize", data=form, headers={"cookie": cookie})
code4 = re.search(r"[?&]code=([^&]+)", r.headers["location"]).group(1)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code4,
           client_id=client_id, redirect_uri=RD, code_verifier=verifier,
           resource="https://evil.example/mcp"))
assert r.status_code == 400 and r.json()["error"] == "invalid_target", r.text
print("12. wrong resource rejected (audience binding works)")

# 13. DCR with a disallowed redirect_uri is rejected
r = c.post(f"{BASE}/oauth/register", json={"client_name": "evil",
           "redirect_uris": ["https://evil.example/cb"]})
assert r.status_code == 400 and r.json()["error"] == "invalid_redirect_uri", r.text
print("13. redirect_uri outside the allowlist rejected")

# 14. the token endpoint requires form-urlencoded
r = c.post(f"{BASE}/oauth/token", json={"grant_type": "refresh_token"})
assert r.status_code == 400 and "x-www-form-urlencoded" in r.json()["error_description"]
print("14. content-type check ok")

# 15. unticking every scope is not consent to all of them
bare = {**params, "_action": "approve"}
r = c.post(f"{BASE}/oauth/authorize", data=bare, headers={"cookie": cookie})
assert r.status_code == 400 and "location" not in r.headers, (r.status_code, r.headers)
assert "at least one" in r.text, r.text[:300]
print("15. approve with no scope ticked -> consent page again, no code")

# 16. what is ticked is exactly what the token carries
r = c.post(f"{BASE}/oauth/authorize", data={**bare, "scope_fleet.read": "on"},
           headers={"cookie": cookie})
code5 = re.search(r"[?&]code=([^&]+)", r.headers["location"]).group(1)
r = c.post(f"{BASE}/oauth/token", data=dict(grant_type="authorization_code", code=code5,
           client_id=client_id, redirect_uri=RD, code_verifier=verifier, resource=RES))
assert r.status_code == 200 and r.json()["scope"] == "fleet.read", r.text
print("16. only fleet.read ticked -> token scope is fleet.read")

import sys, json
json.dump(tok3, open(sys.argv[1], "w"))
print("\naccess token written to", sys.argv[1])
