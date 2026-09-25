"""Built-in OAuth 2.1 authorization server.

authorization_code + PKCE(S256) + refresh_token + DCR/CIMD: the subset every MCP
client needs. Claude, Kimi and GLM all take this path; they differ only in the
callback they return to (see clients.py) and in how strictly they follow the
spec, which is what the rest of this module accounts for.

Client constraints that must be honoured:
  - redirect_uri comes from an enabled client profile, VPSMCP_ALLOWED_REDIRECTS or
    `vpsmcp redirect allow`; Claude Code uses an RFC 8252 loopback address with a
    random port, so compare ignoring the port
  - PKCE S256 on every request; metadata must advertise code_challenge_methods_supported
  - /token takes application/x-www-form-urlencoded, /register takes application/json
  - `resource` may be the endpoint or the origin: clients disagree, and either way
    the token audience stays this server's resource URL
  - a confidential client gets a client_secret at registration and must present it
  - discovery/registration/token endpoints must answer within 10s (refresh 30s)
  - a failed refresh must return the RFC 6749 code invalid_grant
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import ipaddress
import json
import secrets
import shlex
import socket
import time
from urllib.parse import unquote, urlencode, urlparse, urlunparse

import httpx
import jwt
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from ..netutil import client_ip
from ..settings import SCOPES, Settings
from .clients import enabled_profiles, guess_client, profile_for_redirect
from .keys import KeyStore, verify_password
from .store import Store, sha

COOKIE = "vpsmcp_sid"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _err(code: str, desc: str, status: int = 400) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": desc}, status_code=status,
                        headers={"Cache-Control": "no-store"})


def _norm_scopes(requested: str | None, allowed: tuple[str, ...]) -> str:
    want = [s for s in (requested or "").split() if s]
    if not want:
        return " ".join(allowed)
    keep = [s for s in want if s in allowed or s == "offline_access"]
    return " ".join(dict.fromkeys(keep)) or " ".join(allowed)


def redirect_allowed(uri: str, prefixes: tuple[str, ...]) -> bool:
    """Exact prefix match for https; loopback compares without the port (RFC 8252 7.3)."""
    try:
        u = urlparse(uri)
    except ValueError:
        return False
    if u.scheme == "http":
        if u.hostname not in LOOPBACK_HOSTS:
            return False
        bare = urlunparse(("http", u.hostname, u.path or "/", "", "", ""))
        for p in prefixes:
            pu = urlparse(p)
            if pu.scheme == "http" and pu.hostname in LOOPBACK_HOSTS:
                if (pu.path or "/") == (u.path or "/"):
                    return True
        return bare in prefixes
    if u.scheme != "https":
        return False
    return any(uri == p or uri.startswith(p) for p in prefixes)


def _is_public_host(hostname: str) -> bool:
    """SSRF guard for CIMD fetches: reject private, loopback and link-local."""
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True


class AuthorizationServer:
    def __init__(self, settings: Settings, store: Store, keys: KeyStore, audit):
        self.s = settings
        self.store = store
        self.keys = keys
        self.audit = audit

    # ---------------- cookie ----------------
    def _sign(self, sid: str) -> str:
        mac = hmac.new(self.keys.cookie_key, sid.encode(), hashlib.sha256).digest()
        return f"{sid}.{_b64u(mac)}"

    def _unsign(self, raw: str) -> str | None:
        sid, _, mac = raw.partition(".")
        if not sid or not mac:
            return None
        expect = _b64u(hmac.new(self.keys.cookie_key, sid.encode(), hashlib.sha256).digest())
        return sid if hmac.compare_digest(mac, expect) else None

    def _current_subject(self, request: Request) -> str | None:
        raw = request.cookies.get(COOKIE)
        if not raw:
            return None
        sid = self._unsign(raw)
        return self.store.get_session(sid) if sid else None

    def _client_ip(self, request: Request) -> str:
        return client_ip(request, self.s.trusted_proxy_hops) or "?"

    # ---------------- redirect_uri allowlist ----------------
    def redirect_prefixes(self) -> tuple[str, ...]:
        """Configured prefixes plus the ones added at runtime. Read per request:
        `vpsmcp redirect allow` must not need a restart."""
        out = list(self.s.allowed_redirect_prefixes)
        out += [p for p in self.store.redirect_prefixes() if p not in out]
        return tuple(out)

    def redirect_ok(self, uri: str) -> bool:
        return bool(uri) and redirect_allowed(uri, self.redirect_prefixes())

    def _reject_redirect(self, uri: str, client_name: str, reason: str,
                         request: Request) -> None:
        self.store.note_rejected_redirect(uri, client_name)
        self.audit.write(event="oauth.redirect_rejected", redirect_uri=uri[:400],
                         client_name=client_name, reason=reason,
                         ip=self._client_ip(request))

    def _redirect_help(self, uri: str) -> str:
        """What to do about a callback this server does not know yet. The command is
        the point: no vendor callback has to be guessed in advance."""
        known = ", ".join(p.name for p in enabled_profiles(self.s.clients)) or "none"
        # The URL is whatever the client sent. It is escaped for the page, and
        # shell-quoted in the command, which is meant to be copied into a root shell.
        shown = html.escape(uri or "(empty)")
        quoted = html.escape(shlex.quote(uri)) if uri else "&lt;uri&gt;"
        return (f"<p><code>{shown}</code> is not in the "
                f"allowlist.</p><p>Enabled clients: {html.escape(known)}. If this "
                f"callback is really yours, allow it on the gateway:</p>"
                f"<pre>sudo vpsmcp redirect allow {quoted}</pre>"
                f"<p class=\"hint\">It is also listed by <code>sudo vpsmcp redirects</code>, "
                f"together with every other callback that was refused. Allow only a URL "
                f"you recognise: it is where the authorization code is sent.</p>")

    # ---------------- client resolution (DCR / CIMD / pre-registered) ----------------
    async def _resolve_client(self, client_id: str) -> dict | None:
        rec = self.store.get_client(client_id)
        if rec:
            return rec
        if self.s.enable_cimd and client_id.startswith("https://"):
            meta = await self._fetch_cimd(client_id)
            if meta:
                self.store.put_client(client_id, meta)
                return {"client_id": client_id, "secret_hash": None, "metadata": meta}
        return None

    async def _fetch_cimd(self, url: str) -> dict | None:
        u = urlparse(url)
        if u.scheme != "https" or not u.path or u.path == "/":
            return None
        if not _is_public_host(u.hostname or ""):
            return None
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as c:
                r = await c.get(url, headers={"Accept": "application/json"})
            if r.status_code != 200 or len(r.content) > 64_000:
                return None
            meta = r.json()
        except Exception:  # noqa: BLE001
            return None
        if meta.get("client_id") != url or not isinstance(meta.get("redirect_uris"), list):
            return None
        meta.setdefault("client_name", u.netloc)
        meta["_cimd"] = True
        return meta

    # ---------------- routes ----------------
    def routes(self) -> list[Route]:
        mcp_path = self.s.mcp_path
        return [
            Route("/.well-known/oauth-authorization-server", self.metadata, methods=["GET"]),
            Route("/.well-known/openid-configuration", self.metadata, methods=["GET"]),
            # RFC 8414 path-insertion forms. Clients that treat the resource URL
            # (not the origin) as the issuer look here, and get a 404 otherwise.
            Route(f"/.well-known/oauth-authorization-server{mcp_path}", self.metadata,
                  methods=["GET"]),
            Route(f"/.well-known/openid-configuration{mcp_path}", self.metadata,
                  methods=["GET"]),
            Route(f"{mcp_path}/.well-known/oauth-authorization-server", self.metadata,
                  methods=["GET"]),
            Route(f"{mcp_path}/.well-known/openid-configuration", self.metadata,
                  methods=["GET"]),
            Route("/oauth/jwks.json", self.jwks, methods=["GET"]),
            Route("/oauth/register", self.register, methods=["POST"]),
            Route("/oauth/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/oauth/login", self.login, methods=["POST"]),
            Route("/oauth/token", self.token, methods=["POST"]),
            Route("/oauth/revoke", self.revoke, methods=["POST"]),
        ]

    async def metadata(self, request: Request) -> JSONResponse:
        base = self.s.public_url
        doc = {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth/authorize",
            "token_endpoint": f"{base}/oauth/token",
            "revocation_endpoint": f"{base}/oauth/revoke",
            "jwks_uri": f"{base}/oauth/jwks.json",
            "scopes_supported": list(SCOPES) + ["offline_access"],
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": (
                ["S256"] if self.s.require_pkce else ["S256", "plain"]),
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post",
                                                      "client_secret_basic"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "resource_indicators_supported": True,
            "authorization_response_iss_parameter_supported": True,
        }
        if self.s.enable_dcr:
            doc["registration_endpoint"] = f"{base}/oauth/register"
        if self.s.enable_cimd:
            doc["client_id_metadata_document_supported"] = True
        return JSONResponse(doc, headers={"Cache-Control": "public, max-age=300"})

    async def jwks(self, request: Request) -> JSONResponse:
        return JSONResponse(self.keys.jwks(), headers={"Cache-Control": "public, max-age=3600"})

    async def register(self, request: Request) -> JSONResponse:
        if not self.s.enable_dcr:
            return _err("invalid_request", "dynamic client registration is disabled", 403)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return _err("invalid_client_metadata", "body must be JSON (RFC 7591 3.1)")
        name = str(body.get("client_name") or "unnamed")[:120]
        uris = body.get("redirect_uris") or []
        if not isinstance(uris, list) or not uris:
            return _err("invalid_redirect_uri", "missing redirect_uris")
        bad = [u for u in uris if not self.redirect_ok(str(u))]
        if bad:
            for u in bad:
                self._reject_redirect(str(u), name, "register", request)
            return _err("invalid_redirect_uri",
                        f"redirect_uri not allowed: {bad}. Allow it on the gateway with "
                        f"`vpsmcp redirect allow <uri>`, or enable the client profile it "
                        f"belongs to (VPSMCP_CLIENTS)")
        # A client that asks to authenticate gets a secret. Claude does not; several
        # other clients refuse to finish registration without one.
        method = str(body.get("token_endpoint_auth_method") or "none")
        if method not in ("client_secret_post", "client_secret_basic"):
            method = "none"
        client_id = f"dcr_{secrets.token_urlsafe(24)}"
        meta = {
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": body.get("grant_types") or ["authorization_code", "refresh_token"],
            "response_types": body.get("response_types") or ["code"],
            "token_endpoint_auth_method": method,
            "scope": body.get("scope") or " ".join(SCOPES),
            "client_uri": body.get("client_uri"),
        }
        secret = secrets.token_urlsafe(32) if method != "none" else None
        self.store.put_client(client_id, meta, sha(secret) if secret else None)
        self.audit.write(event="oauth.register", client_id=client_id,
                         client_name=name, redirect_uris=uris, auth_method=method,
                         ip=self._client_ip(request))
        out = {**meta, "client_id_issued_at": int(time.time())}
        if secret:
            out["client_secret"] = secret
            out["client_secret_expires_at"] = 0  # never
        return JSONResponse(out, status_code=201, headers={"Cache-Control": "no-store"})

    # ---------------- authorize ----------------
    async def authorize(self, request: Request) -> Response:
        if request.method == "POST":
            form = await request.form()
            params = {k: str(v) for k, v in form.items()}
        else:
            params = dict(request.query_params)

        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        challenge = params.get("code_challenge", "")
        method = params.get("code_challenge_method", "")
        resource = params.get("resource")

        client = await self._resolve_client(client_id)
        if not client:
            # Record the callback too: a client whose registration was refused often
            # comes back here with a client_id it never got, and the refused URL is
            # the thing the admin has to act on.
            if redirect_uri and not self.redirect_ok(redirect_uri):
                self._reject_redirect(redirect_uri, guess_client(redirect_uri),
                                      "unknown_client", request)
            return HTMLResponse(_page("Unknown client",
                "<p>client_id could not be resolved. For DCR, POST /oauth/register first. "
                "For CIMD, the metadata document must be publicly reachable and its "
                "client_id must equal its URL.</p>"
                "<p class=\"hint\">If registration was refused because of the callback "
                "URL, <code>sudo vpsmcp redirects</code> on the gateway prints it and the "
                "command that allows it.</p>"), 400)

        client_name = str(client["metadata"].get("client_name") or guess_client(redirect_uri))
        registered = client["metadata"].get("redirect_uris") or []
        if not redirect_uri or not _match_redirect(redirect_uri, registered):
            return HTMLResponse(_page("redirect_uri mismatch",
                f"<p><code>{html.escape(redirect_uri)}</code> is not registered for this client.</p>"), 400)
        if not self.redirect_ok(redirect_uri):
            self._reject_redirect(redirect_uri, client_name, "authorize", request)
            return HTMLResponse(_page("Callback not allowed",
                                      self._redirect_help(redirect_uri)), 400)

        def bounce(**kw) -> RedirectResponse:
            q = {**kw, "iss": self.s.public_url}
            if state:
                q["state"] = state
            sep = "&" if urlparse(redirect_uri).query else "?"
            return RedirectResponse(f"{redirect_uri}{sep}{urlencode(q)}", status_code=302)

        if params.get("response_type") != "code":
            return bounce(error="unsupported_response_type",
                          error_description="only response_type=code is supported")
        if self.s.require_pkce:
            if method != "S256" or not challenge:
                return bounce(error="invalid_request",
                              error_description="PKCE code_challenge with method=S256 is required")
        elif challenge and method not in ("S256", "plain"):
            return bounce(error="invalid_request",
                          error_description="code_challenge_method must be S256 or plain")
        if not self.s.resource_ok(resource):
            return bounce(error="invalid_target",
                          error_description=f"resource must be {self.s.resource_url}")

        scope = _norm_scopes(params.get("scope"), SCOPES)
        subject = self._current_subject(request)

        if subject is None:
            return HTMLResponse(self._login_page(params, error=None))

        if request.method == "POST" and params.get("_action") == "approve":
            picked = [s for s in scope.split()
                      if s == "offline_access" or params.get(f"scope_{s}")]
            if not any(s != "offline_access" for s in picked):
                # Unticking every box is not consent to everything that was asked for.
                return HTMLResponse(self._consent_page(
                    params, client, scope, subject,
                    error="Select at least one permission, or deny the request."), 400)
            granted = " ".join(picked)
            code = secrets.token_urlsafe(40)
            self.store.put_code(
                code, client_id=client_id, redirect_uri=redirect_uri, scope=granted,
                challenge=challenge, challenge_method=(method if challenge else "none"),
                resource=self.s.resource_url, subject=subject,
                expires_at=int(time.time()) + self.s.code_ttl,
            )
            self.audit.write(event="oauth.authorize", client_id=client_id, subject=subject,
                             scope=granted, redirect_uri=redirect_uri, ip=self._client_ip(request))
            return bounce(code=code)

        if request.method == "POST" and params.get("_action") == "deny":
            return bounce(error="access_denied", error_description="user denied the request")

        return HTMLResponse(self._consent_page(params, client, scope, subject))

    async def login(self, request: Request) -> Response:
        form = await request.form()
        ip = self._client_ip(request)
        left = self.store.login_locked(ip)
        if left:
            return HTMLResponse(_page("Locked out", f"<p>Try again in {left}s.</p>"), 429)
        user = str(form.get("username", ""))
        pwd = str(form.get("password", ""))
        ok = hmac.compare_digest(user, self.s.admin_user) and verify_password(
            pwd, self.s.admin_password_hash)
        params = {k: str(v) for k, v in form.items() if k not in ("username", "password")}
        if not ok:
            self.store.login_failed(ip)
            self.audit.write(event="oauth.login_failed", user=user, ip=ip)
            return HTMLResponse(self._login_page(params, error="Incorrect username or password"), 401)
        self.store.login_ok(ip)
        sid = secrets.token_urlsafe(32)
        self.store.put_session(sid, self.s.admin_user,
                               int(time.time()) + self.s.login_session_ttl)
        self.audit.write(event="oauth.login", user=user, ip=ip)
        params.pop("_action", None)
        resp = RedirectResponse(f"/oauth/authorize?{urlencode(params)}", status_code=303)
        resp.set_cookie(COOKIE, self._sign(sid), httponly=True, secure=True,
                        samesite="lax", max_age=self.s.login_session_ttl, path="/")
        return resp

    # ---------------- token ----------------
    async def token(self, request: Request) -> JSONResponse:
        ctype = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in ctype:
            form = await request.form()
        elif self.s.lenient_token_body and "application/json" in ctype:
            # RFC 6749 says form-encoded, and that stays the default. Some clients
            # post JSON anyway; VPSMCP_LENIENT_TOKEN_BODY=1 accepts it.
            try:
                body = await request.json()
            except Exception:  # noqa: BLE001
                return _err("invalid_request", "body is not valid JSON")
            if not isinstance(body, dict):
                return _err("invalid_request", "JSON body must be an object")
            form = {k: "" if v is None else str(v) for k, v in body.items()}
        else:
            hint = "" if self.s.lenient_token_body else \
                " (VPSMCP_LENIENT_TOKEN_BODY=1 also accepts application/json)"
            return _err("invalid_request",
                        "Content-Type must be application/x-www-form-urlencoded" + hint)
        grant = str(form.get("grant_type", ""))
        client_id, client_secret = _client_credentials(request, form)
        denied = self._check_client_auth(client_id, client_secret)
        if denied is not None:
            return denied
        if grant == "authorization_code":
            return await self._grant_code(request, form, client_id)
        if grant == "refresh_token":
            return await self._grant_refresh(request, form, client_id)
        return _err("unsupported_grant_type", f"unsupported grant_type={grant}")

    def _check_client_auth(self, client_id: str, secret: str) -> JSONResponse | None:
        """A client registered with an auth method must present its secret. Public
        clients (Claude, CIMD, anything registered with `none`) must not be asked
        for one, so an unknown or secretless client_id falls through to the grant
        checks, which bind the code or refresh token to it."""
        if not client_id:
            return None
        rec = self.store.get_client(client_id)
        if not rec or not rec.get("secret_hash"):
            return None
        if not secret or not hmac.compare_digest(sha(secret), rec["secret_hash"]):
            self.audit.write(event="oauth.client_auth_failed", client_id=client_id)
            return _err("invalid_client", "client authentication failed", 401)
        return None

    async def _grant_code(self, request: Request, form, client_id: str) -> JSONResponse:
        code = str(form.get("code", ""))
        verifier = str(form.get("code_verifier", ""))
        redirect_uri = str(form.get("redirect_uri", ""))
        rec = self.store.take_code(code)
        if rec is None:
            return _err("invalid_grant", "unknown authorization code")
        if rec.get("replayed"):
            self.audit.write(event="oauth.code_replay", client_id=client_id,
                             ip=self._client_ip(request))
            return _err("invalid_grant", "authorization code already used; derived tokens revoked")
        if rec["expires_at"] < time.time():
            return _err("invalid_grant", "authorization code expired")
        if rec["client_id"] != client_id:
            return _err("invalid_grant", "client_id does not match the code")
        if redirect_uri and redirect_uri != rec["redirect_uri"]:
            return _err("invalid_grant", "redirect_uri does not match")
        method = str(rec.get("challenge_method") or ("S256" if rec["challenge"] else "none"))
        if method == "S256":
            expect = _b64u(hashlib.sha256(verifier.encode()).digest())
            verified = bool(verifier) and hmac.compare_digest(expect, rec["challenge"])
        elif method == "plain":
            verified = bool(verifier) and hmac.compare_digest(verifier, rec["challenge"])
        else:
            # No challenge was presented, which only happens with VPSMCP_REQUIRE_PKCE=0.
            # If PKCE has been turned back on since, such a code is no longer good.
            verified = not self.s.require_pkce
        if not verified:
            return _err("invalid_grant", "PKCE verification failed")
        resource = str(form.get("resource") or rec["resource"] or self.s.resource_url)
        if not self.s.resource_ok(resource):
            return _err("invalid_target", f"resource must be {self.s.resource_url}")
        return self._issue(client_id, rec["subject"], rec["scope"], family=sha(code),
                           request=request)

    async def _grant_refresh(self, request: Request, form, client_id: str) -> JSONResponse:
        rt = str(form.get("refresh_token", ""))
        # client_id is optional here for public clients, but a client that holds a
        # secret has to name itself: that is what makes token() check the secret.
        # Before take_refresh, so a refused attempt does not rotate the token.
        owner = self.store.refresh_owner(rt)
        if owner and client_id != owner:
            rec_client = self.store.get_client(owner)
            if rec_client and rec_client.get("secret_hash"):
                return _err("invalid_client",
                            "this client must authenticate: send client_id and "
                            "client_secret", 401)
        rec = self.store.take_refresh(rt)
        if rec is None:
            return _err("invalid_grant", "invalid refresh_token")
        if rec.get("reused"):
            self.audit.write(event="oauth.refresh_reuse", client_id=client_id,
                             family=rec["family"], ip=self._client_ip(request))
            return _err("invalid_grant", "refresh token reuse detected; family revoked")
        if rec["expires_at"] < time.time():
            return _err("invalid_grant", "refresh_token expired")
        if client_id and rec["client_id"] != client_id:
            return _err("invalid_grant", "client_id mismatch")
        scope = _norm_scopes(str(form.get("scope") or rec["scope"]), SCOPES)
        scope = " ".join(s for s in scope.split() if s in rec["scope"].split())
        return self._issue(rec["client_id"], rec["subject"], scope or rec["scope"],
                           family=rec["family"], request=request)

    def _issue(self, client_id: str, subject: str, scope: str, *, family: str,
               request: Request) -> JSONResponse:
        now = int(time.time())
        jti = secrets.token_urlsafe(16)
        claims = {
            "iss": self.s.issuer,
            "sub": subject,
            "aud": self.s.resource_url,
            "client_id": client_id,
            "scope": " ".join(s for s in scope.split() if s != "offline_access"),
            "iat": now,
            "nbf": now,
            "exp": now + self.s.access_ttl,
            "jti": jti,
        }
        access = jwt.encode(claims, self.keys.private_pem, algorithm="RS256",
                            headers={"kid": self.keys.kid})
        body = {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": self.s.access_ttl,
            "scope": claims["scope"],
        }
        if True:  # always issue a refresh token
            rt = secrets.token_urlsafe(48)
            self.store.put_refresh(rt, family=family, client_id=client_id, subject=subject,
                                   scope=scope, resource=self.s.resource_url,
                                   expires_at=now + self.s.refresh_ttl)
            body["refresh_token"] = rt
        self.audit.write(event="oauth.token", client_id=client_id, subject=subject,
                         scope=claims["scope"], jti=jti, ip=self._client_ip(request))
        return JSONResponse(body, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def revoke(self, request: Request) -> Response:
        form = await request.form()
        tok = str(form.get("token", ""))
        if tok:
            self.store.revoke_refresh(tok)
        self.audit.write(event="oauth.revoke", ip=self._client_ip(request))
        return Response(status_code=200)

    # ---------------- pages ----------------
    def _login_page(self, params: dict, error: str | None) -> str:
        hidden = "".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
            for k, v in params.items() if k != "_action"
        )
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return _page("Sign in", f"""
{err}
<form method="post" action="/oauth/login">
  {hidden}
  <label>Username<input name="username" autocomplete="username" autofocus></label>
  <label>Password<input name="password" type="password" autocomplete="current-password"></label>
  <button type="submit">Sign in</button>
</form>
<p class="hint">Your own authorization server. A token is issued to the client
only after a successful sign-in.</p>
""")

    def _consent_page(self, params: dict, client: dict, scope: str, subject: str,
                      error: str | None = None) -> str:
        meta = client["metadata"]
        name = html.escape(str(meta.get("client_name", client["client_id"])))
        redirect_uri = params.get("redirect_uri", "")
        redirect_host = html.escape(urlparse(redirect_uri).netloc or "(loopback)")
        origin = " · via CIMD" if meta.get("_cimd") else " · via DCR"
        # The callback host is the one thing worth checking by eye: it is where the
        # authorization code goes. Say which client it belongs to, or say nobody.
        profile = profile_for_redirect(redirect_uri, self.s.clients)
        if profile:
            callback = (f'<p class="warn">Callback host: <code>{redirect_host}</code> '
                        f"&mdash; {html.escape(profile.name)}. Approve only if that is "
                        f"the client you just used.</p>")
        else:
            callback = (f'<p class="warn">Callback host: <code>{redirect_host}</code> '
                        f"belongs to no configured client; it was allowed by hand on "
                        f"this gateway. If you did not add it, <b>do not approve</b>.</p>")
        hidden = "".join(
            f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v)}">'
            for k, v in params.items() if k != "_action"
        )
        rows = []
        for sc in scope.split():
            if sc == "offline_access":
                continue
            rows.append(
                f'<label class="scope"><input type="checkbox" name="scope_{sc}" checked>'
                f"<span><code>{sc}</code> &mdash; {_SCOPE_DESC.get(sc, sc)}</span></label>"
            )
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return _page("Authorize", f"""
{err}
<p><b>{name}</b>{origin} is requesting access to your fleet.</p>
{callback}
<form method="post" action="/oauth/authorize">
  {hidden}
  <div class="scopes">{''.join(rows)}</div>
  <button type="submit" name="_action" value="approve">Approve</button>
  <button type="submit" name="_action" value="deny" class="ghost">Deny</button>
</form>
<p class="hint">Signed in as {html.escape(subject)} &middot; access token valid
{self.s.access_ttl // 60} minutes, renewable with a rotating refresh token.</p>
""")


_SCOPE_DESC = {
    "fleet.read": "list hosts, read files, view logs and job status",
    "fleet.exec": "run commands, open shells, start background jobs",
    "fleet.write": "write, upload and delete files",
    "fleet.admin": "port forwarding, audit log",
}


def _match_redirect(uri: str, registered: list[str]) -> bool:
    if uri in registered:
        return True
    u = urlparse(uri)
    if u.scheme == "http" and u.hostname in LOOPBACK_HOSTS:
        for r in registered:
            ru = urlparse(r)
            if (ru.scheme == "http" and ru.hostname in LOOPBACK_HOSTS
                    and (ru.path or "/") == (u.path or "/")):
                return True
    return False


def _basic_auth(request: Request) -> tuple[str, str]:
    """RFC 6749 2.3.1: both halves are form-urlencoded before base64."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("basic "):
        return "", ""
    try:
        raw = base64.b64decode(auth[6:]).decode()
    except Exception:  # noqa: BLE001
        return "", ""
    cid, _, sec = raw.partition(":")
    return unquote(cid), unquote(sec)


def _client_credentials(request: Request, form) -> tuple[str, str]:
    cid = str(form.get("client_id", "") or "")
    sec = str(form.get("client_secret", "") or "")
    if not (cid and sec):
        bcid, bsec = _basic_auth(request)
        cid, sec = cid or bcid, sec or bsec
    return cid, sec


def _page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>
:root{{color-scheme:light dark;--fg:#1a1a1a;--bg:#fafafa;--card:#fff;--line:#e3e3e3;--accent:#c96442}}
@media(prefers-color-scheme:dark){{:root{{--fg:#e8e6e3;--bg:#1b1b19;--card:#262624;--line:#3a3a37}}}}
*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-sans-serif,system-ui,"Noto Sans SC",sans-serif;padding:24px}}
main{{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:28px;max-width:460px;width:100%}}
h1{{font-size:19px;margin:0 0 16px}}
label{{display:block;margin:12px 0}}
input[type=text],input[type=password],input:not([type]){{width:100%;padding:9px 11px;margin-top:5px;
border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);font-size:15px}}
button{{margin-top:16px;margin-right:8px;padding:10px 18px;border:0;border-radius:8px;
background:var(--accent);color:#fff;font-size:15px;cursor:pointer}}
button.ghost{{background:transparent;color:var(--fg);border:1px solid var(--line)}}
code{{background:var(--bg);padding:1px 5px;border-radius:4px;font-size:13px}}
.scope{{display:flex;gap:9px;align-items:flex-start;margin:9px 0}}
.scope input{{margin-top:5px}}
.hint{{font-size:13px;opacity:.66;margin-top:18px}}
.err{{color:#c0392b}}.warn{{font-size:13.5px;background:rgba(201,100,66,.1);
border-left:3px solid var(--accent);padding:9px 11px;border-radius:0 6px 6px 0}}
</style></head><body><main><h1>{html.escape(title)}</h1>{body}</main></body></html>"""
