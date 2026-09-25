# Architecture

> [← Quick start](../README.md) · [Reference](REFERENCE.md) · [Operations](OPERATIONS.md) · [Troubleshooting](TROUBLESHOOTING.md)

## 1. Topology

```
Claude / Kimi / GLM  (web, desktop, mobile, CLI)
   │  HTTPS, Streamable HTTP + Bearer JWT
   ▼
Gateway VPS - mcp.example.com
   Caddy: TLS, no buffering, no stream timeouts
   │  127.0.0.1:8848
   ├─ Authorization server  OAuth 2.1, RS256 JWT, rotating refresh
   ├─ Resource server       FastMCP, /mcp, scope injected per call
   └─ Execution plane       tools → policy → SSH pool → asyncssh
      state /var/lib/vpsmcp   config /etc/vpsmcp
   │  SSH, key auth, host keys pinned
   ▼
node-1   node-2   node-3   ...
```

One gateway plus SSH, instead of an agent on every machine: SSH is already
running everywhere, so adding a host is one line in `authorized_keys` and needs
no software on the node. The cost is a single point of failure, mitigated by
keeping long-running job state on the node itself (§4.3), so a gateway restart
loses nothing.

## 2. Authorization

A static bearer token would be one never-expiring key to the whole fleet, copied
into several places. OAuth buys three properties: 15-minute access tokens,
rotating refresh tokens with replay detection, and an approval step on a consent
page you control.

```
Client                              Gateway
  POST /mcp (no token)        →
        ← 401 WWW-Authenticate: Bearer resource_metadata="..."
  GET  /.well-known/oauth-protected-resource/mcp     (RFC 9728)
  GET  /.well-known/oauth-authorization-server       (RFC 8414, 3 path forms)
  POST /oauth/register        →     DCR (RFC 7591) or CIMD client_id URL
  GET  /oauth/authorize       →     login (scrypt) + consent, PKCE S256
        ← 302 <the client's callback>?code=...
  POST /oauth/token           →     access token (aud = resource URL) + refresh
  POST /mcp  Bearer ...       →     verify iss/aud/exp/signature → scopes
```

The same path for every client. What differs between Claude, Kimi and GLM is the
callback URL, so that is the only per-client thing the server knows
(`auth/clients.py`, `VPSMCP_CLIENTS`, and the runtime allowlist behind
`vpsmcp redirect allow`).

Details that are easy to get wrong and are already handled:

- `resource` in the metadata, `aud` in the JWT and the URL typed into the client
  must match byte for byte. `VPSMCP_PUBLIC_URL` is a bare origin; resource URL =
  origin + `/mcp`. A client that sends the origin in `resource` instead of the
  endpoint is accepted, and still gets `aud` = resource URL.
- The unauthenticated `/mcp` response must be a real 401; a challenge on a 200 is ignored.
- PKCE S256 only, and the metadata must advertise `code_challenge_methods_supported`
  (`VPSMCP_REQUIRE_PKCE=0` also takes `plain`, for a client that has no S256).
- `/token` accepts form-urlencoded only, `/register` JSON only
  (`VPSMCP_LENIENT_TOKEN_BODY=1` also takes JSON on `/token`).
- Discovery is served on the origin and on both RFC 8414 path forms: clients
  disagree about whether the issuer is the origin or the resource URL.
- A client registered with `client_secret_post`/`_basic` gets a secret and must
  present it; a public client must not be asked for one. Either way the code and
  the refresh token stay bound to the `client_id` they were issued to.
- Failed refresh must return `invalid_grant`.
- Loopback redirects ignore the port (RFC 8252 §7.3) for Claude Code.
- Discovery times out at 10s, refresh at 30s, so no slow I/O on those routes.

Both registration paths are open. CIMD fetches the client metadata document over
HTTPS with SSRF protection (no private/loopback/link-local targets, 64 KB cap, no
redirects). DCR is the fallback and enforces a server-side `redirect_uris`
allowlist, since the endpoint itself is unauthenticated.

## 3. Permission model

Effective permission is the intersection of three layers:

```
token scopes  ∩  per-node scopes  ∩  SSH account rights
```

Only the third is a hard boundary; the first two live in the gateway process and
fall with it. So nodes log in as an unprivileged account, and anything needing
root goes into a `sudoers` command allowlist. `sudo: true` in the inventory only
permits the tools to call `sudo -n`; sudoers still decides.

The regex guardrails in `policy.py` (`rm -rf /`, `mkfs`, `dd of=/dev/sda`, fork
bombs) and the confirm list (reboot, stop service, flush firewall, recursive
delete, drop database, force push) stop accidents, not attackers: any string
match can be bypassed with base64 or variable splicing. Their value is forcing
the model to state the exact command and get `confirm=true` first.

## 4. Execution shapes

Four shapes, one per time scale.

**4.1 `exec` — stateless, synchronous, seconds.** One process per call; `cd` and
`export` do not carry over. Timeouts really kill the remote process and keep the
partial output. Output is truncated to `max_output_bytes` (32 KB default) and
flagged, while still draining the pipe so the remote side never blocks.
`exec_many` is the fan-out version with a concurrency limit.

**4.2 `shell_open` / `shell_run` — stateful, synchronous, debugging.** A remote
`bash -l` that prints an unguessable sentinel plus exit code and `$PWD` after
each command. `cd`, `export`, `source venv/bin/activate` and shell functions
persist. A single command cannot be interrupted on its own - a timeout destroys
the session - and stdout/stderr are merged, so this is for debugging, not jobs.

**4.3 `job_start` / `job_status` / `job_output` — detached, minutes to hours.**
`setsid` + `nohup`, output redirected to `~/.vpsmcp/jobs/<job_id>/` on the node,
with `pid`, `pgid`, `meta.json` and a final `exit_code`. State lives on the node,
not in gateway memory, so jobs survive SSH drops, gateway restarts and even a
gateway migration. `job_output` returns `next_offset` for gap-free incremental
reads. Container PID 1 often does not reap children, so a killed job can stay a
zombie while `kill -0` still succeeds; status also reads `ps -o state=` and maps
`Z` to `aborted`.

**4.4 `log_open` / `log_read` — continuous collection, pull-based.** MCP has no
server push, so the gateway keeps `tail -F` / `journalctl -f` running into a
5000-line ring buffer with sequence numbers, and `log_read(sub_id, since_seq)`
reads incrementally. This allows subscribe → trigger → read, which plain `exec`
cannot do. Buffer overflow is reported as `dropped_lines`.

**4.5 Tunnels.** `tunnel_open` is only useful paired with `tunnel_http`: it maps
a port bound to `127.0.0.1` on a node (Grafana, Prometheus, pprof, an internal
API) to a local port on the gateway, which then issues the HTTP request.

## 5. Connection pool

```
SSHPool = {alias → (conn, created, last_used, pinned)}
  single-flight lock, so concurrent first connects open one connection
  idle reclaim after IDLE_CONN_TTL when pinned == 0
  pinned by persistent shells, log subscriptions and tunnels
  keepalive 30s x3, reconnect on next acquire
  jump hosts acquired recursively as a tunnel, so private nodes need no public IP
```

Host identity is never trust-on-first-use at connect time: either `host_key` is
pinned in the inventory, or the node reports its fingerprint during enrollment
and the gateway verifies before writing it. `VPSMCP_STRICT_HOST_KEYS=0` belongs
in throwaway labs only.

## 6. Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Someone finds the domain | every endpoint needs a bearer token or is public metadata; `/oauth/authorize` needs a password, 5 failures trigger exponential lockout | metadata reveals the service exists |
| Authorization code intercepted | PKCE S256, 120s single-use code, replay revokes the whole token family | — |
| Refresh token leaked | rotation; reuse invalidates the family | attacker may use it once first, which logs you out - that is the alarm |
| Access token leaked | 15-minute expiry, `aud` bound to the resource URL | usable inside that window |
| Phishing authorization | consent page shows the callback domain and which client it belongs to; redirect URIs allowlisted, and a refused one is only allowed by an explicit command | depends on you reading the page; a host-scoped entry trusts that host not to run an open redirect |
| Prompt injection into destructive commands | guardrails, confirm step, `fleet.write` can be withheld, `VPSMCP_READ_ONLY=1` | guardrails are bypassable; SSH account rights are the boundary |
| Gateway compromised | systemd sandbox, key 640 root:vpsmcp, dirs 750 | **the gateway holds the key to every node - full fleet compromise** |
| Accountability | one fsynced JSONL line per call: who, when, which node, what command, exit code | audit file is local and tamperable by whoever owns the gateway |

The concentration risk is structural to the "pure SSH, no agent" choice. The way
out is an SSH CA issuing short-lived certificates, with `TrustedUserCAKeys` on
each node; the connection layer is isolated in `SSHPool._client_keys` for that.

## 7. Tool surface

The tools are cut by how a model reasons, not by wrapping the SSH API:

- Aliases only, never raw addresses, so the gateway cannot be pointed anywhere
  outside the inventory.
- The decision tree lives in the server `INSTRUCTIONS` (`app.py`): when to use
  `exec` vs `job_start`, and read → write → validate → reload for config changes.
- Tool descriptions say *when* to use a tool, not only what it does.
- Errors carry the next step: how to re-enroll, which scopes are held, which tool
  to switch to on timeout.
- `job_output` and `log_read` return the next cursor, so the model never computes
  offsets.

## 8. Extension points

| Goal | Where |
|---|---|
| SSH CA certificates instead of a long-lived key | `SSHPool._client_keys` |
| Multiple users with separate fleet views | subject table in `auth/oauth.py`, filter in `Runtime.resolve` |
| Stronger policy (per-host allowlist, rate limits) | `policy.check_command` |
| Ship audit off-box | `audit.Audit.write` |
| Pull inventory from a provider API | `inventory.InventoryWatcher` |
| Multi-gateway HA | replace `auth/store.py` with a shared backend |
