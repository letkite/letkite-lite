# Operations

> [← Quick start](../README.md) · [Architecture](ARCHITECTURE.md) · [Reference](REFERENCE.md) · [Troubleshooting](TROUBLESHOOTING.md)

## Running commands

Use `sudo vpsmcp ...`. The wrapper installed at `/usr/local/bin/vpsmcp` switches
to the `vpsmcp` service account, so file permissions behave exactly as they do
for the daemon. Running as plain root hides "the service cannot read this file"
failures. The CLI reads `/etc/vpsmcp/vpsmcp.env` itself; nothing to source.

```bash
sudo vpsmcp check                 # connectivity to every node
sudo vpsmcp nodes                 # node_id / alias / address / user / state
sudo vpsmcp nodes --json
sudo vpsmcp hosts                 # TSV inventory, for scripts
sudo vpsmcp grants                # who holds a valid grant
sudo vpsmcp revoke <client_id>    # revoke a client and all its tokens
sudo vpsmcp unlock [ip]           # clear the admin-login lockout (all, or one IP)
sudo vpsmcp clients               # MCP clients accepted (Claude, Kimi, GLM, ...)
sudo vpsmcp redirects             # callback allowlist + callbacks turned away
sudo vpsmcp redirect allow <uri>  # accept one more client, no restart
sudo vpsmcp set-password          # change the admin password and restart
sudo vpsmcp hash-password         # just print a hash (does not apply it)

sudo tail -f /var/lib/vpsmcp/audit.jsonl | jq
journalctl -u vpsmcp -f
```

Inventory changes are hot-reloaded by mtime; no restart needed.

## Nodes

Enrollment is pull-based and tokenless. On the target machine:

```bash
curl -sSf https://mcp.example.com/enroll/install.sh | sudo bash
... | sudo bash -s -- --alias web-01 --tags prod,hk
... | sudo bash -s -- --user deploy
... | sudo bash -s -- -k <key>          # when VPSMCP_ENROLL_KEY is set
... | sudo bash -s -- -v                # verbose
... | sudo bash -s -- --uninstall
```

The run is silent and exits 0. The alias defaults to the hostname; aliases may
repeat, because identity is `node_id` = hash of `address:port:user`.

From the gateway:

```bash
sudo vpsmcp node remove  <node_id|alias>
sudo vpsmcp node scopes  <node_id|alias> fleet.read,fleet.exec
sudo vpsmcp node rename  <node_id|alias> <new-alias>
sudo vpsmcp node tags    <node_id|alias> prod,hk
sudo vpsmcp node approve <node_id>       # when VPSMCP_ENROLL_MODE=approve
```

Enrolled machines are stored one file per node in `hosts.d/<node_id>.yaml`,
loaded alongside a hand-written `hosts.yaml`. Removing a node is deleting a file,
and your comments and formatting in `hosts.yaml` are never rewritten.

### What lands on a node

A low-privilege account and the gateway's **public** key. No code, no private
key, no certificate. Re-running the installer updates the entry in place.

### Who verifies whom

| Direction | Basis |
|---|---|
| Node trusts the gateway | TLS certificate (so the URL must be https) |
| Gateway accepts the node | `VPSMCP_ENROLL_MODE` + optional `VPSMCP_ENROLL_KEY` + optional CIDR allowlist, rate limited per source IP |
| Gateway trusts the host key | fingerprint reported at enrollment, verified by an immediate SSH connection |

The address recorded is the source IP of the enrollment request, never a value
the node claims. Right after writing the entry the gateway makes one real SSH
connection; on failure it rolls the entry back and returns the reason, so a
broken node never stays in the inventory.

With `VPSMCP_ENROLL_MODE=open` anyone who knows the URL can add a machine they
control. That machine gets only an unprivileged account of its own, but it does
appear in your fleet; use `approve`, a key or a CIDR allowlist if that matters.

## Scopes

Effective permission = token scopes ∩ node scopes ∩ SSH account rights.

| Scope | Covers |
|---|---|
| `fleet.read` | inventory, host facts, read files, list dirs, logs, job status, gateway status |
| `fleet.exec` | exec / exec_many / persistent shells / start and kill jobs |
| `fleet.write` | write files, delete, copy between hosts, purge job dirs |
| `fleet.admin` | tunnels, audit tail |

New nodes get `fleet.read,fleet.exec,fleet.write` (`VPSMCP_ENROLL_SCOPES`).
Only the SSH account is a hard boundary, so keep it unprivileged and put
anything privileged in a sudoers command allowlist:

```
ops ALL=(root) NOPASSWD: /bin/systemctl reload nginx, /usr/bin/docker compose *
```

### Emergency stop

```bash
sudo sed -i 's/^VPSMCP_READ_ONLY=.*/VPSMCP_READ_ONLY=1/' /etc/vpsmcp/vpsmcp.env
sudo systemctl restart vpsmcp
```

Every write and exec tool refuses immediately. To go further,
`sudo vpsmcp revoke <client_id>`.

## Health check

```bash
sudo deploy/healthcheck.sh                      # on the gateway
sudo deploy/healthcheck.sh --deep               # also open one SSH connection per node
deploy/healthcheck.sh https://mcp.example.com   # remote, from anywhere
```

Exit code equals the number of failures, so it drops straight into cron.

| Layer | Checks | Typical failure |
|---|---|---|
| Process | `systemctl is-active`, restart count, listening port, local `/healthz` | restarts > 5 means a crash loop |
| Edge | DNS A record, stray AAAA, certificate days left | < 7 days means renewal is broken |
| Discovery | public `/healthz`, `resource` equals the resource URL, S256 advertised, `/mcp` returns 401 with `resource_metadata`, `/oauth/authorize` reachable, `/enroll/install.sh` returns 200 | this is exactly the path Claude walks |
| Fleet | node count, timestamp and tool of the last audit line | an old timestamp means connected but unused |
| Deep | `vpsmcp check` per node | a changed host key shows up here |

## Reverse proxy

```bash
sudo deploy/gen-caddyfile.sh
sudo deploy/gen-caddyfile.sh --email you@example.com -o /etc/caddy/Caddyfile
sudo deploy/gen-caddyfile.sh --lock-anthropic
sudo deploy/gen-caddyfile.sh --dns-route53 Z123ABC   # when port 80 is unusable
sudo deploy/gen-caddyfile.sh --log-file /var/log/caddy/mcp.log
```

Domain, port and path come from `vpsmcp.env`, so the proxied port always matches
the port the service listens on. The file is backed up before writing and run
through `caddy validate` after.

`--lock-anthropic` restricts the endpoints only Anthropic's backend calls to
`160.79.104.0/21`:

| Endpoint | Caller | Lockable |
|---|---|---|
| `/mcp`, `/.well-known/*`, `/oauth/token`, `/oauth/register`, `/oauth/revoke` | Anthropic backend | yes |
| `/oauth/authorize`, `/oauth/login` | your browser | no |

Do not use it at all if you use Claude Code, which connects from your own machine,
or Kimi or GLM, whose egress ranges are not published - the lock blocks them
outright. `--allow-cidr <cidr>` (repeatable) adds networks you do know.

## Upgrade

Config and data are untouched, so nodes stay enrolled and existing grants keep
working; only the code in `/opt/vpsmcp` is replaced.

```bash
cd letkite-lite && git pull
sudo deploy/upgrade.sh --fast          # code only, no dependency resolution, no egress
sudo deploy/upgrade.sh                 # with dependencies, when pyproject changed
sudo deploy/upgrade.sh --no-restart
sudo deploy/upgrade.sh --list-backups
sudo deploy/upgrade.sh --rollback [timestamp]
```

The script backs up the current code, stops the service, installs, runs `check`
as the service account and only then restarts. A failed self-test leaves the
service stopped rather than starting a broken build. Backups live in
`/opt/vpsmcp/.rollback/<timestamp>/`, last three kept. Run `healthcheck.sh` after.

## Migrating the gateway

The resource URL does not change, so nothing changes on the Claude side and
authorized connectors keep working.

```bash
# old machine (stops the service first, so oauth.db is not exported mid-write)
sudo deploy/migrate.sh export /root/vpsmcp-state.tar.gz
scp /root/vpsmcp-state.tar.gz newgw:/root/

# new machine
sudo deploy/install.sh --domain <same domain> -y
sudo deploy/migrate.sh import /root/vpsmcp-state.tar.gz
sudo systemctl enable --now vpsmcp
sudo deploy/gen-caddyfile.sh --email you@example.com -o /etc/caddy/Caddyfile
sudo systemctl reload caddy
# then repoint the DNS A record (lower the TTL to 60 beforehand)
sudo deploy/healthcheck.sh
```

Carried over: SSH private key, inventory, `known_hosts`, OAuth signing key,
cookie key, `oauth.db` (clients and valid refresh tokens) and the audit log.

- Remote jobs are unaffected; their state is on the nodes.
- Persistent shells, log subscriptions and tunnels are lost - they are process state.
- Never run both gateways at once: refresh tokens rotate, two diverging copies of
  `oauth.db` make a valid token look like a replay and kill the whole family.
- Keep the old machine until the new one is green; `systemctl start vpsmcp` rolls back.
- If the gateway was enrolled as a node, re-enroll it: the recorded host key was
  the old machine's.

## Uninstall

```bash
sudo deploy/uninstall.sh
sudo deploy/uninstall.sh --keep-data    # keep /var/lib/vpsmcp
sudo deploy/uninstall.sh --local-only   # gateway only, leave the nodes alone
```

Order matters. The gateway must strip its public key from every node while it
still works, then delete `/etc/vpsmcp`. Reversed, you can never log in again and
the key stays in every `authorized_keys` forever. The script uses the real
inventory loader (a hand-rolled YAML parser misses ports and users inherited from
`defaults:` and silently skips those hosts) and aborts with manual instructions if
the inventory cannot be read.

Left for you to do by hand:

- reverse proxy: delete the block from the Caddyfile, `systemctl reload caddy`
- certificate: `rm -rf /var/lib/caddy/.local/share/caddy/certificates/*/mcp.*`
- DNS: delete the A record
- node accounts: `userdel -r ops`
- the client: remove the connector / MCP server entry (Claude: Settings →
  Connectors)
