# Troubleshooting

> [← Quick start](../README.md) · [Architecture](ARCHITECTURE.md) · [Reference](REFERENCE.md) · [Operations](OPERATIONS.md)

Run `sudo deploy/healthcheck.sh` first; it reports which layer is broken.

| Symptom | Usually | Section |
|---|---|---|
| `configuration error: missing required environment variable VPSMCP_PUBLIC_URL` | ran as `sudo` instead of `sudo vpsmcp` | [env](#env) |
| `Permission denied for user X` | sshd rejects public keys, wrong account, allowlist | [ssh-auth](#ssh-auth) |
| `Host key verification failed` | wrong `known_hosts`, or the machine changed | [hostkey](#hostkey) |
| Claude cannot connect | resource URL mismatch or broken discovery | [claude](#claude) |
| Kimi / GLM / another client cannot finish signing in | its callback URL is not allowed | [client](#client) |
| Caddy never gets a certificate | DNS not live, port 80 blocked | [cert](#cert) |
| Service restarts in a loop | bad config, crash on start | [crashloop](#crashloop) |
| Tool call times out | wrong execution shape | [timeout](#timeout) |
| Enrollment says the gateway could not connect back | fingerprint, port, account or NAT | [enroll](#enroll) |
| Login password never accepted | the hash was mangled by shell expansion | [hash](#hash) |
| `/etc/caddy does not exist; Caddy is not installed` | Caddy is not installed | [cert](#cert) |

---

## <a name="env"></a>Missing environment variable

`sudo` resets the environment, so sourcing `vpsmcp.env` first does not help, and
`/etc/vpsmcp/vpsmcp.env` is `640 root:vpsmcp`, so your own account cannot read it.

```bash
sudo vpsmcp check
```

The wrapper runs as the service account. Do not use root for self-tests: root can
read everything, so a check may pass while the daemon cannot read a file.

---

## <a name="ssh-auth"></a>Permission denied

Reaching "Permission denied" means host key verification already passed. Check in
this order:

```bash
# 1. effective sshd config for that account (-C evaluates Match blocks)
sudo sshd -T -C user=<account>,host=127.0.0.1,addr=127.0.0.1 \
  | grep -iE 'allowusers|allowgroups|denyusers|denygroups|authorizedkeysfile|pubkeyauthentication|usepam|strictmodes'

# 2. account state
getent passwd <account>
sudo getent shadow <account> | cut -d: -f2     # '!' = locked, '*' = no password (fine)

# 3. same key on both sides?
sudo ssh-keygen -yf /etc/vpsmcp/id_ed25519 | ssh-keygen -lf -
sudo awk '{print $1,$2}' /home/<account>/.ssh/authorized_keys | ssh-keygen -lf -

# 4. the real reason is only in the server log
sudo journalctl -u ssh -n 30 --no-pager | grep -iE '<account>|invalid|denied|refused'
```

### `PubkeyAuthentication no`

Common on hardened machines and easy to misdiagnose: the account exists, the key
is installed, the fingerprint matches, but sshd does not accept public keys at
all. The node installer already writes a per-user drop-in for this; if you are
fixing it by hand, do not change the global setting:

```bash
sudo tee /etc/ssh/sshd_config.d/60-vpsmcp-ops.conf >/dev/null <<'CONF'
Match User ops
    PubkeyAuthentication yes
CONF
sudo sshd -t
sudo sshd -T -C user=ops,host=127.0.0.1,addr=127.0.0.1  | grep -i pubkeyauth   # yes
sudo sshd -T -C user=root,host=1.2.3.4,addr=1.2.3.4     | grep -i pubkeyauth   # no
sudo systemctl reload ssh
```

Keep a second SSH session open while reloading. Verified on OpenSSH 9.6p1: a
`Match` block inside a drop-in does not leak into the parent config, but the
third command above is the check that proves it on your build.

If `grep -rn 'TrustedUserCAKeys\|AuthorizedPrincipals' /etc/ssh/` returns
anything, that machine uses SSH certificates; sign `/etc/vpsmcp/id_ed25519` with
the CA instead of enabling raw public keys.

### Allowlists and central key files

```bash
echo 'AllowUsers ops' | sudo tee /etc/ssh/sshd_config.d/60-vpsmcp.conf
# AllowGroups instead:
sudo usermod -aG <group> ops
```

Never add the node account to the `sudo` group; on the gateway that would let it
read the fleet private key.

With a central `AuthorizedKeysFile`:

```bash
sudo install -d -m 755 /etc/ssh/authorized_keys
sudo cp /etc/vpsmcp/id_ed25519.pub /etc/ssh/authorized_keys/ops
sudo chmod 644 /etc/ssh/authorized_keys/ops
```

### Locked account with `UsePAM no`

`useradd` leaves `!` in shadow. Harmless with `UsePAM yes`, rejected outright
with `UsePAM no`. Fix with `sudo usermod -p '*' ops`. Note `passwd -S` reports
both `!` and `*` as `L`; read `getent shadow` instead.

---

## <a name="hostkey"></a>Host key verification failed

Testing by hand needs the gateway's own `known_hosts`:

```bash
sudo ssh -i /etc/vpsmcp/id_ed25519 -o BatchMode=yes \
  -o UserKnownHostsFile=/etc/vpsmcp/known_hosts -o StrictHostKeyChecking=yes \
  ops@<address> 'id -un'
```

If the service reports it, the node's host key changed - reinstall, replacement
or interception. Find out which before re-recording it. Pinning
`host_key: "ssh-ed25519 AAAA..."` in the inventory is stronger than relying on
`known_hosts`.

---

## <a name="claude"></a>Claude cannot connect

Walk the same path Claude does:

```bash
U=https://mcp.example.com
curl -s $U/healthz
curl -s $U/.well-known/oauth-protected-resource/mcp
curl -s $U/.well-known/oauth-authorization-server | grep -o 'code_challenge_methods_supported[^]]*]'
curl -si -X POST $U/mcp -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | head -6
```

The last one must be `401` with
`www-authenticate: Bearer ... resource_metadata="..."`. A challenge on a 200 is
ignored, and without `resource_metadata` the authorization server is never found.

Common causes:

- `resource` does not match the URL typed into Claude. `VPSMCP_PUBLIC_URL` is a
  bare origin with no path; the resource URL is that plus `VPSMCP_MCP_PATH`.
- `--lock-anthropic` is on while you use Claude Code, which connects from your
  own IP - or any client other than Claude on the web.
- The proxy buffers the stream. nginx needs `proxy_buffering off` and long
  timeouts; Caddy needs `flush_interval -1`. `gen-caddyfile.sh` gets this right.
- `/oauth/authorize` is unreachable from your browser because it was IP-locked.
- The enrollment CIDR allowlist rejects everyone, or the login lockout never
  trips: `VPSMCP_TRUSTED_PROXY_HOPS` does not match your proxy chain. It is `1`
  for a single Caddy/nginx; set it to the number of proxies that append to
  `X-Forwarded-For`, or `0` if the app has no proxy in front.

---

## <a name="client"></a>A client cannot finish signing in

The client adds the URL, the sign-in page appears or not, and it never comes back
connected. Almost always the callback: the gateway only sends an authorization
code to a URL on its allowlist, and no vendor callback is guessed in advance.

```bash
sudo vpsmcp clients      # which clients are on, and their callbacks
sudo vpsmcp redirects    # what was refused, verbatim
```

If the client appears under "refused callbacks", allow that exact URL:

```bash
sudo vpsmcp redirect allow https://<the-url-it-printed>
```

It applies immediately - no restart - and the client can retry at once. Allow only
a URL you recognise: whoever owns it receives the authorization code. Remove one
again with `sudo vpsmcp redirect deny <uri>`.

Nothing in the refused list, and the client still fails:

```bash
U=https://mcp.example.com
curl -s $U/.well-known/oauth-authorization-server     | head -c 200; echo
curl -s $U/.well-known/oauth-authorization-server/mcp | head -c 200; echo
curl -s $U/healthz
```

- Both discovery forms must answer; a client that treats the resource URL as the
  issuer uses the second one.
- `--lock-anthropic` blocks every non-Anthropic client, Kimi and GLM included.
  Regenerate without it (`sudo vpsmcp caddyfile -o /etc/caddy/Caddyfile --reload`)
  or add the network with `--allow-cidr`.
- A client that refuses to register without a client secret gets one if it asks
  for `client_secret_post` or `client_secret_basic`; a client that cannot do PKCE
  needs `VPSMCP_REQUIRE_PKCE=0`, and one that posts JSON to `/token` needs
  `VPSMCP_LENIENT_TOKEN_BODY=1`. Both weaken the flow: set them only for the
  client that needs them, and check `sudo journalctl -u vpsmcp -n 50` first to see
  which step actually failed.

The audit log records every refusal with its reason:

```bash
sudo grep oauth /var/lib/vpsmcp/audit.jsonl | tail -20
```

---

## <a name="cert"></a>Certificates and Caddy

**`/etc/caddy does not exist; Caddy is not installed`** means what it says
(`vpsmcp setup`, run by `install.sh`, installs it; `--no-caddy` skips it):

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy
```

**Caddy is `active (running)` but serves nothing.** Look for this in
`systemctl status caddy`:

```
Status: "loading new config: setting up custom log 'log0': opening log writer ...
```

The real error is `open /var/log/caddy/xxx.log: permission denied`. The whole
config fails to load while the process keeps running the packaged default, so
port 80 shows the welcome page and 443 answers nothing.

```bash
sudo mkdir -p /var/log/caddy && sudo chown caddy:caddy /var/log/caddy && sudo chmod 755 /var/log/caddy
sudo systemctl reload caddy
sudo ss -ltnp | grep :443
```

`gen-caddyfile.sh` emits no custom log block by default. `--log-file <path>` adds
one but does not create the directory; create it with the commands above first.

Use `sudo journalctl -u caddy -n 50 --no-pager`; without sudo you are usually not
in the `adm` group and see nothing.

**Issuance fails:**

- DNS not propagated when Caddy reloaded. It backs off exponentially; check with
  `dig +short <domain> @<authoritative-ns>`, then `systemctl restart caddy` to
  retry immediately.
- Port 80 closed. ACME HTTP-01 needs it; cloud firewalls often open only 22 and 443.
- An AAAA record with broken IPv6 makes validation fail intermittently. Remove it
  or fix v6.
- Port 80 unusable at all: switch to DNS-01 with
  `sudo deploy/gen-caddyfile.sh --dns-route53 <ZONE_ID>`, which needs a build with
  the plugin (`xcaddy build --with github.com/caddy-dns/route53`) and the IAM
  policy in `deploy/iam-route53-dns01.json`.

---

## <a name="crashloop"></a>Service restart loop

```bash
systemctl show vpsmcp -p NRestarts --value
journalctl -u vpsmcp -n 60 --no-pager
```

Usually a YAML syntax error in the inventory or a `jump` alias that does not
exist; both raise on startup. Validate on its own with `sudo vpsmcp hosts`.

---

## <a name="enroll"></a>Enrollment fails

After writing the entry the gateway makes one SSH connection; on failure it rolls
back and returns the reason, which the node prints verbatim (add `-v` to the
installer for more).

- **Host key mismatch** - the node reported `/etc/ssh/ssh_host_*_key.pub` but the
  gateway reached a different sshd. Usually several sshd instances, or a port
  belonging to another instance.
- **Permission denied** - see [above](#ssh-auth).
- **Connection timed out** - the gateway cannot reach the node. The address used
  is the source IP of the enrollment request, which does not work for a node
  behind NAT; the node needs a reachable address and port, or a `jump` entry
  added by hand.
- **Refused before any SSH** - `VPSMCP_ENROLL_MODE` is `off` or `approve`, the
  source IP is outside `VPSMCP_ENROLL_ALLOW_CIDRS`, the key is wrong, or the rate
  limit kicked in.

```bash
sudo vpsmcp nodes
sudo tail -5 /var/lib/vpsmcp/audit.jsonl | jq 'select(.event|startswith("enroll"))'
```

---

## <a name="hash"></a>Password never accepted / how to reset it

Reset the admin password with one command (run on the gateway). It hashes the
new password, writes it into `/etc/vpsmcp/vpsmcp.env`, and restarts the service:

```bash
sudo vpsmcp set-password
```

`vpsmcp hash-password` only **prints** a hash - it does not change anything. If
you ran it, restarted, and the password still fails, that is why: the printed
line was never pasted into the env file. Use `set-password`, or paste the line
yourself (keep the single quotes) and restart.

**Passwords with `!` (or other shell metacharacters):** never put them on a
command line. `--password "a!b"` and `verify_password("a!b", ...)` in an
interactive shell both let bash history-expand the `!`, silently changing the
password. `set-password` (and the login form) read the password with `getpass`,
which is safe. To test a password against the stored hash without shell mangling:

```bash
sudo -u vpsmcp /opt/vpsmcp/.venv/bin/python - <<'EOF'
import getpass
from vpsmcp.auth.keys import verify_password
h = next(l.split("=",1)[1].strip().strip("'\"")
         for l in open("/etc/vpsmcp/vpsmcp.env")
         if l.startswith("VPSMCP_ADMIN_PASSWORD_HASH="))
print("MATCH" if verify_password(getpass.getpass("password: "), h) else "NO MATCH")
EOF
```

Locked out after several tries (a `429` "Try again in Ns" page) is not a wrong
password - clear it and check `VPSMCP_TRUSTED_PROXY_HOPS` matches your proxy
chain:

```bash
sudo vpsmcp unlock          # clear all login lockouts (or: sudo vpsmcp unlock <ip>)
```

### The `$` in the hash

`VPSMCP_ADMIN_PASSWORD_HASH` looks like `scrypt$32768$8$1$salt$dk`. Any shell
`source` of the env file expands `$32768`, `$8` and `$1` as positional
parameters:

```
in the file : scrypt$32768$8$1$PId_vhFgHzvM4-Mly...
after source: scrypt2768-Mly8HZKg...
```

With `set -u` this is an `unbound variable` error; without it, silent corruption.
Quote the value:

```bash
sudo sed -i "s#^VPSMCP_ADMIN_PASSWORD_HASH=\(.*\)#VPSMCP_ADMIN_PASSWORD_HASH='\1'#" /etc/vpsmcp/vpsmcp.env
sudo grep ADMIN_PASSWORD /etc/vpsmcp/vpsmcp.env     # check quotes are not doubled
sudo systemctl restart vpsmcp
```

The service itself is unaffected: systemd's `EnvironmentFile=` does not expand,
and the CLI parses line by line. `healthcheck.sh` and `gen-caddyfile.sh` read
values line by line too, never by sourcing.

---

## <a name="timeout"></a>Tool call times out

Almost always the wrong shape:

| Case | Tool |
|---|---|
| Command that finishes in seconds | `exec` |
| Debugging that needs cwd and variables to persist | `shell_open` + `shell_run` |
| Anything that may exceed a minute or two | `job_start` |
| Observing what a trigger produces | `log_open` → trigger → `log_read` |

`exec` timeouts kill the remote process and return `exit_code: 124` with
`timed_out: true`. A single command inside a persistent shell cannot be
interrupted; the timeout destroys the session. `job_start` detaches with `setsid`
and keeps state in `~/.vpsmcp/jobs/` on the node, so it survives a gateway restart.
