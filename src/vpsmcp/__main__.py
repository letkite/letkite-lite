"""Command line entry point.

    vpsmcp setup                    configure the gateway and self-test (sudo)
    vpsmcp serve                    run the server (used by systemd)
    vpsmcp caddyfile                print or write the reverse-proxy config
    vpsmcp check                    connectivity self-check for every node
    vpsmcp hosts                    inventory as TSV
    vpsmcp nodes [--json]           node list: node_id / alias / address / user
    vpsmcp node remove <id|alias>
    vpsmcp node scopes <id|alias> fleet.read,fleet.exec,fleet.write
    vpsmcp node rename|tags|approve ...
    vpsmcp grants                   active OAuth grants
    vpsmcp revoke <client_id>       revoke a client and its tokens
    vpsmcp unlock [ip]              clear the admin-login lockout (all IPs, or one)
    vpsmcp clients                  MCP clients this gateway accepts
    vpsmcp redirects                effective callback allowlist and refused callbacks
    vpsmcp redirect allow <uri>     allow one more callback, no restart
    vpsmcp redirect deny  <uri>
    vpsmcp set-password             set the admin password and restart (sudo)
    vpsmcp proxy                    run the egress forward proxy (used by systemd)
    vpsmcp proxy-password           set the egress-proxy password (sudo)
    vpsmcp hash-password            just print a password hash (does not apply it)
"""
from __future__ import annotations

import asyncio
import getpass
import json
import logging
import os
import shlex
import sys
import time
from pathlib import Path

from .settings import Settings

DEFAULT_ENV_FILE = "/etc/vpsmcp/vpsmcp.env"


def _load_env_file() -> str | None:
    """Load the env file ourselves: systemd uses EnvironmentFile=, but a manual
    invocation has no such step and sudo resets the environment. KEY=VALUE only,
    no shell expansion. Existing variables win."""
    path = Path(os.environ.get("VPSMCP_ENV_FILE", DEFAULT_ENV_FILE))
    try:
        # /etc/vpsmcp is 750 root:vpsmcp, so exists() itself can raise PermissionError
        if not path.exists():
            return None
        text = path.read_text(encoding="utf-8")
    except PermissionError:
        print(
            f"cannot read {path} (mode 640 root:vpsmcp).\n"
            f"Run as the service account:  sudo vpsmcp <command>",
            file=sys.stderr,
        )
        raise SystemExit(2)
    loaded = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = val
            loaded += 1
    return f"{path} ({loaded} variables)" if loaded else None


def _setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
    )
    # asyncssh logs every channel command at INFO
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


def cmd_serve() -> int:
    import uvicorn

    from .app import build

    s = Settings.from_env()
    mcp, _rt = build(s)
    app = mcp.http_app(path=s.mcp_path)
    logging.getLogger("vpsmcp").info(
        "listening on %s:%s   resource URL=%s",
        s.bind_host, s.bind_port, s.resource_url,
    )
    # proxy_headers=False on purpose: uvicorn would rewrite request.client from the
    # leftmost X-Forwarded-For (which the client can prefill), poisoning the very
    # value we fall back to. We keep request.client as the true TCP peer and derive
    # the real client ourselves (netutil.client_ip, VPSMCP_TRUSTED_PROXY_HOPS), so a
    # caller cannot forge its source address.
    uvicorn.run(app, host=s.bind_host, port=s.bind_port,
                proxy_headers=False, log_level="info")
    return 0


def cmd_hash_password() -> int:
    from .auth.keys import hash_password

    pw = getpass.getpass("new admin password: ")
    if len(pw) < 12:
        print("password must be at least 12 characters", file=sys.stderr)
        return 2
    if pw != getpass.getpass("repeat: "):
        print("passwords do not match", file=sys.stderr)
        return 2
    # quoted: the hash contains $ and would be expanded if the file were sourced
    print("\nVPSMCP_ADMIN_PASSWORD_HASH='" + hash_password(pw) + "'")
    print("\nThis only prints the hash. To actually change the password, either run"
          "\n  sudo vpsmcp set-password"
          "\nor paste the line above into /etc/vpsmcp/vpsmcp.env (keep the single"
          "\nquotes) and run: sudo systemctl restart vpsmcp", file=sys.stderr)
    return 0


def cmd_set_password() -> int:
    """Set the admin password and apply it: hash it, write the env file, restart."""
    import os

    from .auth.keys import hash_password
    from .setup import set_env_line

    if os.geteuid() != 0:
        print("run with sudo: sudo vpsmcp set-password", file=sys.stderr)
        return 1
    path = Path(os.environ.get("VPSMCP_ENV_FILE", DEFAULT_ENV_FILE))
    if not path.exists():
        print(f"{path} does not exist; run `sudo vpsmcp setup` first", file=sys.stderr)
        return 2
    # getpass reads the password raw from the tty: characters like ! that the shell
    # would mangle as an argument are safe here. Re-prompt instead of aborting.
    while True:
        pw = getpass.getpass("new admin password: ")
        if len(pw) < 12:
            print("password must be at least 12 characters; try again", file=sys.stderr)
            continue
        if pw != getpass.getpass("repeat: "):
            print("passwords do not match; try again", file=sys.stderr)
            continue
        break
    action = set_env_line(path, "VPSMCP_ADMIN_PASSWORD_HASH", hash_password(pw))
    print(f"{action} VPSMCP_ADMIN_PASSWORD_HASH in {path}")
    if Path("/run/systemd/system").is_dir():
        import subprocess
        r = subprocess.run(["systemctl", "restart", "vpsmcp"])
        print("restarted vpsmcp; the new password is live" if r.returncode == 0
              else "wrote the hash, but restart failed; run: sudo systemctl restart vpsmcp")
        return 0 if r.returncode == 0 else 1
    print("wrote the hash; now run: sudo systemctl restart vpsmcp")
    return 0


def cmd_proxy() -> int:
    """Run the authenticated egress forward proxy (nodes point http_proxy at it)."""
    import asyncio

    from .audit import Audit
    from .proxy import serve

    s = Settings.from_env()
    if not s.proxy_pass_hash:
        print("VPSMCP_PROXY_PASS_HASH is not set; run `sudo vpsmcp proxy-password` first",
              file=sys.stderr)
        return 2
    logging.getLogger("vpsmcp").info(
        "starting egress proxy on %s:%s", s.proxy_bind_host, s.proxy_bind_port)
    try:
        asyncio.run(serve(s, Audit(s.audit_path)))
    except KeyboardInterrupt:
        pass
    return 0


def cmd_proxy_password() -> int:
    """Set the egress-proxy password (VPSMCP_PROXY_PASS_HASH) in the env file."""
    import os

    from .auth.keys import hash_password
    from .setup import set_env_line

    if os.geteuid() != 0:
        print("run with sudo: sudo vpsmcp proxy-password", file=sys.stderr)
        return 1
    path = Path(os.environ.get("VPSMCP_ENV_FILE", DEFAULT_ENV_FILE))
    if not path.exists():
        print(f"{path} does not exist; run `sudo vpsmcp setup` first", file=sys.stderr)
        return 2
    while True:
        pw = getpass.getpass("new egress-proxy password: ")
        if len(pw) < 12:
            print("password must be at least 12 characters; try again", file=sys.stderr)
            continue
        if pw != getpass.getpass("repeat: "):
            print("passwords do not match; try again", file=sys.stderr)
            continue
        break
    set_env_line(path, "VPSMCP_PROXY_PASS_HASH", hash_password(pw))
    set_env_line(path, "VPSMCP_PROXY_ENABLE", "1")
    print(f"wrote VPSMCP_PROXY_PASS_HASH and VPSMCP_PROXY_ENABLE=1 in {path}")
    if Path("/run/systemd/system").is_dir():
        import subprocess
        unit = Path("/etc/systemd/system/vpsmcp-proxy.service")
        if not unit.exists():
            print("the vpsmcp-proxy unit is not installed yet; install it, then enable:\n"
                  "    sudo deploy/upgrade.sh --fast   # (or vpsmcp setup) installs the unit\n"
                  "    sudo systemctl enable --now vpsmcp-proxy")
            return 0
        active = subprocess.run(["systemctl", "is-active", "--quiet", "vpsmcp-proxy"]).returncode == 0
        if active:
            r = subprocess.run(["systemctl", "restart", "vpsmcp-proxy"])
            print("restarted vpsmcp-proxy; the new password is live" if r.returncode == 0
                  else "wrote the hash, but restart failed; check: journalctl -u vpsmcp-proxy")
        else:
            print("now start it: sudo systemctl enable --now vpsmcp-proxy")
    else:
        print("now start it: sudo systemctl enable --now vpsmcp-proxy")
    return 0


def cmd_check() -> int:
    from .inventory import load_inventory
    from .ssh.pool import SSHPool
    from .ssh.runner import run_command

    s = Settings.from_env()
    print(f"issuer       : {s.issuer}")
    print(f"resource URL : {s.resource_url}")
    print(f"clients      : {', '.join(s.clients) or '(none)'}")
    print(f"data dir     : {s.data_dir}")
    print(f"ssh key      : {s.ssh_key_path}  exists={s.ssh_key_path.exists()}")
    print(f"known_hosts  : {s.known_hosts_path}  strict={s.strict_host_keys}")
    inv = load_inventory(s.inventory_path)
    print(f"hosts        : {len(inv.hosts)}\n")

    async def probe() -> int:
        pool = SSHPool(s)
        bad = 0
        for alias, h in sorted(inv.hosts.items()):
            try:
                conn = await pool.acquire(h, inv)
                r = await run_command(conn, "id -un; uname -sr", timeout=15, max_bytes=4096)
                who = " / ".join(r.stdout.split())
                print(f"  ✓ {alias:<16} {h.user}@{h.address}:{h.port}  {who}")
            except Exception as exc:  # noqa: BLE001
                bad += 1
                print(f"  ✗ {alias:<16} {exc}")
        await pool.close()
        return bad

    bad = asyncio.run(probe())
    print(f"\n{len(inv.hosts) - bad} reachable, {bad} failed.")
    return 1 if bad else 0


def cmd_caddyfile(argv: list[str]) -> int:
    from . import caddy as caddymod

    def opt(n, d=""):
        return argv[argv.index(n) + 1] if n in argv and argv.index(n) + 1 < len(argv) else d

    def opts(n):
        """Every --flag <value> pair, so --allow-cidr can be repeated."""
        return tuple(argv[i + 1] for i, a in enumerate(argv)
                     if a == n and i + 1 < len(argv))

    s = Settings.from_env()
    host = s.public_url.split("://", 1)[-1].split("/")[0]
    conf = caddymod.render(
        host=host, upstream=f"{s.bind_host}:{s.bind_port}", mcp_path=s.mcp_path,
        email=opt("--email") or None, log_file=opt("--log-file") or None,
        lock_anthropic="--lock-anthropic" in argv,
        route53_zone=opt("--dns-route53") or None,
        allow_cidrs=opts("--allow-cidr"))
    out = opt("-o") or opt("--out")
    if not out:
        print(conf)
        return 0
    good, msg = caddymod.write(conf, out)
    print(msg, file=sys.stderr)
    if good and "--reload" in argv:
        good2, m2 = caddymod.reload()
        print(f"Caddy {m2}", file=sys.stderr)
        return 0 if good2 else 1
    return 0 if good else 1


def cmd_hosts() -> int:
    """Machine-readable output for scripts; uses the same loader as the service."""
    from .inventory import load_inventory

    s = Settings.from_env()
    inv = load_inventory(s.inventory_path)
    for h in sorted(inv.hosts.values(), key=lambda x: x.alias):
        print(f"{h.alias}\t{h.address}\t{h.port}\t{h.user}\t{','.join(h.tags)}")
    return 0


def _bits():
    from .enroll import EnrollStore
    from .inventory import InventoryWatcher
    st = Settings.from_env()
    return st, EnrollStore(st.data_dir / "oauth.db"), InventoryWatcher(st.inventory_path)


def cmd_nodes(argv: list[str]) -> int:
    """Admin view: one line per machine, identified by address and user."""
    st, store, watcher = _bits()
    inv = watcher.get()
    pend = {p["node_id"]: p for p in store.pending()}
    seen = {n["node_id"]: n for n in store.nodes()}
    if "--json" in argv:
        rows = [{"node_id": h.node_id, "alias": h.alias, "address": h.address,
                 "user": h.user, "port": h.port, "tags": list(h.tags),
                 "scopes": list(h.scopes), "state": "active",
                 "last_seen": seen.get(h.node_id, {}).get("last_seen")}
                for h in inv.hosts.values()]
        rows += [{**p, "state": "pending"} for p in pend.values()]
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    if not inv.hosts and not pend:
        print("No nodes yet.")
        print(f"On a target machine: curl -sSf {st.public_url}/enroll/install.sh | sudo bash")
        return 0
    print(f"{'NODE_ID':<14}{'ALIAS':<18}{'ADDRESS':<22}{'USER':<10}{'STATE':<10}TAGS")
    for h in sorted(inv.hosts.values(), key=lambda x: (x.alias, x.address)):
        addr = f"{h.address}:{h.port}"
        print(f"{h.node_id:<14}{h.alias:<18}{addr:<22}{h.user:<10}{'active':<10}"
              f"{','.join(h.tags)}")
    for p in pend.values():
        addr = f"{p['address']}:{p['port']}"
        print(f"{p['node_id']:<14}{p['alias']:<18}{addr:<22}{p['user']:<10}{'pending':<10}"
              f"{','.join(p.get('tags') or [])}")
    dupes = {}
    for h in inv.hosts.values():
        dupes.setdefault(h.alias, []).append(h)
    for alias, group in dupes.items():
        if len(group) > 1:
            print(f"\nNote: alias {alias!r} maps to {len(group)} hosts; use node_id.")
    return 0


def cmd_node(argv: list[str]) -> int:
    sub = argv[2] if len(argv) > 2 else ""
    args = argv[3:]
    from .inventory import InventoryError, remove_host, write_host
    st, store, watcher = _bits()

    def resolve(key: str):
        try:
            return watcher.get().get(key)
        except InventoryError as exc:
            print(exc, file=sys.stderr)
            raise SystemExit(1)

    if sub == "remove" and args:
        h = resolve(args[0])
        remove_host(st.inventory_path, h.node_id)
        store.forget(h.node_id)
        print(f"removed {h.label}  [{h.node_id}]")
        print(f"On the node: curl -sSf {st.public_url}/enroll/install.sh | "
              f"sudo bash -s -- --uninstall --user {h.user}")
        return 0

    if sub == "scopes" and len(args) >= 2:
        h = resolve(args[0])
        scopes = [x for x in args[1].split(",") if x]
        write_host(st.inventory_path, {
            "alias": h.alias, "address": h.address, "port": h.port, "user": h.user,
            "host_key": h.host_key, "tags": list(h.tags), "scopes": scopes,
            "sudo": h.sudo, "notes": h.notes})
        print(f"{h.label} scopes -> {', '.join(scopes)}")
        return 0

    if sub == "rename" and len(args) >= 2:
        h = resolve(args[0])
        write_host(st.inventory_path, {
            "alias": args[1], "address": h.address, "port": h.port, "user": h.user,
            "host_key": h.host_key, "tags": list(h.tags), "scopes": list(h.scopes),
            "sudo": h.sudo, "notes": h.notes})
        print(f"{h.node_id} alias {h.alias} -> {args[1]}")
        return 0

    if sub == "tags" and len(args) >= 2:
        h = resolve(args[0])
        write_host(st.inventory_path, {
            "alias": h.alias, "address": h.address, "port": h.port, "user": h.user,
            "host_key": h.host_key, "tags": [x for x in args[1].split(",") if x],
            "scopes": list(h.scopes), "sudo": h.sudo, "notes": h.notes})
        print(f"{h.label} tags -> {args[1]}")
        return 0

    if sub == "approve" and args:
        host = store.take_pending(args[0])
        if host is None:
            print(f"{args[0]} is not pending", file=sys.stderr)
            return 1
        write_host(st.inventory_path, host)
        print(f"approved {host['alias']} ({host['user']}@{host['address']})")
        return 0

    print("""usage:
  vpsmcp nodes [--json]
  vpsmcp node remove  <node_id|alias>
  vpsmcp node scopes  <node_id|alias> fleet.read,fleet.exec,fleet.write
  vpsmcp node rename  <node_id|alias> <new-alias>
  vpsmcp node tags    <node_id|alias> a,b
  vpsmcp node approve <node_id>""", file=sys.stderr)
    return 2


def _safe(text: str, limit: int = 300) -> str:
    """Anything a client sent is printed through this: no control characters (an
    ANSI escape would rewrite the terminal), length capped."""
    s = "".join(ch if ch.isprintable() else "?" for ch in str(text or ""))
    return s[:limit] + ("..." if len(s) > limit else "")


def _oauth_store():
    from .auth.store import Store
    s = Settings.from_env()
    return s, Store(s.data_dir / "oauth.db")


def cmd_clients(argv: list[str]) -> int:
    """Which MCP clients may complete a login, and where each one calls back."""
    from .auth.clients import PROFILES, unknown_keys

    s, store = _oauth_store()
    on = [k.strip().lower() for k in s.clients]
    if "--json" in argv:
        print(json.dumps({
            "enabled": on,
            "profiles": {k: {"name": v.name, "redirects": list(v.redirects),
                             "enabled": k in on} for k, v in PROFILES.items()},
            "extra_redirects": list(s.extra_redirect_prefixes),
            "runtime_redirects": list(store.redirect_prefixes()),
        }, ensure_ascii=False, indent=2))
        return 0
    print(f"resource URL : {s.resource_url}    <- enter this in the client\n")
    print(f"{'CLIENT':<10}{'STATE':<10}{'NAME':<26}CALLBACKS")
    for key, prof in PROFILES.items():
        state = "on" if key in on else "off"
        print(f"{key:<10}{state:<10}{prof.name:<26}{prof.redirects[0]}")
        for extra in prof.redirects[1:]:
            print(f"{'':<46}{extra}")
        if prof.notes:
            print(f"{'':<20}{prof.notes}")
    bad = unknown_keys(s.clients)
    if bad:
        print(f"\nVPSMCP_CLIENTS has unknown entries, ignored: {', '.join(bad)}")
    print("\nTurn one on or off with VPSMCP_CLIENTS in /etc/vpsmcp/vpsmcp.env, "
          "then restart:\n    sudo systemctl restart vpsmcp")
    return 0


def cmd_redirects(argv: list[str]) -> int:
    """Callbacks that would be accepted now, and the ones that were turned away."""
    from .auth.clients import profile_for_redirect

    s, store = _oauth_store()
    runtime = store.redirect_prefixes()
    rejected = store.rejected_redirects()
    if "--json" in argv:
        print(json.dumps({"allowed": list(s.allowed_redirect_prefixes) + list(runtime),
                          "runtime": store.redirect_allow_rows(),
                          "rejected": rejected}, ensure_ascii=False, indent=2))
        return 0
    print("allowed callback prefixes")
    for pre in s.allowed_redirect_prefixes:
        prof = profile_for_redirect(pre, s.clients)
        print(f"  {pre:<52}{prof.key if prof else 'VPSMCP_ALLOWED_REDIRECTS'}")
    for row in store.redirect_allow_rows():
        note = f"  ({_safe(row['note'], 40)})" if row["note"] else ""
        print(f"  {_safe(row['prefix'], 52):<52}added by hand{note}")
    if not rejected:
        print("\nNo refused callbacks recorded.")
        return 0
    print(f"\nrefused callbacks ({len(rejected)}) - a client that cannot finish "
          f"authorizing shows up here")
    for r in rejected:
        when = time.strftime("%Y-%m-%d %H:%M", time.localtime(r["last_seen"]))
        print(f"  {when}  x{r['hits']:<4}{_safe(r['client_name'], 60) or '?'}")
        print(f"    {_safe(r['uri'], 400)}")
    print("\nAllow one (it is where the authorization code is sent - only a URL you "
          "recognise):")
    # shell-quoted: the URL came from a client and this line gets pasted into a shell
    print(f"    sudo vpsmcp redirect allow {shlex.quote(_safe(rejected[0]['uri'], 400))}")
    return 0


def cmd_redirect(argv: list[str]) -> int:
    sub = argv[2] if len(argv) > 2 else ""
    uri = argv[3] if len(argv) > 3 else ""
    s, store = _oauth_store()
    if sub == "allow" and uri:
        if not uri.startswith("https://") and not uri.startswith("http://127.0.0.1") \
                and not uri.startswith("http://localhost"):
            print("a callback must be https, or http on a loopback address",
                  file=sys.stderr)
            return 2
        store.allow_redirect(uri, note=f"added {time.strftime('%Y-%m-%d')}")
        print(f"allowed {uri}")
        print("Takes effect immediately; the allowlist is read per request.")
        return 0
    if sub == "deny" and uri:
        if store.disallow_redirect(uri):
            print(f"removed {uri}")
            print("Prefixes from the client profiles and VPSMCP_ALLOWED_REDIRECTS are "
                  "not stored here; change VPSMCP_CLIENTS or the env file for those.")
            return 0
        print(f"{uri} is not a hand-added prefix; `vpsmcp redirects` lists them",
              file=sys.stderr)
        return 1
    if sub == "clear-rejected":
        store.clear_rejected_redirects()
        print("cleared the refused-callback list")
        return 0
    print("""usage:
  vpsmcp redirects [--json]
  vpsmcp redirect allow <uri>
  vpsmcp redirect deny  <uri>
  vpsmcp redirect clear-rejected""", file=sys.stderr)
    return 2


def cmd_grants() -> int:
    from .auth.store import Store

    s = Settings.from_env()
    store = Store(s.data_dir / "oauth.db")
    print(json.dumps({"clients": store.list_clients(),
                      "active_grants": store.active_grants()},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_unlock(argv: list[str]) -> int:
    """Clear the consent-page login lockout (login_attempts). Handy after too many
    failed tries, or when a proxy/CDN buckets everyone under one IP."""
    from .auth.store import Store

    s = Settings.from_env()
    store = Store(s.data_dir / "oauth.db")
    ip = argv[2] if len(argv) > 2 else None
    locks = store.login_locks()
    if not locks:
        print("no login lockouts recorded")
        return 0
    n = store.clear_login_locks(ip)
    if ip:
        print(f"cleared lockout for {ip} ({n} row(s))")
    else:
        print(f"cleared {n} login lockout(s): " +
              ", ".join(f"{l['ip']}(fails={l['fails']})" for l in locks))
    return 0


def cmd_revoke(client_id: str) -> int:
    from .auth.store import Store

    s = Settings.from_env()
    store = Store(s.data_dir / "oauth.db")
    store.delete_client(client_id)
    print(f"deleted client {client_id} and revoked its refresh tokens")
    return 0


def main(argv: list[str]) -> int:
    _setup_logging()
    cmd = argv[1] if len(argv) > 1 else "serve"
    if cmd not in ("hash-password", "set-password", "proxy-password", "setup"):
        src = _load_env_file()
        if src and cmd != "serve":
            print(f"config: {src}\n", file=sys.stderr)
    try:
        return _dispatch(cmd, argv)
    except RuntimeError as exc:
        # a missing setting should not produce a traceback
        print(f"\nconfiguration error: {exc}", file=sys.stderr)
        print(
            f"check that {os.environ.get('VPSMCP_ENV_FILE', DEFAULT_ENV_FILE)} exists "
            f"and is readable; run commands as `sudo vpsmcp ...`",
            file=sys.stderr,
        )
        return 2


def _dispatch(cmd: str, argv: list[str]) -> int:
    if cmd == "serve":
        return cmd_serve()
    if cmd in ("hash-password", "hash_password"):
        return cmd_hash_password()
    if cmd in ("set-password", "set_password"):
        return cmd_set_password()
    if cmd == "proxy":
        return cmd_proxy()
    if cmd in ("proxy-password", "proxy_password"):
        return cmd_proxy_password()
    if cmd == "check":
        return cmd_check()
    if cmd == "setup":
        from .setup import run as setup_run
        return setup_run(argv)
    if cmd == "caddyfile":
        return cmd_caddyfile(argv)
    if cmd == "hosts":
        return cmd_hosts()
    if cmd == "nodes":
        return cmd_nodes(argv)
    if cmd == "node":
        return cmd_node(argv)
    if cmd == "clients":
        return cmd_clients(argv)
    if cmd == "redirects":
        return cmd_redirects(argv)
    if cmd == "redirect":
        return cmd_redirect(argv)
    if cmd == "grants":
        return cmd_grants()
    if cmd == "revoke":
        if len(argv) < 3:
            print("usage: vpsmcp revoke <client_id>", file=sys.stderr)
            return 2
        return cmd_revoke(argv[2])
    if cmd == "unlock":
        return cmd_unlock(argv)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
