"""Node enrollment.

Nodes pull; the gateway never dials an unknown machine. Trust:
  node -> gateway: TLS certificate
  gateway -> node: admission gate (mode / key / CIDR), then a live SSH check
  host identity:   node reports its own host key (TOFU), pinned on first contact

Only two things land on a node: a low-privilege account and the gateway's
public key. No code, no private keys, no certificates.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import sys
import json
import logging
import secrets
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

from .netutil import client_ip

log = logging.getLogger("vpsmcp.enroll")

SCHEMA = """
-- Identity is node_id (hash of address:port:user); alias is a label and may repeat.
CREATE TABLE IF NOT EXISTS nodes (
    node_id    TEXT PRIMARY KEY,
    alias      TEXT NOT NULL,
    address    TEXT NOT NULL,
    node_user  TEXT NOT NULL,
    port       INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    enrolls    INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS pending (
    node_id    TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS enroll_attempts (
    ip TEXT PRIMARY KEY, fails INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0
);
"""


def _h(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


class EnrollStore:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    def _x(self, sql: str, args: tuple = ()) -> None:
        with self._lock:
            self._db.execute(sql, args)
            self._db.commit()

    def _q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # ---- node registry (admin view) ----
    def seen(self, node_id: str, address: str, user: str, port: int, alias: str) -> None:
        now = int(time.time())
        if self._q("SELECT 1 FROM nodes WHERE node_id=?", (node_id,)):
            self._x("UPDATE nodes SET alias=?, last_seen=?, enrolls=enrolls+1 WHERE node_id=?",
                    (alias, now, node_id))
        else:
            self._x("INSERT INTO nodes VALUES(?,?,?,?,?,?,?,1)",
                    (node_id, alias, address, user, int(port), now, now))

    def nodes(self) -> list[dict]:
        return [dict(r) for r in self._q("SELECT * FROM nodes ORDER BY last_seen DESC")]

    def forget(self, node_id: str) -> None:
        self._x("DELETE FROM nodes WHERE node_id=?", (node_id,))
        self._x("DELETE FROM pending WHERE node_id=?", (node_id,))

    # ---- approval queue (VPSMCP_ENROLL_MODE=approve) ----
    def pend(self, node_id: str, host: dict) -> None:
        self._x("INSERT OR REPLACE INTO pending VALUES(?,?,?)",
                (node_id, json.dumps(host, ensure_ascii=False), int(time.time())))

    def pending(self) -> list[dict]:
        out = []
        for r in self._q("SELECT * FROM pending ORDER BY created_at DESC"):
            d = json.loads(r["payload"])
            d["node_id"] = r["node_id"]
            d["created_at"] = r["created_at"]
            out.append(d)
        return out

    def take_pending(self, node_id: str) -> dict | None:
        rows = self._q("SELECT * FROM pending WHERE node_id=?", (node_id,))
        if not rows:
            return None
        self._x("DELETE FROM pending WHERE node_id=?", (node_id,))
        return json.loads(rows[0]["payload"])

    # ---- rate limit ----
    def locked(self, ip: str) -> int:
        rows = self._q("SELECT * FROM enroll_attempts WHERE ip=?", (ip,))
        return max(0, rows[0]["locked_until"] - int(time.time())) if rows else 0

    def failed(self, ip: str) -> None:
        rows = self._q("SELECT * FROM enroll_attempts WHERE ip=?", (ip,))
        n = (rows[0]["fails"] if rows else 0) + 1
        lock = int(time.time()) + min(1800, 2 ** min(n, 11)) if n >= 5 else 0
        self._x("INSERT OR REPLACE INTO enroll_attempts VALUES(?,?,?)", (ip, n, lock))

    def ok(self, ip: str) -> None:
        self._x("DELETE FROM enroll_attempts WHERE ip=?", (ip,))

    def gc(self) -> None:
        self._x("DELETE FROM pending WHERE created_at < ?", (int(time.time()) - 30 * 86400,))


# ────────────────────────────────────────────────────────────────────
ENROLL_SH = r'''#!/usr/bin/env bash
# Node enrollment. Silent: no output on success, exit 0.
#
#   curl -sSf __BASE__/enroll/install.sh | sudo bash
#   curl -sSf __BASE__/enroll/install.sh | sudo bash -s -- --alias web-01 --tags prod
#   curl -sSf __BASE__/enroll/install.sh | bash -s -- --rootless   # no root
#
#   --alias NAME   node name, defaults to this machine's hostname
#   --tags a,b     tags
#   --user NAME    local account to create, default __DEFUSER__ (root mode only)
#   --self         use the current login user ($SUDO_USER) as the node account
#                  instead of the shared default; see the sudo note under --rootless
#   --rootless     enroll the current user without root; no account is created
#                  and sshd is not touched, so PubkeyAuthentication must already
#                  be enabled for you. The gateway then logs in as your own user,
#                  which is only as isolated as that account - do not use it for a
#                  user that can sudo unless you accept the gateway acting as root.
#   --port N       SSH port to register; needed with --rootless on a non-default
#                  port, since detecting it from sshd usually needs root
#   --proxy URL    route this account's egress through the gateway proxy, e.g.
#                  http://node:PASS@mcp.example.com:8443 ; toggle with vpsmcp-proxy
#   -k KEY         enrollment key, if the server requires one
#   -v             verbose, for troubleshooting
#   --uninstall    detach this machine
set -euo pipefail

BASE="__BASE__"
ALIAS=""
NODE_USER="__DEFUSER__"
TAGS=""
KEY=""
V=0
MODE=install
ROOTLESS=0
SELF=0
PORT_OVERRIDE=""
PROXY_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --alias) ALIAS="${2:-}"; shift 2 ;;
    --tags)  TAGS="${2:-}";  shift 2 ;;
    --user)  NODE_USER="${2:-}"; shift 2 ;;
    --rootless) ROOTLESS=1; shift ;;
    --self) SELF=1; shift ;;
    --port) PORT_OVERRIDE="${2:-}"; shift 2 ;;
    --proxy) PROXY_URL="${2:-}"; shift 2 ;;
    -k|--key) KEY="${2:-}"; shift 2 ;;
    -v|--verbose) V=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    *) shift ;;
  esac
done

log() { [[ $V -eq 1 ]] && printf '%s\n' "$*" >&2 || true; }
die() { printf 'vpsmcp: %s\n' "$1" >&2; exit "${2:-1}"; }

# Root creates a dedicated unprivileged account and can enable pubkey auth.
# Without root, --rootless enrolls the current user in place instead.
if [[ $EUID -ne 0 ]]; then
  [[ $ROOTLESS -eq 1 ]] || die "root required; re-run with sudo, or pass --rootless to enroll your own user without root (needs PubkeyAuthentication already enabled for you)"
fi
[[ $EUID -eq 0 ]] && ROOTLESS=0
if [[ $ROOTLESS -eq 1 ]]; then
  ME="$(id -un)"
  [[ "$NODE_USER" == "__DEFUSER__" || "$NODE_USER" == "$ME" ]] \
    || log "ignoring --user $NODE_USER; rootless enrolls the current user"
  NODE_USER="$ME"
elif [[ $SELF -eq 1 || "$NODE_USER" == "@session" ]]; then
  # Enroll the login user who ran this (the one behind sudo), not the shared
  # default account. Under `sudo bash` the current user is root, so the real
  # login user is $SUDO_USER. This makes the gateway log in as that account,
  # which is only as isolated as it is - do not use it for a user that can sudo.
  NODE_USER="${SUDO_USER:-$(id -un)}"
  [[ "$NODE_USER" != "root" ]] \
    || die "--self needs a login user; run it via sudo as that user, or pass --user NAME"
  log "enrolling the login user $NODE_USER"
fi
[[ -n "$ALIAS" ]] || ALIAS="$(hostname -s 2>/dev/null || hostname || echo node)"
ALIAS="$(printf '%s' "$ALIAS" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-64)"

SSHD=$(command -v sshd || echo /usr/sbin/sshd)
[[ -x "$SSHD" ]] || die "no sshd on this machine"

if [[ "$MODE" == uninstall ]]; then
  log "removing $NODE_USER"
  if id -u "$NODE_USER" >/dev/null 2>&1; then
    HOME_DIR=$(getent passwd "$NODE_USER" | cut -d: -f6)
    GW=$(curl -sSf "$BASE/enroll/pubkey" 2>/dev/null || echo "")
    f="$HOME_DIR/.ssh/authorized_keys"
    if [[ -f "$f" && -n "$GW" ]]; then
      kp=$(printf '%s' "$GW" | awk '{print $2}')
      tmp=$(mktemp); grep -vF "$kp" "$f" > "$tmp" || true; cp "$tmp" "$f"; rm -f "$tmp"
    fi
    rm -rf "$HOME_DIR/.vpsmcp" 2>/dev/null || true
    rm -f "/etc/ssh/sshd_config.d/60-vpsmcp-$NODE_USER.conf" 2>/dev/null || true
  fi
  PORT=$($SSHD -T 2>/dev/null | awk '/^port /{print $2; exit}') || PORT=""
  PORT="${PORT:-22}"
  [[ -n "$PORT_OVERRIDE" ]] && PORT="$PORT_OVERRIDE"
  curl -sSf -X POST "$BASE/enroll/deregister" -H 'content-type: application/json' \
       --data "{\"user\":\"$NODE_USER\",\"port\":$PORT}" >/dev/null 2>&1 || true
  exit 0
fi

# sshd: public key auth
log "checking sshd"
PORT=$($SSHD -T 2>/dev/null | awk '/^port /{print $2; exit}') || PORT=""
PORT="${PORT:-22}"
[[ -n "$PORT_OVERRIDE" ]] && PORT="$PORT_OVERRIDE"
if [[ $ROOTLESS -eq 0 ]]; then
  PK=$($SSHD -T -C "user=$NODE_USER,host=127.0.0.1,addr=127.0.0.1" 2>/dev/null \
       | awk '/^pubkeyauthentication/{print $2}') || PK=""
  if [[ "$PK" == "no" ]]; then
    log "enabling public key auth for $NODE_USER"
    install -d -m 755 /etc/ssh/sshd_config.d
    printf 'Match User %s\n    PubkeyAuthentication yes\n' "$NODE_USER" \
      > "/etc/ssh/sshd_config.d/60-vpsmcp-$NODE_USER.conf"
    $SSHD -t 2>/dev/null || {
      rm -f "/etc/ssh/sshd_config.d/60-vpsmcp-$NODE_USER.conf"
      die "cannot enable public key auth for this account"
    }
    NEW=$($SSHD -T -C "user=$NODE_USER,host=127.0.0.1,addr=127.0.0.1" 2>/dev/null \
          | awk '/^pubkeyauthentication/{print $2}') || NEW=""
    [[ "$NEW" == "yes" ]] || die "public key auth overridden by another config"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null \
      || service ssh reload >/dev/null 2>&1 || true
  fi
else
  # Rootless cannot change sshd; warn if we can even tell it is off. sshd -T
  # usually needs root, so this is best-effort - the gateway's connect-back is
  # the real check, and it fails clearly if pubkey auth is disabled for you.
  PK=$($SSHD -T -C "user=$NODE_USER,host=127.0.0.1,addr=127.0.0.1" 2>/dev/null \
       | awk '/^pubkeyauthentication/{print $2}') || PK=""
  [[ "$PK" == "no" ]] && printf 'vpsmcp: warning: PubkeyAuthentication is off for %s; enrollment will fail until an admin enables it\n' "$NODE_USER" >&2
fi

# account
GW_PUBKEY=$(curl -sSf "$BASE/enroll/pubkey" 2>/dev/null) || die "cannot reach the service" 4
[[ "$GW_PUBKEY" == ssh-* ]] || die "unexpected response from the service" 4

if [[ $ROOTLESS -eq 0 ]]; then
  log "configuring $NODE_USER"
  id -u "$NODE_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$NODE_USER"
  # useradd leaves '!' in shadow; harmless with UsePAM yes, rejected with UsePAM no
  cur=$(getent shadow "$NODE_USER" | cut -d: -f2)
  case "$cur" in ""|"!"|"!!") usermod -p '*' "$NODE_USER" ;; esac
  HOME_DIR=$(getent passwd "$NODE_USER" | cut -d: -f6)
  [[ -n "$HOME_DIR" ]] || die "$NODE_USER has no home directory"

  install -d -m 700 -o "$NODE_USER" -g "$NODE_USER" "$HOME_DIR/.ssh"
  touch "$HOME_DIR/.ssh/authorized_keys"
  grep -qxF "$GW_PUBKEY" "$HOME_DIR/.ssh/authorized_keys" \
    || echo "$GW_PUBKEY" >> "$HOME_DIR/.ssh/authorized_keys"
  chmod 600 "$HOME_DIR/.ssh/authorized_keys"
  chown -R "$NODE_USER:$NODE_USER" "$HOME_DIR/.ssh"
  # install -d only applies -o to the last component, so create both explicitly
  install -d -m 700 -o "$NODE_USER" -g "$NODE_USER" "$HOME_DIR/.vpsmcp"
  install -d -m 700 -o "$NODE_USER" -g "$NODE_USER" "$HOME_DIR/.vpsmcp/jobs"
else
  log "configuring your own account ($NODE_USER)"
  HOME_DIR="${HOME:-$(getent passwd "$NODE_USER" | cut -d: -f6)}"
  [[ -n "$HOME_DIR" ]] || die "$NODE_USER has no home directory"
  # Own home: no root, no chown - we already own everything we touch.
  mkdir -p "$HOME_DIR/.ssh"; chmod 700 "$HOME_DIR/.ssh"
  touch "$HOME_DIR/.ssh/authorized_keys"
  grep -qxF "$GW_PUBKEY" "$HOME_DIR/.ssh/authorized_keys" \
    || echo "$GW_PUBKEY" >> "$HOME_DIR/.ssh/authorized_keys"
  chmod 600 "$HOME_DIR/.ssh/authorized_keys"
  mkdir -p "$HOME_DIR/.vpsmcp/jobs"; chmod 700 "$HOME_DIR/.vpsmcp" "$HOME_DIR/.vpsmcp/jobs"
fi

# optional: route this account's egress through the gateway proxy (--proxy URL).
# Per-account only: writes ~/.vpsmcp/proxy.sh and sources it from the account's
# shell rc; a `vpsmcp-proxy on|off|status` toggle flips between the gateway proxy
# and the system default. Activated on deploy; the node can switch at any time.
if [[ -n "$PROXY_URL" ]]; then
  log "configuring egress proxy for $NODE_USER"
  vdir="$HOME_DIR/.vpsmcp"; mkdir -p "$vdir"
  cat > "$vdir/proxy.sh" <<PROXYEOF
# vpsmcp egress proxy (per-account). Managed by enrollment; edit the URL here.
VPSMCP_GATEWAY_PROXY='$PROXY_URL'
__vpsmcp_pstate="\$HOME/.vpsmcp/proxy.state"
vpsmcp_proxy_apply() {
  if [ "\$(cat "\$__vpsmcp_pstate" 2>/dev/null)" = gateway ]; then
    export http_proxy="\$VPSMCP_GATEWAY_PROXY" https_proxy="\$VPSMCP_GATEWAY_PROXY"
    export HTTP_PROXY="\$VPSMCP_GATEWAY_PROXY" HTTPS_PROXY="\$VPSMCP_GATEWAY_PROXY"
  fi
}
vpsmcp-proxy() {
  case "\${1:-status}" in
    on|gateway) echo gateway > "\$__vpsmcp_pstate"; vpsmcp_proxy_apply
                echo "egress: gateway (\$VPSMCP_GATEWAY_PROXY)" ;;
    off|system) echo system > "\$__vpsmcp_pstate"
                unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
                echo "egress: system (proxy env cleared for new shells)" ;;
    status)     echo "egress: \$(cat "\$__vpsmcp_pstate" 2>/dev/null || echo system)" ;;
    *) echo "usage: vpsmcp-proxy on|off|status" >&2; return 2 ;;
  esac
}
vpsmcp_proxy_apply
PROXYEOF
  echo gateway > "$vdir/proxy.state"   # activated at deploy time
  for rc in "$HOME_DIR/.bashrc" "$HOME_DIR/.profile"; do
    touch "$rc"
    grep -q 'vpsmcp/proxy.sh' "$rc" 2>/dev/null \
      || printf '\n[ -f "$HOME/.vpsmcp/proxy.sh" ] && . "$HOME/.vpsmcp/proxy.sh"\n' >> "$rc"
  done
  chmod 700 "$vdir"; chmod 600 "$vdir/proxy.sh" "$vdir/proxy.state"
  [[ $ROOTLESS -eq 0 ]] && chown -R "$NODE_USER:$NODE_USER" "$vdir" \
      "$HOME_DIR/.bashrc" "$HOME_DIR/.profile" 2>/dev/null || true
fi

# register
log "registering $ALIAS"
HK=""
for t in ed25519 ecdsa rsa; do
  f="/etc/ssh/ssh_host_${t}_key.pub"
  [[ -f "$f" ]] && { HK=$(awk '{print $1" "$2}' "$f"); break; }
done
[[ -n "$HK" ]] || die "no SSH host key found"

json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
PAYLOAD=$(printf '{"alias":"%s","host_key":"%s","port":%s,"user":"%s","tags":"%s","hostname":"%s","os":"%s","arch":"%s"}' \
  "$(json_esc "$ALIAS")" "$(json_esc "$HK")" "$PORT" "$(json_esc "$NODE_USER")" \
  "$(json_esc "$TAGS")" \
  "$(json_esc "$(hostname -f 2>/dev/null || hostname)")" \
  "$(json_esc "$( ( . /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -s)")" \
  "$(json_esc "$(uname -m)")")

# no -f: the failure reason is in the response body
RESP=$(curl -sS -m 60 -w '\n__C__%{http_code}' -X POST "$BASE/enroll/register" \
       -H 'content-type: application/json' ${KEY:+-H "x-enroll-key: $KEY"} \
       --data "$PAYLOAD" 2>&1) || RESP=$'\n__C__000'
CODE="${RESP##*__C__}"
BODY="${RESP%$'\n'__C__*}"
if [[ "$CODE" != "200" ]]; then
  REASON=$(printf '%s' "$BODY" | sed -n 's/.*"msg":"\([^"]*\)".*/\1/p')
  ERRC=$(printf '%s' "$BODY" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')
  die "${REASON:-registration failed}${ERRC:+ ($ERRC)}" 5
fi
log "done"
exit 0
'''

UNINSTALL_SH = r'''#!/usr/bin/env bash
# Detach this machine. No token needed: it only touches local state.
#   curl -sSf <base>/enroll/uninstall.sh | sudo bash -s -- --user ops [--purge]
set -euo pipefail
NODE_USER="ops"; PURGE=0
while [[ $# -gt 0 ]]; do case "$1" in
  --user) NODE_USER="$2"; shift 2 ;;
  --purge) PURGE=1; shift ;;
  *) shift ;;
esac; done
[[ $EUID -eq 0 ]] || { echo "root required" >&2; exit 1; }
id -u "$NODE_USER" >/dev/null 2>&1 || exit 0
HOME_DIR=$(getent passwd "$NODE_USER" | cut -d: -f6)

GW_PUBKEY="__PUBKEY__"
f="$HOME_DIR/.ssh/authorized_keys"
if [[ -f "$f" ]]; then
  # match on the key material, not the comment
  KEYPART=$(echo "$GW_PUBKEY" | awk '{print $2}')
  tmp=$(mktemp)
  if [[ -n "$KEYPART" && "$KEYPART" != "__PUB"* ]]; then
    grep -vF "$KEYPART" "$f" > "$tmp" || true
  else
    grep -v 'vpsmcp-gateway' "$f" > "$tmp" || true
  fi
  if [[ -n "$KEYPART" ]] && grep -qF "$KEYPART" "$tmp"; then
    echo "removal failed, file unchanged" >&2; rm -f "$tmp"; exit 1
  fi
  cp "$tmp" "$f"; rm -f "$tmp"
fi
rm -rf "$HOME_DIR/.vpsmcp" 2>/dev/null || true
rm -f "/etc/ssh/sshd_config.d/60-vpsmcp-$NODE_USER.conf" 2>/dev/null && {
  sshd -t 2>/dev/null && { systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true; }
}
if [[ $PURGE -eq 1 ]]; then
  pkill -u "$NODE_USER" 2>/dev/null || true
  userdel -r "$NODE_USER" 2>/dev/null || true
fi
exit 0
'''


class EnrollService:
    """Fixed endpoint, no token, permanently valid.

    Trade-off: anyone who knows the URL can add a machine they control to the
    inventory. They gain no access to your other hosts (only the gateway public
    key is handed out), but your sessions would operate on their box. Three gates:

        VPSMCP_ENROLL_MODE=open|approve|off
        VPSMCP_ENROLL_KEY=<secret>            installer must pass -k
        VPSMCP_ENROLL_ALLOW_CIDRS=1.2.3.0/24
    """

    def __init__(self, settings, store: EnrollStore, inventory, pool, audit):
        self.s = settings
        self.store = store
        self.inv = inventory
        self.pool = pool
        self.audit = audit

    # ---------- helpers ----------
    def _ip(self, request: Request) -> str:
        return client_ip(request, self.s.trusted_proxy_hops)

    def _pubkey(self) -> str:
        p = Path(str(self.s.ssh_key_path) + ".pub")
        if not p.exists():
            raise FileNotFoundError("gateway key missing")
        return p.read_text(encoding="utf-8").strip()

    def _base(self, request: Request) -> str:
        host = request.headers.get("host", "")
        if host.startswith(("127.0.0.1", "localhost")):
            return f"http://{host}"
        return self.s.public_url

    def _gate(self, request: Request) -> tuple[str, str] | None:
        """Return (code, msg) to reject, None to allow. Messages leak no server detail."""
        ip = self._ip(request)
        if self.s.enroll_mode == "off":
            return ("E_CLOSED", "enrollment is disabled")
        if self.store.locked(ip):
            return ("E_RATE", "too many attempts, try again later")
        cidrs = self.s.enroll_allow_cidrs
        if cidrs:
            try:
                addr = ipaddress.ip_address(ip)
                if not any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs):
                    return ("E_NOT_ALLOWED", "source address not allowed")
            except ValueError:
                return ("E_NOT_ALLOWED", "unrecognised source address")
        if self.s.enroll_key:
            if request.headers.get("x-enroll-key", "") != self.s.enroll_key:
                self.store.failed(ip)
                return ("E_KEY", "invalid enrollment key")
        return None

    # ---------- routes ----------
    async def get_pubkey(self, request: Request) -> PlainTextResponse:
        deny = self._gate(request)
        if deny:
            return PlainTextResponse(deny[1], 403)
        try:
            return PlainTextResponse(self._pubkey() + "\n", media_type="text/plain")
        except FileNotFoundError:
            return PlainTextResponse("service not ready", 503)

    async def get_script(self, request: Request) -> PlainTextResponse:
        # The script holds no secret; admission is enforced on /enroll/register
        script = (ENROLL_SH
                  .replace("__BASE__", self._base(request))
                  .replace("__DEFUSER__", self.s.enroll_user))
        return PlainTextResponse(script, media_type="text/x-shellscript",
                                 headers={"Cache-Control": "no-store"})

    async def get_uninstall(self, request: Request) -> PlainTextResponse:
        try:
            pub = self._pubkey()
        except FileNotFoundError:
            pub = ""
        return PlainTextResponse(UNINSTALL_SH.replace("__PUBKEY__", pub),
                                 media_type="text/x-shellscript")

    async def register(self, request: Request) -> JSONResponse:
        ip = self._ip(request)
        deny = self._gate(request)
        if deny:
            self.audit.write(event="enroll.deny", ip=ip, code=deny[0])
            return JSONResponse({"ok": False, "code": deny[0], "msg": deny[1]}, 403)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse({"ok": False, "code": "E_BAD_REQUEST",
                                 "msg": "malformed request"}, 400)

        from .inventory import valid_host_key
        host_key = str(body.get("host_key", "")).strip()
        # Strict single-line validation: this value is templated into a known_hosts
        # document, so a newline would inject extra entries.
        if not valid_host_key(host_key):
            return JSONResponse({"ok": False, "code": "E_BAD_REQUEST",
                                 "msg": "bad host key format"}, 400)
        if not ip:
            return JSONResponse({"ok": False, "code": "E_BAD_REQUEST",
                                 "msg": "cannot determine source address"}, 400)

        alias = re.sub(r"[^A-Za-z0-9._-]", "-", str(body.get("alias") or "node"))[:64] or "node"
        user = re.sub(r"[^A-Za-z0-9._-]", "", str(body.get("user") or self.s.enroll_user))[:32]
        try:
            port = int(body.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        if not (0 < port < 65536):
            port = 22
        tags = [t for t in re.split(r"[,\s]+", str(body.get("tags") or "")) if t][:16]

        host = {
            "alias": alias, "address": ip, "port": port, "user": user,
            "host_key": host_key, "tags": tags, "scopes": list(self.s.enroll_scopes),
            "sudo": False,
            "notes": " · ".join(x for x in (str(body.get("hostname") or ""),
                                            str(body.get("os") or ""),
                                            str(body.get("arch") or "")) if x),
        }
        from .inventory import node_id_of, remove_host, write_host
        nid = node_id_of(ip, port, user)

        if self.s.enroll_mode == "approve":
            self.store.pend(nid, host)
            self.audit.write(event="enroll.pending", node_id=nid, alias=alias,
                             ip=ip, user=user, port=port)
            return JSONResponse({"ok": True, "node_id": nid, "state": "pending"})

        write_host(self.s.inventory_path, host)
        try:
            h = self.inv.get().get(nid)
            conn = await self.pool.acquire(h, self.inv.get())
            from .ssh.runner import run_command
            res = await run_command(conn, "id -un", timeout=20, max_bytes=2048)
            if res.exit_code != 0:
                raise RuntimeError("probe command failed")
            who = res.stdout.strip()
        except Exception:  # noqa: BLE001  - details go to the audit log only
            remove_host(self.s.inventory_path, nid)
            self.audit.write(event="enroll.failed", node_id=nid, alias=alias, ip=ip,
                             user=user, port=port, error=repr(sys.exc_info()[1])[:300])
            return JSONResponse({"ok": False, "code": "E_SSH",
                                 "msg": f"cannot reach {user}@{ip}:{port}; check firewall and sshd"},
                                502)

        self.store.ok(ip)
        self.store.seen(nid, ip, user, port, alias)
        self.audit.write(event="enroll.ok", node_id=nid, alias=alias, ip=ip,
                         user=user, port=port, verified=who)
        log.info("node enrolled: %s (%s %s@%s:%s)", alias, nid, user, ip, port)
        return JSONResponse({"ok": True, "node_id": nid, "alias": alias})

    async def deregister(self, request: Request) -> JSONResponse:
        """Self-service removal: a node can only remove itself (source IP + user)."""
        ip = self._ip(request)
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            body = {}
        user = str(body.get("user") or self.s.enroll_user)
        try:
            port = int(body.get("port") or 22)
        except (TypeError, ValueError):
            port = 22
        if not (0 < port < 65536):
            port = 22
        from .inventory import node_id_of, remove_host
        nid = node_id_of(ip, port, user)
        removed = remove_host(self.s.inventory_path, nid)
        self.audit.write(event="enroll.deregister", node_id=nid, ip=ip,
                         user=user, port=port, removed=removed)
        return JSONResponse({"ok": True, "removed": removed})
