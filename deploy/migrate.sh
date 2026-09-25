#!/usr/bin/env bash
# Move the gateway to another machine. The resource URL does not change, so the
# Claude connector keeps working and nodes stay enrolled.
#
#   old host:  sudo deploy/migrate.sh export /root/vpsmcp-state.tar.gz
#   transfer:  scp /root/vpsmcp-state.tar.gz newgw:/root/
#   new host:  sudo deploy/install.sh --domain <same domain> -y
#              sudo deploy/migrate.sh import /root/vpsmcp-state.tar.gz
#   finally:   point the DNS A record at the new host
#
# Export stops the service first: oauth.db holds rotating refresh tokens, and two
# live copies diverge - the client would trip the reuse detector and lose its grant.
#
# Detached jobs are unaffected: their state lives on the nodes. Shell sessions,
# log subscriptions and tunnels are in-process and are lost.
set -euo pipefail

MODE="${1:-}"
FILE="${2:-}"
ETC=/etc/vpsmcp
DATA=/var/lib/vpsmcp

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -n "$MODE" && -n "$FILE" ]] || { sed -n '2,15p' "$0"; exit 2; }

case "$MODE" in
export)
  echo "==> stopping the service"
  systemctl stop vpsmcp 2>/dev/null || echo "    (was not running)"
  sleep 1

  echo "==> packing state"
  tar czf "$FILE" --numeric-owner -p -C / \
    etc/vpsmcp \
    $( [[ -d "$DATA" ]] && echo var/lib/vpsmcp )
  chmod 600 "$FILE"

  echo
  echo "==> wrote $FILE ($(du -h "$FILE" | cut -f1))"
  tar tzf "$FILE" | sed 's/^/    /'
  echo
  echo "    This archive contains the private key for every node. Move it over"
  echo "    scp and delete it afterwards."
  echo "    sha256: $(sha256sum "$FILE" | cut -d' ' -f1)"
  echo
  echo "==> the old gateway is stopped; keep it until the new one is verified"
  ;;

import)
  [[ -f "$FILE" ]] || { echo "no such file: $FILE" >&2; exit 1; }
  getent group vpsmcp >/dev/null || { echo "run deploy/install.sh first" >&2; exit 1; }

  echo "==> backing up anything already here"
  ts=$(date +%Y%m%d%H%M%S)
  for d in "$ETC" "$DATA"; do
    [[ -d "$d" ]] && { cp -a "$d" "$d.pre-migrate-$ts"; echo "    $d -> $d.pre-migrate-$ts"; }
  done

  echo "==> unpacking"
  tar xzf "$FILE" -C / --numeric-owner -p

  echo "==> fixing ownership"
  chown -R root:vpsmcp "$ETC";  chmod 750 "$ETC"
  chmod 640 "$ETC"/vpsmcp.env "$ETC"/hosts.yaml 2>/dev/null || true
  chmod 644 "$ETC"/known_hosts 2>/dev/null || true
  chown root:vpsmcp "$ETC"/id_ed25519 "$ETC"/id_ed25519.pub 2>/dev/null || true
  chmod 640 "$ETC"/id_ed25519 2>/dev/null || true
  chown -R vpsmcp:vpsmcp "$ETC/hosts.d" 2>/dev/null || true
  chmod 750 "$ETC/hosts.d" 2>/dev/null || true
  chown -R vpsmcp:vpsmcp "$DATA"; chmod 750 "$DATA"
  chmod 600 "$DATA"/oauth_signing_key.pem "$DATA"/cookie.key 2>/dev/null || true

  echo
  echo "==> self-check"
  PY=/opt/vpsmcp/.venv/bin/python
  if   [[ -x "$PY" ]];               then "$PY" -m vpsmcp check || true
  elif command -v vpsmcp >/dev/null; then vpsmcp check || true
  else echo "    vpsmcp not found; run deploy/install.sh"; fi

  cat <<'NEXT'

Next:
  1. systemctl enable --now vpsmcp
  2. sudo deploy/gen-caddyfile.sh --email you@example.com -o /etc/caddy/Caddyfile
     systemctl reload caddy
  3. point the DNS A record at this host (lower the TTL beforehand)
  4. sudo deploy/healthcheck.sh
  5. only then shut down the old gateway, and shred its copy of the archive

The gateway is a node too: re-run the enrollment on this machine so its own
host key is correct.
NEXT
  ;;
*) echo "usage: $0 export|import <file>"; exit 2 ;;
esac
