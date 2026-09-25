#!/usr/bin/env bash
# Remove the gateway.
#
#   sudo deploy/uninstall.sh              # interactive
#   sudo deploy/uninstall.sh --keep-data  # keep /var/lib/vpsmcp
#   sudo deploy/uninstall.sh --local-only # do not touch the nodes
#   sudo deploy/uninstall.sh -y           # answer yes to every prompt
#
# Order matters: strip the gateway public key from every node while the gateway
# still works, then delete /etc/vpsmcp. The other way round leaves that key on
# every machine forever.
set -uo pipefail

KEEP_DATA=0; LOCAL_ONLY=0; YES=0
for a in "$@"; do case "$a" in
  --keep-data)  KEEP_DATA=1 ;;
  --local-only) LOCAL_ONLY=1 ;;
  --yes|-y)     YES=1 ;;
  -h|--help)    sed -n '2,11p' "$0"; exit 0 ;;
  *) echo "unknown argument: $a" >&2; exit 2 ;;
esac; done

ETC=/etc/vpsmcp
DATA=/var/lib/vpsmcp
APP=/opt/vpsmcp
UNIT=/etc/systemd/system/vpsmcp.service
PY="$APP/.venv/bin/python"

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }

ask() { [[ $YES -eq 1 ]] && return 0; read -r -p "$1 (yes/no) " a; [[ "$a" == "yes" ]]; }

echo "will remove:"
echo "  $UNIT"
echo "  $APP    (venv and code)"
echo "  $ETC    (ssh key, inventory, known_hosts, password hash)"
[[ $KEEP_DATA -eq 1 ]] && echo "  $DATA   kept (--keep-data)" \
                       || echo "  $DATA   (oauth db, signing key, audit log)"
echo "  system account vpsmcp"
echo

if [[ -x "$PY" ]] && [[ -r "$ETC/vpsmcp.env" ]]; then
  echo "==> active grants"
  "$PY" -m vpsmcp grants 2>/dev/null | head -40 || echo "   (unavailable)"
  echo
  echo "Also delete the connector in Claude's settings."
  ask "Done with the Claude side?" || { echo "Remove the connector first."; exit 1; }
fi

if [[ $LOCAL_ONLY -eq 0 && -f "$ETC/id_ed25519.pub" && -r "$ETC/hosts.yaml" ]]; then
  PUB="$(cat "$ETC/id_ed25519.pub")"
  echo
  echo "==> stripping the gateway key from every node"
  echo "    fingerprint: $(ssh-keygen -lf "$ETC/id_ed25519.pub" 2>/dev/null | awk '{print $2}')"
  if ask "Clean the nodes now? (skipping leaves this key on them permanently)"; then
    # Use the service's own loader: hosts.d and defaults: would be missed by a
    # hand-rolled YAML parse, and a silent skip is the worst outcome here.
    ROWS=()
    if [[ -x "$PY" ]]; then
      mapfile -t ROWS < <("$PY" -m vpsmcp hosts 2>/dev/null)
    elif command -v vpsmcp >/dev/null; then
      mapfile -t ROWS < <(vpsmcp hosts 2>/dev/null)
    fi
    if [[ ${#ROWS[@]} -eq 0 ]]; then
      echo "    cannot read the inventory; aborting before anything is deleted."
      echo "    Either remove this line from ~/.ssh/authorized_keys on each node by hand"
      echo "    and re-run with --local-only, or fix the inventory and re-run:"
      echo "      $PUB"
      exit 1
    fi
    for row in "${ROWS[@]}"; do
      IFS=$'\t' read -r alias addr port user tags <<<"$row"
      [[ -n "$addr" ]] || continue
      printf '    %-16s %s@%s:%s  ' "$alias" "$user" "$addr" "$port"
      out=$(ssh -i "$ETC/id_ed25519" -p "$port" -o BatchMode=yes -o ConnectTimeout=10 \
              -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$ETC/known_hosts" \
              "$user@$addr" bash -s <<REMOTE 2>&1
f="\$HOME/.ssh/authorized_keys"
[ -f "\$f" ] || { echo "no authorized_keys"; exit 0; }
tmp=\$(mktemp)
grep -vF '$(echo "$PUB" | awk '{print $2}')' "\$f" > "\$tmp" || true
cp "\$tmp" "\$f"; rm -f "\$tmp"
rm -rf "\$HOME/.vpsmcp" 2>/dev/null || true
echo "removed, \$(grep -c . "\$f" 2>/dev/null || true) key(s) left"
REMOTE
      )
      echo "$out" | tail -1
    done
    echo
    echo "    Accounts themselves are kept; use userdel -r <user> to remove them."
  fi
else
  [[ $LOCAL_ONLY -eq 1 ]] && echo "==> skipping nodes (--local-only)" \
                          || echo "==> skipping nodes (no key or inventory)"
fi

echo
echo "==> stopping the service"
systemctl disable --now vpsmcp 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload 2>/dev/null || true
systemctl reset-failed vpsmcp 2>/dev/null || true

if ask "Delete $ETC (contains the ssh private key)?"; then
  [[ -f "$ETC/id_ed25519" ]] && { command -v shred >/dev/null && shred -u "$ETC/id_ed25519" || rm -f "$ETC/id_ed25519"; }
  rm -rf "$ETC"; echo "    removed $ETC"
fi
if [[ $KEEP_DATA -eq 0 ]]; then
  if ask "Delete $DATA (signing key, grants, audit log)?"; then
    rm -rf "$DATA"; echo "    removed $DATA"
  fi
else
  echo "    kept $DATA"
fi
rm -rf "$APP" && echo "    removed $APP"
rm -f /usr/local/bin/vpsmcp

if id -u vpsmcp >/dev/null 2>&1 && ask "Delete the vpsmcp system account?"; then
  userdel vpsmcp 2>/dev/null && echo "    removed account vpsmcp"
fi

cat <<'NEXT'

Left for you:
  - reverse proxy: remove the site block, reload caddy
  - certificates:  rm -rf /var/lib/caddy/.local/share/caddy/certificates/*/<host>*
  - DNS:           delete the A record
  - node accounts: userdel -r <user> on each machine
NEXT
echo "done."
