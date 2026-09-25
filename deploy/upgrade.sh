#!/usr/bin/env bash
# In-place code upgrade. Config and data are untouched, so nodes stay enrolled
# and existing OAuth grants keep working.
#
#   cd <new source tree> && sudo deploy/upgrade.sh
#   sudo deploy/upgrade.sh --fast           # skip dependency resolution (no network)
#   sudo deploy/upgrade.sh --no-restart
#   sudo deploy/upgrade.sh --list-backups
#   sudo deploy/upgrade.sh --rollback [timestamp]
set -euo pipefail

APP=/opt/vpsmcp
VENV="$APP/.venv"
PY="$VENV/bin/python"
FAST=0; RESTART=1; ROLLBACK=0; LISTBAK=0; STAMP_WANT=""
while [[ $# -gt 0 ]]; do case "$1" in
  --fast)          FAST=1; shift ;;
  --no-restart)    RESTART=0; shift ;;
  --list-backups)  LISTBAK=1; shift ;;
  --rollback)      ROLLBACK=1; shift
                   [[ ${1:-} =~ ^[0-9]{14}$ ]] && { STAMP_WANT="$1"; shift; } ;;
  -h|--help)       sed -n '2,9p' "$0"; exit 0 ;;
  *) echo "unknown argument: $1" >&2; exit 2 ;;
esac; done

PIP_Q=(-q --disable-pip-version-check)

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
[[ -x "$PY" ]] || { echo "$PY not found; run deploy/install.sh first" >&2; exit 1; }

cur_ver() { "$PY" -c "import vpsmcp;print(vpsmcp.__version__)" 2>/dev/null || echo "?"; }
bak_ver() { grep -m1 '^__version__' "$1/src/vpsmcp/__init__.py" 2>/dev/null | cut -d'"' -f2 || echo "?"; }
list_baks() {
  local any=0
  for d in $(ls -1d "$APP"/.rollback/* 2>/dev/null | sort -r); do
    printf "  %s  version %s\n" "$(basename "$d")" "$(bak_ver "$d")"; any=1
  done
  [[ $any -eq 1 ]] || echo "  (none)"
}

if [[ $LISTBAK -eq 1 ]]; then
  echo "installed: $(cur_ver)"
  echo "backups (newest first):"
  list_baks
  exit 0
fi

if [[ $ROLLBACK -eq 1 ]]; then
  if [[ -n "$STAMP_WANT" ]]; then
    last="$APP/.rollback/$STAMP_WANT"
    [[ -d "$last" ]] || { echo "no such backup: $STAMP_WANT"; list_baks; exit 1; }
  else
    last=$(ls -1d "$APP"/.rollback/* 2>/dev/null | sort | tail -1)
  fi
  [[ -n "${last:-}" && -d "${last:-}" ]] || { echo "nothing to roll back to"; exit 1; }
  echo "==> $(cur_ver)  ->  $(bak_ver "$last")   (backup $(basename "$last"))"
  systemctl stop vpsmcp 2>/dev/null || true
  rm -rf "$APP/src"; cp -a "$last/src" "$APP/src"
  cp -a "$last/pyproject.toml" "$APP/pyproject.toml" 2>/dev/null || true
  "$VENV/bin/pip" install "${PIP_Q[@]}" --force-reinstall --no-deps "$APP"
  chown -R vpsmcp:vpsmcp "$APP"
  systemctl start vpsmcp 2>/dev/null || true
  echo "rolled back to $(cur_ver)"
  exit 0
fi

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ -d "$SRC/src/vpsmcp" ]] || { echo "no src/vpsmcp in $SRC" >&2; exit 1; }
[[ "$SRC" != "$APP" ]] || { echo "run this from the new source tree, not $APP" >&2; exit 1; }

OLD=$(cur_ver)
NEW=$(grep -m1 '^__version__' "$SRC/src/vpsmcp/__init__.py" | cut -d'"' -f2)
echo "==> $OLD  ->  $NEW"

STAMP=$(date +%Y%m%d%H%M%S)
BAK="$APP/.rollback/$STAMP"
install -d -m 700 "$APP/.rollback"
mkdir -p "$BAK"
cp -a "$APP/src" "$BAK/src" 2>/dev/null || true
cp -a "$APP/pyproject.toml" "$BAK/" 2>/dev/null || true
echo "==> backed up current code to $BAK"
ls -1d "$APP"/.rollback/* 2>/dev/null | sort | head -n -3 | xargs -r rm -rf

WAS_ACTIVE=0
systemctl is-active --quiet vpsmcp 2>/dev/null && WAS_ACTIVE=1 || true
[[ $WAS_ACTIVE -eq 1 ]] && { echo "==> stopping service"; systemctl stop vpsmcp; }

echo "==> installing"
rm -rf "$APP/src"
cp -a "$SRC/src" "$APP/src"
cp -a "$SRC/pyproject.toml" "$APP/pyproject.toml"
if [[ $FAST -eq 1 ]]; then
  "$VENV/bin/pip" install "${PIP_Q[@]}" --force-reinstall --no-deps "$APP"
else
  "$VENV/bin/pip" install "${PIP_Q[@]}" --upgrade "$APP"
fi
install -m 755 "$SRC/deploy/vpsmcp-wrapper" /usr/local/bin/vpsmcp 2>/dev/null || true
# Refresh the optional egress-proxy unit so existing installs (which upgrade,
# not re-run setup) pick it up. Not enabled here - that needs a proxy password.
if [[ -d /etc/systemd/system && -f "$SRC/deploy/vpsmcp-proxy.service" ]]; then
  install -m 644 "$SRC/deploy/vpsmcp-proxy.service" \
    /etc/systemd/system/vpsmcp-proxy.service 2>/dev/null \
    && systemctl daemon-reload 2>/dev/null || true
fi
chown -R vpsmcp:vpsmcp "$APP"
find "$APP" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
echo "==> version $(cur_ver)"

echo "==> self-check as the service account"
if ! sudo -u vpsmcp "$PY" -m vpsmcp check; then
  echo
  echo "self-check failed; the service was not started."
  echo "roll back with: sudo deploy/upgrade.sh --rollback"
  exit 1
fi

if [[ $RESTART -eq 1 && $WAS_ACTIVE -eq 1 ]]; then
  echo "==> restarting"
  systemctl start vpsmcp
  sleep 2
  systemctl is-active --quiet vpsmcp 2>/dev/null && echo "    running" \
    || { echo "    failed to start; journalctl -u vpsmcp -n 40"; exit 1; }
elif [[ $WAS_ACTIVE -eq 0 ]]; then
  echo "==> service was not running; not started"
else
  echo "==> --no-restart: start it yourself with systemctl start vpsmcp"
fi

echo
echo "done ($OLD -> $(cur_ver)). Config and data untouched."
echo "next: sudo deploy/healthcheck.sh"
