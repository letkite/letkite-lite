#!/usr/bin/env bash
# One-shot gateway install: system deps -> venv -> package -> `vpsmcp setup`.
#
#   sudo deploy/install.sh                                 # interactive
#   sudo deploy/install.sh --domain mcp.example.com -y     # unattended
#
# setup flags: --domain --admin-user --password --email --port --mcp-path
#              --self-enroll --lock-anthropic --allow-cidr <cidr> --no-caddy -y
set -euo pipefail

# Re-exec under sudo so setup can read SUDO_USER for the default admin name.
[[ $EUID -eq 0 ]] || exec sudo -E bash "$0" "$@"

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP=/opt/vpsmcp

echo "==> system dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip curl ca-certificates openssh-client >/dev/null

echo "==> service account and directories"
id -u vpsmcp >/dev/null 2>&1 || useradd --system --home "$APP" --shell /usr/sbin/nologin vpsmcp
install -d -o vpsmcp -g vpsmcp -m 750 "$APP" /var/lib/vpsmcp
install -d -o root   -g vpsmcp -m 750 /etc/vpsmcp

echo "==> package"
rm -rf "$APP/src"
cp -a "$SRC/src" "$APP/src"
cp -a "$SRC/pyproject.toml" "$APP/pyproject.toml"
[[ -x "$APP/.venv/bin/python" ]] || python3 -m venv "$APP/.venv"
"$APP/.venv/bin/pip" install -q --disable-pip-version-check --upgrade pip >/dev/null
"$APP/.venv/bin/pip" install -q --disable-pip-version-check --upgrade "$APP"
chown -R vpsmcp:vpsmcp "$APP"
echo "    version $("$APP/.venv/bin/python" -c 'import vpsmcp;print(vpsmcp.__version__)')"

install -m 755 "$SRC/deploy/vpsmcp-wrapper" /usr/local/bin/vpsmcp

exec "$APP/.venv/bin/python" -m vpsmcp setup "$@"
