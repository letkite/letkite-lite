#!/usr/bin/env bash
# The lab tests/README.md describes, scripted for CI: a local sshd on 127.0.0.1:2222,
# an inventory with one host, the gateway on 127.0.0.1:8848, then every test that
# runs against it. Usage: .github/ci/lab.sh (from the repository root, with
# PYTHON pointing at an interpreter that has the package installed).
set -euo pipefail
PY="${PYTHON:-python3}"
D="$(mktemp -d)"; export D
U="$(id -un)"; H="$(getent passwd "$U" | cut -d: -f6)"
mkdir -p /run/sshd 2>/dev/null || sudo mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$D/host_ed25519"
ssh-keygen -q -t ed25519 -N '' -f "$D/client_key"
mkdir -p "$H/.ssh" && cat "$D/client_key.pub" >> "$H/.ssh/authorized_keys" && chmod 600 "$H/.ssh/authorized_keys"
# A locked password ("!" in shadow, as on GitHub's runner) makes sshd without PAM refuse
# even key logins; with PAM the key is enough
PAM=no
[[ "$(sudo -n passwd -S "$U" 2>/dev/null | awk '{print $2}')" == L ]] && PAM=yes
cat > "$D/sshd_config" <<CFG
Port 2222
ListenAddress 127.0.0.1
HostKey $D/host_ed25519
PidFile $D/sshd.pid
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
AuthorizedKeysFile $H/.ssh/authorized_keys
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM $PAM
StrictModes no
CFG
SUDO=""; [[ $EUID -ne 0 ]] && SUDO=sudo
$SUDO /usr/sbin/sshd -f "$D/sshd_config"
for _ in $(seq 20); do ssh-keyscan -p 2222 -t ed25519 127.0.0.1 > "$D/known_hosts" 2>/dev/null && [[ -s "$D/known_hosts" ]] && break; sleep 0.5; done
cat > "$D/hosts.yaml" <<YAML
defaults: {user: $U, port: 2222}
hosts:
  - alias: lab-1
    address: 127.0.0.1
    tags: [lab, local]
    scopes: [fleet.read, fleet.exec, fleet.write, fleet.admin]
    workdir: /tmp
YAML
export PYTHONPATH="$PWD/src"
export VPSMCP_PUBLIC_URL=http://localhost:8848
export VPSMCP_DATA_DIR="$D/data" VPSMCP_INVENTORY="$D/hosts.yaml"
export VPSMCP_SSH_KEY="$D/client_key" VPSMCP_KNOWN_HOSTS="$D/known_hosts"
export VPSMCP_ADMIN_USER=admin
VPSMCP_ADMIN_PASSWORD_HASH="$("$PY" -c "
import sys; sys.path.insert(0, 'src')
from vpsmcp.auth.keys import hash_password; print(hash_password('correct-horse-battery'))")"
export VPSMCP_ADMIN_PASSWORD_HASH
"$PY" -m vpsmcp serve > "$D/serve.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null; $SUDO kill "$(cat "$D/sshd.pid" 2>/dev/null)" 2>/dev/null; true' EXIT
for _ in $(seq 60); do curl -fsS -o /dev/null http://127.0.0.1:8848/.well-known/oauth-authorization-server 2>/dev/null && break; sleep 0.5; done
fail=0
run() { echo "::group::$*"; if "$@"; then echo "::endgroup::"; else echo "::endgroup::"; echo "::error::failed: $*"; fail=1; fi; }
run "$PY" tests/test_oauth_flow.py "$D/token.json"
run "$PY" tests/test_client_compat.py
run "$PY" tests/test_tools_e2e.py "$D/token.json"
run "$PY" tests/test_scopes.py
run env SKIP_LIVE=1 "$PY" tests/test_client_ip_spoof.py
if (( fail )); then echo "--- server log"; tail -n 60 "$D/serve.log"; fi
exit $fail
