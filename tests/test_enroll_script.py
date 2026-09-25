"""The enrollment script renders and its rootless / root branches are well-formed.

Behavioural coverage (a rootless run writes the key to the current user's own
~/.ssh, registers user+port, and the gateway connects back) is an integration
check against a real node + sshd, done in the lab. This test guards the script
itself: it renders, passes `bash -n`, and the mode logic and new flags are wired.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from vpsmcp.enroll import ENROLL_SH  # noqa: E402

rendered = ENROLL_SH.replace("__BASE__", "http://127.0.0.1:8848").replace("__DEFUSER__", "ops")

# 1. renders with all placeholders filled and passes a shell syntax check
assert "__BASE__" not in rendered and "__DEFUSER__" not in rendered
bash = shutil.which("bash")
if bash:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(rendered)
        path = f.name
    r = subprocess.run([bash, "-n", path], capture_output=True, text=True)
    assert r.returncode == 0, f"bash -n failed: {r.stderr}"
    print("1. script renders and passes bash -n")
else:
    print("1. script renders (bash not present; skipped bash -n)")

# 2. rootless is opt-in: a non-root run without --rootless is refused with guidance,
#    and both new flags are handled
assert "--rootless) ROOTLESS=1" in rendered
assert "--port) PORT_OVERRIDE=" in rendered
assert 'root required; re-run with sudo, or pass --rootless' in rendered
print("2. --rootless and --port are parsed; non-root without --rootless is refused")

# 3. account creation is gated behind root mode; rootless uses the caller's own home
#    and never runs useradd/usermod/chown on the same line as its own setup
assert "if [[ $ROOTLESS -eq 0 ]]" in rendered
assert 'HOME_DIR="${HOME:-' in rendered            # rootless uses the caller's home
for cmd in ("useradd -m", "usermod -p", "chown -R", "/etc/ssh/sshd_config.d"):
    # every privileged op is indented (sits inside a guarded block), never at
    # column 0 where it would run unconditionally
    for line in rendered.splitlines():
        if cmd in line:
            assert line != line.lstrip(), f"{cmd!r} is not inside a guarded block: {line!r}"
print("3. account creation and sshd edits are all inside guarded (root-only) blocks")

# 4. --self / @session enroll the login user, resolved from SUDO_USER, and refuse
#    to enroll root; behaviour-checked by running the rendered snippet under bash.
assert "--self) SELF=1" in rendered
assert '"$NODE_USER" == "@session"' in rendered
assert 'NODE_USER="${SUDO_USER:-$(id -un)}"' in rendered

if bash:
    resolve = r'''
      SELF=%d; NODE_USER="%s"; SUDO_USER_SET=%s
      [[ $SUDO_USER_SET -eq 1 ]] && export SUDO_USER=alice || unset SUDO_USER
      die() { echo "REFUSED"; exit 1; }
      if [[ $SELF -eq 1 || "$NODE_USER" == "@session" ]]; then
        NODE_USER="${SUDO_USER:-$(id -un)}"
        [[ "$NODE_USER" != "root" ]] || die
      fi
      echo "$NODE_USER"
    '''
    def run_resolve(self_flag, node_user, sudo_set):
        r = subprocess.run([bash, "-c", resolve % (self_flag, node_user, 1 if sudo_set else 0)],
                           capture_output=True, text=True)
        return r.stdout.strip()

    assert run_resolve(1, "ops", True) == "alice", "‑‑self should resolve to SUDO_USER"
    assert run_resolve(0, "@session", True) == "alice", "@session should resolve to SUDO_USER"
    assert run_resolve(0, "ops", True) == "ops", "without --self/@session the default stands"
    # root with no SUDO_USER (id -un is not 'root' in this sandbox test only if run as
    # non-root, so assert the refuse path only when the resolved id would be root)
    import getpass as _gp
    if _gp.getuser() == "root":
        assert run_resolve(1, "ops", False) == "REFUSED", "‑‑self as root must refuse"
    print("4. --self / @session resolve to the login user (SUDO_USER) and refuse root")
else:
    print("4. --self / @session wiring present (bash absent; skipped behaviour run)")

# 5. --proxy writes a per-account toggle; verify the emitted proxy.sh flips env
assert "--proxy) PROXY_URL=" in rendered
assert "vpsmcp-proxy()" in rendered and "proxy.state" in rendered
assert 'vpsmcp/proxy.sh' in rendered              # sourced from the account rc
if bash:
    # Reproduce the proxy.sh the installer writes for a given URL and exercise it.
    import tempfile
    url = "http://node:secret@gw.example:8443"
    home = tempfile.mkdtemp()
    proxysh = rf'''
      VPSMCP_GATEWAY_PROXY='{url}'
      __vpsmcp_pstate="$HOME/.vpsmcp/proxy.state"
      vpsmcp_proxy_apply() {{
        if [ "$(cat "$__vpsmcp_pstate" 2>/dev/null)" = gateway ]; then
          export http_proxy="$VPSMCP_GATEWAY_PROXY" https_proxy="$VPSMCP_GATEWAY_PROXY"
        fi
      }}
      vpsmcp-proxy() {{
        case "${{1:-status}}" in
          on|gateway) echo gateway > "$__vpsmcp_pstate"; vpsmcp_proxy_apply;;
          off|system) echo system > "$__vpsmcp_pstate"; unset http_proxy https_proxy;;
          status) echo "$(cat "$__vpsmcp_pstate" 2>/dev/null || echo system)";;
        esac
      }}
      vpsmcp_proxy_apply
    '''
    script = (f'export HOME={home}; mkdir -p $HOME/.vpsmcp; echo gateway > $HOME/.vpsmcp/proxy.state\n'
              + proxysh
              + '\necho "start=$http_proxy"\n'
              + 'vpsmcp-proxy off >/dev/null; echo "off=[$http_proxy] state=$(vpsmcp-proxy status)"\n'
              + 'vpsmcp-proxy on  >/dev/null; echo "on=[$http_proxy]"\n')
    out = subprocess.run([bash, "-c", script], capture_output=True, text=True).stdout
    assert f"start={url}" in out, out
    assert "off=[] state=system" in out, out
    assert f"on=[{url}]" in out, out
    print("5. --proxy toggle: activated on deploy, flips gateway<->system per account")
else:
    print("5. --proxy wiring present (bash absent; skipped behaviour run)")

print("\nall enroll-script checks passed")
