## Summary

<!-- What does this change and why? Link related issues: Fixes #123 -->

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Security / hardening
- [ ] Docs
- [ ] Deploy scripts / packaging

## Affected areas

- [ ] Gateway (`src/vpsmcp`)
- [ ] OAuth / scopes
- [ ] Node enrollment (`enroll.py` scripts run on nodes)
- [ ] Deploy scripts (`deploy/`)
- [ ] Docs (`README.md`, `docs/`)

## Testing

<!-- Commands run and results. See tests/README.md for the local lab. -->

- [ ] `python3 tests/test_oauth_flow.py`
- [ ] `python3 tests/test_tools_e2e.py`
- [ ] `python3 tests/test_scopes.py`
- [ ] Tried on a real gateway (`deploy/install.sh` or `deploy/upgrade.sh`)

## Checklist

- [ ] `README.md` and `docs/README_ZH.md` stay in sync (commands, flags, defaults)
- [ ] `docs/REFERENCE.md` updated for new settings, endpoints, scopes or file paths
- [ ] `deploy/vpsmcp.service` and `_systemd_unit()` in `setup.py` still match
- [ ] Existing installs keep working after `deploy/upgrade.sh` (config and data untouched)
- [ ] No secrets, keys, tokens or real hostnames/IPs committed
