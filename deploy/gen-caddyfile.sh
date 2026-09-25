#!/usr/bin/env bash
# Thin wrapper; the implementation lives in src/vpsmcp/caddy.py so that
# `vpsmcp setup` and manual generation share one code path.
exec "${VPSMCP_PY:-/opt/vpsmcp/.venv/bin/python}" -m vpsmcp caddyfile "$@"
