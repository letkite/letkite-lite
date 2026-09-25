#!/usr/bin/env bash
# Layered health check: process -> ingress -> discovery -> fleet.
#
#   sudo deploy/healthcheck.sh
#   sudo deploy/healthcheck.sh --deep                 # also SSH to every node
#   deploy/healthcheck.sh https://mcp.example.com     # remote, public layers only
#
# Exit code = number of failed checks.

DEEP=0
URL=""
for a in "$@"; do
  case "$a" in
    --deep) DEEP=1 ;;
    http*)  URL="${a%/}" ;;
  esac
done

ENVFILE=${VPSMCP_ENV_FILE:-/etc/vpsmcp/vpsmcp.env}
LOCAL=0

# Do not source the env file: the password hash contains $ and would be expanded.
envget() {
  sed -n "s/^[[:space:]]*$1=//p" "$ENVFILE" 2>/dev/null | tail -1 \
    | sed "s/^[[:space:]]*//; s/[[:space:]]*$//; s/^'\(.*\)'$/\1/; s/^\"\(.*\)\"$/\1/"
}

if [[ -r "$ENVFILE" ]]; then LOCAL=1; fi
URL="${URL:-$(envget VPSMCP_PUBLIC_URL)}"
URL="${URL%/}"
_mp="$(envget VPSMCP_MCP_PATH)"; _mp="${_mp:-mcp}"
MCP_PATH="/$(echo "$_mp" | sed 's#^/*##; s#/*$##')"
RESOURCE="${URL}${MCP_PATH}"
PORT="$(envget VPSMCP_BIND_PORT)"; PORT="${PORT:-8848}"

FAIL=0
ok()      { printf '  \033[32m/\033[0m %-28s %s\n' "$1" "${2:-}"; }
bad()     { printf '  \033[31mX\033[0m %-28s %s\n' "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip()    { printf '  \033[90m-\033[0m %-28s %s\n' "$1" "${2:-}"; }
section() { printf '\n\033[1m%s\033[0m\n' "$1"; }

[[ -n "$URL" ]] || { echo "no public URL: pass one, or run on the gateway"; exit 2; }
echo "resource URL: $RESOURCE"

section "1. process"
if [[ $LOCAL -eq 1 ]]; then
  state=$(systemctl is-active vpsmcp 2>/dev/null || true)
  if [[ -z "$state" ]]; then
    skip "systemd unit" "systemd unavailable or unit not installed"
  elif [[ "$state" == "active" ]]; then
    since=$(systemctl show vpsmcp -p ActiveEnterTimestamp --value 2>/dev/null)
    nrestart=$(systemctl show vpsmcp -p NRestarts --value 2>/dev/null)
    ok "systemd unit" "active since ${since:-?}, ${nrestart:-?} restarts"
    [[ "${nrestart:-0}" -gt 5 ]] && bad "restart count" "$nrestart - likely a crash loop"
  else
    bad "systemd unit" "$state - systemctl status vpsmcp"
  fi
  listener=""
  if   command -v ss      >/dev/null; then listener=$(ss -ltn 2>/dev/null      | grep ":$PORT " | head -1)
  elif command -v netstat >/dev/null; then listener=$(netstat -ltn 2>/dev/null | grep ":$PORT " | head -1)
  else skip "listen port $PORT" "no ss/netstat"; fi
  if [[ -n "$listener" ]]; then
    ok "listen port $PORT" "$(echo "$listener" | awk '{print $4}')"
  elif command -v ss >/dev/null || command -v netstat >/dev/null; then
    bad "listen port $PORT" "nothing listening"
  fi
  if curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    ok "local /healthz" "$(curl -fsS --max-time 5 "http://127.0.0.1:$PORT/healthz")"
  else
    bad "local /healthz" "port open but the app does not answer"
  fi
else
  skip "local checks" "not on the gateway"
fi

section "2. ingress"
HOSTNAME_ONLY=$(echo "$URL" | sed -E 's#^https?://##; s#[:/].*##')
if command -v dig >/dev/null; then
  ips=$(dig +short "$HOSTNAME_ONLY" A | tr '\n' ' ')
  [[ -n "$ips" ]] && ok "DNS A" "$ips" || bad "DNS A" "$HOSTNAME_ONLY does not resolve"
  v6=$(dig +short "$HOSTNAME_ONLY" AAAA | tr '\n' ' ')
  [[ -n "$v6" ]] && skip "DNS AAAA" "$v6 (broken IPv6 causes intermittent failures)"
else
  getent hosts "$HOSTNAME_ONLY" >/dev/null 2>&1 \
    && ok "DNS" "$(getent hosts "$HOSTNAME_ONLY" | awk '{print $1}' | tr '\n' ' ')" \
    || bad "DNS" "$HOSTNAME_ONLY does not resolve"
fi

if [[ $LOCAL -eq 1 ]] && command -v caddy >/dev/null; then
  cstate=$(systemctl is-active caddy 2>/dev/null || true)
  listening=""
  if command -v ss >/dev/null; then listening=$(ss -ltn 2>/dev/null | grep -c ':443 ') || listening=0; fi
  if [[ "$cstate" != "active" ]]; then
    bad "caddy" "${cstate:-unknown} - systemctl status caddy -l"
  elif [[ "${listening:-0}" == "0" ]]; then
    bad "caddy on 443" "active but not listening - the config likely failed to load"
    echo "       a log block pointing at an unwritable directory does this"
  else
    ok "caddy" "active, listening on 443"
  fi
elif [[ $LOCAL -eq 1 ]]; then
  skip "reverse proxy" "caddy not installed"
fi

if [[ "$URL" == https://* ]]; then
  end=$(echo | openssl s_client -connect "$HOSTNAME_ONLY:443" -servername "$HOSTNAME_ONLY" 2>/dev/null \
        | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  if [[ -n "$end" ]]; then
    left=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
    if   [[ $left -lt 7  ]]; then bad "TLS certificate" "$left days left - renewal is broken"
    elif [[ $left -lt 21 ]]; then ok  "TLS certificate" "$left days left"
    else ok "TLS certificate" "$left days left"; fi
  else
    bad "TLS certificate" "unreachable on 443"
  fi
else
  skip "TLS certificate" "not https"
fi

section "3. discovery and auth"
hz=$(curl -fsS --max-time 10 "$URL/healthz" 2>/dev/null) \
  && ok "public /healthz" "$hz" || bad "public /healthz" "proxy cannot reach the app"

prm=$(curl -fsS --max-time 10 "$URL/.well-known/oauth-protected-resource$MCP_PATH" 2>/dev/null)
if [[ -n "$prm" ]]; then
  got=$(echo "$prm" | sed -nE 's/.*"resource":"([^"]+)".*/\1/p')
  [[ "$got" == "$RESOURCE" ]] \
    && ok "protected resource metadata" "resource matches" \
    || bad "protected resource metadata" "resource=$got != $RESOURCE"
else
  bad "protected resource metadata" "not served (RFC 9728)"
fi

asm=$(curl -fsS --max-time 10 "$URL/.well-known/oauth-authorization-server" 2>/dev/null)
if [[ -n "$asm" ]]; then
  # ["S256"] normally, ["S256","plain"] with VPSMCP_REQUIRE_PKCE=0
  echo "$asm" | grep -q '"code_challenge_methods_supported":\["S256"' \
    && ok "authorization server metadata" "PKCE S256 advertised" \
    || bad "authorization server metadata" "code_challenge_methods_supported missing"
else
  bad "authorization server metadata" "not served (RFC 8414)"
fi

# clients that take the resource URL for the issuer look here instead
asm2=$(curl -fsS --max-time 10 "$URL/.well-known/oauth-authorization-server$MCP_PATH" 2>/dev/null)
[[ -n "$asm2" ]] && ok "authorization server metadata (path form)" "served" \
                 || bad "authorization server metadata (path form)" \
                        "not served; clients that derive it from the resource URL cannot log in"

chal=$(curl -sS -o /dev/null -D- --max-time 10 -X POST "$RESOURCE" \
       -H 'content-type: application/json' -H 'accept: application/json, text/event-stream' \
       -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' 2>/dev/null)
code=$(echo "$chal" | head -1 | awk '{print $2}')
if [[ "$code" == "401" ]] && echo "$chal" | grep -qi 'www-authenticate:.*resource_metadata='; then
  ok "MCP 401 challenge" "carries resource_metadata"
elif [[ "$code" == "401" ]]; then
  bad "MCP 401 challenge" "no resource_metadata - the client cannot find the AS"
else
  bad "MCP 401 challenge" "got $code, expected 401"
fi

enr=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$URL/enroll/install.sh" 2>/dev/null)
[[ "$enr" == "200" ]] && ok "enrollment endpoint" "HTTP 200" \
                      || bad "enrollment endpoint" "HTTP $enr"

adm=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$URL/oauth/authorize" 2>/dev/null)
[[ "$adm" =~ ^(200|400)$ ]] && ok "consent page" "HTTP $adm" \
                            || bad "consent page" "HTTP $adm - blocked by an IP allowlist?"

section "4. fleet"
if [[ $LOCAL -eq 1 ]]; then
  PY_BIN="${VPSMCP_PY:-/opt/vpsmcp/.venv/bin/python}"
  n=$("$PY_BIN" -m vpsmcp hosts 2>/dev/null | grep -c . ) || n=0
  n="${n//[^0-9]/}"; n="${n:-0}"
  if [[ "$n" -gt 0 ]]; then
    ok "inventory" "$n node(s)"
  else
    skip "inventory" "no nodes yet"
  fi
  audit="$(envget VPSMCP_AUDIT_LOG)"; audit="${audit:-/var/lib/vpsmcp/audit.jsonl}"
  if [[ -r "$audit" ]]; then
    lastline=$(tail -1 "$audit" 2>/dev/null)
    last=$(echo "$lastline" | sed -nE 's/.*"iso":[[:space:]]*"([^"]+)".*/\1/p')
    lasttool=$(echo "$lastline" | sed -nE 's/.*"(tool|event)":[[:space:]]*"([^"]+)".*/\2/p' | head -1)
    cnt=$(wc -l < "$audit" 2>/dev/null | tr -d ' ')
    ok "audit log" "${cnt} records, last ${last:-none} ${lasttool:+($lasttool)}"
  else
    skip "audit log" "no records yet"
  fi
  if [[ $DEEP -eq 1 ]]; then
    echo
    "$PY_BIN" -m vpsmcp check 2>&1 | sed 's/^/    /'
    [[ ${PIPESTATUS[0]} -eq 0 ]] || FAIL=$((FAIL+1))
  else
    skip "per-node SSH" "add --deep"
  fi
else
  skip "fleet" "not on the gateway"
fi

section "result"
if [[ $FAIL -eq 0 ]]; then
  echo "  all checks passed. Connector URL: $RESOURCE"
else
  echo "  $FAIL check(s) failed."
fi
exit $FAIL
