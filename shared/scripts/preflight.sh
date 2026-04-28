#!/usr/bin/env bash
# shared/scripts/preflight.sh
#
# Validates that this Pi's .env, repo, and host state are sane before
# update.sh / deploy-all.sh proceed. Fails loud and early — never silently.
# Exits 0 on success, 1 on any failure with one error per line on stderr.
#
# Idempotent + side-effect-free. Safe to run any time.

set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/d2-edge/.env}"
COMPOSE_DIR="${COMPOSE_DIR:-/opt/d2-edge}"

errors=()
fail() { errors+=("$1"); }

# --- 1. .env exists, mode 0600 ------------------------------------------
if [[ ! -f "$ENV_FILE" ]]; then
    fail ".env missing at $ENV_FILE — re-run bootstrap.sh"
else
    perms=$(stat -c %a "$ENV_FILE")
    [[ "$perms" == "600" ]] || fail ".env perms are $perms, expected 600 (run: chmod 600 $ENV_FILE)"
fi

# --- 2. No CRLF / markdown contamination from copy-paste ----------------
if [[ -f "$ENV_FILE" ]]; then
    grep -q $'\r' "$ENV_FILE" \
        && fail ".env has CRLF line endings — run: sudo dos2unix $ENV_FILE"

    grep -qE '\]\((mailto|http)s?:' "$ENV_FILE" \
        && fail ".env contains markdown link syntax (e.g. [KEY=v](mailto:...)) — strip the brackets/parens"

    grep -qE '^[[:space:]]+[A-Z_]+=' "$ENV_FILE" \
        && fail ".env has lines with leading whitespace before KEY= — strip it"
fi

# --- 3. Required keys present + non-empty -------------------------------
# These are operator-supplied and must be set before any deploy. Auto-managed
# keys (DOCKER_GID, GIT_SHA, COMPOSE_PROFILES) are handled by update.sh and
# are deliberately NOT required here.
required=(
    TZ EDGE_HOSTNAME EDGE_SITE_ID NETBOX_SITE_SLUG
    TENANT_ID TENANT_NAME ENVIRONMENT
    TS_AUTHKEY
    GRAYLOG_HOST ZABBIX_SERVER_HOST ZABBIX_SERVER_PORT RADIUS_HOME_SERVER
    RADIUS_SHARED_SECRET LOCAL_CLIENT_SECRET LOCAL_CLIENT_SUBNET
    AUVIK_USERNAME AUVIK_API_KEY AUVIK_DOMAIN_PREFIX
    AGENT_TOKEN CONTROLLER_URL
    RADSEC_CLIENT_SECRET
)

if [[ -f "$ENV_FILE" ]]; then
    set +u
    set +e
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE" 2>/dev/null
    src_rc=$?
    set +a
    set -e
    set -u

    if (( src_rc != 0 )); then
        fail ".env contains shell syntax errors (likely paste contamination — see check 2)"
    fi

    for k in "${required[@]}"; do
        val="${!k:-}"
        if [[ -z "$val" || "$val" == "REPLACE_ME" ]]; then
            fail "required .env key '$k' is missing, empty, or still REPLACE_ME"
        fi
    done
fi

# --- 4. TS_AUTHKEY must be OAuth-client format --------------------------
# Pre-auth keys (tskey-auth-*) expire after 90d and break Pis. Only OAuth
# client secrets (tskey-client-*) are acceptable in production.
if [[ -n "${TS_AUTHKEY:-}" && "${TS_AUTHKEY}" != "REPLACE_ME" \
      && "$TS_AUTHKEY" != tskey-client-* ]]; then
    fail "TS_AUTHKEY must start with 'tskey-client-' (OAuth secret); pre-auth keys expire and re-break Pis"
fi

# --- 5. DOCKER_GID, if set in .env, must match host's docker group ------
# update.sh exports DOCKER_GID at deploy time so this is just a drift check.
if [[ -n "${DOCKER_GID:-}" ]]; then
    if [[ ! "$DOCKER_GID" =~ ^[0-9]+$ ]]; then
        fail "DOCKER_GID='$DOCKER_GID' in .env is non-numeric"
    else
        actual_gid=$(getent group docker | cut -d: -f3 || true)
        if [[ -z "$actual_gid" ]]; then
            fail "host has no 'docker' group — docker not installed?"
        elif [[ "$DOCKER_GID" != "$actual_gid" ]]; then
            fail "DOCKER_GID=$DOCKER_GID in .env but host's docker GID is $actual_gid — update .env"
        fi
    fi
fi

# --- 6. docker-compose.yml parses with this .env ------------------------
# Ensure the env vars docker compose needs are exported so its interpolation
# doesn't yield empty values during validation.
[[ -z "${DOCKER_GID:-}" ]] && export DOCKER_GID="$(getent group docker | cut -d: -f3 2>/dev/null || echo 0)"
[[ -z "${COMPOSE_PROFILES:-}" ]] && export COMPOSE_PROFILES=enabled

if ! (cd "$COMPOSE_DIR" && docker compose config >/dev/null 2>"$COMPOSE_DIR/.preflight-compose.err"); then
    fail "docker compose config failed: $(tr '\n' ' ' < "$COMPOSE_DIR/.preflight-compose.err" | head -c 240)"
fi
rm -f "$COMPOSE_DIR/.preflight-compose.err"

# --- 7. Disk headroom for image pulls -----------------------------------
free_gb=$(df -BG --output=avail "$COMPOSE_DIR" | tail -1 | tr -dc '0-9')
(( free_gb < 2 )) && fail "only ${free_gb}GB free on $COMPOSE_DIR — image pulls need ~2GB headroom"

# --- 8. Hostname / /etc/hosts sanity (sudo breaks otherwise) ------------
current_hostname=$(hostname)
if ! grep -qE "^[0-9.]+[[:space:]]+.*\b${current_hostname}\b" /etc/hosts; then
    fail "hostname '$current_hostname' has no /etc/hosts entry — sudo will warn 'unable to resolve host'"
fi

# --- Report -------------------------------------------------------------
if (( ${#errors[@]} > 0 )); then
    echo "PREFLIGHT FAILED ($COMPOSE_DIR):" >&2
    for e in "${errors[@]}"; do echo "  - $e" >&2; done
    exit 1
fi

echo "preflight OK ($COMPOSE_DIR, $(git -C "$COMPOSE_DIR" rev-parse --short HEAD 2>/dev/null || echo 'no-git'))"
exit 0
