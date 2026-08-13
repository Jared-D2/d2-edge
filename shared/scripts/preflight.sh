#!/usr/bin/env bash
# shared/scripts/preflight.sh
#
# Validates that this Pi's .env, repo, and host state are sane before
# update.sh / deploy-all.sh proceed. Fails loud and early — never silently.
# Exits 0 on success, 1 on any failure with one error per line on stderr.
#
# Idempotent: appends known-default keys to .env when missing (heal phase
# below), otherwise read-only. Safe to run any time.

set -euo pipefail

ENV_FILE="${ENV_FILE:-/opt/d2-edge/.env}"
COMPOSE_DIR="${COMPOSE_DIR:-/opt/d2-edge}"

# Single .env parser (env_get / deploy_flag) shared with update.sh — parses
# quotes/comments/whitespace with docker compose's dotenv semantics so
# validation here can never disagree with what compose actually deploys.
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/envfile.sh"

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

    # Conflicting duplicate keys: same key, different values. Bash sourcing
    # silently takes the last occurrence — masking operator intent. Same-
    # value duplicates are auto-deduped by update.sh so they don't reach
    # here; if they do, we still flag them as cosmetic noise via 'cosmetic'
    # set (non-blocking).
    while IFS= read -r dupkey; do
        [[ -z "$dupkey" ]] && continue
        # shellcheck disable=SC2016
        vals=$(grep -E "^${dupkey}=" "$ENV_FILE" | awk -F= '{$1=""; sub(/^ /,""); print}' | sort -u | wc -l)
        if (( vals > 1 )); then
            fail ".env has conflicting duplicate key '$dupkey' (multiple values) — keep one"
        else
            echo "  preflight: WARN .env has same-value duplicate '$dupkey' (auto-fixed by update.sh)" >&2
        fi
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$ENV_FILE" | cut -d= -f1 | sort | uniq -d)
fi

# --- 2.5. Heal known defaults before the required-key check -------------
# Co-located with the check so a new required key with a known default is
# a single edit: add to both `heal_defaults` here and `required` below.
# Pre-2026-05-18 these heals lived in update.sh, which created a chicken-
# and-egg — `git pull` brought a new preflight.sh enforcing a new required
# key, but the old update.sh on disk hadn't yet loaded the matching heal
# block, so the first `sudo bash update.sh` failed preflight and only the
# second succeeded (because the first attempt's pull had refreshed
# update.sh). Healing here means the new check and its default land in the
# same commit and arrive together via one git pull.
if [[ -f "$ENV_FILE" ]]; then
    declare -A heal_defaults=(
        [SENSOR_MODE]=passive
        [NETFLOW_COLLECTOR_HOST]=192.168.166.8
        # Service deployment toggles — discoverability heal. NOT in
        # required[] below: operators may legitimately set these to
        # 'disabled', and the compose `${VAR:-enabled}` fallback means
        # absence is functionally equivalent to 'enabled'. Healing them
        # in surfaces the toggle keys in every Pi's .env so the on/off
        # switches are visible alongside the rest of the config.
        [DEPLOY_AUVIK]=enabled
        [DEPLOY_D2_AGENT]=enabled
        [DEPLOY_FREERADIUS_PROXY]=enabled
        [DEPLOY_NETFLOW_PROXY]=enabled
        [DEPLOY_SYSLOG_PROXY]=enabled
        [DEPLOY_ZABBIX_AGENT2]=enabled
        [DEPLOY_ZABBIX_PROXY]=enabled
        # OOB console heals to DISABLED, unlike the toggles above — it is
        # opt-in per Pi (4G HAT hardware required). Healing the key in
        # keeps update.sh's absent-key handling unambiguous.
        [DEPLOY_OOB_CONSOLE]=disabled
    )
    # DOCKER_GID default is host-derived, not a fleet-wide literal.
    host_docker_gid=$(getent group docker 2>/dev/null | cut -d: -f3 || true)
    [[ -n "$host_docker_gid" ]] && heal_defaults[DOCKER_GID]="$host_docker_gid"

    # NETBOX_SITE_SLUG mirrors EDGE_SITE_ID by convention — both keys hold
    # the tenant's NetBox site slug (steelriver, etc.). Heal so that Pis
    # provisioned before NETBOX_SITE_SLUG was a required key recover via
    # `git pull && update.sh` instead of needing manual .env editing.
    existing_site_id=$(env_get EDGE_SITE_ID)
    [[ -n "$existing_site_id" ]] && heal_defaults[NETBOX_SITE_SLUG]="$existing_site_id"

    for k in "${!heal_defaults[@]}"; do
        if ! grep -q "^${k}=" "$ENV_FILE"; then
            if echo "${k}=${heal_defaults[$k]}" >> "$ENV_FILE" 2>/dev/null; then
                echo "  preflight: healed .env — appended ${k}=${heal_defaults[$k]}" >&2
            fi
        fi
    done
fi

# --- 3. Required keys present + non-empty -------------------------------
# Operator-supplied keys + DOCKER_GID. DOCKER_GID is required because
# docker compose interpolates it from .env at graph-parse time, so a
# missing key leaves zabbix-agent2's group_add unresolved and silently
# stops the start phase mid-recreate (containers stuck in 'Created').
# Auto-managed (GIT_SHA, COMPOSE_PROFILES) are handled by update.sh and
# are deliberately NOT required here.
required=(
    TZ EDGE_HOSTNAME EDGE_SITE_ID NETBOX_SITE_SLUG
    TENANT_ID TENANT_NAME ENVIRONMENT
    TS_AUTHKEY
    GRAYLOG_HOST ZABBIX_SERVER_HOST ZABBIX_SERVER_PORT RADIUS_HOME_SERVER
    NETFLOW_COLLECTOR_HOST
    RADIUS_SHARED_SECRET LOCAL_CLIENT_SECRET LOCAL_CLIENT_SUBNET
    AUVIK_USERNAME AUVIK_API_KEY AUVIK_DOMAIN_PREFIX
    AGENT_TOKEN CONTROLLER_URL SENSOR_MODE
    DOCKER_GID
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

# --- 3.5. OOB console: conditional requirements + hardware gating -------
# Only when the operator has switched the OOB stack on. Both directions:
# enabled-without-HAT aborts (flag on wrong Pi / HAT not seated);
# HAT-without-enabled is a non-fatal notice (freshly fitted, not yet on).
# Uses the shared envfile.sh parser — a raw grep here dies SILENTLY under
# pipefail when a key line is absent entirely (review 2026-08-13 finding
# #4), bypassing the fail() aggregation contract; env_get returns empty
# with rc 0 for absent keys and matches compose's dotenv semantics.
if [[ -f "$ENV_FILE" ]]; then
    oob_flag=$(deploy_flag DEPLOY_OOB_CONSOLE disabled)
    hat_present=false
    for _v in /sys/bus/usb/devices/*/idVendor; do
        [[ -f "$_v" && "$(cat "$_v" 2>/dev/null)" == "1e0e" ]] && hat_present=true && break
    done
    if [[ "$oob_flag" == "enabled" ]]; then
        for k in OOB_APN TS_OOB_AUTHKEY; do
            v=$(env_get "$k")
            [[ -n "$v" && "$v" != "REPLACE_ME" ]] || fail "DEPLOY_OOB_CONSOLE=enabled but $k is missing or empty"
        done
        [[ -f "$COMPOSE_DIR/oob-console/ports.yaml" ]] \
            || fail "DEPLOY_OOB_CONSOLE=enabled but oob-console/ports.yaml missing"
        $hat_present || fail "DEPLOY_OOB_CONSOLE=enabled but no SIM7600 (USB vendor 1e0e) found — wrong Pi, or HAT not seated"
    elif $hat_present; then
        echo "  preflight: NOTE 4G HAT detected but DEPLOY_OOB_CONSOLE is not 'enabled'" >&2
    fi
fi

# --- 4. TS_AUTHKEY must be OAuth-client format --------------------------
# Pre-auth keys (tskey-auth-*) expire after 90d and break Pis. Only OAuth
# client secrets (tskey-client-*) are acceptable in production.
if [[ -n "${TS_AUTHKEY:-}" && "${TS_AUTHKEY}" != "REPLACE_ME" \
      && "$TS_AUTHKEY" != tskey-client-* ]]; then
    fail "TS_AUTHKEY must start with 'tskey-client-' (OAuth secret); pre-auth keys expire and re-break Pis"
fi

# --- 5. DOCKER_GID format and host match --------------------------------
# DOCKER_GID is required (check 3 catches absence). Here we validate it's
# numeric and matches the host's actual docker group GID.
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

# --- 5b. SENSOR_MODE must be one of passive|active|lab ------------------
# Agent's resolve_sensor_mode() coerces invalid values to 'passive' with a
# warning log; preflight catches typos (e.g. 'actively', 'lab1') here so
# operators get a loud failure at deploy time instead of a silently downgraded
# sensor mode.
if [[ -n "${SENSOR_MODE:-}" && "${SENSOR_MODE}" != "REPLACE_ME" ]]; then
    case "$SENSOR_MODE" in
        passive|active|lab) ;;
        *) fail "SENSOR_MODE='$SENSOR_MODE' is not one of: passive, active, lab" ;;
    esac
fi

# --- 6. docker-compose.yml parses with this .env ------------------------
# DOCKER_GID is sourced via the `set -a` block above (required key, check 3).
# COMPOSE_PROFILES has a sane default for legacy .envs that predate it.
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
