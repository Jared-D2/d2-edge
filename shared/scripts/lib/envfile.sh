# shared/scripts/lib/envfile.sh
#
# The ONE .env parser for shell scripts in this repo. Source it; never
# re-implement a grep|cut pipeline inline. History: update.sh's private
# deploy_flag() required the literal unquoted string 'enabled', while
# docker compose's dotenv loader strips surrounding quotes and inline
# comments — so DEPLOY_SYSLOG_PROXY="enabled" was enabled to compose but
# 'disabled' to update.sh, which then tore the running service down
# (introduced 40181c5, fleet-wide). These helpers exist to keep the shell
# side agreeing with compose's dotenv semantics:
#   - surrounding double/single quotes stripped, inner content preserved
#     verbatim (including # and spaces; no trimming inside quotes)
#   - unquoted values: comment starts at whitespace-then-#; a # glued to
#     the value is data; leading/trailing whitespace trimmed
#   - last occurrence of a key wins; `export ` prefix and spaces around =
#     are accepted
# Never `source` a .env to read it — that executes operator content.

# env_get KEY [FILE] — print KEY's value, empty if absent/unreadable.
# FILE defaults to $ENV_FILE, then /opt/d2-edge/.env.
env_get() {
    local key="$1" file="${2:-${ENV_FILE:-/opt/d2-edge/.env}}" raw
    [[ -f "$file" ]] || return 0
    raw=$(sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?${key}[[:space:]]*=(.*)\$/\2/p" "$file" | tail -n1)
    raw="${raw#"${raw%%[![:space:]]*}"}"
    case "$raw" in
        \"*)
            raw="${raw#\"}"
            raw="${raw%%\"*}"
            ;;
        \'*)
            raw="${raw#\'}"
            raw="${raw%%\'*}"
            ;;
        \#*)
            raw=""
            ;;
        *)
            raw=$(sed -E 's/[[:space:]]+#.*$//' <<<"$raw")
            raw="${raw%"${raw##*[![:space:]]}"}"
            ;;
    esac
    printf '%s\n' "$raw"
}

# deploy_flag KEY [DEFAULT] — value of KEY from $ENV_FILE, falling back to
# DEFAULT (default 'enabled') when the key is absent or empty. Mirrors the
# compose-side `${KEY:-DEFAULT}` in docker-compose.yml profiles: — keep the
# DEFAULT argument in lockstep with the profile's fallback there
# (original eight services: enabled; oob pair: disabled).
deploy_flag() {
    local val
    val=$(env_get "$1")
    echo "${val:-${2:-enabled}}"
}
