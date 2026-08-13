#!/usr/bin/env bash
# Tests for shared/scripts/lib/envfile.sh — the single .env parsing helper.
# Semantics under test are docker compose's dotenv rules, because these
# values gate compose `profiles:` and the two parsers MUST agree:
#   - surrounding single/double quotes are stripped, inner content kept
#   - unquoted values: comment starts at whitespace-then-#, edges trimmed
#   - quoted values: # inside quotes is data; after the close quote, comment
#   - last occurrence of a key wins; `export ` prefix and spaces around =
#   - empty/absent value falls back to the caller's default (${VAR:-def})
set -uo pipefail
HERE="$(cd "$(dirname "$0")/../.." && pwd)"
LIB="$HERE/shared/scripts/lib/envfile.sh"
fails=0
check(){ if [[ "$1" == "$2" ]]; then echo "ok: $3"; else echo "FAIL: $3 (got '$1', want '$2')"; fails=$((fails+1)); fi; }

[[ -f "$LIB" ]] || { echo "FAIL: lib missing at $LIB"; exit 1; }
# shellcheck source=/dev/null
. "$LIB"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ENVF="$TMP/test.env"

cat > "$ENVF" <<'EOF'
PLAIN=enabled
DQUOTED="enabled"
SQUOTED='enabled'
TRAILWS=enabled
INLINE_COMMENT=enabled  # switched on 2026-08-01
HASH_NO_SPACE=en#abled
QUOTED_HASH="enabled # not a comment"
QUOTED_THEN_COMMENT="enabled" # comment
DQUOTED_DISABLED="disabled"
EMPTY=
LAST_WINS=disabled
LAST_WINS=enabled
export EXPORTED=enabled
SPACED = enabled
EOF

# --- env_get ---------------------------------------------------------------
check "$(env_get PLAIN "$ENVF")"              "enabled"  "plain value"
check "$(env_get DQUOTED "$ENVF")"            "enabled"  "double quotes stripped"
check "$(env_get SQUOTED "$ENVF")"            "enabled"  "single quotes stripped"
check "$(env_get TRAILWS "$ENVF")"            "enabled"  "trailing whitespace trimmed"
check "$(env_get INLINE_COMMENT "$ENVF")"     "enabled"  "inline comment stripped"
check "$(env_get HASH_NO_SPACE "$ENVF")"      "en#abled" "# without preceding space is data"
check "$(env_get QUOTED_HASH "$ENVF")"        "enabled # not a comment" "# inside quotes is data"
check "$(env_get QUOTED_THEN_COMMENT "$ENVF")" "enabled" "comment after closing quote stripped"
check "$(env_get EMPTY "$ENVF")"              ""         "empty value -> empty"
check "$(env_get ABSENT "$ENVF")"             ""         "absent key -> empty"
check "$(env_get LAST_WINS "$ENVF")"          "enabled"  "last occurrence wins"
check "$(env_get EXPORTED "$ENVF")"           "enabled"  "export prefix accepted"
check "$(env_get SPACED "$ENVF")"             "enabled"  "spaces around = accepted"
check "$(env_get PLAIN /nonexistent)"         ""         "missing file -> empty, no error"

# --- deploy_flag -----------------------------------------------------------
# deploy_flag KEY [DEFAULT] reads ENV_FILE; default default is 'enabled'.
ENV_FILE="$ENVF"
check "$(deploy_flag DQUOTED)"                "enabled"  "deploy_flag: quoted enabled counts as enabled"
check "$(deploy_flag DQUOTED_DISABLED)"       "disabled" "deploy_flag: quoted disabled counts as disabled"
check "$(deploy_flag INLINE_COMMENT)"         "enabled"  "deploy_flag: inline comment ignored"
check "$(deploy_flag ABSENT)"                 "enabled"  "deploy_flag: absent key -> default enabled"
check "$(deploy_flag ABSENT disabled)"        "disabled" "deploy_flag: absent key -> caller default"
check "$(deploy_flag EMPTY)"                  "enabled"  "deploy_flag: empty value -> default (matches \${VAR:-enabled})"
check "$(deploy_flag EMPTY disabled)"         "disabled" "deploy_flag: empty value -> caller default"

# --- consumers actually source the lib -------------------------------------
for f in shared/scripts/update.sh shared/scripts/preflight.sh \
         scripts/install-wazuh-agent.sh scripts/auvik-ensure-tenant.sh; do
    grep -q 'lib/envfile.sh' "$HERE/$f"; check "$?" "0" "$f sources envfile.sh"
    bash -n "$HERE/$f";                  check "$?" "0" "$f syntax OK"
done
# The buggy inline parsers must be gone: no stray grep|cut .env toggle reads.
grep -Eq 'DEPLOY_OOB_CONSOLE=enabled' "$HERE/shared/scripts/update.sh"
check "$?" "1" "update.sh: literal-match OOB gate removed"

[[ "$fails" -eq 0 ]] && { echo "ALL PASS"; exit 0; } || { echo "$fails FAILED"; exit 1; }
