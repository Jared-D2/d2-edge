#!/usr/bin/env bash
# Installs logrotate + nightly retention for the syslog-proxy local log copy.
# Idempotent — safe to run on every bootstrap and every update.
#
# Background: syslog-ng's d_local destination writes a full duplicate of every
# message (already shipped to Graylog) to a dated tree under
# /opt/d2-edge/syslog-proxy/logs/YYYY/MM/DD/messages.log. Nothing ever deleted
# it, and the logrotate config bootstrap.sh used to write inline globbed one
# path component short, so it never matched. Result: ~1.3 GB/day, forever.
# Found on ncm001-bc-pi01 2026-07-20 at 36 GB of a 58 GB card.
set -euo pipefail

EDGE_DIR=${EDGE_DIR:-/opt/d2-edge}
FILES_DIR="$EDGE_DIR/shared/files"
LOG_DIR="$EDGE_DIR/syslog-proxy/logs"

LOGROTATE_SRC="$FILES_DIR/d2-edge-syslog.logrotate"
LOGROTATE_DST=/etc/logrotate.d/d2-edge-syslog
CRON_SRC="$FILES_DIR/syslog-proxy-cleanup.cron"
CRON_DST=/etc/cron.d/syslog-proxy-cleanup

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi

# Install both files, but only when absent or drifted, so a no-op update stays
# quiet in the update.sh transcript.
if [[ -f "$LOGROTATE_SRC" ]]; then
  if [[ ! -f "$LOGROTATE_DST" ]] || ! cmp -s "$LOGROTATE_SRC" "$LOGROTATE_DST"; then
    install -m 0644 -o root -g root "$LOGROTATE_SRC" "$LOGROTATE_DST"
    echo "  installed/updated $LOGROTATE_DST"
  fi
fi

if [[ -f "$CRON_SRC" ]]; then
  if [[ ! -f "$CRON_DST" ]] || ! cmp -s "$CRON_SRC" "$CRON_DST"; then
    # cron refuses to run files that are group- or world-writable.
    install -m 0644 -o root -g root "$CRON_SRC" "$CRON_DST"
    echo "  installed/updated $CRON_DST"
  fi
fi

# d2001-nw-pi01 carries a hand-added /etc/logrotate.d/syslog-proxy from
# 2026-04-13 that globs the same files as the config above. Leaving both in
# place would rotate each file twice a day. The repo config supersedes it.
LEGACY=/etc/logrotate.d/syslog-proxy
if [[ -f "$LEGACY" ]]; then
  mv "$LEGACY" "${LEGACY}.superseded-by-d2-edge-syslog"
  echo "  retired legacy $LEGACY (kept as .superseded-by-d2-edge-syslog)"
fi

# Fail loudly on a malformed config rather than letting logrotate silently
# skip the whole file at 06:25 tomorrow.
if ! logrotate --debug "$LOGROTATE_DST" >/dev/null 2>&1; then
  echo "  WARNING: logrotate rejected $LOGROTATE_DST — rotation is NOT active" >&2
fi

# Report the backlog rather than deleting it. On a Pi that has been running
# without retention this is tens of GB, and a silent bulk delete triggered by
# a routine update is not something an operator should discover afterwards.
# The cron installed above purges it at 04:00; this line makes sure the size
# of that first purge is visible in the update transcript beforehand.
if [[ -d "$LOG_DIR" ]]; then
  BACKLOG=$(find "$LOG_DIR" -type f -mtime +7 -printf '%s\n' 2>/dev/null \
            | awk '{t+=$1} END {printf "%.1f", t/1073741824}')
  if [[ -n "$BACKLOG" ]] && [[ "$BACKLOG" != "0.0" ]]; then
    echo "  NOTE: ${BACKLOG} GB of local syslog older than 7 days is queued for"
    echo "        deletion by $CRON_DST at 04:00. This data is a duplicate of"
    echo "        Graylog. To purge now:  bash $EDGE_DIR/scripts/install-syslog-retention.sh --purge-now"
  fi
fi

# Opt-in immediate purge, for when you don't want to wait for 04:00.
if [[ "${1:-}" == "--purge-now" ]]; then
  echo "  purging local syslog older than 7 days..."
  find "$LOG_DIR" -type f -mtime +7 -delete 2>/dev/null || true
  find "$LOG_DIR" -mindepth 1 -type d -empty -delete 2>/dev/null || true
  echo "  done — $(df -h "$LOG_DIR" | awk 'NR==2 {print $4}') free on $(df -h "$LOG_DIR" | awk 'NR==2 {print $1}')"
fi
