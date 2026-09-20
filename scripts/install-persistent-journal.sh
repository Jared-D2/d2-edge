#!/usr/bin/env bash
# Makes the systemd journal survive reboots on this Pi. Idempotent — safe to
# run on every bootstrap and every update. See the header of
# shared/files/60-d2-journald-persistent.conf for the why.
set -euo pipefail

EDGE_DIR=${EDGE_DIR:-/opt/d2-edge}
SRC="$EDGE_DIR/shared/files/60-d2-journald-persistent.conf"
DST_DIR=/etc/systemd/journald.conf.d
DST="$DST_DIR/60-d2-journald-persistent.conf"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)" >&2
  exit 1
fi
[[ -f "$SRC" ]] || exit 0

changed=0
if [[ ! -f "$DST" ]] || ! cmp -s "$SRC" "$DST"; then
  mkdir -p "$DST_DIR"
  install -m 0644 -o root -g root "$SRC" "$DST"
  changed=1
fi

# journald only writes to disk when its machine-id directory exists with the
# right group/ACLs; tmpfiles owns that layout.
if [[ ! -d "/var/log/journal/$(cat /etc/machine-id)" ]]; then
  mkdir -p /var/log/journal
  systemd-tmpfiles --create --prefix /var/log/journal >/dev/null 2>&1 || true
  changed=1
fi

if (( changed )); then
  # Restart picks up Storage=; --flush moves this boot's /run journal onto
  # disk so the current boot is retained too, not just future ones.
  systemctl restart systemd-journald
  journalctl --flush >/dev/null 2>&1 || true
  echo "  persistent journal enabled ($DST)"
fi
