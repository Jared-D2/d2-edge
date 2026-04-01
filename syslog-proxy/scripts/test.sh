#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-127.0.0.1}"
PORT="${2:-514}"

logger \
  --server "$TARGET" \
  --port "$PORT" \
  --udp \
  --tag "proxy-test" \
  "Test syslog message from $(hostname) at $(date -Iseconds)"
