#!/usr/bin/env bash
# Republish messages from a JetStream DLQ subject back to the primary subject.
# Usage: nats-replay jobs.volume.dlq jobs.volume
set -euo pipefail
DLQ="${1:?dlq subject}"
PRIMARY="${2:?primary subject}"
NATS_URL="${NATS_URL:-nats://localhost:4222}"
nats --server "$NATS_URL" stream view "${DLQ//./_}" --raw | while read -r line; do
  nats --server "$NATS_URL" pub "$PRIMARY" "$line"
done
