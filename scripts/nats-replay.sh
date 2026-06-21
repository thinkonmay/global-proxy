#!/usr/bin/env bash
# Republish messages from a JetStream DLQ subject back to the primary subject.
#
# Usage:
#   ./scripts/nats-replay.sh jobs.volume.dlq jobs.volume
#   NATS_URL=nats://localhost:4222 ./scripts/nats-replay.sh jobs.volume.dlq jobs.volume
#
# Requires: nats CLI (https://github.com/nats-io/natscli)
set -euo pipefail

DLQ="${1:?dlq subject (e.g. jobs.volume.dlq)}"
PRIMARY="${2:?primary subject (e.g. jobs.volume)}"
NATS_URL="${NATS_URL:-nats://localhost:4222}"
STREAM="${DLQ//./_}"

echo "Replaying stream ${STREAM} (${DLQ}) -> ${PRIMARY} via ${NATS_URL}"

count=0
while IFS= read -r line; do
  [[ -z "${line}" ]] && continue
  nats --server "$NATS_URL" pub "$PRIMARY" "$line"
  count=$((count + 1))
done < <(nats --server "$NATS_URL" stream view "$STREAM" --raw 2>/dev/null || true)

echo "Replayed ${count} message(s)"
