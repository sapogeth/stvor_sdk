#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")"/.. && pwd)
cd "$ROOT"

PORT=8080

echo "Starting relay server on ws://localhost:$PORT"
node relay-server.js &
RELAY_PID=$!
echo "relay pid=$RELAY_PID"

sleep 0.5

echo "Starting alice"
node demo/client.js alice@example.com &
ALICE_PID=$!

sleep 0.2

echo "Starting bob"
node demo/client.js bob@example.com &
BOB_PID=$!

echo "Clients started: $ALICE_PID $BOB_PID"

wait $ALICE_PID $BOB_PID || true

echo "Shutting down relay ($RELAY_PID)"
kill $RELAY_PID || true
