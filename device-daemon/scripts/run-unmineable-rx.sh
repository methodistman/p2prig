#!/usr/bin/env bash
set -euo pipefail

# Sample script to mine RandomX (Monero algo) on Unmineable via TLS
# Requires: socat (sudo apt-get install socat)
# Usage: ./run-unmineable-rx.sh [extra miner args]
# Env overrides: MINER_BIN, USER, LOCAL_PORT, POOL_HOST, POOL_PORT

MINER_BIN=${MINER_BIN:-p2p-miner}
POOL_HOST=${POOL_HOST:-rx.unmineable.com}
POOL_PORT=${POOL_PORT:-443}
LOCAL_PORT=${LOCAL_PORT:-3333}
# Replace with your wallet/worker as needed
USER=${USER:-"TRX:TRzVcqTsDE1fr6XLmhKkoWMEJHojgwaxdH.unmineable_worker_dikyct"}
PASS=${PASS:-x}

# Find miner binary if not in PATH
if ! command -v "$MINER_BIN" >/dev/null 2>&1; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -x "$SCRIPT_DIR/../bin/p2p-miner" ]; then
    MINER_BIN="$SCRIPT_DIR/../bin/p2p-miner"
  else
    echo "Error: p2p-miner not found in PATH and ../bin/p2p-miner not executable" >&2
    exit 1
  fi
fi

# Check socat availability
if ! command -v socat >/dev/null 2>&1; then
  echo "Error: socat is required. Install with: sudo apt-get install socat" >&2
  exit 1
fi

# Start TLS tunnel: local TCP -> TLS to pool
# For strict cert validation, add: ,verify=1,cafile=/etc/ssl/certs/ca-certificates.crt
# and optionally ,servername=$POOL_HOST (requires newer socat)
TUNNEL_LOG=$(mktemp)
(socat -d -d TCP-LISTEN:"$LOCAL_PORT",reuseaddr,fork OPENSSL:"$POOL_HOST":"$POOL_PORT",verify=0 >>"$TUNNEL_LOG" 2>&1) &
TUNNEL_PID=$!

echo "Started TLS tunnel PID $TUNNEL_PID: localhost:$LOCAL_PORT -> $POOL_HOST:$POOL_PORT (TLS)"
trap 'echo "Stopping TLS tunnel..."; kill "$TUNNEL_PID" 2>/dev/null || true' EXIT INT TERM

# Give the tunnel a moment to be ready
sleep 0.5

# Run miner pointing at the local tunnel
exec "$MINER_BIN" \
  --algo randomx \
  --pool 127.0.0.1:"$LOCAL_PORT" \
  --user "$USER" \
  --password "$PASS" \
  "$@"
