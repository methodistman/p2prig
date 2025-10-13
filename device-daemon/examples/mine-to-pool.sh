#!/bin/bash
# Mine directly to a pool using Stratum protocol

# Configuration
POOL_HOST="pool.supportxmr.com"
POOL_PORT="3333"
WALLET="YOUR_WALLET_ADDRESS_HERE"
THREADS=$(nproc)
ALGORITHM="randomx"

# Check if wallet is set
if [ "$WALLET" = "YOUR_WALLET_ADDRESS_HERE" ]; then
    echo "Error: Please set your wallet address in this script"
    echo "Edit this file and change WALLET variable"
    exit 1
fi

echo "=== Mining to Pool ==="
echo "Pool: $POOL_HOST:$POOL_PORT"
echo "Wallet: $WALLET"
echo "Threads: $THREADS"
echo "Algorithm: $ALGORITHM"
echo ""

# Start mining
../bin/p2p-miner \
    -o "$POOL_HOST:$POOL_PORT" \
    -u "$WALLET" \
    -a "$ALGORITHM" \
    -t "$THREADS"
