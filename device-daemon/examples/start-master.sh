#!/bin/bash
# Start a master node with dataset hosting capability
# Use this on a system with sufficient RAM (4GB+ for RandomX)

PORT=${1:-9999}
ALGO=${2:-randomx}
THREADS=${3:-auto}

echo "Starting P2P Mining Cluster - Master Node"
echo "Port: $PORT"
echo "Algorithm: $ALGO"
echo "Threads: $THREADS"
echo ""

if [ "$THREADS" = "auto" ]; then
    ../bin/p2p-miner --mode master --port "$PORT" --algo "$ALGO" --dataset-host
else
    ../bin/p2p-miner --mode master --port "$PORT" --algo "$ALGO" --dataset-host --threads "$THREADS"
fi
