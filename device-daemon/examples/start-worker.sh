#!/bin/bash
# Start a worker node that connects to a master
# Use this on systems with many CPUs but potentially limited RAM

if [ -z "$1" ]; then
    echo "Usage: $0 <master_ip:port> [algo] [threads]"
    echo "Example: $0 192.168.1.100:9999 randomx 8"
    exit 1
fi

MASTER=$1
ALGO=${2:-randomx}
THREADS=${3:-auto}

echo "Starting P2P Mining Cluster - Worker Node"
echo "Connecting to: $MASTER"
echo "Algorithm: $ALGO"
echo "Threads: $THREADS"
echo ""

if [ "$THREADS" = "auto" ]; then
    ../bin/p2p-miner --mode worker --connect "$MASTER" --algo "$ALGO"
else
    ../bin/p2p-miner --mode worker --connect "$MASTER" --algo "$ALGO" --threads "$THREADS"
fi
