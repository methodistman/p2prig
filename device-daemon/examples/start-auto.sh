#!/bin/bash
# Start in auto mode - the node will discover the network
# and determine its optimal role based on hardware capabilities

ALGO=${1:-randomx}

echo "Starting P2P Mining Cluster - Auto Mode"
echo "Algorithm: $ALGO"
echo "The node will auto-detect hardware and network configuration"
echo ""

../bin/p2p-miner --algo "$ALGO"
