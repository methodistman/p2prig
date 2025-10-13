#!/bin/bash
# Test script to demonstrate cluster functionality locally
# Starts a master and worker node for testing

echo "=== P2P Mining Cluster Test ==="
echo ""
echo "This will start:"
echo "  1. Master node on port 9999"
echo "  2. Worker node on port 10000 connecting to master"
echo ""
echo "Press Ctrl+C in each terminal to stop"
echo ""

# Start master in a new terminal
echo "Starting master node..."
if command -v gnome-terminal &> /dev/null; then
    gnome-terminal -- bash -c "cd $(dirname $0) && ./start-master.sh 9999 randomx 2; exec bash"
    sleep 2
    gnome-terminal -- bash -c "cd $(dirname $0) && ../bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --algo randomx --threads 2; exec bash"
elif command -v xterm &> /dev/null; then
    xterm -e "cd $(dirname $0) && ./start-master.sh 9999 randomx 2; exec bash" &
    sleep 2
    xterm -e "cd $(dirname $0) && ../bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --algo randomx --threads 2; exec bash" &
else
    echo "No terminal emulator found. Run manually:"
    echo "  Terminal 1: ./examples/start-master.sh 9999 randomx 2"
    echo "  Terminal 2: ../bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --algo randomx --threads 2"
fi
