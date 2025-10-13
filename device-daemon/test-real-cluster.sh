#!/bin/bash
# Test real RandomX P2P cluster

echo "=== Testing P2P Cluster with Real RandomX ==="
echo ""

# Check if binary exists
if [ ! -f "./bin/p2p-miner" ]; then
    echo "Error: p2p-miner not found. Run 'make' first."
    exit 1
fi

# Kill any existing instances
pkill -f p2p-miner 2>/dev/null || true
sleep 1

echo "Starting Master Node (port 9999, 2 threads)..."
./bin/p2p-miner --mode master --port 9999 --dataset-host --algo randomx --threads 2 > /tmp/master.log 2>&1 &
MASTER_PID=$!
echo "Master PID: $MASTER_PID"

# Wait for master to initialize
echo "Waiting for master to initialize (60 seconds)..."
sleep 65

if ! ps -p $MASTER_PID > /dev/null; then
    echo "Error: Master node failed to start"
    cat /tmp/master.log
    exit 1
fi

echo ""
echo "Starting Worker Node (port 10000, 2 threads)..."
./bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --algo randomx --threads 2 > /tmp/worker.log 2>&1 &
WORKER_PID=$!
echo "Worker PID: $WORKER_PID"

# Wait for worker to initialize
echo "Waiting for worker to initialize (60 seconds)..."
sleep 65

if ! ps -p $WORKER_PID > /dev/null; then
    echo "Error: Worker node failed to start"
    cat /tmp/worker.log
    exit 1
fi

echo ""
echo "=== Cluster Running ==="
echo "Master: PID $MASTER_PID, Log: /tmp/master.log"
echo "Worker: PID $WORKER_PID, Log: /tmp/worker.log"
echo ""
echo "Monitoring for 30 seconds..."
sleep 30

echo ""
echo "=== Master Node Stats ==="
tail -20 /tmp/master.log | grep -E "(Statistics|Hashrate|Shares|Peers)" || echo "No stats yet"

echo ""
echo "=== Worker Node Stats ==="
tail -20 /tmp/worker.log | grep -E "(Statistics|Hashrate|Shares)" || echo "No stats yet"

echo ""
echo "=== Stopping Cluster ==="
kill $MASTER_PID $WORKER_PID 2>/dev/null || true
sleep 2
pkill -9 -f p2p-miner 2>/dev/null || true

echo ""
echo "Test complete. Check logs at:"
echo "  /tmp/master.log"
echo "  /tmp/worker.log"
