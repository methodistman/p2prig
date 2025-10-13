#!/bin/bash
# Set up a P2P cluster that mines to a pool
# Master connects to pool, workers connect to master

POOL_HOST="pool.supportxmr.com"
POOL_PORT="3333"
WALLET="YOUR_WALLET_ADDRESS_HERE"

if [ "$WALLET" = "YOUR_WALLET_ADDRESS_HERE" ]; then
    echo "Error: Please set your wallet address"
    exit 1
fi

case "$1" in
    master)
        echo "Starting Master Node (connects to pool)"
        ../bin/p2p-miner \
            -o "$POOL_HOST:$POOL_PORT" \
            -u "$WALLET" \
            --mode master \
            --dataset-host \
            --port 9999 \
            -t 2
        ;;
    worker)
        if [ -z "$2" ]; then
            echo "Usage: $0 worker <master_ip>"
            exit 1
        fi
        echo "Starting Worker Node (connects to master)"
        ../bin/p2p-miner \
            --mode worker \
            --connect "$2:9999" \
            -t 4
        ;;
    *)
        echo "Usage: $0 {master|worker <master_ip>}"
        echo ""
        echo "Example:"
        echo "  Terminal 1: $0 master"
        echo "  Terminal 2: $0 worker 192.168.1.100"
        exit 1
        ;;
esac
