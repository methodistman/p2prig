# Quick Start Guide

## Build the Project

```bash
make
```

## Test Locally

The easiest way to test is to run both a master and worker on the same machine:

### Terminal 1 - Start Master
```bash
./bin/p2p-miner --mode master --port 9999 --dataset-host --threads 2
```

### Terminal 2 - Start Worker
```bash
./bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --threads 2
```

Or use the test script:
```bash
./examples/test-cluster.sh
```

## Real-World Deployment

### Scenario: 2 Machines

**Machine A** (High RAM, Low CPU) - 192.168.1.100
- 8GB RAM, 4 cores
- Acts as master and dataset host

```bash
./bin/p2p-miner --mode master --port 9999 --dataset-host --algo randomx
```

**Machine B** (Low RAM, High CPU) - 192.168.1.101
- 2GB RAM, 16 cores
- Acts as worker, uses remote dataset

```bash
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999 --algo randomx
```

### Scenario: Multiple Workers

You can connect multiple workers to the same master:

**Master** (192.168.1.100):
```bash
./bin/p2p-miner --mode master --port 9999 --dataset-host
```

**Worker 1** (192.168.1.101):
```bash
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999
```

**Worker 2** (192.168.1.102):
```bash
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999
```

**Worker 3** (192.168.1.103):
```bash
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999
```

## Monitoring

The program prints statistics every 30 seconds showing:
- Node information (ID, uptime)
- Hardware capabilities
- Mining statistics (hashes, shares, work units)
- Network information (connected peers)

## Stopping

Press `Ctrl+C` to gracefully shut down any node.

## Troubleshooting

### Connection Refused
- Ensure the master node is running first
- Check firewall rules allow traffic on the specified port
- Verify IP address and port are correct

### Low Performance
- Check if dataset hosting is enabled on a high-RAM node
- Adjust thread count with `--threads` option
- Monitor RAM usage to ensure no swapping

### Port Already in Use
- Change the port with `--port` option
- Ensure no other process is using the default port 9999

## Next Steps

1. **Integrate Mining Libraries**: Link RandomX and Ghostrider libraries for actual mining
2. **Connect to Pool**: Add pool connectivity for production use
3. **Monitoring Dashboard**: Set up web-based monitoring
4. **Optimize Network**: Tune protocol for your specific hardware and network
