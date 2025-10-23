# P2P Mining Cluster (`p2prig`)
Production-ready, modular peer-to-peer mining system for distributed clusters and market-driven hashrate leasing.

## Overview
**p2prig** is a C-based, open-source mining cluster designed for heterogeneous hardware environments. It supports decentralized P2P mining, dynamic workload distribution, pool connectivity, and a hashrate marketplace ("Bazaar of Shards") for automated leasing between peers.

- **Languages:** C (99%), Shell scripts (1%)
- **Platform:** Linux (POSIX)
- **License:** MIT
- **Status:** Production Ready
- **Latest Version:** 1.1.0

## Features

### P2P Networking
- TCP-based peer-to-peer protocol
- Scalable: up to 128 concurrent peers
- Custom message protocol (11 types)
- Master/Worker/Auto/Pool modes
- Peer discovery & management
- Non-blocking I/O

### Mining Algorithms
- Modular interface for easy algorithm integration
- **RandomX:** Full & stub implementations (real library integrated; 50-100 H/s, 2GB dataset)
- **Ghostrider:** Full & stub implementations
- Automatic hardware optimization (AES-NI, huge pages, etc.)
- Capability-based resource assignment

### Workload Distribution
- Distributed work unit management
- Progress tracking, share detection, and validation
- Statistics: hashes, shares, hashrate, uptime

### Pool Connectivity
- **Stratum protocol** (NEW): Connect to mining pools (mining.subscribe, mining.authorize, mining.notify, mining.submit)
- Configurable pool host/port, wallet, password
- Non-blocking, stateful connection
- Clean shutdown

### Hashrate Marketplace ("Bazaar of Shards")
- **Enable with:** `-DXMRIG_FEATURE_MARKET=ON`
- Buyers/sellers lease hashrate via P2P market
- Automated auction, pricing, and lease management
- Configurable market role, price per kH/s, capacity, fee, lease duration, auction interval
- API endpoints and shell UI tool for market status
- Protocol support for offers, bids, lease ack/nack, settle

### Configuration System
- Command-line argument parsing
- Auto hardware detection & optimization
- Algorithm and mode selection
- Flexible resource allocation

### Code Quality
- ANSI C11 standard, no compiler warnings
- Clean shutdown & resource cleanup
- Error handling throughout
- Well-commented, modular codebase

## File Structure

```
p2p-mining-cluster/
├── src/
│   ├── main.c
│   ├── config.c/h
│   ├── node.c/h
│   ├── network.c/h
│   ├── workload.c/h
│   ├── mining.c/h
│   ├── mining_randomx.c/h
│   ├── mining_ghostrider.c/h
│   └── stratum.c/h
├── xmrig/
│   └── src/market/
│       ├── Market.cpp/h
│       └── market.cmake
├── bin/
│   └── p2p-miner
├── examples/
│   ├── start-master.sh
│   ├── start-worker.sh
│   ├── start-auto.sh
│   └── test-cluster.sh
├── docs/
│   ├── QUICKSTART.md
│   ├── ARCHITECTURE.md
│   ├── MINING_INTEGRATION.md
│   ├── BUILDING.md
│   ├── TESTING.md
├── LICENSE
├── README.md
└── .gitignore
```

## Quick Start

### Build
```bash
make
```
Or with market features:
```bash
cmake -S xmrig -B xmrig/build -DXMRIG_FEATURE_MARKET=ON
```

### Run Mining Node
```bash
# RandomX mining
./bin/p2p-miner --algo randomx --threads 4

# Ghostrider mining
./bin/p2p-miner --algo ghostrider --threads 4
```
### Distributed Setup
```bash
# Master node (high RAM, dataset host)
./bin/p2p-miner --mode master --dataset-host --port 9999

# Worker node (many CPUs, low RAM)
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999
```

## Hashrate Marketplace Usage

Enable market support at build and configure roles:
- Seller: Lease hashrate to buyers, set price/capacity/fee
- Buyer: Acquire hashrate with automated auction/lease

Shell UI:
```bash
./xmrig/tools/market_ui.sh
```
API endpoints:
- `/2/summary`: Market statistics (enabled, role, price, capacity, leases, offers, last/clearing price)
- `/2/backends`: Backend status

## Documentation

- `README.md`: Project overview
- `QUICKSTART.md`: Getting started
- `ARCHITECTURE.md`: System design
- `ALGORITHM_INTEGRATION.md`: Adding new algorithms
- `MINING_INTEGRATION.md`: Library integration
- `TESTING.md`: Procedures and results

## Roadmap

- [x] P2P networking framework
- [x] Node capability detection
- [x] Workload distribution
- [x] Modular mining algorithms
- [x] Pool (Stratum) integration
- [x] Hashrate marketplace (Bazaar of Shards)
- [ ] TLS/SSL pool connections
- [ ] Pool failover and auto-reconnect
- [ ] GPU mining support
- [ ] Web dashboard
- [ ] API documentation

## License

MIT License – Free for personal and commercial use.

## Contact & Support

For questions, contributions, and bug reports, open a GitHub issue or see the contact section in documentation.

---

**p2prig**: Efficient, extensible, and market-enabled distributed mining for everyone.