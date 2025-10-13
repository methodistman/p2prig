# P2P Mining Cluster
A peer-to-peer distributed mining system for heterogeneous hardware. Nodes collaborate on RandomX and Ghostrider mining by sharing datasets and distributing workloads efficiently.

## Features

- **P2P Networking**: TCP-based P2P protocol with capabilities exchange and stats
- **Pool Connectivity**: Monero-style Stratum client (TLS via helper script)
- **Distributed Mining**: Batch hashing with OpenMP and remote hashing support
- **Dataset Hosting**: High-RAM nodes host RandomX dataset for low-RAM peers
- **Auto-Discovery**: MODE_AUTO uses UDP broadcast (port 10000) to elect a master
- **Algorithm Support**: RandomX (shared lib) and Ghostrider (modular design)
- **Target Gating**: Full 256-bit target validation to avoid low-diff rejects
- **CLI**: Lightweight, terminal-based operation

## Architecture

### Node Types
{{ ... }}
1. **Master Node**: Coordinates workload distribution, manages peer connections, and optionally hosts datasets
2. **Worker Node**: Executes mining work units assigned by the master
3. **Auto Mode**: Automatically discovers network and determines optimal role

### Key Components

- **Network Layer**: TCP-based P2P communication with message protocol
- **Node Management**: Capability detection, statistics tracking, and mining control
- **Workload Distribution**: Smart assignment of work units based on node capabilities
- **Dataset Hosting**: Allows nodes with ample RAM to serve datasets to memory-constrained nodes

## Building

```bash
make
```

This creates the executable at `bin/p2p-miner`.

## Usage

### Start a Master Node (with dataset hosting)

```bash
./bin/p2p-miner --mode master --port 9999 --dataset-host --algo randomx
```

### Start a Worker Node

```bash
./bin/p2p-miner --mode worker --connect 192.168.1.100:9999 --algo randomx
```

### Auto Mode (Network Discovery + Master Election)

```bash
./bin/p2p-miner --mode auto --algo randomx

Discovery beacons are sent over UDP port 10000 (broadcast domain only). A leader (master) is elected by the smallest node ID; workers auto-connect to the master’s TCP port (default 9999).
```

### Command-Line Options

```
-m, --mode MODE          Operation mode: master, worker, or auto (default: auto)
-p, --port PORT          Listen port (default: 9999)
-c, --connect HOST:PORT  Connect to master node
-a, --algo ALGO          Mining algorithm: randomx or ghostrider (default: randomx)
-t, --threads NUM        Number of mining threads (default: auto-detect)
-r, --ram SIZE           Available RAM in MB (default: auto-detect)
-d, --dataset-host       Act as dataset host for nodes with low RAM
-h, --help               Show help message
```

## Use Cases

### Scenario 1: High-RAM Low-CPU System + Low-RAM High-CPU System

**System A** (16GB RAM, 4 cores):
```bash
./bin/p2p-miner --mode master --dataset-host --threads 2
```

**System B** (2GB RAM, 16 cores):
```bash
./bin/p2p-miner --mode worker --connect <System-A-IP>:9999 --threads 16
```

System A is selected as dataset host (highest RAM). System B cannot host (simulate with `--ram 2000`) and requests remote batch hashing from System A using the current pool seed.

### Scenario 2: Heterogeneous Cluster

Multiple systems with varying specifications can join a cluster where the master intelligently distributes work based on each node's capabilities.

## Protocol

The P2P protocol uses a simple message-based system:

- **MSG_HELLO**: Initial handshake with capability exchange
- **MSG_CAPABILITIES**: Announce or update node capabilities
- **MSG_WORKUNIT_REQUEST**: Request work from master
- **MSG_WORKUNIT_ASSIGN**: Master assigns work to node
- **MSG_WORKUNIT_RESULT**: Submit completed work
- **MSG_CAPABILITIES**: Capability update for dataset-host selection
- **MSG_HASH_REQUEST / MSG_HASH_RESPONSE**: Remote hashing via dataset host
- **MSG_HEARTBEAT**: Keep-alive messages

## Memory Requirements

### RandomX
- Dataset: ~2080 MB
- Scratchpad per thread: ~2 MB

### Ghostrider
- Dataset: ~256 MB
- Variable per algorithm

## Algorithm Status

✅ **RandomX** - Modular implementation complete (stub + full support)
✅ **Ghostrider** - Modular implementation complete (stub + full support)

RandomX is integrated via `librandomx.so` and bundled into our Debian packages. Ghostrider remains modular.

## Future Enhancements

- [ ] Add encryption for P2P communication
- [ ] Implement work validation and share submission
- [ ] Add pool connectivity for production mining
- [ ] Web-based monitoring dashboard
- [ ] Dynamic workload rebalancing
- [ ] Fault tolerance and work reassignment
- [ ] GPU coprocessor support

## Debian Packages

Prebuilt .debs (amd64, arm64) bundle `librandomx.so` and include a TLS helper.

Install on Debian/Ubuntu (example for amd64):

```bash
sudo apt-get install -y libgomp1 socat ca-certificates
sudo dpkg -i dist/p2p-miner_1.2.0_amd64.deb
```

Run with Unmineable via TLS:

```bash
USER="TRX:YOURADDR.worker" p2p-miner-unmineable-rx --mode auto --threads 4
```

Notes:
- Open TCP 9999 on the master and UDP 10000 on all nodes for discovery.
- Extra miner flags can be appended to `p2p-miner-unmineable-rx` and are forwarded.

## Development Status

This is an actively evolving implementation. Core P2P networking, auto-discovery, dataset-host selection, and RandomX pool mining are implemented. Remote hashing provides dataset sharing for low-RAM nodes.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions welcome! Areas of focus:
- Mining algorithm integration
- Protocol optimization
- Security hardening
- Performance tuning
- Documentation
