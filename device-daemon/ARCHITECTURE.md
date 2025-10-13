# Architecture Overview

## System Design

The P2P Mining Cluster is designed as a decentralized system where nodes collaborate to perform mining operations efficiently across heterogeneous hardware.

## Components

### 1. Node Management (`node.c`, `node.h`)

Responsible for:
- Node lifecycle (creation, destruction)
- Hardware capability detection (CPU cores, RAM, AES-NI)
- Mining statistics tracking
- Local mining control

**Key Structures:**
- `node_t`: Represents a local or remote node
- `node_capabilities_t`: Hardware specifications
- `node_stats_t`: Performance metrics

### 2. Network Layer (`network.c`, `network.h`)

Handles all P2P communication:
- TCP socket management
- Peer discovery and connection
- Message protocol implementation
- Connection lifecycle

**Protocol Messages:**
```
MSG_HELLO           - Initial handshake with capability exchange
MSG_HELLO_REPLY     - Handshake response
MSG_CAPABILITIES    - Capability announcement
MSG_PEER_LIST       - Peer sharing
MSG_WORKUNIT_*      - Work distribution
MSG_DATASET_*       - Dataset sharing
MSG_HEARTBEAT       - Keep-alive
MSG_GOODBYE         - Graceful disconnect
```

**Message Format:**
```c
struct msg_header_t {
    uint32_t magic;      // 0x4D494E45 ("MINE")
    uint16_t version;    // Protocol version
    uint16_t msg_type;   // Message type
    uint32_t payload_len;// Payload length
    uint32_t checksum;   // Data integrity
}
```

### 3. Workload Management (`workload.c`, `workload.h`)

Distributes and tracks mining work:
- Work unit creation and management
- Assignment based on node capabilities
- Progress tracking
- Result collection

**Work Unit Lifecycle:**
```
PENDING -> ASSIGNED -> COMPUTING -> COMPLETED/FAILED
```

### 4. Configuration (`config.c`, `config.h`)

Centralized configuration management:
- Command-line argument parsing
- Default values
- Mode selection (master/worker/auto)

## Data Flow

### Worker Connection Flow
```
1. Worker connects to Master TCP socket
2. Worker sends MSG_HELLO with capabilities
3. Master responds with MSG_HELLO_REPLY
4. Master adds worker to peer list
5. Periodic MSG_HEARTBEAT messages
```

### Work Distribution Flow
```
1. Worker sends MSG_WORKUNIT_REQUEST
2. Master evaluates available work
3. Master considers worker capabilities
4. Master assigns work via MSG_WORKUNIT_ASSIGN
5. Worker processes work locally
6. Worker submits MSG_WORKUNIT_RESULT
7. Master validates and records result
```

### Dataset Sharing Flow
```
1. Low-RAM worker needs dataset
2. Worker sends MSG_DATASET_REQUEST to master
3. Master checks if dataset host available
4. Master forwards request to dataset host
5. Dataset host sends MSG_DATASET_CHUNK(s)
6. Worker caches dataset chunks
7. Worker uses cached data for mining
```

## Threading Model

Current implementation is single-threaded for simplicity. Future enhancements could include:

- **Network Thread**: Handle all I/O operations
- **Mining Threads**: One per CPU core
- **Management Thread**: Statistics, heartbeats, cleanup

## Memory Architecture

### Master Node
```
- Peer list (connection state, capabilities)
- Work queue (pending, assigned, completed)
- Optional: Dataset (if acting as host)
```

### Worker Node
```
- Connection to master
- Current work unit
- Mining context (algorithm-specific)
- Optional: Dataset cache chunks
```

## Capability-Based Work Assignment

The master considers:

1. **CPU Cores**: More cores = more parallel work
2. **RAM**: Sufficient RAM = can handle larger datasets
3. **AES-NI**: Hardware acceleration for RandomX
4. **Compute Power**: Weighted score for assignment priority

Formula:
```c
compute_power = cpu_cores * (has_aes_ni ? 1.5 : 1.0)
```

## Fault Tolerance

### Connection Loss
- Periodic heartbeats detect dead connections
- Master reassigns abandoned work units
- Workers attempt reconnection

### Work Unit Timeout
- Master tracks assignment time
- Unfinished work reassigned after timeout
- Prevents worker crashes from losing work

## Security Considerations

**Current Implementation:**
- No encryption (plaintext TCP)
- No authentication
- No work validation

**Future Enhancements:**
- TLS for encrypted communication
- Node authentication with keys
- Work proof validation
- Rate limiting

## Extensibility

### Adding New Mining Algorithms

1. Define algorithm constants in `config.h`
2. Implement mining logic in algorithm-specific module
3. Update work unit structure if needed
4. Add initialization in `node_create()`

### Adding New Message Types

1. Define type in `msg_type_t` enum
2. Implement handler in `network_handle_message()`
3. Add sender function if needed
4. Update protocol documentation

## Performance Considerations

### Network Optimization
- Non-blocking I/O prevents stalls
- Batch work assignment reduces round-trips
- Dataset chunking enables progressive loading

### CPU Optimization
- Work unit size tunable per algorithm
- Thread affinity (future)
- SIMD optimizations (algorithm-specific)

### Memory Optimization
- Dataset shared among workers
- Work queue size limited
- Peer list bounded

## Deployment Topologies

### Star Topology (Current)
```
        [Master]
       /   |    \
   [W1]  [W2]  [W3]
```

### Hierarchical (Future)
```
      [Master]
      /      \
  [Sub1]    [Sub2]
   / \        / \
 [W1][W2]  [W3][W4]
```

### Mesh (Future)
```
[N1]---[N2]
 |  \ /  |
 |   X   |
 |  / \  |
[N3]---[N4]
```

## Build System

Uses GNU Make with:
- Separate object directory
- Automatic dependency detection
- Clean/install targets
- Configurable compiler flags

## Testing Strategy

1. **Unit Tests**: Test individual components
2. **Integration Tests**: Test component interaction
3. **Network Tests**: Test P2P communication
4. **Load Tests**: Stress test with many workers
5. **Algorithm Tests**: Validate mining correctness

## Future Architecture Enhancements

1. **Dynamic Discovery**: Multicast/broadcast for auto-discovery
2. **Load Balancing**: Real-time work redistribution
3. **Fault Recovery**: Checkpoint/resume for long work
4. **Metrics System**: Prometheus/Grafana integration
5. **Hot Reload**: Configuration updates without restart
