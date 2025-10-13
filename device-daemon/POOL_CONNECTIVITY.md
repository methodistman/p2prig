# Pool Connectivity Guide

## Overview

The P2P Mining Cluster now supports **Stratum protocol** for connecting to mining pools. This enables real-world mining and share submission to production pools.

## Features

✅ **Stratum Protocol** - Industry-standard mining protocol  
✅ **Pool Connection** - Connect to any Stratum-compatible pool  
✅ **Authentication** - Username/password authorization  
✅ **Job Management** - Receive and process mining jobs  
✅ **Share Submission** - Submit valid shares to pool  
✅ **Statistics** - Track accepted/rejected shares  

## Quick Start

### Basic Pool Mining

```bash
./bin/p2p-miner \
  -o pool.supportxmr.com:3333 \
  -u YOUR_WALLET_ADDRESS \
  -a randomx \
  -t 4
```

### With Password

```bash
./bin/p2p-miner \
  -o pool.example.com:3333 \
  -u YOUR_WALLET \
  -w YOUR_PASSWORD \
  -a randomx
```

### P2P Cluster with Pool

**Master Node (connects to pool):**
```bash
./bin/p2p-miner \
  -o pool.supportxmr.com:3333 \
  -u YOUR_WALLET \
  --mode master \
  --dataset-host \
  -t 2
```

**Worker Nodes (connect to master):**
```bash
./bin/p2p-miner \
  --mode worker \
  --connect MASTER_IP:9999 \
  -t 4
```

## Command-Line Options

### Pool Options

| Option | Description | Default |
|--------|-------------|---------|
| `-o HOST:PORT` | Pool address | None (required) |
| `-u USERNAME` | Wallet/username | None (required) |
| `-w PASSWORD` | Pool password | `x` |

### Example

```bash
./bin/p2p-miner \
  --pool pool.minexmr.com:4444 \
  --user 4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge \
  --algo randomx \
  --threads 8
```

## Popular Pools

### Monero (RandomX)

**SupportXMR:**
```bash
-o pool.supportxmr.com:3333
```

**MineXMR:**
```bash
-o pool.minexmr.com:4444
```

**HashVault:**
```bash
-o pool.hashvault.pro:3333
```

### Other Coins

For other RandomX or Ghostrider coins, check the pool's documentation for:
- Pool address and port
- Stratum configuration
- Wallet format

## Stratum Protocol

### Connection Flow

1. **Connect** - TCP connection to pool
2. **Subscribe** - `mining.subscribe` - Get session info
3. **Authorize** - `mining.authorize` - Authenticate
4. **Receive Jobs** - Pool sends `mining.notify`
5. **Submit Shares** - Send `mining.submit` when found

### Example Session

```
→ {"id":1,"method":"mining.subscribe","params":["p2p-miner/1.0"]}
← {"id":1,"result":[[["mining.notify","<session_id>"]],<nonce>]}

→ {"id":2,"method":"mining.authorize","params":["YOUR_WALLET","x"]}
← {"id":2,"result":true}

← {"method":"mining.notify","params":[...]}  # New job

→ {"id":3,"method":"mining.submit","params":["<user>","<job_id>","<nonce>","<result>"]}
← {"id":3,"result":true}  # Share accepted!
```

## Statistics

The system tracks:
- **Jobs Received** - Number of jobs from pool
- **Shares Submitted** - Total shares sent
- **Shares Accepted** - Accepted by pool
- **Shares Rejected** - Rejected (stale/invalid)
- **Acceptance Rate** - Percentage accepted

### Example Output

```
=== Stratum Statistics ===
Pool: pool.supportxmr.com:3333
State: Authorized
Jobs Received: 15
Shares Submitted: 42
Shares Accepted: 40
Shares Rejected: 2
Acceptance Rate: 95.2%
Connected For: 1847 seconds
```

## Troubleshooting

### Connection Refused

**Symptom:** `Failed to connect to pool`

**Solutions:**
- Check pool address and port
- Verify firewall rules
- Test with telnet: `telnet pool.address.com 3333`
- Check if pool is online

### Authorization Failed

**Symptom:** `Error from pool` or rejected shares

**Solutions:**
- Verify wallet address format
- Check if pool requires payment ID
- Ensure correct algorithm (RandomX vs others)
- Some pools require registration

### High Rejection Rate

**Symptom:** Many rejected shares

**Causes:**
- Stale shares (slow network)
- Wrong difficulty
- Invalid nonce range

**Solutions:**
- Use lower latency pool
- Reduce share submission delay
- Check system time sync

### No Jobs Received

**Symptom:** Connected but no mining jobs

**Solutions:**
- Wait longer (pools send jobs periodically)
- Check Stratum logs for errors
- Verify pool is active and has blocks

## Advanced Usage

### Multiple Workers to One Pool

All workers can mine to the same pool with different wallet addresses:

```bash
# Worker 1
./bin/p2p-miner -o pool.com:3333 -u WALLET1 -t 4

# Worker 2
./bin/p2p-miner -o pool.com:3333 -u WALLET2 -t 4

# Worker 3
./bin/p2p-miner -o pool.com:3333 -u WALLET3 -t 4
```

### Hybrid Mode: P2P + Pool

Master connects to pool, distributes work to P2P workers:

```bash
# Master (pool connection)
./bin/p2p-miner \
  -o pool.supportxmr.com:3333 \
  -u YOUR_WALLET \
  --mode master \
  --dataset-host \
  --port 9999

# Workers (P2P connection)
./bin/p2p-miner --mode worker --connect master:9999 -t 8
./bin/p2p-miner --mode worker --connect master:9999 -t 4
```

## Implementation Details

### Stratum Module

**Files:**
- `src/stratum.h` - Protocol definitions
- `src/stratum.c` - Implementation (~450 lines)

**Key Functions:**
- `stratum_connect()` - Establish connection
- `stratum_subscribe()` - Subscribe to pool
- `stratum_authorize()` - Authenticate user
- `stratum_submit_share()` - Submit found share
- `stratum_process()` - Event loop processing

### JSON-RPC

Minimal JSON implementation for Stratum:
- Simple string-based parsing
- No external dependencies
- Efficient for mining protocol

### Message Handling

The system handles:
- `mining.notify` - New job from pool
- `mining.set_difficulty` - Difficulty updates
- Result responses (accept/reject)
- Error messages

## Performance Considerations

### Network Latency

- Lower latency = fewer stale shares
- Choose geographically close pool
- Typical latency: 10-100ms acceptable

### Share Submission

- Shares submitted immediately when found
- No queuing or batching
- Direct TCP connection for speed

### Connection Stability

- Automatic reconnection (future enhancement)
- Graceful disconnect handling
- Keep-alive heartbeats

## Security

### Current Implementation

⚠️ **No TLS/SSL** - Plaintext connection  
⚠️ **Password sent in clear** - Not encrypted  

### Recommendations

- Use pools that support TLS (future)
- Don't reuse passwords
- Pool password is usually not sensitive (`x` is common)

### Best Practices

✅ Use dedicated mining wallet  
✅ Monitor pool activity  
✅ Check pool reputation  
✅ Review pool fees  

## Testing

### Test Without Real Pool

For development/testing, you can test connection without mining:

```bash
# This will connect but not mine (no -u specified)
./bin/p2p-miner -o pool.supportxmr.com:3333 -u test -t 1
```

### Verify Connection

```bash
# Short test run
timeout 60 ./bin/p2p-miner \
  -o pool.supportxmr.com:3333 \
  -u YOUR_WALLET \
  -t 2
```

Check output for:
- "Stratum: Connected"
- "Stratum: Subscribing..."
- "Stratum: Authorizing..."
- "New job received"

## Future Enhancements

- [ ] TLS/SSL support
- [ ] Auto-reconnection
- [ ] Failover pools
- [ ] Pool benchmarking
- [ ] Nicehash support
- [ ] Proxy mode
- [ ] Share caching

## Examples

See `examples/` directory for:
- `mine-to-pool.sh` - Pool mining script
- `pool-cluster.sh` - P2P cluster with pool
- `test-pool.sh` - Connection testing

## References

- [Stratum Protocol](https://en.bitcoin.it/wiki/Stratum_mining_protocol)
- [XMR Pool List](https://miningpoolstats.stream/monero)
- [RandomX Spec](https://github.com/tevador/RandomX)

---

**Status:** ✅ **PRODUCTION READY**

Pool connectivity is fully functional and ready for real mining operations.
