# Testing Guide

## Quick Tests

### Test RandomX (Stub Implementation)
```bash
./bin/p2p-miner --algo randomx --threads 2
```

Expected output:
- RandomX initialization messages
- Hash computation starting
- Periodic statistics every 30 seconds
- Share discoveries (with low difficulty for testing)

### Test Ghostrider (Stub Implementation)
```bash
./bin/p2p-miner --algo ghostrider --threads 2
```

Expected output similar to RandomX but with Ghostrider branding.

### Test Master/Worker Setup

**Terminal 1 - Master:**
```bash
./bin/p2p-miner --mode master --port 9999 --algo randomx --threads 2 --dataset-host
```

**Terminal 2 - Worker:**
```bash
./bin/p2p-miner --mode worker --connect 127.0.0.1:9999 --port 10000 --algo randomx --threads 2
```

Expected:
- Master starts listening
- Worker connects successfully
- Both nodes mine independently
- Peer connection shown in network statistics

## Verification Checklist

### Algorithm Integration
- [x] RandomX stub compiles and runs
- [x] Ghostrider stub compiles and runs
- [x] Algorithm selection via CLI works
- [x] Hash computation produces output
- [x] Share detection works
- [x] Statistics display correctly

### Node Functionality
- [x] Hardware capability detection
- [x] Mining start/stop
- [x] Hashrate calculation
- [x] Clean shutdown

### Network Functionality
- [x] Listener starts on specified port
- [x] Peer connections accepted
- [x] Message protocol works
- [x] Graceful disconnect

## Performance Benchmarks

### Stub Implementation
- **RandomX**: ~100-1000 H/s (not real hashing)
- **Ghostrider**: ~100-1000 H/s (not real hashing)

### With Real Libraries
- **RandomX**: Depends on CPU (1000-10000 H/s typical)
- **Ghostrider**: Varies by CPU and algorithm mix

## Testing with Real Libraries

### Install RandomX
```bash
git clone https://github.com/tevador/randomx.git
cd randomx
mkdir build && cd build
cmake -DARCH=native ..
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Update Makefile
Edit `Makefile` and uncomment:
```makefile
CFLAGS += -DHAVE_RANDOMX -I/usr/local/include
LDFLAGS += -lrandomx
```

### Rebuild and Test
```bash
make clean
make
./bin/p2p-miner --algo randomx --threads $(nproc)
```

## Common Issues

### Build Errors
- **Missing math library**: Add `-lm` to LDFLAGS (already included)
- **Implicit function warnings**: Check includes

### Runtime Errors
- **Port already in use**: Change port with `--port`
- **Connection refused**: Ensure master is running first
- **Low hashrate**: Normal for stub implementation

### Memory Issues
- **Out of memory**: Reduce threads with `--threads`
- **Dataset allocation failed**: Use `--dataset-host` flag only on high-RAM systems

## Automated Testing

Create `test.sh`:
```bash
#!/bin/bash
echo "Testing RandomX..."
timeout 5 ./bin/p2p-miner --algo randomx --threads 1 > /tmp/test_rx.log 2>&1
grep -q "Mining started successfully" /tmp/test_rx.log && echo "✓ RandomX OK" || echo "✗ RandomX FAILED"

echo "Testing Ghostrider..."
timeout 5 ./bin/p2p-miner --algo ghostrider --threads 1 > /tmp/test_gr.log 2>&1
grep -q "Mining started successfully" /tmp/test_gr.log && echo "✓ Ghostrider OK" || echo "✗ Ghostrider FAILED"

echo "All tests completed"
```

## Next Steps

1. Install real mining libraries
2. Test with actual mining pools
3. Benchmark performance
4. Tune for your hardware
5. Deploy to production cluster
