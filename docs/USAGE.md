### Connect to a remote device (Phase 1/2)

Configure via environment variables (temporary interface for POC):

```bash
export P2PRIG_HOST=127.0.0.1
export P2PRIG_PORT=9000
export P2PRIG_TOKEN=secret-token   # optional if device doesn’t require token
./xmrig/build/xmrig --stress --donate-level=0 --print-time=10
```

On successful handshake, XMRig logs a remote connection message and keeps the backend enabled.
# Usage

## Device Daemon (ARM64)

### Install (.deb)

```bash
# On the ARM64 target
sudo dpkg -i device-daemon_0.1.0_arm64.deb || sudo apt -f install
```

### Run

```bash
# Basic (no auth, legacy-compatible)
device_daemon -p 9000

# Require handshake + token auth (Phase 1/2)
P2PRIG_TOKEN=secret-token device_daemon -p 9000 --require-handshake -T secret-token

# Optional TLS (if built with HAVE_OPENSSL)
device_daemon -p 9000 --tls-cert server.crt --tls-key server.key \
  --tls-ca ca.crt --tls-require-client-cert --require-handshake -T secret-token
```

- On start, the daemon listens on TCP `:9000` and sends a `META_RESP` JSON with `cpu_count` and `max_batch`.
- It accepts `JOB_SUBMIT`, optional `JOB_ABORT`, responds with `RESULT` and final `DONE`.
- Keepalive `PING/PONG` supported.

### RandomX

If job `flags` has bit0 set, the daemon expects RandomX fields and will compute RandomX hashes:
- `rx_seed[32]` and `rx_height` (be32) supplied by the host.
- Device maintains a per-process RandomX cache and thread-local VMs.

### Notes

- Huge pages are recommended for RandomX performance.
- Endianness: all multibyte integers in frames are big-endian.

## XMRig (amd64)

### Build

```bash
cmake -S xmrig -B xmrig/build \
  -DWITH_REMOTE=ON \
  -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_HWLOC=OFF
cmake --build xmrig/build -j$(nproc)
```

### Quick tests

- Stress test (internet required; 10-second stats):
  ```bash
  ./xmrig/build/xmrig --stress --donate-level=0 --print-time=10
  ```
- Embedded RandomX benchmark:
  ```bash
  ./xmrig/build/xmrig --bench=1M
  ./xmrig/build/xmrig --bench=10M
  ```

### Remote backend status

- The remote backend is included as an experimental scaffold in `src/backend/remote/` and compiled when `-DWITH_REMOTE=ON`.
- Integration to enumerate remote devices and spawn socket workers is pending. Until then, CPU mining, benchmark and stress test work as usual.

## Protocol reference

See `docs/PROTOCOL.md` for frame formats and opcodes.
