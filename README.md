# p2prig

A monorepo for a peer-to-peer mining setup:

- device-daemon (C): lightweight remote hashing daemon for ARM64 devices (phones/tablets). Handles work frames over TCP/TLS, executes RandomX, streams results.
- xmrig (C++): XMRig miner with an experimental remote backend scaffold (disabled by default unless built with WITH_REMOTE=ON).

## Repository layout

- device-daemon/: Remote worker daemon (arm64-focused)
- xmrig/: XMRig miner with remote backend scaffold
- docs/: Protocol, build, and packaging docs

## Quick start

- Build and run XMRig locally (amd64):
  ```bash
  cmake -S xmrig -B xmrig/build -DWITH_REMOTE=ON -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_HWLOC=OFF
  cmake --build xmrig/build -j$(nproc)
  ./xmrig/build/xmrig --stress --donate-level=0 --print-time=10
  ```

- Build/package instructions for device-daemon (Android aarch64 and Debian arm64/amd64): see `docs/PACKAGING.md`.

- Run device-daemon on target:
  ```bash
  # Android/Termux (aarch64, bionic):
  dpkg -i deviced-<version>-arm64.deb  # installs /usr/bin/device-daemon
  device-daemon --bind 127.0.0.1 -p 9000

  # Native Linux (amd64):
  sudo dpkg -i device-daemon-<version>-amd64.deb || sudo apt -f install
  device-daemon --bind 127.0.0.1 -p 9000
  ```

- Example XMRig to UnMineable (SSL 443), with remote backend env:
  ```bash
  export P2PRIG_HOST=127.0.0.1
  export P2PRIG_PORT=9000
  xmrig -a rx -k \
    -o stratum+ssl://rx.unmineable.com:443 \
    -u TRX:TRzVcqTsDE1fr6XLmhKkoWMEJHojgwaxdH.worker1 \
    -p x --threads=4
  ```

- Protocol reference: see `docs/PROTOCOL.md`.
- Build and packaging guides: see `docs/BUILDING.md`, `docs/PACKAGING.md`.

## Status

- device-daemon: RandomX integrated; job submit/abort, result streaming, heartbeat; per-connection write mutex; AArch64 inline asm for endian swaps and 256-bit compare.
- xmrig remote backend: minimal scaffold for integration. CPU backend and stress/bench run are fully functional.

## Licensing

- xmrig/ is GPLv3 (see `xmrig/LICENSE`).
- device-daemon: GPLv3 (see `device-daemon/LICENSE`).

