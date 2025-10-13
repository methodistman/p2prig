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

- Cross-build ARM64 .deb for device-daemon:
  ```bash
  cd device-daemon
  dpkg-buildpackage -us -uc -B -aarm64
  ```
  Artifacts appear in repo root (../device-daemon_*.deb).

- Run device-daemon on ARM64 target:
  ```bash
  sudo dpkg -i device-daemon_0.1.0_arm64.deb || sudo apt -f install
  device_daemon 9000
  ```

- Protocol reference: see `docs/PROTOCOL.md`.
- Build and packaging guides: see `docs/BUILDING.md`, `docs/PACKAGING.md`.

## Status

- device-daemon: RandomX integrated; job submit/abort, result streaming, heartbeat; per-connection write mutex; AArch64 inline asm for endian swaps and 256-bit compare.
- xmrig remote backend: minimal scaffold for integration. CPU backend and stress/bench run are fully functional.

## Licensing

- xmrig/ is GPLv3 (see `xmrig/LICENSE`).
- device-daemon: pending license selection by repository owner. Until then, treat as "All rights reserved" for redistribution; intended to be compatible with GPLv3.

