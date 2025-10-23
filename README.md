# p2prig

A monorepo for a peer-to-peer mining setup:

- device-daemon (C): lightweight remote hashing daemon for ARM64 devices (phones/tablets). Handles work frames over TCP/TLS, executes RandomX, streams results.
- xmrig (C++): XMRig miner with an experimental remote backend scaffold (disabled by default unless built with WITH_REMOTE=ON).

## Repository layout

- device-daemon/: Remote worker daemon (arm64-focused)
- xmrig/: XMRig miner with remote backend scaffold
- docs/: Protocol, build, and packaging docs

## Dependencies

### Common (Debian/Ubuntu)

- build-essential, pkg-config, git, cmake
- Install with:
  ```bash
  sudo apt-get update
  sudo apt-get install -y build-essential pkg-config git cmake
  ```

### XMRig (miner) build/runtime

- libuv1-dev, libssl-dev
- Install with:
  ```bash
  sudo apt-get install -y libuv1-dev libssl-dev
  ```
- Notes:
  - Default build here disables optional features: `-DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_HWLOC=OFF`.
  - If you enable them, you must install corresponding SDKs/dev headers and drivers on your system.
  - XMRig’s TLS Stratum requires OpenSSL; `libssl-dev` provides headers for build and pulls in runtime libs.

### device-daemon (native Linux)

- Optional RandomX acceleration via `librandomx`:
  ```bash
  sudo apt-get install -y librandomx-dev
  ```
- Build examples (see `docs/BUILDING.md` for full commands):
  - Without RandomX: `gcc -O2 -pthread -o device_daemon device_daemon.c`
  - With RandomX: `gcc -O2 -pthread -DHAVE_RANDOMX -o device_daemon device_daemon.c -lrandomx`
- Runtime libs: glibc, pthread; when linking with RandomX also `librandomx` (and `dl`, `m` as needed by toolchain).

### Cross-building device-daemon for arm64

- Debian multiarch toolchains and RandomX (arm64):
  ```bash
  sudo dpkg --add-architecture arm64
  sudo apt-get update
  sudo apt-get install -y crossbuild-essential-arm64 gcc-aarch64-linux-gnu librandomx-dev:arm64
  ```

### Android (aarch64/Termux)

- Android NDK r26d (or newer) for aarch64 toolchains.
- Build RandomX for Android and point includes/libs accordingly.
- See `docs/BUILDING.md` for the exact clang wrapper invocations and linker flags.

### Performance/system prerequisites

- RandomX benefits from huge pages on Linux; consider configuring `nr_hugepages` for best performance.
- Ensure CPU governor and power settings allow sustained performance if benchmarking.

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

