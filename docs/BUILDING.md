# Building

This repository contains two components:

- `device-daemon/` (C): ARM64-friendly remote hashing daemon using a small binary RPC protocol, with optional RandomX integration.
- `xmrig/` (C++): XMRig miner with an experimental remote backend scaffold (disabled by default unless built with `-DWITH_REMOTE=ON`).

## Prerequisites (Debian/Ubuntu)

```bash
sudo apt-get update
# Common
sudo apt-get install -y build-essential pkg-config git cmake
# XMRig deps
sudo apt-get install -y libuv1-dev libssl-dev
# RandomX (for daemon, native build)
sudo apt-get install -y librandomx-dev
```

For Android (aarch64/Termux) cross-builds, install Android NDK r26d or newer and ensure the LLVM toolchain wrappers are on disk (e.g. `.../android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin`).

## Build XMRig (amd64)

```bash
cmake -S xmrig -B xmrig/build \
  -DWITH_REMOTE=ON \
  -DWITH_OPENCL=OFF -DWITH_CUDA=OFF -DWITH_HWLOC=OFF
cmake --build xmrig/build -j$(nproc)
```

Run a quick stress test:
```bash
./xmrig/build/xmrig --stress --donate-level=0 --print-time=10
```

## Build device-daemon (native)

Without RandomX (for quick smoke tests):
```bash
cd device-daemon
gcc -O2 -pthread -o device_daemon device_daemon.c
```

With RandomX (recommended):
```bash
gcc -O2 -pthread -DHAVE_RANDOMX -o device_daemon device_daemon.c -lrandomx
```

On amd64 you can also build a release binary under `build/amd64/`:
```bash
mkdir -p build/amd64
cc -O2 -pthread -DHAVE_RANDOMX \
  -Idevice-daemon \
  device-daemon/device_daemon.c \
  -o build/amd64/device-daemon -lrandomx -ldl -lm
```

## Cross-building device-daemon for arm64

```bash
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install -y crossbuild-essential-arm64 gcc-aarch64-linux-gnu librandomx-dev:arm64
cd device-daemon
# Using Debian packaging (see PACKAGING.md)
dpkg-buildpackage -us -uc -B -aarm64
```

### Android (aarch64/Termux) via NDK

Compile with the NDK Clang wrappers and link against RandomX built for Android:
```bash
BIN=/path/to/android-ndk-r26d/toolchains/llvm/prebuilt/linux-x86_64/bin
PREFIX=/path/to/android/randomx/prefix
SRC=device-daemon/device_daemon.c
OBJ=build/android-aarch64/device_daemon.o
OUT=device-daemon-android-aarch64

"$BIN/aarch64-linux-android24-clang" \
  -Wall -Wextra -O2 -std=c11 -pthread -DHAVE_RANDOMX -fPIE \
  -I"$PREFIX/include" -c "$SRC" -o "$OBJ"

"$BIN/aarch64-linux-android24-clang++" \
  -fPIE -pie -Wl,-z,relro -Wl,-z,now \
  -o "$OUT" "$OBJ" -L"$PREFIX/lib" -lrandomx \
  -static-libstdc++ -static-libgcc -latomic -ldl -lm
```

Notes:
- On Android/Termux huge pages and JIT may be unavailable. The daemon falls back to interpreter mode for correctness.
- The Android binary is dynamically linked against bionic; deploy via Termux and run directly.

## Performance considerations

- Huge pages for RandomX greatly improve performance. Example (allocate ~2.3 GB):
  ```bash
  echo 1200 | sudo tee /proc/sys/vm/nr_hugepages
  grep -i huge /proc/meminfo
  ```
- MSR optimizations (XMRig, x86):
  ```bash
  sudo modprobe msr
  # Run XMRig with sufficient privileges so it can apply MSR tweaks
  ```
