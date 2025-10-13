# Packaging

This repository provides Debian packaging for both components.

## device-daemon (arm64)

Cross-build on amd64 host:

```bash
sudo dpkg --add-architecture arm64
sudo apt-get update
sudo apt-get install -y debhelper devscripts dpkg-dev pkg-config \
  crossbuild-essential-arm64 gcc-aarch64-linux-gnu librandomx-dev:arm64

cd device-daemon
# Build binary-only for arm64
dpkg-buildpackage -us -uc -B -aarm64
```

Artifacts are placed one level above the project directory, e.g.:

- `../device-daemon_0.1.0_arm64.deb`
- `../device-daemon-dbgsym_0.1.0_arm64.deb`

Notes:
- `debian/control` declares `librandomx-dev:arm64` to satisfy `dpkg-checkbuilddeps` in cross builds.
- The daemon links `-lrandomx` when compiled with `-DHAVE_RANDOMX`.

## xmrig (amd64)

Build with remote backend enabled and minimal deps:

```bash
sudo apt-get install -y debhelper devscripts dpkg-dev build-essential \
  cmake pkg-config libuv1-dev libssl-dev

cd xmrig
# Binary-only build (native arch)
dpkg-buildpackage -us -uc -b
```

Artifacts:
- `../xmrig-remote_6.21.0+remote1_amd64.deb`
- `../xmrig-remote-dbgsym_6.21.0+remote1_amd64.deb`

Packaging details:
- `debian/rules` configures with `-DWITH_REMOTE=ON` and disables OpenCL/CUDA/HWLOC.
- `debian/control` declares build deps (`cmake`, `pkg-config`, `libuv1-dev`, `libssl-dev`).
