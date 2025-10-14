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

### Android (aarch64, bionic) packaging

The Android/Termux build is an Android PIE binary linked against bionic. Package with a simple staging tree and `dpkg-deb`:

```bash
ROOT=$(pwd)
OUT=$ROOT/device-daemon-android-aarch64   # built with NDK
VER=0.1.1+android1
PKGDIR=$ROOT/pkg/deviced-$VER-arm64
rm -rf "$PKGDIR" && mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/bin"
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: device-daemon
Version: $VER
Architecture: arm64
Maintainer: <maintainer@example.com>
Priority: optional
Section: utils
Description: Remote mining device daemon (Android aarch64 build)
 Android (bionic) build of the device-side RPC daemon for RandomX jobs.
EOF
install -m 0755 "$OUT" "$PKGDIR/usr/bin/device-daemon"
dpkg-deb --build "$PKGDIR"
```

The resulting `.deb` can be installed on Termux via `dpkg -i`.

### device-daemon (amd64, native Linux)

To package a native Linux amd64 daemon without modifying cross-build control, use a minimal staging tree:

```bash
ROOT=$(pwd)
BIN=$ROOT/build/amd64/device-daemon   # built natively and linked with -lrandomx
VER=0.1.1
PKGDIR=$ROOT/pkg/device-daemon-$VER-amd64
rm -rf "$PKGDIR" && mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/bin"
cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: device-daemon
Version: $VER
Architecture: amd64
Maintainer: <maintainer@example.com>
Priority: optional
Section: utils
Depends: librandomx0 (>= 1.1.10), libc6 (>= 2.31)
Description: Remote mining device daemon (amd64)
 Native Linux build of the device-side RPC daemon for RandomX jobs.
EOF
install -m 0755 "$BIN" "$PKGDIR/usr/bin/device-daemon"
dpkg-deb --build "$PKGDIR"
```

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
