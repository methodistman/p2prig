#!/bin/bash

set -ex # Exit on error and print commands

# Change to the script's directory to make relative paths work
cd "$(dirname "$0")"

# Project root (parent of packaging/)
PROJECT_ROOT="$(cd .. && pwd)"

# Get the project version from the Debian changelog
VERSION=$(dpkg-parsechangelog -lDEBIAN/changelog -S Version)

# Create a dist directory in the project root
mkdir -p ../dist

# Architectures to build for
ARCHS=("amd64" "arm64")

for ARCH in "${ARCHS[@]}"; do
    echo "--- Building for $ARCH ---"

    # Set up build environment
    BUILD_DIR="/tmp/p2p-miner-build-$ARCH"
    PKG_DIR="$BUILD_DIR/p2p-miner_${VERSION}_${ARCH}"
    rm -rf "$BUILD_DIR"
    mkdir -p "$PKG_DIR/usr/local/bin"
    mkdir -p "$PKG_DIR/DEBIAN"

    # Create control file from template
    sed -e "s/##VERSION##/$VERSION/" -e "s/##ARCH##/$ARCH/" DEBIAN/control > "$PKG_DIR/DEBIAN/control"

    # Copy changelog
    cp DEBIAN/changelog "$PKG_DIR/DEBIAN/"

    # Set compilers and enable RandomX for both arches
    if [ "$ARCH" = "arm64" ]; then
        export CC=aarch64-linux-gnu-gcc
        export CXX=aarch64-linux-gnu-g++
    else
        export CC=gcc
        export CXX=g++
    fi
    RX_FLAG=1

    # Build RandomX and stage into arch-specific prefix
    # Prefer submodule at $PROJECT_ROOT/randomx; fall back to cloning if missing
    use_clone=0
    RX_SRC_DIR="$PROJECT_ROOT/randomx"
    RX_BUILD_DIR="$BUILD_DIR/RandomX-build"
    RX_PREFIX="$BUILD_DIR/randomx-dist"
    if [ ! -f "$RX_SRC_DIR/CMakeLists.txt" ]; then
        use_clone=1
        RX_SRC_DIR="$BUILD_DIR/RandomX-src"
        rm -rf "$RX_SRC_DIR"
        git clone --depth 1 https://github.com/tevador/RandomX.git "$RX_SRC_DIR"
    fi
    rm -rf "$RX_BUILD_DIR" "$RX_PREFIX"
    CMAKE_ARGS=(
        -S "$RX_SRC_DIR"
        -B "$RX_BUILD_DIR"
        -DCMAKE_BUILD_TYPE=Release
        -DBUILD_SHARED_LIBS=ON
        -DPORTABLE=ON
        -DCMAKE_INSTALL_PREFIX="$RX_PREFIX"
    )
    if [ "$ARCH" = "arm64" ]; then
        CMAKE_ARGS+=(
            -DCMAKE_SYSTEM_NAME=Linux
            -DCMAKE_SYSTEM_PROCESSOR=aarch64
            -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc
            -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++
        )
    fi
    cmake "${CMAKE_ARGS[@]}"
    cmake --build "$RX_BUILD_DIR" -j
    cmake --install "$RX_BUILD_DIR"
    # Additionally build static library variant into the same prefix (if supported)
    RX_BUILD_DIR_STATIC="$BUILD_DIR/RandomX-build-static"
    rm -rf "$RX_BUILD_DIR_STATIC"
    STATIC_ARGS=(
        -S "$RX_SRC_DIR"
        -B "$RX_BUILD_DIR_STATIC"
        -DCMAKE_BUILD_TYPE=Release
        -DPORTABLE=ON
        -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_INSTALL_PREFIX="$RX_PREFIX"
    )
    if [ "$ARCH" = "arm64" ]; then
        STATIC_ARGS+=(
            -DCMAKE_SYSTEM_NAME=Linux
            -DCMAKE_SYSTEM_PROCESSOR=aarch64
            -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc
            -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++
        )
    fi
    cmake "${STATIC_ARGS[@]}"
    cmake --build "$RX_BUILD_DIR_STATIC" -j || true
    cmake --install "$RX_BUILD_DIR_STATIC" || true
    if [ ! -e "$RX_PREFIX/lib/librandomx.so" ] && [ -z "$(ls -1 "$RX_PREFIX"/lib/librandomx.so* 2>/dev/null)" ]; then
        echo "Error: Failed to build RandomX shared library for $ARCH" >&2
        exit 1
    fi

    # Build the project from the parent directory, linking against staged RandomX
    (cd .. && make clean && \
      make ENABLE_RANDOMX=$RX_FLAG \
        CFLAGS='-Wall -Wextra -O2 -std=c11 -pthread -DHAVE_RANDOMX -I'"$RX_PREFIX/include"' -fopenmp' \
        LDFLAGS='-pthread -lm -L'"$RX_PREFIX/lib"' -lrandomx -lstdc++ -fopenmp -ldl')

    # Copy the binary
    cp ../bin/p2p-miner "$PKG_DIR/usr/local/bin/"

    # Install helper script for Unmineable TLS
    install -m 0755 ../scripts/run-unmineable-rx.sh "$PKG_DIR/usr/local/bin/p2p-miner-unmineable-rx"

    # Bundle staged RandomX libraries for runtime (shared + static if available)
    if [ "$RX_FLAG" = "1" ]; then
        mkdir -p "$PKG_DIR/usr/local/lib"
        for f in "$RX_PREFIX"/lib/librandomx.so* "$RX_PREFIX"/lib/librandomx.a; do
            [ -e "$f" ] || continue
            cp -a "$f" "$PKG_DIR/usr/local/lib/"
        done
        # ldconfig hooks
        cat >"$PKG_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v ldconfig >/dev/null 2>&1; then ldconfig || true; fi
exit 0
EOF
        chmod 0755 "$PKG_DIR/DEBIAN/postinst"
        cat >"$PKG_DIR/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if command -v ldconfig >/dev/null 2>&1; then ldconfig || true; fi
exit 0
EOF
        chmod 0755 "$PKG_DIR/DEBIAN/postrm"
    fi

    # Build the .deb package
    dpkg-deb --build "$PKG_DIR"

    # Move the package to the dist directory
    mv "$BUILD_DIR"/*.deb ../dist/

    echo "--- Built ../dist/$(basename "$PKG_DIR").deb ---"

done

# Clean up
unset CC CXX
(cd .. && make clean)

echo "
All packages built successfully:"
ls -l ../dist/
