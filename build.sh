#!/bin/bash
set -euo pipefail

# Xray-core optimized build script
# Target: Linux amd64 (AVX2/GOAMD64=v3)
#
# All performance optimizations are pure Go:
#   - TCP_NODELAY on all TCP sockets
#   - Zero-alloc IsCompleteRecord for Vision
#   - Uplink + downlink splice for Vision and Trojan
#   - Fast math/rand/v2 PRNG for Vision padding
#   - recvmmsg(2) batch UDP reads (64 packets/syscall)
#   - kTLS kernel offload (AES-128/256-GCM, ChaCha20-Poly1305)
#   - eBPF XDP + sockmap programs
#   - Configurable TLS session cache (XRAY_TLS_CACHE_SIZE env)
#
# Usage:
#   ./build.sh              # Build for current platform
#   ./build.sh amd64        # Build for amd64 (GOAMD64=v3, AVX2 required)
#   ./build.sh arm64        # Build for arm64

GO="${GO:-/usr/local/go/bin/go}"
OUTNAME="xray"
GOARCH="${1:-amd64}"
GOOS="linux"

LDFLAGS="-s -w"
BUILDFLAGS="-trimpath"

if [ "$GOARCH" = "amd64" ]; then
    export GOAMD64=v3  # AVX2, BMI1/2, FMA — requires Haswell+ or Zen+
fi

echo "Building Xray-core for ${GOOS}/${GOARCH}..."
CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" \
    "$GO" build -o "$OUTNAME" $BUILDFLAGS -ldflags="$LDFLAGS" ./main/

echo "Done: $(ls -lh $OUTNAME | awk '{print $5}') static binary"
file "$OUTNAME"
